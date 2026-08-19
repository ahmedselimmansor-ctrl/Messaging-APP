/**
 * The browser MTProto client.
 *
 * WebSocket rather than a raw socket, because browsers cannot open one — and
 * WebSocket already frames messages, so no MTProto transport codec is needed:
 * one binary WebSocket message carries exactly one MTProto frame.
 *
 * The Go equivalent is pkg/mtclient; the two speak the same protocol and any
 * change to one needs the same change to the other.
 */

import {
  AUTH_KEY_SIZE,
  C,
  DH_G,
  DH_PRIME,
  DH_Q,
  type DHGenOK,
  type Envelope,
  MsgIDGenerator,
  type ReqDHParams,
  type ResPQ,
  SeqNoCounter,
  type ServerDHInner,
  type ServerDHParams,
  authKeyID,
  bigIntToBytes,
  bytesToBigInt,
  decodePayload,
  decodePlain,
  decryptMessage,
  encodePQInnerData,
  encodePayload,
  encodePlain,
  encryptMessage,
  factorPQ,
  igeOpen,
  igeSeal,
  importServerKey,
  modPow,
  peekConstructor,
  randomBigInt,
  randomBytes,
  rsaFingerprint,
  tmpAESKeyIV,
  validateDHValue,
} from "./protocol";
import { equalConstantTime, sha1, toHex } from "./crypto";
import type { Bytes } from "./crypto";

export interface ClientOptions {
  /** WebSocket URL, e.g. wss://api.example.com/mtproto */
  url: string;
  /**
   * The pinned server public key.
   *
   * Pinning is not optional. The handshake protects against a passive
   * observer; only the pin protects against an active one, who would
   * otherwise substitute their own key, learn new_nonce and read the whole
   * Diffie-Hellman exchange.
   */
  serverPublicKeyPEM: string;
  onUpdate?: (update: ServerUpdate) => void;
  onStateChange?: (state: ConnectionState) => void;
  requestTimeoutMs?: number;
}

export type ConnectionState =
  | "disconnected"
  | "connecting"
  | "handshaking"
  | "connected"
  | "reconnecting";

export interface ServerUpdate {
  kind: string;
  chat_id?: number;
  seq?: number;
  user_id?: number;
  date: number;
  payload?: unknown;
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class RPCError extends Error {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(`mtproto rpc error ${code}: ${message}`);
    this.name = "RPCError";
  }

  /** Seconds to wait, parsed out of a FLOOD_WAIT_X message. */
  get floodWaitSeconds(): number | null {
    const m = /FLOOD_WAIT_(\d+)/.exec(this.message);
    return m?.[1] ? parseInt(m[1], 10) : null;
  }
}

export class MTProtoClient {
  private ws: WebSocket | null = null;
  private authKey: Bytes | null = null;
  private keyID: Bytes | null = null;

  private sessionID = 0n;
  private salt = 0n;
  private msgIDs = new MsgIDGenerator();
  private seqNo = new SeqNoCounter();

  private pending = new Map<string, Pending>();
  private handshakeQueue: Array<(frame: Bytes) => void> = [];

  private state: ConnectionState = "disconnected";
  private reconnectAttempt = 0;
  private closing = false;

  userID = 0;
  deviceID = 0;

  constructor(private readonly opts: ClientOptions) {}

  // -------------------------------------------------------------------------
  // Connection
  // -------------------------------------------------------------------------

  async connect(): Promise<void> {
    this.closing = false;
    this.setState("connecting");

    await new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(this.opts.url);
      ws.binaryType = "arraybuffer";
      this.ws = ws;

      const onOpen = () => {
        ws.removeEventListener("error", onError);
        resolve();
      };
      const onError = () => {
        ws.removeEventListener("open", onOpen);
        reject(new Error(`mtproto: cannot connect to ${this.opts.url}`));
      };

      ws.addEventListener("open", onOpen, { once: true });
      ws.addEventListener("error", onError, { once: true });
      ws.addEventListener("message", (ev) => this.onMessage(ev));
      ws.addEventListener("close", () => this.onClose());
    });

    this.setState("handshaking");
    await this.handshake();

    this.sessionID = bytesToBigInt(randomBytes(8)) & ((1n << 62n) - 1n);
    this.reconnectAttempt = 0;
    this.setState("connected");
  }

  close(): void {
    this.closing = true;
    this.ws?.close();
    this.ws = null;
    this.setState("disconnected");
  }

  get authKeyIDHex(): string {
    return this.keyID ? toHex(this.keyID) : "";
  }

  private setState(s: ConnectionState): void {
    this.state = s;
    this.opts.onStateChange?.(s);
  }

  private onClose(): void {
    // Fail everything in flight: the answers are never coming.
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(new Error("mtproto: connection closed"));
    }
    this.pending.clear();

    if (this.closing) {
      this.setState("disconnected");
      return;
    }

    this.setState("reconnecting");

    // Exponential backoff with jitter. The jitter is the important part: the
    // server drains a pod by telling every client at once to reconnect, and
    // without jitter they would all come back simultaneously.
    const base = Math.min(1000 * 2 ** this.reconnectAttempt, 30_000);
    const delay = base * (0.5 + Math.random() * 0.5);
    this.reconnectAttempt += 1;

    setTimeout(() => {
      this.connect().catch(() => {
        /* the next close schedules another attempt */
      });
    }, delay);
  }

  private send(frame: Bytes): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("mtproto: not connected");
    }
    this.ws.send(frame);
  }

  // -------------------------------------------------------------------------
  // Handshake
  // -------------------------------------------------------------------------

  private async handshake(): Promise<void> {
    const serverKey = await importServerKey(this.opts.serverPublicKeyPEM);
    const expectedFingerprint = await rsaFingerprint(this.opts.serverPublicKeyPEM);

    const nonce = randomBytes(16);

    // 1 → req_pq
    this.sendPlain(C.reqPQ, { nonce: Array.from(nonce) });

    // 2 ← res_pq
    const resPQ = await this.awaitPlain<ResPQ>(C.resPQ);
    const serverNonce = new Uint8Array(resPQ.server_nonce);
    if (!equalConstantTime(new Uint8Array(resPQ.nonce), nonce)) {
      throw new Error("mtproto: nonce mismatch");
    }
    if (!resPQ.rsa_fingerprints.includes(expectedFingerprint)) {
      throw new Error(
        "mtproto: the server offered a key we have not pinned — refusing to continue",
      );
    }

    // 3 → req_dh_params, with the proof-of-work factorisation
    const { p, q } = factorPQ(resPQ.pq);
    const newNonce = randomBytes(32);

    const inner = encodePQInnerData({
      pq: resPQ.pq, p, q, nonce, serverNonce, newNonce,
    });
    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt({ name: "RSA-OAEP" }, serverKey, inner),
    );

    this.sendPlain(C.reqDHParams, {
      nonce: Array.from(nonce),
      server_nonce: Array.from(serverNonce),
      p, q,
      rsa_fingerprint: expectedFingerprint,
      encrypted_data: Array.from(encrypted),
    } satisfies ReqDHParams);

    // 4 ← server_dh_params
    const serverDH = await this.awaitPlain<ServerDHParams>(C.serverDHParams);
    const { key: tmpKey, iv: tmpIV } = await tmpAESKeyIV(newNonce, serverNonce);
    const answerBytes = await igeOpen(tmpKey, tmpIV, new Uint8Array(serverDH.encrypted_answer));
    const answer: ServerDHInner = JSON.parse(new TextDecoder().decode(answerBytes));

    // Verify the group. A server that quietly substitutes a weak or composite
    // prime could recover the shared secret, so this check is not optional.
    if (bytesToBigInt(new Uint8Array(answer.dh_prime)) !== DH_PRIME) {
      throw new Error("mtproto: the server proposed a different DH prime");
    }
    if (answer.g !== 2) {
      throw new Error(`mtproto: unexpected generator ${answer.g}`);
    }

    const gA = bytesToBigInt(new Uint8Array(answer.g_a));
    validateDHValue(gA);

    // 5 → set_client_dh_params
    const b = randomBigInt(DH_Q) + (1n << 20n);
    const gB = modPow(DH_G, b, DH_PRIME);

    const clientInner = new TextEncoder().encode(
      JSON.stringify({
        nonce: Array.from(nonce),
        server_nonce: Array.from(serverNonce),
        retry_id: 0,
        g_b: Array.from(bigIntToBytes(gB)),
      }),
    );
    const sealed = await igeSeal(tmpKey, tmpIV, clientInner);

    this.sendPlain(C.setClientDHParams, {
      nonce: Array.from(nonce),
      server_nonce: Array.from(serverNonce),
      encrypted_data: Array.from(sealed),
    });

    // 6 ← dh_gen_ok
    const genOK = await this.awaitPlain<DHGenOK>(C.dhGenOK);

    const shared = modPow(gA, b, DH_PRIME);
    const authKey = bigIntToBytes(shared, AUTH_KEY_SIZE);

    // Verify the server derived the same key.
    const digest = await sha1(authKey);
    const hashInput = new Uint8Array(32 + 1 + 8);
    hashInput.set(newNonce, 0);
    hashInput[32] = 1;
    hashInput.set(digest.subarray(0, 8), 33);
    const expectedHash = (await sha1(hashInput)).subarray(4, 20);

    if (!equalConstantTime(expectedHash, new Uint8Array(genOK.new_nonce_hash))) {
      throw new Error("mtproto: new_nonce_hash mismatch; the server derived a different key");
    }

    this.authKey = authKey;
    this.keyID = await authKeyID(authKey);
  }

  private sendPlain(id: number, value: unknown): void {
    this.send(encodePlain(this.msgIDs.next(0), encodePayload(id, value)));
  }

  private awaitPlain<T>(want: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error("mtproto: handshake step timed out"));
      }, 30_000);

      this.handshakeQueue.push((frame) => {
        clearTimeout(timer);
        try {
          const { body } = decodePlain(frame);
          const got = peekConstructor(body);
          if (got !== want) {
            if (got === C.handshakeError) {
              const e = decodePayload<{ code: string }>(body);
              reject(new Error(`mtproto: the server rejected the handshake: ${e.code}`));
              return;
            }
            reject(new Error(`mtproto: expected constructor 0x${want.toString(16)}`));
            return;
          }
          resolve(decodePayload<T>(body));
        } catch (err) {
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      });
    });
  }

  // -------------------------------------------------------------------------
  // Messages
  // -------------------------------------------------------------------------

  private async onMessage(ev: MessageEvent): Promise<void> {
    const frame = new Uint8Array(ev.data as ArrayBuffer);

    // During the handshake everything is plain and answered in order.
    if (!this.authKey) {
      const handler = this.handshakeQueue.shift();
      handler?.(frame);
      return;
    }

    let msg: Envelope;
    try {
      msg = await decryptMessage(this.authKey, frame);
    } catch {
      // A decryption failure means the stream position is unknown; the
      // connection is unusable.
      this.ws?.close();
      return;
    }

    const constructor = peekConstructor(msg.body);

    switch (constructor) {
      case C.rpcResult: {
        const res = decodePayload<{ req_msg_id: number | string; result: unknown }>(msg.body);
        this.resolve(String(res.req_msg_id), res.result, null);
        break;
      }
      case C.rpcError: {
        const e = decodePayload<{ req_msg_id: number | string; error_code: number; error_message: string }>(msg.body);
        this.resolve(String(e.req_msg_id), null, new RPCError(e.error_code, e.error_message));
        break;
      }
      case C.badServerSalt: {
        // Adopt the corrected salt. This is why a rotation costs one round
        // trip rather than a reconnect.
        const bs = decodePayload<{ new_server_salt: number | string }>(msg.body);
        this.salt = BigInt(bs.new_server_salt);
        break;
      }
      case C.newSessionReset: {
        const ns = decodePayload<{ server_salt: number | string }>(msg.body);
        this.salt = BigInt(ns.server_salt);
        break;
      }
      case C.pong: {
        const p = decodePayload<{ msg_id: number | string }>(msg.body);
        this.resolve(String(p.msg_id), { ok: true }, null);
        break;
      }
      case C.update: {
        const u = decodePayload<ServerUpdate>(msg.body);
        // "reconnect" means the pod is draining: reconnect promptly, because
        // the server is deliberately spreading its shutdown across clients.
        if (u.kind === "reconnect") {
          this.ws?.close();
          return;
        }
        this.opts.onUpdate?.(u);
        break;
      }
      default:
        break;
    }
  }

  private resolve(msgID: string, value: unknown, error: Error | null): void {
    const p = this.pending.get(msgID);
    if (!p) return;
    this.pending.delete(msgID);
    clearTimeout(p.timer);
    if (error) p.reject(error);
    else p.resolve(value);
  }

  /** Sends a method and waits for its answer. */
  async invoke<T>(id: number, request: unknown): Promise<T> {
    if (!this.authKey || !this.keyID) throw new Error("mtproto: not connected");

    const msgID = this.msgIDs.next(0);
    const frame = await encryptMessage(this.authKey, this.keyID, {
      salt: this.salt,
      sessionID: this.sessionID,
      msgID,
      seqNo: this.seqNo.next(true),
      body: encodePayload(id, request),
    });

    const key = String(msgID);
    const timeoutMs = this.opts.requestTimeoutMs ?? 30_000;

    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(key);
        reject(new Error("mtproto: request timed out"));
      }, timeoutMs);

      this.pending.set(key, {
        resolve: resolve as (v: unknown) => void,
        reject,
        timer,
      });

      try {
        this.send(frame);
      } catch (err) {
        this.pending.delete(key);
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  // -------------------------------------------------------------------------
  // API
  // -------------------------------------------------------------------------

  /** Attaches an authenticated identity to the negotiated auth key. */
  async bind(accessToken: string): Promise<{ user_id: number; device_id: number }> {
    const res = await this.invoke<{
      user_id: number;
      device_id: number;
      server_salt: number | string;
      session_id: number | string;
    }>(C.authBind, {
      access_token: accessToken,
      platform: "web",
      app_version: "1.0.0",
      device_model: navigator.userAgent.slice(0, 64),
    });

    this.userID = res.user_id;
    this.deviceID = res.device_id;
    if (res.server_salt) this.salt = BigInt(res.server_salt);
    if (res.session_id) this.sessionID = BigInt(res.session_id);
    return res;
  }

  async sendMessage(chatID: number, body: string, randomID: number) {
    return this.invoke<{
      message_id: string;
      chat_id: number;
      seq: number;
      date: number;
      duplicate?: boolean;
    }>(C.sendMessage, {
      chat_id: chatID,
      type: "text",
      body,
      // The idempotency key. A retry after a network failure sends the same
      // value and gets the original message back rather than posting twice.
      random_id: randomID,
    });
  }

  async getHistory(chatID: number, beforeSeq = 0, limit = 50) {
    return this.invoke<{ messages: HistoryMessage[]; next_before_seq: number }>(
      C.getHistory,
      { chat_id: chatID, before_seq: beforeSeq, limit },
    );
  }

  /**
   * The reconnect catch-up. This is what makes the fire-and-forget realtime
   * layer safe: whatever was missed while disconnected is read back from
   * durable storage.
   */
  async getDifference(cursors: Record<number, number>, limit = 300) {
    return this.invoke<{
      messages: HistoryMessage[];
      truncated: boolean;
      new_cursors: Record<number, number>;
    }>(C.getDifference, { cursors, limit });
  }

  async readHistory(chatID: number, maxSeq: number) {
    return this.invoke<{ chat_id: number; last_read_seq: number; unread_count: number }>(
      C.readHistory,
      { chat_id: chatID, max_seq: maxSeq },
    );
  }

  async getDialogs(limit = 50, offset = 0) {
    return this.invoke<{ dialogs: Dialog[] }>(C.getDialogs, {
      limit, offset, include_archived: false,
    });
  }

  async setTyping(chatID: number, action = "typing") {
    return this.invoke<{ ok: boolean }>(C.setTyping, { chat_id: chatID, action });
  }

  async ping(): Promise<void> {
    const pingID = Number(bytesToBigInt(randomBytes(6)));
    await this.invoke(C.ping, { ping_id: pingID });
  }
}

export interface HistoryMessage {
  message_id: string;
  chat_id: number;
  seq: number;
  sender_id: number;
  type: string;
  body?: string;
  date: string;
  edited_at?: string;
  deleted?: boolean;
}

export interface Dialog {
  chat_id: number;
  type: string;
  title: string;
  peer_id?: number;
  max_seq: number;
  last_read_seq: number;
  unread_count: number;
  muted: boolean;
  pinned: boolean;
}
