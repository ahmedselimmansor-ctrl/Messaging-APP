/**
 * MTProto message envelope, constructor ids and the auth-key handshake.
 *
 * Mirrors pkg/mtproto in the Go server. The wire format is defined there; this
 * is the other half of it.
 */

import type { Bytes } from "./crypto";
import {
  AUTH_KEY_SIZE,
  CLIENT_TO_SERVER,
  SERVER_TO_CLIENT,
  authKeyID,
  bigIntToBytes,
  bytesToBigInt,
  concat,
  deriveKeyIV,
  equalConstantTime,
  fromHex,
  fromUtf8,
  igeDecrypt,
  igeEncrypt,
  modPow,
  msgKey,
  randomBigInt,
  randomBytes,
  sha1,
  utf8,
} from "./crypto";

// ---------------------------------------------------------------------------
// Constructor ids
// ---------------------------------------------------------------------------

export const C = {
  // Handshake, sent unencrypted.
  reqPQ: 0x60469778,
  resPQ: 0x05162463,
  reqDHParams: 0xd712e4be,
  serverDHParams: 0xd0e8075c,
  setClientDHParams: 0xf5045f1f,
  dhGenOK: 0x3bcbf734,
  handshakeError: 0x0a1b2c3d,

  // Service.
  ping: 0x7abe77ec,
  pong: 0x347773c5,
  msgsAck: 0x62d6b459,
  badMsgNotify: 0xa7eff811,
  badServerSalt: 0xedab447b,
  newSessionReset: 0x9ec20908,
  msgContainer: 0x73f1f8dc,
  rpcError: 0x2144ca19,
  rpcResult: 0xf35c6d01,
  destroySession: 0xe7512126,

  // API.
  authBind: 0x10000001,
  sendMessage: 0x10000010,
  getHistory: 0x10000012,
  getDifference: 0x10000014,
  readHistory: 0x10000016,
  setTyping: 0x10000018,
  getDialogs: 0x10000019,
  update: 0x10000030,
  ok: 0x10000031,
} as const;

// ---------------------------------------------------------------------------
// Payload encoding: constructor id + JSON
// ---------------------------------------------------------------------------

export function encodePayload(id: number, value: unknown): Bytes {
  const body = utf8(JSON.stringify(value));
  const out = new Uint8Array(4 + body.length);
  new DataView(out.buffer).setUint32(0, id, true);
  out.set(body, 4);
  return out;
}

export function peekConstructor(payload: Bytes): number {
  if (payload.length < 4) throw new Error("mtproto: payload is shorter than a constructor id");
  return new DataView(payload.buffer, payload.byteOffset, 4).getUint32(0, true);
}

export function decodePayload<T>(payload: Bytes): T {
  if (payload.length < 4) throw new Error("mtproto: payload is shorter than a constructor id");
  return JSON.parse(fromUtf8(payload.subarray(4))) as T;
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

const HEADER_SIZE = 32; // salt(8) session_id(8) msg_id(8) seq_no(4) length(4)
const MIN_PADDING = 12;
const MAX_PADDING = 1024;
export const MAX_MESSAGE_SIZE = 16 << 20;

export interface Envelope {
  salt: bigint;
  sessionID: bigint;
  msgID: bigint;
  seqNo: number;
  body: Bytes;
}

/** Builds the wire frame: auth_key_id ‖ msg_key ‖ AES-IGE(header ‖ body ‖ padding). */
export async function encryptMessage(
  authKey: Bytes,
  keyID: Bytes,
  msg: Envelope,
): Promise<Bytes> {
  if (msg.body.length > MAX_MESSAGE_SIZE) {
    throw new Error(`mtproto: body of ${msg.body.length} bytes exceeds the limit`);
  }

  // Padding is 12..1024 bytes taking the total to a 16-byte boundary. Fixed
  // padding would leak the exact body size.
  const unpadded = HEADER_SIZE + msg.body.length;
  let pad = MIN_PADDING + (16 - ((unpadded + MIN_PADDING) % 16));
  if (pad < MIN_PADDING) pad += 16;

  const header = new Uint8Array(HEADER_SIZE);
  const view = new DataView(header.buffer);
  view.setBigUint64(0, BigInt.asUintN(64, msg.salt), true);
  view.setBigUint64(8, BigInt.asUintN(64, msg.sessionID), true);
  view.setBigUint64(16, BigInt.asUintN(64, msg.msgID), true);
  view.setUint32(24, msg.seqNo >>> 0, true);
  view.setUint32(28, msg.body.length, true);

  const plaintext = concat(header, msg.body, randomBytes(pad));

  const mk = await msgKey(authKey, plaintext, CLIENT_TO_SERVER);
  const { key, iv } = await deriveKeyIV(authKey, mk, CLIENT_TO_SERVER);
  const ciphertext = await igeEncrypt(key, iv, plaintext);

  return concat(keyID, mk, ciphertext);
}

/** Parses and authenticates a wire frame. */
export async function decryptMessage(
  authKey: Bytes,
  frame: Bytes,
): Promise<Envelope> {
  if (frame.length < 8 + 16 + HEADER_SIZE + MIN_PADDING) {
    throw new Error("mtproto: frame is too short");
  }

  const mk = frame.subarray(8, 24);
  const ciphertext = frame.subarray(24);
  if (ciphertext.length % 16 !== 0) {
    throw new Error("mtproto: ciphertext is not block-aligned");
  }

  const { key, iv } = await deriveKeyIV(authKey, mk, SERVER_TO_CLIENT);
  const plaintext = await igeDecrypt(key, iv, ciphertext);

  // Authenticate before parsing. Everything below this line is trusted only
  // because this check passed.
  const expected = await msgKey(authKey, plaintext, SERVER_TO_CLIENT);
  if (!equalConstantTime(expected, mk)) {
    throw new Error("mtproto: msg_key mismatch (forged, corrupt, or wrong key)");
  }

  const view = new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.length);
  const bodyLen = view.getUint32(28, true);
  if (bodyLen > MAX_MESSAGE_SIZE || HEADER_SIZE + bodyLen > plaintext.length) {
    throw new Error(`mtproto: declared body length ${bodyLen} is invalid`);
  }
  const padding = plaintext.length - HEADER_SIZE - bodyLen;
  if (padding < MIN_PADDING || padding > MAX_PADDING) {
    throw new Error(`mtproto: padding of ${padding} bytes is out of range`);
  }

  return {
    salt: view.getBigUint64(0, true),
    sessionID: view.getBigUint64(8, true),
    msgID: view.getBigUint64(16, true),
    seqNo: view.getUint32(24, true),
    body: plaintext.slice(HEADER_SIZE, HEADER_SIZE + bodyLen),
  };
}

/** Builds an unencrypted frame: auth_key_id(0) ‖ msg_id ‖ length ‖ body. */
export function encodePlain(msgID: bigint, body: Bytes): Bytes {
  const out = new Uint8Array(20 + body.length);
  const view = new DataView(out.buffer);
  view.setBigUint64(0, 0n, true);
  view.setBigUint64(8, BigInt.asUintN(64, msgID), true);
  view.setUint32(16, body.length, true);
  out.set(body, 20);
  return out;
}

export function decodePlain(frame: Bytes): { msgID: bigint; body: Bytes } {
  if (frame.length < 20) throw new Error("mtproto: plain frame is too short");
  const view = new DataView(frame.buffer, frame.byteOffset, frame.length);
  if (view.getBigUint64(0, true) !== 0n) {
    throw new Error("mtproto: not a plain message");
  }
  const msgID = view.getBigUint64(8, true);
  const n = view.getUint32(16, true);
  if (20 + n > frame.length) throw new Error("mtproto: declared length exceeds the frame");
  return { msgID, body: frame.slice(20, 20 + n) };
}

// ---------------------------------------------------------------------------
// msg_id
// ---------------------------------------------------------------------------

/**
 * Produces monotonically increasing message identifiers.
 *
 * The high 32 bits are unix seconds and the low 32 a counter, so a msg_id is
 * simultaneously a timestamp, a nonce and an ordering key. The low two bits
 * encode the kind.
 */
export class MsgIDGenerator {
  private last = 0n;
  private offset = 0n;

  next(kind = 0): bigint {
    const now = BigInt(Math.floor(Date.now() / 1000)) + this.offset;
    let candidate = now << 32n;

    if (candidate <= this.last) candidate = this.last + 4n;
    candidate = (candidate & ~3n) | BigInt(kind & 3);
    if (candidate <= this.last) candidate = ((this.last + 4n) & ~3n) | BigInt(kind & 3);

    this.last = candidate;
    return candidate;
  }

  /** Shifts our time base towards a server whose clock differs. */
  adoptPeerTime(peerMsgID: bigint): void {
    const peerSeconds = peerMsgID >> 32n;
    const delta = peerSeconds - BigInt(Math.floor(Date.now() / 1000));
    if (delta > 0n) this.offset = delta;
  }
}

/** Tracks the per-session sequence number: odd for content, even for service. */
export class SeqNoCounter {
  private n = 0;

  next(contentRelated: boolean): number {
    if (!contentRelated) return this.n * 2;
    this.n += 1;
    return this.n * 2 - 1;
  }
}

// ---------------------------------------------------------------------------
// The Diffie-Hellman group
// ---------------------------------------------------------------------------

/** RFC 3526 MODP group 14: a 2048-bit safe prime, g = 2. */
const DH_PRIME_HEX = `
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B
302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9
A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6
49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8
FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C
180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF
FFFFFFFF`;

export const DH_PRIME = bytesToBigInt(fromHex(DH_PRIME_HEX));
export const DH_G = 2n;
const DH_Q = (DH_PRIME - 1n) / 2n;

/**
 * Rejects DH values that would collapse the shared secret.
 *
 * 1 < v < p-1 is the minimum; the 2^(2048-64) margin additionally rules out
 * the small-subgroup and near-boundary tricks that make the discrete log easy.
 */
export function validateDHValue(v: bigint): void {
  if (v <= 1n || v >= DH_PRIME - 1n) {
    throw new Error("mtproto: DH value is 0, 1 or p-1");
  }
  const margin = 1n << BigInt(2048 - 64);
  if (v < margin) throw new Error("mtproto: DH value is too close to 0");
  if (v > DH_PRIME - margin) throw new Error("mtproto: DH value is too close to p");
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

export interface ResPQ {
  nonce: number[];
  server_nonce: number[];
  pq: number;
  rsa_fingerprints: number[];
}

export interface ReqDHParams {
  nonce: number[];
  server_nonce: number[];
  p: number;
  q: number;
  rsa_fingerprint: number;
  encrypted_data: number[];
}

export interface ServerDHParams {
  nonce: number[];
  server_nonce: number[];
  encrypted_answer: number[];
}

export interface ServerDHInner {
  nonce: number[];
  server_nonce: number[];
  g: number;
  dh_prime: number[];
  g_a: number[];
  server_time: number;
}

export interface DHGenOK {
  nonce: number[];
  server_nonce: number[];
  new_nonce_hash: number[];
}

/**
 * Factors a semiprime by Pollard's rho.
 *
 * This is the client's side of the proof of work: the server refuses to spend
 * a 2048-bit modular exponentiation on a stranger until they have paid a few
 * milliseconds of CPU.
 */
export function factorPQ(pq: number): { p: number; q: number } {
  const n = BigInt(pq);
  if (n % 2n === 0n) return { p: 2, q: Number(n / 2n) };

  for (let c = 1n; c < 64n; c++) {
    const f = (x: bigint) => (x * x + c) % n;
    let x = 2n;
    let y = 2n;
    let d = 1n;

    for (let step = 0; step < 1 << 22; step++) {
      x = f(x);
      y = f(f(y));
      let diff = x - y;
      if (diff < 0n) diff = -diff;
      if (diff === 0n) break;
      d = gcd(diff, n);
      if (d > 1n) break;
    }

    if (d > 1n && d < n) {
      const a = Number(d);
      const b = Number(n / d);
      return a < b ? { p: a, q: b } : { p: b, q: a };
    }
  }
  throw new Error(`mtproto: failed to factor ${pq}`);
}

function gcd(a: bigint, b: bigint): bigint {
  while (b) [a, b] = [b, a % b];
  return a;
}

/**
 * Derives the temporary AES key protecting the DH exchange.
 *
 *   key = SHA1(new_nonce ‖ server_nonce) ‖ substr(SHA1(server_nonce ‖ new_nonce), 0, 12)
 *   iv  = substr(SHA1(server_nonce ‖ new_nonce), 12, 8) ‖ SHA1(new_nonce ‖ new_nonce) ‖ substr(new_nonce, 0, 4)
 */
export async function tmpAESKeyIV(
  newNonce: Bytes,
  serverNonce: Bytes,
): Promise<{ key: Bytes; iv: Bytes }> {
  const ns = await sha1(newNonce, serverNonce);
  const sn = await sha1(serverNonce, newNonce);
  const nn = await sha1(newNonce, newNonce);

  return {
    key: concat(ns, sn.subarray(0, 12)),
    iv: concat(sn.subarray(12, 20), nn, newNonce.subarray(0, 4)),
  };
}

/** Wraps an inner payload with a SHA-1 integrity prefix and encrypts it. */
export async function igeSeal(
  key: Bytes,
  iv: Bytes,
  data: Bytes,
): Promise<Bytes> {
  const digest = await sha1(data);
  let buf = concat(digest, data);
  const pad = (16 - (buf.length % 16)) % 16;
  if (pad > 0) buf = concat(buf, randomBytes(pad));
  return igeEncrypt(key, iv, buf);
}

/** Reverses igeSeal and verifies the integrity prefix. */
export async function igeOpen(
  key: Bytes,
  iv: Bytes,
  sealed: Bytes,
): Promise<Bytes> {
  const plain = await igeDecrypt(key, iv, sealed);
  if (plain.length < 20) throw new Error("mtproto: inner data is too short");

  const digest = plain.subarray(0, 20);
  const body = plain.subarray(20);

  // The payload length is unknown because of the padding, so try candidate
  // lengths from longest to shortest. Padding is at most 15 bytes, so this is
  // a bounded scan.
  for (let cut = body.length; cut >= 0 && body.length - cut <= 16; cut--) {
    const sum = await sha1(body.subarray(0, cut));
    if (equalConstantTime(sum, digest)) return body.slice(0, cut);
  }
  throw new Error("mtproto: inner data integrity check failed");
}

/**
 * The fixed 88-byte layout of pq_inner_data.
 *
 * Binary rather than JSON because it must fit inside one RSA-OAEP block: a
 * 2048-bit key with SHA-256 OAEP carries at most 190 bytes, and the JSON
 * rendering of three nonces alone exceeds that.
 */
export function encodePQInnerData(d: {
  pq: number;
  p: number;
  q: number;
  nonce: Bytes;
  serverNonce: Bytes;
  newNonce: Bytes;
}): Bytes {
  const out = new Uint8Array(88);
  const view = new DataView(out.buffer);
  view.setBigUint64(0, BigInt(d.pq), false);
  view.setBigUint64(8, BigInt(d.p), false);
  view.setBigUint64(16, BigInt(d.q), false);
  out.set(d.nonce, 24);
  out.set(d.serverNonce, 40);
  out.set(d.newNonce, 56);
  return out;
}

/** Imports a PEM-encoded RSA public key for OAEP encryption. */
export async function importServerKey(pem: string): Promise<CryptoKey> {
  const body = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
  const der = Uint8Array.from(atob(body), (ch) => ch.charCodeAt(0));

  return crypto.subtle.importKey(
    "spki",
    der,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
}

/** The low 64 bits of SHA-1 over the DER public key, little-endian. */
export async function rsaFingerprint(pem: string): Promise<number> {
  const body = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
  const der = Uint8Array.from(atob(body), (ch) => ch.charCodeAt(0));

  const digest = await sha1(der);
  const view = new DataView(digest.buffer, digest.byteOffset + 12, 8);
  // The Go side stores this as a uint64; JavaScript numbers lose precision
  // past 2^53, so it is carried as a bigint and compared as one.
  return Number(BigInt.asUintN(64, view.getBigUint64(0, true)));
}

export { AUTH_KEY_SIZE, DH_Q, authKeyID, bigIntToBytes, bytesToBigInt, modPow, randomBigInt, randomBytes };
