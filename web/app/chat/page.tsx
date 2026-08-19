"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { getAccessToken, getDialogs, type DialogEntry } from "@/lib/api";
import {
  MTProtoClient,
  RPCError,
  type ConnectionState,
  type HistoryMessage,
  type ServerUpdate,
} from "@/lib/mtproto/client";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "wss://api.example.com/mtproto";

/**
 * The pinned MTProto server public key.
 *
 * In a real build this is baked in at compile time, never fetched — fetching
 * it would defeat the entire point, since an attacker who can intercept the
 * connection can also intercept the fetch. `scripts/bootstrap-secrets.sh`
 * prints the value to paste here.
 */
const SERVER_PUBLIC_KEY = process.env.NEXT_PUBLIC_MTPROTO_KEY ?? "";

export default function ChatPage() {
  const router = useRouter();

  const clientRef = useRef<MTProtoClient | null>(null);
  const [state, setState] = useState<ConnectionState>("disconnected");
  const [dialogs, setDialogs] = useState<DialogEntry[]>([]);
  const [activeChat, setActiveChat] = useState<number | null>(null);
  const [messages, setMessages] = useState<HistoryMessage[]>([]);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);

  // The per-chat cursor: the last sequence this client holds. It is what
  // getDifference resumes from after a reconnect, which is what makes the
  // fire-and-forget realtime layer safe.
  const cursors = useRef<Record<number, number>>({});

  const onUpdate = useCallback((u: ServerUpdate) => {
    if (u.kind !== "new_message" || !u.chat_id || !u.seq) return;

    cursors.current[u.chat_id] = Math.max(cursors.current[u.chat_id] ?? 0, u.seq);

    setDialogs((prev) =>
      prev.map((d) =>
        d.chat.id === u.chat_id
          ? { ...d, max_seq: u.seq!, unread_count: d.unread_count + 1 }
          : d,
      ),
    );

    setActiveChat((current) => {
      if (current === u.chat_id && u.payload) {
        setMessages((prev) => {
          const incoming = u.payload as HistoryMessage;
          // The sender also receives its own message through the fanout, so
          // deduplicate by sequence rather than appending blindly.
          if (prev.some((m) => m.seq === incoming.seq)) return prev;
          return [...prev, incoming];
        });
      }
      return current;
    });
  }, []);

  // Connect once, on mount.
  useEffect(() => {
    const token = getAccessToken();
    if (!token) {
      router.replace("/");
      return;
    }
    if (!SERVER_PUBLIC_KEY) {
      setError(
        "No MTProto server key is configured. Set NEXT_PUBLIC_MTPROTO_KEY at build time.",
      );
      return;
    }

    const client = new MTProtoClient({
      url: WS_URL,
      serverPublicKeyPEM: SERVER_PUBLIC_KEY,
      onUpdate,
      onStateChange: setState,
    });
    clientRef.current = client;

    let cancelled = false;

    (async () => {
      try {
        await client.connect();
        await client.bind(token);
        if (cancelled) return;

        const { dialogs: list } = await getDialogs();
        setDialogs(list);
        for (const d of list) cursors.current[d.chat.id] = d.max_seq;

        // Catch up on anything missed while this tab was closed.
        const diff = await client.getDifference(cursors.current);
        if (diff.messages.length > 0) {
          cursors.current = { ...cursors.current, ...diff.new_cursors };
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      }
    })();

    // Keep the connection warm. The server reclaims it after 150 seconds of
    // silence, which tolerates two missed pings.
    const keepalive = setInterval(() => {
      client.ping().catch(() => {
        /* the reconnect logic handles a dead socket */
      });
    }, 60_000);

    return () => {
      cancelled = true;
      clearInterval(keepalive);
      client.close();
    };
  }, [router, onUpdate]);

  async function openChat(chatID: number) {
    const client = clientRef.current;
    if (!client) return;

    setActiveChat(chatID);
    setMessages([]);
    try {
      const history = await client.getHistory(chatID, 0, 50);
      // History arrives newest first; render oldest first.
      setMessages(history.messages.slice().reverse());

      const newest = history.messages[0];
      if (newest) {
        cursors.current[chatID] = newest.seq;
        await client.readHistory(chatID, newest.seq);
        setDialogs((prev) =>
          prev.map((d) => (d.chat.id === chatID ? { ...d, unread_count: 0 } : d)),
        );
      }
    } catch (err) {
      setError(describe(err));
    }
  }

  async function send(e: React.FormEvent) {
    e.preventDefault();
    const client = clientRef.current;
    const body = draft.trim();
    if (!client || !activeChat || !body) return;

    setDraft("");
    try {
      // A random id makes the send idempotent: if this times out and the
      // client retries with the same value, the server returns the original
      // message rather than posting a second one.
      const randomID = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER);
      await client.sendMessage(activeChat, body, randomID);
    } catch (err) {
      setDraft(body); // put it back so the text is not lost
      setError(describe(err));
    }
  }

  return (
    <main style={{ display: "grid", gridTemplateColumns: "280px 1fr", height: "100vh" }}>
      <aside
        style={{
          borderRight: "1px solid var(--border)",
          background: "var(--surface)",
          overflowY: "auto",
        }}
      >
        <div style={{ padding: 16, borderBottom: "1px solid var(--border)" }}>
          <strong>Chats</strong>
          <div style={{ fontSize: 12, color: "var(--text-dim)" }}>
            <ConnectionBadge state={state} />
          </div>
        </div>

        {dialogs.length === 0 && (
          <p style={{ padding: 16, color: "var(--text-dim)" }}>No conversations yet.</p>
        )}

        {dialogs.map((d) => (
          <button
            key={d.chat.id}
            className="secondary"
            onClick={() => openChat(d.chat.id)}
            style={{
              display: "block",
              width: "100%",
              textAlign: "left",
              borderRadius: 0,
              background: activeChat === d.chat.id ? "var(--surface-2)" : "transparent",
              borderBottom: "1px solid var(--border)",
              padding: "12px 16px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span>{d.chat.title || d.peer?.display_name || `Chat ${d.chat.id}`}</span>
              {d.unread_count > 0 && (
                <span
                  style={{
                    background: "var(--accent)",
                    color: "#fff",
                    borderRadius: 10,
                    padding: "0 7px",
                    fontSize: 12,
                  }}
                >
                  {d.unread_count}
                </span>
              )}
            </div>
          </button>
        ))}
      </aside>

      <section style={{ display: "flex", flexDirection: "column", minWidth: 0 }}>
        <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
          {activeChat === null ? (
            <p style={{ color: "var(--text-dim)" }}>Select a conversation.</p>
          ) : (
            messages.map((m) => (
              <div key={m.message_id || m.seq} style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 12, color: "var(--text-dim)" }}>
                  {m.sender_id} · seq {m.seq}
                </div>
                <div
                  style={{
                    background: "var(--surface)",
                    borderRadius: 10,
                    padding: "8px 12px",
                    display: "inline-block",
                    maxWidth: "70%",
                    wordBreak: "break-word",
                  }}
                >
                  {m.deleted ? <em style={{ color: "var(--text-dim)" }}>Deleted</em> : m.body}
                </div>
              </div>
            ))
          )}
        </div>

        {error && (
          <p role="alert" style={{ color: "var(--danger)", padding: "0 16px" }}>
            {error}
          </p>
        )}

        <form
          onSubmit={send}
          style={{
            display: "flex",
            gap: 8,
            padding: 16,
            borderTop: "1px solid var(--border)",
          }}
        >
          <input
            placeholder={activeChat ? "Message" : "Select a conversation first"}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            disabled={activeChat === null || state !== "connected"}
          />
          <button type="submit" disabled={!draft.trim() || state !== "connected"}>
            Send
          </button>
        </form>
      </section>
    </main>
  );
}

function ConnectionBadge({ state }: { state: ConnectionState }) {
  const label: Record<ConnectionState, string> = {
    disconnected: "Disconnected",
    connecting: "Connecting…",
    handshaking: "Securing connection…",
    connected: "Connected",
    reconnecting: "Reconnecting…",
  };
  const colour = state === "connected" ? "var(--accent)" : "var(--text-dim)";
  return <span style={{ color: colour }}>{label[state]}</span>;
}

function describe(err: unknown): string {
  if (err instanceof RPCError) {
    const wait = err.floodWaitSeconds;
    if (wait !== null) return `Sending too fast. Wait ${wait} seconds.`;
    return err.message;
  }
  return err instanceof Error ? err.message : String(err);
}
