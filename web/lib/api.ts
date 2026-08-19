/**
 * REST client.
 *
 * Everything request/response goes here — registration, profile, media
 * negotiation, chat management. Sending and reading go over MTProto instead,
 * because those are the latency-critical, high-volume paths.
 */

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "https://api.example.com";

export interface APIErrorBody {
  code: string;
  message: string;
  retry_after?: number;
  details?: Record<string, string>;
}

export class APIError extends Error {
  constructor(
    readonly status: number,
    readonly body: APIErrorBody,
  ) {
    super(body.message);
    this.name = "APIError";
  }

  /** True when the caller should back off rather than retry immediately. */
  get isRateLimited(): boolean {
    return this.body.code === "FLOOD_WAIT" || this.body.code === "RATE_LIMITED";
  }
}

let accessToken: string | null = null;
let refreshToken: string | null = null;

export function setTokens(access: string, refresh: string): void {
  accessToken = access;
  refreshToken = refresh;
  // sessionStorage, not localStorage: the token dies with the tab. A
  // long-lived token in localStorage survives every XSS that ever touches the
  // origin.
  try {
    sessionStorage.setItem("refresh_token", refresh);
  } catch {
    /* private browsing */
  }
}

export function clearTokens(): void {
  accessToken = null;
  refreshToken = null;
  try {
    sessionStorage.removeItem("refresh_token");
  } catch {
    /* ignore */
  }
}

export function getAccessToken(): string | null {
  return accessToken;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  retryOn401 = true,
): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (accessToken) headers["Authorization"] = `Bearer ${accessToken}`;

  const res = await fetch(`${API_URL}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "omit",
  });

  if (res.status === 401 && retryOn401 && refreshToken) {
    // One refresh attempt, then give up. Retrying a refresh that failed will
    // not succeed and turns an expired session into a request loop.
    const refreshed = await refreshSession();
    if (refreshed) return request<T>(method, path, body, false);
  }

  if (!res.ok) {
    let errorBody: APIErrorBody = { code: "UNKNOWN", message: res.statusText };
    try {
      const parsed = (await res.json()) as { error?: APIErrorBody };
      if (parsed.error) errorBody = parsed.error;
    } catch {
      /* not JSON */
    }
    throw new APIError(res.status, errorBody);
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

async function refreshSession(): Promise<boolean> {
  if (!refreshToken) return false;
  try {
    const res = await fetch(`${API_URL}/v1/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) return false;
    const data = (await res.json()) as { access_token: string; refresh_token: string };
    setTokens(data.access_token, data.refresh_token);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

export interface SendCodeResult {
  challenge_id: string;
  code_length: number;
  expires_in: number;
  registered: boolean;
}

export function sendCode(phone: string) {
  return request<SendCodeResult>("POST", "/v1/auth/send-code", { phone });
}

export interface User {
  id: number;
  phone: string;
  username?: string;
  display_name: string;
  about?: string;
  avatar_object?: string;
}

export interface SignInResult {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  user: User;
  device_id: number;
  created: boolean;
}

export async function signIn(args: {
  challenge_id: string;
  code: string;
  display_name?: string;
  auth_key_id?: string;
}): Promise<SignInResult> {
  const result = await request<SignInResult>("POST", "/v1/auth/sign-in", {
    ...args,
    platform: "web",
    app_version: "1.0.0",
    device_model: navigator.userAgent.slice(0, 64),
  });
  setTokens(result.access_token, result.refresh_token);
  return result;
}

export function me() {
  return request<User>("GET", "/v1/me");
}

// ---------------------------------------------------------------------------
// Chats
// ---------------------------------------------------------------------------

export interface Chat {
  id: number;
  type: "private" | "group" | "channel";
  title: string;
  member_count: number;
}

export function createPrivateChat(peerID: number) {
  return request<{ chat: Chat; created: boolean }>("POST", "/v1/chats", {
    type: "private",
    peer_id: peerID,
  });
}

export function createGroup(title: string, members: number[]) {
  return request<{ chat: Chat; created: boolean }>("POST", "/v1/chats", {
    type: "group",
    title,
    members,
  });
}

export interface DialogEntry {
  chat: Chat;
  role: string;
  last_read_seq: number;
  max_seq: number;
  unread_count: number;
  pinned: boolean;
  archived: boolean;
  peer?: User;
}

export function getDialogs(limit = 50) {
  return request<{ dialogs: DialogEntry[] }>("GET", `/v1/dialogs?limit=${limit}`);
}

// ---------------------------------------------------------------------------
// Media
// ---------------------------------------------------------------------------

export interface UploadTicket {
  upload_id: string;
  object: string;
  upload_url: string;
  method: string;
  headers: Record<string, string>;
  expires_in: number;
}

/**
 * Uploads a file directly to Cloud Storage.
 *
 * The bytes never touch our servers: the API issues a signed URL and the
 * browser PUTs to it. Content-Type and Content-Length are bound into the
 * signature, so a URL issued for a 2MB image cannot carry a 1GB file.
 */
export async function uploadFile(file: File, purpose = "message"): Promise<string> {
  const ticket = await request<UploadTicket>("POST", "/v1/uploads", {
    filename: file.name,
    mime_type: file.type || "application/octet-stream",
    size_bytes: file.size,
    purpose,
  });

  const put = await fetch(ticket.upload_url, {
    method: ticket.method,
    headers: ticket.headers,
    body: file,
  });
  if (!put.ok) {
    throw new Error(`upload failed: ${put.status} ${put.statusText}`);
  }

  await request<unknown>("POST", `/v1/uploads/${ticket.upload_id}/complete`);
  return ticket.object;
}
