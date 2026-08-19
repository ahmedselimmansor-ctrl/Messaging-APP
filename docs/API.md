# API

Two surfaces. Which one a call belongs on is not arbitrary:

- **REST** for anything request/response — registration, profile edits, media
  negotiation, chat management. Cacheable, debuggable with `curl`, works
  through any proxy.
- **MTProto** for anything latency-critical or high-volume — sending, reading,
  catching up, typing, and the server-pushed update stream.

A client uses both. It registers over REST, obtains a JWT, opens an MTProto
connection and binds that JWT to the negotiated auth key.

---

## REST

Base URL `https://api.example.com`. All bodies are JSON. Authenticated
endpoints take `Authorization: Bearer <access_token>`.

### Errors

Every failure returns the same envelope:

```json
{
  "error": {
    "code": "FLOOD_WAIT",
    "message": "too many requests; retry in 30s",
    "retry_after": 30,
    "details": {"field": "why it was rejected"}
  }
}
```

`code` is stable and safe to switch on; `message` may change. Codes:
`BAD_REQUEST`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`,
`RATE_LIMITED`, `FLOOD_WAIT`, `PAYLOAD_TOO_LARGE`, `UNPROCESSABLE`,
`UNAVAILABLE`, `INTERNAL`.

On `FLOOD_WAIT`, back off by exactly `retry_after` seconds. Retrying sooner
consumes the allowance and extends the wait.

---

### Authentication

#### `POST /v1/auth/send-code`

```json
{"phone": "+201234567890"}
```

```json
{"challenge_id": "550e8400-...", "code_length": 5, "expires_in": 300, "registered": true}
```

`registered` tells the client whether to ask for a display name next.

Rate limited per phone (3, then one per 5 minutes) and per IP (10, then one
per minute), and again at the edge. This is the endpoint an attacker turns
into an SMS bill.

#### `POST /v1/auth/sign-in`

```json
{
  "challenge_id": "550e8400-...",
  "code": "12345",
  "display_name": "Ahmed",
  "platform": "android",
  "app_version": "1.0.0",
  "device_model": "Pixel 8",
  "auth_key_id": "a1b2c3d4e5f6a7b8"
}
```

`display_name` is required only when the account does not exist.
`auth_key_id` binds this session to an already-negotiated MTProto key;
REST-only clients omit it.

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "expires_in": 900,
  "token_type": "Bearer",
  "user": {"id": 123456789, "phone": "+201234567890", "display_name": "Ahmed"},
  "device_id": 987654321,
  "created": false
}
```

A wrong code and an unknown challenge return the same error, deliberately.

#### `POST /v1/auth/refresh`

```json
{"refresh_token": "eyJ..."}
```

Returns a fresh pair. The device is re-validated on every refresh, so a
revoked session stops working immediately rather than when its refresh token
expires.

#### `GET /.well-known/jwks.json`

The public key set. Cached for an hour. Verifiers poll this so a signing-key
rotation needs no redeploy.

---

### Account

| | |
|---|---|
| `GET /v1/me` | The authenticated user |
| `PATCH /v1/me` | Update `display_name`, `about`, `avatar_object`, `lang_code` |
| `DELETE /v1/me` | Delete the account; frees the phone and username, keeps history attributable |
| `PUT /v1/me/username` | Claim a public `@username`; 409 if taken |
| `GET /v1/me/devices` | Active sessions. Push tokens are never returned. |
| `DELETE /v1/me/devices/{id}` | Revoke one session |
| `POST /v1/me/devices/revoke-others` | Log out everywhere else |
| `PUT /v1/me/push-token` | Register the FCM token |

---

### Chats

#### `POST /v1/chats`

```json
{"type": "private", "peer_id": 987654321}
```

```json
{"type": "group", "title": "Team", "members": [111, 222, 333]}
```

Private chats are deduplicated: two devices tapping "message" simultaneously
converge on one chat. The response's `created` says which happened.

| | |
|---|---|
| `GET /v1/dialogs?limit=50&include_archived=false` | The chat list, with unread counts |
| `GET /v1/chats/{id}` | One chat |
| `PATCH /v1/chats/{id}` | Title, description, photo (owner or admin) |
| `GET /v1/chats/{id}/members` | Roster, capped at 500 hydrated |
| `POST /v1/chats/{id}/members` | Add a member (owner or admin) |
| `DELETE /v1/chats/{id}/members/{userID}` | Remove a member |
| `PATCH /v1/chats/{id}/members/{userID}` | Change a member's role |
| `DELETE /v1/chats/{id}` | Delete a chat (owner only, groups and channels) |
| `POST /v1/chats/{id}/leave` | Leave; an owner must transfer first |
| `PUT /v1/chats/{id}/mute` | `muted_for_seconds` (0 unmutes, negative mutes indefinitely), `pinned`, `archived` |

A non-member gets **404**, not 403 — confirming a chat exists to an outsider
is an enumeration oracle.

---

### Messages over REST

The same operations exist on MTProto and should be preferred there. These are
for clients that cannot hold a socket.

| | |
|---|---|
| `POST /v1/chats/{id}/messages` | Send |
| `GET /v1/chats/{id}/messages?before_seq=&limit=` | History, newest first |
| `PATCH /v1/chats/{id}/messages/{seq}` | Edit your own |
| `DELETE /v1/chats/{id}/messages/{seq}` | Delete yours; admins may delete any |
| `POST /v1/chats/{id}/read` | Advance the read pointer |
| `POST /v1/difference` | Catch-up: `{"cursors": {"chat_id": last_seq}}` |

**`random_id` makes sending idempotent.** A client that retries after a
timeout sends the same value and gets the original message back with
`"duplicate": true` rather than posting twice.

---

### Media

#### `POST /v1/uploads`

```json
{"filename": "photo.jpg", "mime_type": "image/jpeg", "size_bytes": 2048576, "purpose": "message"}
```

```json
{
  "upload_id": "...",
  "object": "photo/2026/08/17/123456789/uuid.jpg",
  "upload_url": "https://storage.googleapis.com/...",
  "method": "PUT",
  "headers": {"Content-Type": "image/jpeg", "Content-Length": "2048576"},
  "expires_in": 900
}
```

`PUT` the bytes directly to `upload_url` with exactly those headers. Both are
bound into the signature, so a URL issued for a 2MB JPEG cannot carry a 1GB
executable.

#### `POST /v1/uploads/{upload_id}/complete`

Confirms the object landed and queues processing. The server checks the actual
size against what was declared and deletes a mismatch.

Then send a message with `media_object` set to the returned `object`.

Allowlisted types: JPEG, PNG, WebP, GIF, HEIC, MP4, QuickTime, WebM, OGG,
MP3, MP4 audio, AAC, PDF, ZIP, plain text, octet-stream.

#### `GET /v1/media/download?object=<path>`

Returns a signed, short-lived download URL — but only after checking that the
caller is a member of the chat the object was posted to. That check is the
whole point: object paths are guessable, so without it a signed-URL endpoint
is an enumeration oracle for other people's media.

Derivatives resolve to the same ACL as their original: `photo_s`, `photo_m`,
`photo_l`, `poster`, `720p` and `480p` all map to one stem. The mapping uses
an allowlist of suffixes rather than pattern-stripping, so an attacker cannot
craft a name that resolves to a stem they do have access to.

Uploaded media is virus-scanned before any derivative is produced. A scanner
that is unreachable causes a retry, never a pass-through — "we could not
check" must not become "it is fine".

#### Role and deletion rules

These are stricter than "admins can administrate", and the reasons are worth
stating because each rule exists to stop a specific takeover:

| Rule | Why |
|---|---|
| Only the **owner** may grant or revoke admin | Otherwise one compromised admin account promotes itself to sole control |
| An admin may not remove a fellow admin | The same escalation, run backwards |
| Nobody may change or remove the **owner** — including the owner | A chat with no owner cannot appoint one, and is unrecoverable through the API |
| Nobody may change their own role | An accidental self-demotion is unrecoverable without an owner |
| Ownership is not granted here | A chat has exactly one owner; transfer must move it, not add a second |
| A **private chat** cannot be deleted | Both participants own that conversation equally; leave or archive instead |

The rules live in `services/chat-service/internal/authz.go` as pure functions
and are tested exhaustively over every role pair.

### Reporting and moderation

| Endpoint | Notes |
|---|---|
| `POST /v1/reports` | Report a user, optionally naming a message |

Reasons: `spam`, `abuse`, `violence`, `csam`, `illegal`, `impersonation`,
`other`. A message reference is only accepted from someone who can see that
message, so the endpoint cannot be used to probe whether an arbitrary
`(chat, seq)` pair exists.

One open report per reporter per subject, enforced by a partial unique index.
Without it, a coordinated group can bury an account in identical reports and
the queue depth stops meaning anything. Filing again while the first is open
returns success with `"pending": true` rather than an error — the user's
report is already in the queue and a second adds nothing.

`csam` and `violence` are flagged urgent: they carry legal reporting
obligations with clocks attached, so they are surfaced at warn level into the
alert path rather than only into a queue somebody reads on Monday.

A banned account is refused on the send path before it learns anything about
the chat. The authoritative check is at token issuance, so within one
access-token lifetime (15 minutes) a banned account cannot obtain credentials
at all; the send-path check closes that window.

### Your data

| Endpoint | Notes |
|---|---|
| `GET /v1/me/export` | A machine-readable copy of your data |

Rate limited to roughly twice a day — it is the most expensive request the
platform serves.

What it contains, and the one decision worth defending: **messages you sent
are included in full; messages other people sent are listed with sender and
timing but without their text.** A conversation is not one person's data.
Including correspondents' message bodies would let any user extract their
contacts' writing in bulk by asking, turning a privacy right into a disclosure
mechanism. The structure is preserved so the requester can still see when they
talked to whom, and what they themselves said.

Secret chats appear as metadata with an explicit note. The server holds
ciphertext it cannot decrypt, so their contents cannot appear — and the file
says so rather than leaving someone to conclude their history was lost.

The export is audited, because it is the request an attacker with a stolen
session makes first.

### Contacts and blocking

| Endpoint | Notes |
|---|---|
| `GET /v1/contacts` | The contact list |
| `POST /v1/contacts` | Add by user id or `@username` |
| `DELETE /v1/contacts/{userID}` | Remove |
| `POST /v1/contacts/import` | Bulk match by phone |
| `GET /v1/blocks` | Blocked users |
| `POST /v1/blocks` | Block a user |
| `DELETE /v1/blocks/{userID}` | Unblock |

Import sends **HMAC-SHA256 hashes** of E.164 numbers, never the numbers
themselves, keyed with a server-side pepper. A plain hash of a phone number is
not private — the space is small enough to enumerate exhaustively — so the
pepper is what makes the hash meaningless to anyone who obtains the table.

Blocking is enforced on the send path, not just in the UI, and
`IsBlockedBetween` is symmetric: if either party has blocked the other,
neither can send.

### Search

| Endpoint | Notes |
|---|---|
| `GET /v1/search/messages?q=&chat_id=&limit=` | Full-text over messages the caller can see |
| `GET /v1/search/users?q=&limit=` | By username or display name |

Message search always applies an ACL filter — a `members` term for the calling
user — and the query is refused outright before it is sent if the user id is
zero. Search over an index is only as safe as its filter, so the filter is not
optional and cannot be omitted by a caller.

Secret-chat messages are never indexed. The server cannot read them.

### Secret chats

End-to-end encrypted, with the server as a blind relay. Key exchange is
Diffie-Hellman between the two devices; the server forwards the parameters and
stores only ciphertext.

Both sides can display a **key fingerprint** as a sequence of words from a
2048-entry list, so two people can verify out of band that no one is between
them. This is the only defence against an active man-in-the-middle at the
exchange, and it depends on the users actually comparing.

The server holds no key material for these chats. Losing every device loses
the history — that is the trade, and it is deliberate.

### Calls

Signalling only. Media goes peer-to-peer, or through coturn when a NAT forbids
that. The call service mints TURN credentials with the REST-API mechanism: an
expiry plus an HMAC over it, so there is no user database and every credential
expires on its own. A compromise of the signalling path cannot record a call.

---

## MTProto

Endpoint `mt.example.com:4443`, TCP and UDP. WebSocket at
`wss://api.example.com/mtproto`.

Full protocol detail in [`pkg/mtproto/doc.go`](../pkg/mtproto/doc.go). A
complete reference client is [`pkg/mtclient`](../pkg/mtclient/client.go).

### Connecting

1. **Select a framing** by sending its magic prefix — `0xef` for abridged,
   `0xeeeeeeee` for intermediate, `0xdddddddd` for padded — or send a 64-byte
   obfuscation2 init packet, which carries the framing inside itself.

2. **Negotiate an auth key** — five messages, all unencrypted with
   `auth_key_id = 0`:

   ```
   → req_pq(nonce)
   ← res_pq(nonce, server_nonce, pq, rsa_fingerprints)
   → req_dh_params(nonce, server_nonce, p, q, RSA-OAEP(pq_inner_data))
   ← server_dh_params(nonce, server_nonce, AES-IGE(server_dh_inner_data))
   → set_client_dh_params(nonce, server_nonce, AES-IGE(client_dh_inner_data))
   ← dh_gen_ok(nonce, server_nonce, new_nonce_hash)
   ```

   Factoring `pq` is the proof of work. `auth_key = g_a^b mod p`.

   **Pin the server's public key.** Without pinning, an attacker who can
   intercept the connection substitutes their own, learns `new_nonce` and
   reads the whole exchange.

3. **Bind an identity** — send `auth.bind` with a JWT obtained over REST.
   Until this succeeds, every method except `ping` returns
   `401 AUTH_KEY_UNBOUND`.

### Message format

```
auth_key_id(8) ‖ msg_key(16) ‖ AES-256-IGE(
    salt(8) ‖ session_id(8) ‖ msg_id(8) ‖ seq_no(4) ‖ length(4) ‖ body ‖ padding
)
```

`body` is a 4-byte little-endian constructor id followed by a JSON object.

**`msg_id` rules.** Unix seconds in the high 32 bits, a counter in the low 32,
strictly increasing within a session. The low two bits encode the kind: `00`
from the client, `01` a server response, `11` a server push. It must be within
300 seconds behind and 30 seconds ahead of server time and must not repeat —
this is what stops a captured call being replayed later.

**`seq_no`.** Odd and incrementing for content messages, even for service
messages. The parity tells the peer what must be acknowledged.

### Methods

| Constructor | Method | Request → Response |
|---|---|---|
| `0x7abe77ec` | `ping` | `Ping` → `Pong` |
| `0x10000001` | `auth.bind` | `AuthBind` → `AuthBindResult` |
| `0x10000010` | `messages.send` | `SendMessage` → `SendMessageResult` |
| `0x10000012` | `messages.getHistory` | `GetHistory` → `GetHistoryResult` |
| `0x10000014` | `updates.getDifference` | `GetDifference` → `DifferenceResult` |
| `0x10000016` | `messages.readHistory` | `ReadHistory` → `ReadHistoryResult` |
| `0x10000018` | `messages.setTyping` | `SetTyping` → `OK` |
| `0x10000019` | `messages.getDialogs` | `GetDialogs` → `GetDialogsResult` |
| `0xe7512126` | `destroy_session` | `DestroySession` → `OK` |

Responses come back as `rpc_result` (`0xf35c6d01`) or `rpc_error`
(`0x2144ca19`), both carrying `req_msg_id` so answers correlate to calls
rather than to arrival order.

### Service messages the server sends

| Constructor | Meaning | What the client must do |
|---|---|---|
| `bad_server_salt` | The salt rotated | Adopt `new_server_salt` and resend |
| `bad_msg_notification` | `msg_id` or `seq_no` rejected | Correct per the error code; do not blindly retry |
| `new_session_created` | The server started a new session | Resend anything unacknowledged |
| `update` | A server push | Render it |

### Updates

```json
{
  "kind": "new_message",
  "chat_id": 42,
  "seq": 1337,
  "user_id": 123,
  "date": 1755400000000,
  "payload": {"message_id": "...", "body": "hello", "type": "text"}
}
```

Kinds: `new_message`, `edit_message`, `delete_message`, `read_receipt`,
`typing`, `presence`, `chat_created`, `member_changed`, `reconnect`.

**`reconnect` means the pod is draining.** Reconnect promptly; the server is
spreading its shutdown across clients precisely to avoid every client
reconnecting at once.

**Updates are fire-and-forget.** A client that was disconnected, or whose
outbound queue overflowed, recovers with `updates.getDifference`. That call is
what makes best-effort realtime delivery safe.

### Reconnecting

1. Reconnect and present the same `auth_key_id`. Any pod resolves it from
   Redis — no fresh handshake.
2. Call `updates.getDifference` with the last sequence held per chat.
3. Apply what comes back, then resume.

### Keepalive

Ping every 60 seconds. The server reclaims a connection after 150 seconds of
silence, which tolerates two missed pings — enough to survive a tunnel,
short enough that dead sockets do not accumulate.

Set `disconnect_after` on the ping when backgrounding the app to tell the
server how long to hold the connection, so it releases resources promptly
instead of waiting for a TCP timeout.

---

## Admin

Not reachable from the internet. There is no route through the public load
balancer, and the AuthorizationPolicy in `deploy/k8s/mesh` restricts the
service to the operator gateway's identity. A user token — even a valid one —
cannot reach these endpoints because they are not routable from where users
are.

Operator identity comes from the IAP-authenticated header. Every endpoint
requires it, and no action is accepted without one: an unattributable
administrative action is refused rather than recorded as "system".

| Endpoint | Notes |
|---|---|
| `GET /admin/v1/reports` | The queue, oldest first |
| `GET /admin/v1/reports/subject/{userID}` | Everything filed against one account, with a distinct-reporter count |
| `POST /admin/v1/reports/{reportID}/resolve` | `actioned` or `dismissed`, with a written resolution |
| `GET /admin/v1/users/{userID}?reason=…` | Look up an account |
| `POST /admin/v1/users/{userID}/ban` | Ban, revoking sessions by default |
| `POST /admin/v1/users/{userID}/unban` | Lift a ban |

**Reasons are mandatory and length-checked.** "abuse" and "spam" are not
reasons, they are restatements of the report; the person reading this in six
months needs to know what was decided and why.

**Distinct reporters matter more than the count.** Ten reports from ten
unrelated people is a signal; ten from one person is a different problem,
usually with the reporter. The endpoint returns both.

**A lookup is audited before it happens, and refused if it cannot be.**
Everywhere else in the platform the action happens first and the audit entry
follows, because a missing entry beats a false one. Here the ordering flips:
looking someone up leaves no other trace — no message is sent, nothing
changes — so the whole point is that no lookup happens without a record.

**What the service cannot do.** There is no Cassandra client in it and the
`svc_admin` Postgres role has no grant on the phone column. A moderator
decides on reported behaviour, not by reading conversations, and the absence
of the capability is what makes that checkable rather than a promise.
