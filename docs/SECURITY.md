# Security

What is protected, how, and — just as importantly — what is not yet.

---

## Threat model

Who we are defending against, in rough order of likelihood:

1. **Opportunistic attackers** — scanners, credential stuffing, spam
   registration. High volume, low sophistication. Handled at the edge and by
   rate limiting.
2. **Abusive users** — spam, harassment, scraping the user directory. Handled
   by per-user limits and by refusing to confirm what an attacker guessed.
3. **Network observers** — anyone between the client and us: a hostile wifi
   network, an ISP, a state-level filter. Handled by transport encryption and
   the obfuscation layer.
4. **A compromised workload** — one service is breached. Handled by
   least-privilege identity, network policy and mesh authorization.
5. **A malicious insider or a stolen operator credential** — handled by
   Binary Authorization, audit logging and separation of duties.

Explicitly **out of scope**: an adversary with Google Cloud's own
infrastructure access, and an adversary who compromises the user's device.

---

## What is enforced

### Transport

| Path | Protection |
|---|---|
| Client → HTTPS LB | TLS 1.2+, MODERN cipher profile, HSTS via 301 redirect, HTTP/3 |
| Client → Network LB | MTProto's own AES-256-IGE with per-message keys |
| LB → pod | Google's internal encrypted transport |
| Pod → pod | STRICT mTLS via Anthos Service Mesh |
| Pod → Cloud SQL | Cloud SQL Auth Proxy, TLS, IAM tokens |
| Pod → Redis | TLS with server authentication |
| Pod → Kafka | TLS with SASL/OAUTHBEARER |

### Authentication

**Phone verification.** Five-digit codes, bcrypt-hashed at rest so a database
leak does not expose live codes, five-minute expiry, five-attempt cap, and
rate limits at three layers (per phone, per IP, and at the edge). The verify
path returns the same error for "no such challenge" and "wrong code" so it
cannot be used to enumerate live challenges.

**Tokens.** ES256 JWTs. 15-minute access tokens, 60-day refresh tokens with a
separate audience so a leaked access token cannot be exchanged for a longer
one. The algorithm is pinned at verification, which is what stops the classic
`alg: none` and HMAC-with-the-public-key confusion attacks. Refresh
re-validates the device on every use, so "log out this session" takes effect
immediately rather than in two months.

**MTProto auth keys.** 256-byte secrets from a 2048-bit Diffie-Hellman
exchange. Fresh exponents per handshake and discarded afterwards, so
compromising the RSA key later does not reveal past auth keys. `new_nonce`
travels RSA-OAEP encrypted, so only the server learns it. Both sides validate
the peer's DH value against small-subgroup and near-boundary values — skipping
that check would let a peer force a shared secret of 0, 1 or p−1.

**Clients must pin the server's public key.** The handshake protects against a
passive observer; only the pin protects against an active one, who would
otherwise substitute their own key, learn `new_nonce` and read the entire
exchange.

### Authorisation

Every message send checks chat membership and posting rights in one query
(`Members.CanPost`), cached in Redis. A non-member gets **404, not 403** —
confirming that a chat exists to someone not in it is an enumeration oracle.

Admins cannot remove owners or fellow admins; only an owner can remove an
admin. Without that, one compromised admin account takes over a chat.

Search results are ACL-filtered at the index: every document carries its
member list and every query filters on it, so a user can only ever match
messages from chats they are in.

### Rate limiting

A Redis token bucket evaluated inside a Lua script — atomic without a lock,
one round trip per decision.

The fail-open/fail-closed split is deliberate and worth stating:

- **Message sending fails open.** A Redis outage must degrade rate limiting,
  not stop the product working.
- **OTP issuance and login fail closed.** Failing open there turns a cache
  outage into an SMS-billing incident or a credential-stuffing window.

| Limit | Burst | Sustained |
|---|---|---|
| Send message (per user) | 30 | 5/s |
| Send message (per chat) | 20 | 3/s |
| OTP request (per phone) | 3 | 1 per 5 min |
| OTP request (per IP) | 10 | 1/min |
| OTP verify (per phone) | 5 | 1/min |
| Login (per IP) | 20 | 1 per 10s |
| Handshake (per IP) | 20 | 1 per 2s |
| Connection (per IP) | 60 | 2/s |

The handshake limit matters more than it looks: the DH exchange is the most
CPU-expensive unauthenticated operation the server performs. The `req_pq`
proof of work raises the cost of a flood by orders of magnitude, but it is a
speed bump, not a replacement for this limit or for Cloud Armor.

### Identity and secrets

No service account keys exist anywhere in this repository or in the cluster.
Workload Identity binds each Kubernetes service account to a Google one and
the metadata server issues short-lived tokens. Signed URLs are produced
through the IAM `signBlob` API rather than a local key.

Secrets live in Secret Manager, projected into pods by the CSI driver. They
never appear in a manifest, in Git, or in Terraform state — Terraform creates
the secrets empty and `scripts/bootstrap-secrets.sh` seeds the values.

Per-service scoping means the media service cannot read the JWT signing key,
and the push consumer cannot read phone numbers (see the column-level grants
in migration `0002`).

**Credentials are files, not environment variables.** The CSI driver projects
each secret as a file and `config.Secret` reads it once at startup. An
environment variable would be readable from `/proc/<pid>/environ`, inherited
by every child process, and captured in a crash dump. It would also require
syncing the value into a Kubernetes Secret, which makes it readable by
anything in the namespace that can `get secrets` — the exact namespace-wide
exposure per-service credentials exist to remove. Coturn is the one documented
exception, in *Known gaps*.

**One SecretProviderClass per workload, not one per namespace.** A shared
class mounts every credential into every pod, which would make the
per-service database roles decorative. The binding that gives them force is
IAM: each workload's Google service account is granted `secretAccessor` on its
own secrets and no others, so editing a manifest to mount someone else's
secret yields a permission error rather than the secret.

### Database roles

**Postgres** has per-service roles with column-level grants, in migrations
`0002` and `0007`. None of them has a password: on Cloud SQL they authenticate
through IAM database authentication, so the Cloud SQL proxy's
`--auto-iam-authn` plus the pod's Workload Identity is the whole credential
and there is nothing to rotate or leak.

The push consumer can read a device token but not the phone number attached to
it. `svc_admin` can read the columns a moderator needs and update only the four
ban columns — `phone` is absent from its grants entirely, and it has no
Cassandra role at all, so message content is equally out of reach.

**Cassandra** has per-service roles in `db/cassandra/roles.cql`, applied by the
schema Job:

| Role | Grants | Why |
|---|---|---|
| `svc_chat` | SELECT + MODIFY on message tables | Reads history, writes edits and soft deletes — but cannot insert |
| `svc_persister` | SELECT + MODIFY, plus inserts | The only writer of message history, downstream of Kafka |
| `svc_media` | SELECT on `media_acl` only | Internet-facing, handles attacker-supplied paths, must never read a message body |
| `svc_readonly` | SELECT on the keyspace | Investigation and analytics, so nobody hands out a writing role to answer a question |

The split between `svc_chat` and `svc_persister` is the interesting one: the
chat service cannot insert a message. Every message reaches Cassandra through
the persister, downstream of Kafka's `acks=all` durability boundary, so a
compromised chat service cannot forge history that skipped it.

### The audit trail

Administrative and privacy-relevant actions — a member removed, an account
deleted, an operator looking someone up — are recorded to a dedicated Kafka
topic with a year of retention, separate from application logs so a
log-volume purge cannot take the trail with it.

Entries are hash-chained per writer: each carries the hash of its predecessor,
so altering or removing one invalidates every entry after it. This does not
*prevent* tampering — anything with write access could rewrite the whole
chain — but it makes selective, quiet tampering detectable, which is the
realistic threat.

The `auditor` consumer verifies each chain as records arrive, raises
`messaging_audit_chain_breaks_total` on a break, and archives every entry to a
Cloud Storage bucket whose retention policy is **locked** in prod. A locked
policy cannot be shortened or removed by anyone — including the project owner
and Google — which is what makes the archive evidence rather than a report.
The auditor holds `objectCreator`, not `objectAdmin`, so it cannot delete from
the archive it writes.

Entries deliberately carry no message content, no phone numbers and no key
material. An audit log is read by more people than the data it describes.

### Moderation and bans

Banning an account is the platform's sharpest power over a person, so it is
concentrated in one place — `admin-service` — behind one boundary, writing to
one audit trail. That service is not routable from the internet and the mesh
policy restricts it to the operator gateway's identity.

A ban is enforced at two points, and both exist for a reason:

| Point | Reads | Why |
|---|---|---|
| Token issuance (sign-in and refresh) | Postgres | Authoritative, on a cold path where a database read is free. Within one access-token lifetime a banned account cannot obtain credentials at all. |
| The send path | Redis | Closes the window where a ban lands while an access token is still valid. |

The send-path check **fails open** on a Redis error, deliberately. The
authoritative check is already elsewhere, so failing closed would silence the
entire platform to enforce a rule that is still being enforced — trading a
bounded problem for a total one. The admin service reconciles the cache from
Postgres on a timer, because a Redis flush would otherwise stop that check
working with nothing to say so.

Every ban records the operator, the time and a written reason, enforced by a
CHECK constraint. A boolean alone cannot answer "why is this account banned?"
six months later, which is exactly when the question gets asked.

### Data export

Exports include the requester's own messages in full and other people's
message bodies not at all. Including them would let any user extract their
correspondents' writing in bulk simply by asking — a privacy right turned
into a disclosure mechanism. Exports are audited, because a bulk read of an
account's history is the request an attacker with a stolen session makes
first, and the record is what lets the real owner see that it happened.

### Supply chain

Binary Authorization refuses to run any image without an attestation from the
Cloud Build pipeline, and the pipeline only attests after tests, `govulncheck`
and a container vulnerability scan pass. Artifact Registry uses immutable
tags, so `:v1.2.3` cannot be repointed at different bytes after the fact.

---

## Privacy decisions

**Push notifications carry no message content by default.** The server
composes the notification text, so a preview would put message content on a
lock screen. For encrypted chats it is impossible anyway.

**Presence is not public.** The presence service has no external route; it is
reachable only from the gateway, the chat service and the pusher, enforced by
an AuthorizationPolicy. Publishing it directly would let anyone poll whether a
given user is online.

**Deleting an account frees the phone number and username** by rewriting them,
so the identifiers can be reused, while keeping the row so message history
stays attributable.

**Messages are soft-deleted, not tombstoned.** A real Cassandra `DELETE`
creates a tombstone that every subsequent read of the partition must skip, and
enough of them make a query time out. Overwriting in place keeps reads cheap;
the row is reclaimed by TTL.

**Media uploads are allowlisted by MIME type.** The danger is a file a browser
renders as active content when a victim opens the CDN URL, and there are far
more ways to spell "HTML" than ways to spell "JPEG".

**Media access follows chat membership.** The `media_acl` table records which
chat an object was shared into, written by the persister once the message is
durable. Downloading requires membership in that chat, so a forwarded object
path grants nothing and removing someone from a chat removes their access to
its media. Derivatives resolve to their original's binding, so a thumbnail is
governed by the same row — see `gcsx.ACLKey`.

**Every upload is scanned before it can be served.** ClamAV runs as a sidecar
to the media processor, so object bytes never leave the pod to be scanned. An
unreachable scanner fails the job and retries; it never passes the file
through. A file too large to scan is refused rather than skipped, or the size
limit becomes the bypass.

---

## Known gaps

Listed because an unstated gap is worse than a stated one.

### No end-to-end encryption for regular chats

Cloud chats are encrypted in transit and at rest, but the server can read
them — which is what makes server-side search, push previews and multi-device
sync without key exchange possible. The `encrypted` flag and opaque-body
handling are the hooks for secret chats; the client-side key exchange is not
built.

### The internal-header trust boundary

`chat-service`'s `/internal` endpoints trust `X-User-Id` without verifying a
token. This is safe only while the mesh AuthorizationPolicy restricts those
paths to the gateway's workload identity. **If that policy is ever removed,
this is a complete authentication bypass.**

*Mitigation:* the policy lives in the same kustomize base as the Deployment,
so it cannot be deployed without it. A stronger design would have the gateway
mint a short-lived internal token.

### Moderation is human, not automated

Users can report, staff can review and ban, and every step is audited — but
there is no content classification, no reputation scoring and nothing that
acts without a person. Rate limits stop volume; they do not stop a patient
spammer, and a queue only works while someone is reading it.

`user.events` carries the signal an automated pipeline would consume.

### Cassandra's grants are coarser than Postgres's

Per-service roles exist (`db/cassandra/roles.cql`): `svc_chat` reads history
and writes edits, `svc_persister` is the only role that may insert a message,
`svc_media` may read the media ACL table and nothing else. Each has its own
password in Secret Manager, and each workload's Google service account can
read only its own — so a manifest edit alone cannot widen access.

What remains a gap is granularity. Cassandra grants on keyspaces and tables,
never on columns, so a role that may read a table may read every column of it.
Postgres gives column-level grants and this does not.

### Truncating the end of the audit chain is not self-evident

The hash chain detects an altered entry, a removed one and a reordered one.
It cannot detect entries cut off the *end* — the remainder verifies perfectly,
because a chain says nothing about records that were never written to it.

Two things cover it, neither perfectly: the per-writer sequence numbers, which
make a jump from seq 40 to seq 60 visible, and the archive bucket, whose
retention policy is locked in prod and therefore cannot be shortened or
emptied by anyone, including the project owner. A writer that is silenced
*before* it ever records is outside what any of this can see.

### The audit trail can lose its most recent entries

Entries are recorded after the action succeeds, so the log never claims
something that did not happen. The cost is a window: a pod killed between the
database commit and the Kafka publish loses that one entry. Recording first
would trade a missing entry for a false one, and a trail that reports removals
which never occurred is worse than one with a gap — the gap is detectable from
the sequence numbers, the lie is not.

### Coturn's secret is a namespace-visible Kubernetes Secret

Every other credential is projected as a file and read once at startup, so it
never enters a process environment or etcd. Coturn is a third-party image that
takes its `static-auth-secret` from an environment variable and has no
file-based equivalent, so that one value is synced to a Kubernetes Secret and
is readable by anything in the namespace with `get secrets`.

The exposure is bounded: the TURN secret grants relay bandwidth, not access to
messages. TURN relays already-encrypted media and never holds a key.

---

## Reporting

Send vulnerability reports to `security@pervagans.com`. Please include a
description, reproduction steps and impact. We will acknowledge within two
business days.

Do not open a public issue for a security bug.
