# Messaging platform on Google Cloud

A realtime messaging backend: MTProto-derived protocol over TCP, UDP and
WebSocket, nine Go services, Kafka-backed persistence, and the Terraform and
Cloud Build to run it on GKE.

Arabic overview: [README.ar.md](README.ar.md).

---

## What is here

```
pkg/                    shared libraries
  mtproto/              the protocol: AES-IGE, KDF, envelope, DH handshake
    codec/              transport framings + obfuscation2
    transport/          TCP, UDP (fragmentation + path validation), WebSocket
  mtclient/             a complete client — drives the end-to-end tests
  kafkax/ cassandrax/   data-layer clients with the settings that matter
  redisx/ pgstore/      documented inline
  authn/ ratelimit/     credentials and the distributed token bucket
  push/ gcsx/           FCM and signed-URL media
  mediaproc/ searchx/   thumbnails, transcode, virus scan; ACL-filtered search
  secretchat/ turn/     E2E key exchange; TURN REST credentials
  auditlog/             hash-chained administrative audit trail
services/
  auth-service/         phone verification, JWT issuance, device sessions
  chat-service/         the message write path and chat management
  realtime-gateway/     terminates MTProto over three transports
  presence-service/     who is online, and where
  media-service/        signed upload/download URLs, ACL-checked
  notification-service/ FCM dispatch
  search-service/       message and user search
  call-service/         WebRTC signalling and TURN credentials
  admin-service/        moderation; not reachable from the internet
  consumers/            persister, pusher, indexer, mediaproc, auditor
web/                    Next.js client with its own MTProto implementation
android/                Kotlin MTProto module, pinned to the same vectors
db/                     Cassandra CQL, per-service roles, Postgres migrations
deploy/
  terraform/            the full GCP footprint, three environments
  k8s/                  kustomize base + dev/staging/prod overlays
  cloudbuild/           per-service pipeline, PR validation
  clouddeploy/          staging → canary → production
build/                  Dockerfiles
tools/loadgen/          synthetic clients against the real protocol
docs/                   architecture, security, runbook, cost
```

## Quick start

```bash
make dev-up && make dev-migrate
```

That brings up Kafka, Cassandra, Postgres, Redis and Elasticsearch in Docker
and applies both schemas. Then, in separate terminals:

```bash
make run-auth
```

```bash
make run-chat
```

```bash
make run-gateway
```

`make help` lists everything.

## Verify

```bash
make check
```

Runs `go vet`, the formatter check, and the full suite under the race
detector. The manifests and infrastructure have their own gates:

```bash
make k8s-validate
```

```bash
make tf-validate
```

---

## How a message travels

```
  phone ──MTProto/TCP──▶ realtime-gateway ──HTTP──▶ chat-service
                                                         │
                                    ┌────────────────────┼────────────────────┐
                                    ▼                    ▼                    ▼
                              Redis INCR          Kafka messages.raw    Redis pub/sub
                            (sequence number)      (acks=all — the        (fanout to
                                                  durability boundary)   online devices)
                                                         │
                                                         ▼
                                                    persister
                                                    │        │
                                             Cassandra   messages.persisted
                                                              │        │
                                                          pusher    indexer
                                                          (FCM)   (Elasticsearch)
```

Six steps in the send path, in this order:

1. Authorise from the Redis membership cache, falling back to Postgres.
2. Deduplicate against the client's `random_id`.
3. Allocate a dense per-chat sequence number (Redis `INCR`).
4. Publish to Kafka with `acks=all`. **This is the durability boundary.**
5. Fan out over Redis pub/sub to whoever is connected.
6. Return the sequence number.

Cassandra is deliberately *not* on this path. Kafka with `acks=all` already
means the message survives a broker failure, so waiting for Cassandra as well
would double send latency for no additional guarantee. The persister commits
it a few milliseconds later.

## The decisions worth knowing about

**Two load balancers.** The Global External HTTPS LB is an L7 proxy: it cannot
carry raw MTProto over TCP and has no UDP path at all. The Network LB in
passthrough mode carries both, and preserves the client's source address so
per-IP rate limiting sees real addresses. See
[`deploy/terraform/modules/lb-network`](deploy/terraform/modules/lb-network/main.tf).

**Redis holds the sequence counters, so `maxmemory-policy` is `noeviction`.**
The instinct is `allkeys-lru`; it is wrong here. Silently evicting a chat's
counter would restart its sequence mid-conversation and overwrite history.
Failing writes loudly under memory pressure is far better.

**Cassandra partitions are bucketed at 10k messages.** A chat's history is
unbounded and an unbounded partition is the classic way to kill a Cassandra
cluster. See [`db/cassandra/schema.cql`](db/cassandra/schema.cql).

**The gateway cannot reach Postgres or Cassandra.** It is the tier most
exposed to the internet and holds no business logic, so a compromise there is
not a path to the data — enforced by both NetworkPolicy and IAM.

**Messages are pushed from `messages.persisted`, never `messages.raw`.**
Waking someone's phone for a message that a later failure would lose is the
worst kind of bug: visible, unexplainable, unrecoverable.

**No service account keys anywhere.** Workload Identity binds each Kubernetes
service account to a Google one and the metadata server issues short-lived
tokens. Signed URLs go through the IAM `signBlob` API rather than a local key.

## Protocol: what is faithful, what is not

The cryptography and transport are MTProto 2.0:

- AES-256-IGE with Telegram's exact chaining, pinned by a known-answer test.
- The `msg_key` construction and the interleaved AES key/IV derivation, with
  the `x=0`/`x=8` split giving each direction its own keys.
- The envelope: `auth_key_id ‖ msg_key ‖ AES-IGE(salt ‖ session_id ‖ msg_id ‖
  seq_no ‖ length ‖ body ‖ padding)`.
- `msg_id` semantics, replay rejection and the time window.
- The auth-key handshake: `req_pq` proof of work, RSA-wrapped `new_nonce`,
  2048-bit Diffie-Hellman, `tmp_aes_key` derivation.
- Abridged, intermediate and padded-intermediate framings, plus obfuscation2.

**The RPC payload is not TL.** A call is a 4-byte constructor id followed by a
JSON body. Telegram's TL schema is a large, generated, version-locked artefact
and carrying a hand-written subset of it would be a permanent maintenance cost
for a platform whose clients we also write.

**Stated plainly: an official Telegram client cannot talk to this server.**
This is not a Telegram-compatible implementation. It is a messaging protocol
built on MTProto's cryptographic and transport design. Everything above the
payload boundary is unchanged, so swapping in a real TL codec means replacing
one file — `pkg/mtproto/tl.go`.

The DH group is RFC 3526 MODP group 14 rather than Telegram's own prime: a
published, widely reviewed group with the same properties, which a client can
verify against the RFC instead of trusting the server.

## Deploying

```bash
cd deploy/terraform && terraform init -backend-config=envs/prod/backend.hcl
```

```bash
terraform apply -var-file=envs/prod/terraform.tfvars
```

The apply is two-phase, and `terraform output next_steps` prints exactly what
to do between them: the HTTPS load balancer's backend is a network endpoint
group that the GKE Gateway controller creates, so it does not exist until the
cluster is up and the workloads are deployed.

Then seed the secrets — Terraform never holds a secret value, because state is
a file that gets copied and diffed:

```bash
./scripts/bootstrap-secrets.sh messaging-prod prod
```

```bash
kubectl apply -k deploy/k8s/overlays/prod
```

## Documentation

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component-by-component design and the trade-offs behind it |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, what is protected, what is not yet |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Incident procedures and routine operations |
| [docs/COST.md](docs/COST.md) | What this costs and which knobs move it |
| [docs/API.md](docs/API.md) | REST and MTProto surface |

## What is not built

Stated up front rather than discovered later:

- **An iOS client.** There are three independent MTProto implementations — Go
  (`pkg/mtclient`), TypeScript (`web/lib/mtproto`) and Kotlin
  (`android/mtproto`), all pinned to the same test vectors — but no Swift one.
- **A production moderation pipeline.** `user.events` carries the signal one
  would consume, and the audit trail records the actions a moderator takes,
  but there is no content classification or reputation scoring.
- **Server-side E2E key escrow for secret chats — deliberately.** The server
  is a blind relay for those, which is the point; it also means a user who
  loses every device loses that history.
- **A verified production deployment.** Every gate below runs green, but no
  GCP project was available, so the manifests are schema-validated rather
  than applied, and the Terraform is `validate`-clean rather than `plan`-clean
  against a real project.

Verification runs via `make check` and the gates in
[deploy/cloudbuild/pr-validate.yaml](deploy/cloudbuild/pr-validate.yaml):
`go test -race` across every package, `tsc` and the web crypto tests, the
Kotlin module's tests, the cross-implementation vectors that pin all three
protocol implementations to the same bytes, `kubeconform` against all three
overlays, and `terraform validate`.

Some tests need a Redis to be meaningful — the rate limiter's token bucket is
a Lua script, and a mock would only prove the mock works. Those skip loudly
when there is no server rather than passing quietly:

```bash
docker run -d --rm -p 63799:6379 redis:7-alpine
```
