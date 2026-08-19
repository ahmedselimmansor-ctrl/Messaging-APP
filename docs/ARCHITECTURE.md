# Architecture

This document explains why the system is shaped the way it is. The code
comments cover local decisions; this covers the ones that span components.

---

## 1. The shape of the problem

A messaging platform has an unusual load profile, and almost every decision
below follows from it:

- **Connections vastly outnumber requests.** A user with the app open holds a
  connection all day and sends a handful of messages. The realtime tier scales
  with *connected users*; the API tier scales with *actions*. Those are
  different curves, which is why they are different services on different node
  pools with different autoscaling signals.
- **Writes are append-only and unbounded.** Message history only grows. No
  relational database absorbs that indefinitely at the write rate of every
  chat in the system.
- **Reads are overwhelmingly recent.** People scroll the last screen, not last
  year. That makes a bucketed, time-ordered store ideal and makes cold storage
  tiering nearly free.
- **Fanout is the expensive part.** One message to a 200-member group is one
  write and 200 deliveries.
- **Latency is felt.** A 300ms send is noticeable in a way a 300ms page load
  is not.

## 2. Tiers

### Edge

Two load balancers, because one cannot do the job:

| | Global External HTTPS LB | Network LB (passthrough) |
|---|---|---|
| Carries | REST, GraphQL, WebSocket | MTProto over TCP and UDP |
| Address | Global anycast | Regional |
| TLS | Terminated at the edge | Not terminated — MTProto is self-encrypting |
| Client IP | `X-Forwarded-For` | Preserved exactly |
| Protection | Cloud Armor WAF + rate limiting | Network-edge DDoS protection |

The HTTPS LB is an L7 proxy: it cannot carry a protocol it does not
understand, and it has no UDP path. Passthrough matters beyond protocol
support — the gateway's per-IP rate limiting needs real client addresses, and
no proxy should terminate a connection whose encryption was negotiated end to
end.

The cost of passthrough is a regional IP. Going multi-region means one Network
LB per region plus a layer above it (see §8).

### Realtime

The gateway is the only stateful tier. A pod holds tens of thousands of
connections, each with a negotiated auth key and a subscription to its user's
update channel.

All of that state is recoverable:

- The auth key lives in Redis, so a reconnect lands on any pod and resumes
  without a fresh 2048-bit Diffie-Hellman exchange. Without that, every
  rolling update would trigger a full re-handshake from every client — an
  expensive, self-inflicted thundering herd.
- Subscriptions are rebuilt on reconnect.
- Missed updates are recovered by `getDifference`, which reads from durable
  storage.

So losing a pod costs a reconnect, not data. That is what makes it safe to
treat the realtime layer's delivery as best-effort.

**One Redis subscription per pod, not per connection.** A pod with 40k
connections must not open 40k Redis subscriptions. A registry maps a channel
to the sessions interested in it, and a single dispatch goroutine fans out.

**Draining is deliberate and slow.** On SIGTERM the gateway sends every live
client a "reconnect elsewhere" update and waits. Without it, a rolling update
severs tens of thousands of connections simultaneously and every client
reconnects on its own backoff — a reconnect storm against the new pods.

### API

Stateless, horizontally scaled, no session affinity. The chat service is the
only writer of messages and the only allocator of sequence numbers, which is
what makes ordering a local property rather than a distributed agreement
problem.

### Async

Kafka is the spine. Everything after "the message was accepted" hangs off it,
which means a slow Cassandra or a broken search cluster degrades a feature
rather than blocking sends.

## 3. Data stores, and why each one

| Store | Holds | Why this and not something else |
|---|---|---|
| **Cassandra** | Message history | Linear write scaling, time-ordered reads, no single write master. This is the only store that must absorb every chat's full write rate. |
| **Cloud SQL (Postgres)** | Accounts, devices, chats, membership | Small, relational, mutable data that benefits from joins, foreign keys and transactions. "Add a member" in Cassandra would be a read-modify-write race. |
| **Memorystore (Redis)** | Presence, routing, sequences, fanout, rate limits | Sub-millisecond. None of it is the system of record, so every path degrades rather than fails. |
| **Cloud Storage** | Media | Objects, not rows. Signed URLs mean the service never carries a byte. |
| **Elasticsearch** | Search index | Full-text search with an ACL filter. No GCP-managed equivalent exists. |

### Why messages are not in Postgres

At any meaningful scale the message table becomes the largest table by orders
of magnitude, every insert contends on the same indexes, and vacuum on an
append-only table of that size becomes an operational problem in itself.
Cassandra's write path — append to a commit log, insert into a memtable — has
no such contention and scales by adding nodes.

### Why membership is not in Cassandra

Membership is small, changes rarely, and is read constantly for authorisation.
It needs a consistent read and a transaction for "add a member and increment
the count". Cassandra offers neither without lightweight transactions, which
are slow and easy to misuse. Postgres does both trivially, and the Redis cache
in front means the send path rarely touches it.

### The sequence number

Clients need "everything after seq N" to be answerable with a range read and
"unread count" to be subtraction. That requires a **dense, gap-free,
per-chat** counter — which rules out snowflakes (sparse) and Cassandra
counters (not read-modify-write safe).

Redis `INCR` gives both in one round trip. The cost is that losing the key
would restart the counter, so `SeqAllocator.Next` handles a cold key by taking
a short lock, reading the true maximum from Cassandra, and seeding past it
with headroom. That path is why `maxmemory-policy` is `noeviction`: silently
evicting a counter would corrupt message ordering.

## 4. The send path, step by step

```
1. rate limit           Redis token bucket, per user and per user-per-chat
2. authorise            Redis membership cache → Postgres on miss
3. deduplicate          Cassandra lookup on (chat, sender, random_id)
4. allocate sequence    Redis INCR
5. publish              Kafka messages.raw, acks=all  ← durability boundary
6. fan out              Redis pub/sub to recipients   ← best effort
7. respond              sequence number to the sender
```

Then, asynchronously:

```
persister:  messages.raw → Cassandra → chat_sequences → messages.persisted
pusher:     messages.persisted → presence check → mute check → FCM
indexer:    search.index → Elasticsearch (batched)
mediaproc:  media.processing → virus scan → thumbnails/transcode → media.processed
auditor:    platform.audit → chain verification → GCS archive
```

**mediaproc scans before it derives, not after.** A thumbnail of a malicious
file is a second copy of the problem, and generating one hands attacker-
controlled bytes to an image decoder. A scanner that is unreachable causes a
retry, never a pass-through: "we could not check" must not become "it is
fine".

**auditor runs as a single replica.** The audit topic has one partition, so
one reader sees every entry in write order — which is what chain verification
needs. A second replica would sit idle in the consumer group.

**Why Cassandra is not in the critical path.** Kafka with `acks=all` means the
leader and every in-sync replica hold the record; the message survives a
broker failure. Waiting for Cassandra as well would double send latency and
add nothing. The client gets its sequence number in step 7; durability
happened in step 5.

**Why the sequence is allocated before publishing.** The client needs it
immediately to render the message in the right place. If the publish then
fails, the sequence number is burned — which is harmless, because sequences
must be monotonic, not gapless-under-failure.

**Why push comes from `messages.persisted`.** Notifying a user about a message
that a later failure would lose is worse than notifying them 50ms later.

## 5. The protocol

See [`pkg/mtproto/doc.go`](../pkg/mtproto/doc.go) for the precise list of what
is faithful to MTProto 2.0 and what deviates. In summary: the cryptography,
the envelope, the handshake and the transport framings are MTProto; the RPC
payload is a constructor id plus JSON rather than TL. An official Telegram
client cannot talk to this server.

### Why three transports

| | When | Trade |
|---|---|---|
| TCP | Default | Ordered and reliable, but head-of-line blocking means one lost packet stalls everything behind it |
| UDP | Lossy or high-latency links | No head-of-line blocking; ordering, retransmission and path validation move into the application |
| WebSocket | Restrictive networks, browsers | Passes any proxy that passes HTTPS; browsers cannot open raw sockets |

The UDP transport rebuilds what TCP provides, with choices a chat protocol
wants: connections keyed by a client-chosen id rather than the 4-tuple (so a
wifi-to-cellular switch keeps the session), bounded time-limited reassembly,
and **path validation before migrating** — the server challenges a new address
with a random token and only moves once the client echoes it. Without that,
anyone who guessed a connection id could redirect a victim's traffic.

## 6. Failure modes

| Failure | Effect | Why it is bounded |
|---|---|---|
| Gateway pod dies | Its clients reconnect | Auth keys are in Redis; `getDifference` recovers missed updates |
| Redis unavailable | No realtime delivery, no rate limiting; sends still work | Sequence allocation fails, so sends do stop — this is the one hard dependency |
| Kafka unavailable | Sends rejected | Correct: the durability boundary is unavailable, so accepting a message would be a lie |
| Cassandra slow | History reads slow; persister lags | Sends unaffected — they only touch Kafka |
| Cassandra down | New messages queue in Kafka | Seven-day retention; the backlog drains on recovery |
| Postgres down | No login, no chat creation; existing chats keep working | The send path reads membership from the Redis cache |
| Elasticsearch down | Search degraded | Indexer buffers, bounded, then drops — reindexable from Kafka |
| FCM down | No push for offline users | Retried; the message is already durable |
| One zone lost | ~⅓ capacity | Regional cluster, three-zone spread, `LOCAL_QUORUM` survives it |

The honest weak point is Redis: a total Memorystore outage stops sequence
allocation and therefore stops sends. Mitigations in place are the cluster's
per-shard replicas with automatic failover and hourly RDB snapshots.
Eliminating the dependency entirely would mean moving sequence allocation into
Cassandra with lightweight transactions, which trades an availability risk for
a latency cost on every single send.

## 7. Security posture

Layered, with each layer assuming the one outside it may fail:

1. **Edge** — Cloud Armor: WAF, per-IP rate limiting, adaptive L7 DDoS.
2. **Network** — private nodes, no public IPs, default-deny NetworkPolicy,
   VPC firewall.
3. **Mesh** — STRICT mTLS; AuthorizationPolicy restricts `/internal` to the
   gateway's identity.
4. **Identity** — Workload Identity, one service account per workload, no keys.
5. **Application** — JWT verification, distributed rate limiting, per-chat
   authorisation.
6. **Data** — CMEK on media, encrypted etcd, IAM database auth, per-service
   column grants.
7. **Supply chain** — Binary Authorization, vulnerability gates,
   immutable tags.

The most load-bearing rule: `chat-service`'s `/internal` endpoints trust the
`X-User-Id` header. That is safe **only** because the mesh's
AuthorizationPolicy restricts those paths to the gateway's workload identity.
Drop that policy and it becomes a complete authentication bypass — which is
why it lives in the same kustomize base as the Deployment rather than as an
optional add-on.

See [SECURITY.md](SECURITY.md) for the threat model.

## 8. Multi-region

Built, in `deploy/terraform/modules/multiregion` and
`services/chat-service/internal/region.go`. The design is **region-affine
chats**: every chat has a home region, fixed when it is created and recorded
in Postgres. Connections terminate at the gateway nearest the user, and a send
for a chat homed elsewhere is proxied to that region.

The constraint that forces this shape is sequence allocation. It is a Redis
`INCR`, Redis is regional, and two regions allocating sequences for one chat
would produce duplicate numbers and silently overwrite history — the worst
failure this system has. Ordering follows the same logic: messages of one chat
are ordered because they pass through one Kafka partition.

The cost is honest: a user in Cairo messaging a chat homed in Belgium pays one
cross-region round trip on send, roughly 60–80 ms. The alternatives pay it on
every message for everyone, or give up ordering. `crossRegionSend` is
histogrammed by home region, and an alert fires above 500 ms at p99.

Two details worth naming. The VPC must use GLOBAL routing before a second
region is added — REGIONAL does not propagate routes between them, and
switching later is a live change to the VPC. And the proxy sets
`X-Proxied-From`; without it, a misconfiguration where two regions each
believe the other is the home would bounce a request between them until
something timed out.

### The pieces, in order of difficulty

1. **Realtime.** One Network LB per region, plus Cloud DNS geo-routing or a
   global anycast layer. Straightforward.
2. **Cassandra.** Add the region to the keyspace replication map and
   `nodetool rebuild`. Cross-region replication is asynchronous, so a message
   is durable locally before it is durable remotely.
3. **Kafka.** Managed Kafka is regional. Either one cluster per region with
   MirrorMaker, or accept cross-region latency on produce.
4. **Postgres.** Cloud SQL cross-region replicas are read-only, so writes
   still funnel to one region. Account operations are rare enough that this is
   tolerable.
5. **Redis.** Memorystore is regional. Presence and sequences would have to be
   partitioned by chat home region, which is the genuinely hard part: it means
   a chat has a home region and cross-region members pay a round trip.

Points 1–3 and 5 are implemented. Point 4 stands: Cloud SQL cross-region
replicas are read-only, so account writes still funnel to one region. Account
operations are rare enough that this is tolerable, and making them multi-master
would be a much larger change for a much smaller benefit.

## 9. Alternatives considered

**Cassandra vs. Bigtable.** Bigtable is managed, scales further and removes
the entire operational burden — repair, backup, upgrades — that §11 of the
runbook describes. It was not chosen because CQL, a declarative schema and
portability off GCP are worth real money here, and because Bigtable's data
model would require reshaping the message layout. **If the operational cost of
Cassandra becomes the constraint, Bigtable or DataStax Astra is the correct
answer, and the persister is the only component that would change.**

**Pub/Sub vs. Kafka.** Pub/Sub is fully managed and needs no capacity
planning. Kafka was chosen for ordered partitions — message ordering within a
chat depends on it — and for consumer groups with replayable offsets, which is
what makes "rebuild Cassandra from the log" possible.

**gRPC vs. HTTP+JSON between services.** gRPC would be faster and typed. HTTP
was chosen because the payloads are small, the hop count is low, and every
service is debuggable with `curl`. This is the decision most likely to be
revisited under load.

**Autopilot vs. Standard GKE.** Autopilot removes node management entirely.
Standard was necessary for Cassandra: local SSDs, sysctls and kubelet
configuration are not available on Autopilot. Splitting into two clusters to
get Autopilot for the stateless tier would cost more in cross-cluster
networking than it saves.
