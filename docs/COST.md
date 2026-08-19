# Cost

What this platform costs to run, which components dominate, and what to cut
first.

All figures are **rough monthly estimates in USD for `europe-west1` at
on-demand list prices**, current as of early 2026. They are for reasoning
about relative magnitude and about which knob matters — not for a budget. Use
the [GCP pricing calculator](https://cloud.google.com/products/calculator) for
a real number, and check current prices before committing.

---

## The three environments

| | dev | staging | prod (launch) |
|---|---|---|---|
| GKE nodes | 9 × e2-standard-2 (spot) | 9 × mixed | 18 × mixed |
| Cloud SQL | db-f1-micro | db-custom-2-8192 | db-custom-8-32768 HA + replica |
| Memorystore | 1 shard, no replica | 1 shard + replica | 3 shards + replicas |
| Kafka | 3 vCPU | 3 vCPU | 6 vCPU |
| Cassandra | 3 nodes on spot | 3 nodes | 6 nodes, 500GB SSD each |
| **Rough total** | **~$400** | **~$1,400** | **~$5,500** |

---

## Production, broken down

| Component | Configuration | ~$/month | Share |
|---|---|---|---|
| GKE — stateful pool (Cassandra) | 6 × n2-highmem-8 | 1,700 | 31% |
| GKE — persistent disks | 6 × 500GB pd-ssd | 1,020 | 19% |
| GKE — realtime pool | 6 × n2d-standard-8 | 1,000 | 18% |
| GKE — stateless pool | 6 × n2d-standard-4 | 500 | 9% |
| Cloud SQL | db-custom-8-32768 HA + 1 replica | 700 | 13% |
| Managed Kafka | 6 vCPU, 24GB | 350 | 6% |
| Memorystore | 3 shards + 3 replicas | 300 | 5% |
| GKE cluster fee | regional | 72 | 1% |
| Cloud Storage | 1TB standard + lifecycle | 25 | <1% |
| Load balancers | 2 forwarding rules + rules | 40 | <1% |
| Cloud Armor | policy + rules | 20 | <1% |
| Logging & monitoring | ~200GB ingest | 100 | 2% |
| Egress | 500GB to internet | 60 | 1% |
| Secret Manager, KMS, DNS, Artifact Registry | | 30 | <1% |
| **Total** | | **~$5,900** | |

Added since that table was first written, and small enough not to change its
shape:

| Component | Configuration | ~$/month | Note |
|---|---|---|---|
| mediaproc | 2 pods on the stateless pool, +1 vCPU each for ffmpeg | 60 | Transcoding is the CPU-hungriest thing here; it is a consumer, so a backlog costs latency, not errors |
| ClamAV sidecar | 2Gi memory per mediaproc pod | 20 | The signature database, not the scanner, is what needs the memory |
| coturn | DaemonSet on the realtime pool, host networking | 0 + egress | No instance cost — it shares the realtime nodes. Relay **egress** is the real cost, and it is unbounded per call |
| search-service | 2 pods | 30 | Query path only; the index itself is the Elasticsearch line below |
| auditor | 1 pod | 15 | Single replica by design — one partition, one reader |
| admin-service | 2 pods + Cloud SQL proxy | 25 | Serves staff, not users; never the thing that needs scaling |
| Audit archive bucket | ~1GB/month, ARCHIVE after 90 days | 2 | Retention-locked for seven years in prod. Note it can never be deleted early, so it accrues indefinitely — at this volume, about $150 over the full seven years |

**Watch coturn's egress.** Every other line here is predictable from user
count. TURN relay is not: it only engages when both peers are behind
symmetric NAT, and when it does, it carries the entire call. Budget on the
fraction of calls that need relaying — typically 10–20% — times the call
minutes times the bitrate. At 1 Mbit/s and 20% relayed, 100,000 call-minutes a
month is roughly 150GB of egress, about $18. Ten times the calls is ten times
the number, with no step function to warn you.

**Cassandra is half the bill** — 50% once its disks are counted. That single
fact drives most of the advice below.

Not included: Elasticsearch (Elastic Cloud starts around $100/month for a
usable cluster, or self-host on the stateless pool), FCM (free), and SMS,
which is the one cost that scales with signups rather than infrastructure —
typically $0.01–0.05 per message, so 10,000 registrations a month is
$100–500 and an OTP abuse incident is genuinely expensive. That is why the
OTP limiter fails *closed*.

---

## Cutting it down

### Starting small: ~$5,900 → ~$1,500

Reasonable for a pre-launch or early product:

1. **Cassandra: 6 nodes → 3, n2-highmem-8 → n2-standard-4, 500GB → 200GB.**
   Saves ~$1,900. RF=3 still holds with 3 nodes; you lose the headroom to lose
   a node without capacity pressure.
2. **Realtime pool: 6 → 3 nodes.** Saves ~$500. Three pods at 40k connections
   is 120k concurrent users.
3. **Stateless pool: 6 → 3 nodes.** Saves ~$250.
4. **Cloud SQL: db-custom-8-32768 → db-custom-2-8192, drop the read replica.**
   Saves ~$500. Keep Regional HA — losing the account database is losing
   login.
5. **Kafka: 6 vCPU → 3.** Saves ~$175. Three is the minimum.
6. **Memorystore: 3 shards → 1.** Saves ~$200. Keep one replica for failover.

### The bigger lever: managed Cassandra

At ~$2,700/month for six nodes and their disks, plus the operational load in
[the runbook](RUNBOOK.md) — repair, snapshots, upgrades, replacement — the
alternatives deserve a serious look:

- **Bigtable.** Fully managed, scales further, no repair, no snapshots, no
  node replacement. A 3-node cluster with 1TB of SSD is roughly $1,500/month —
  cheaper *and* less work. The cost is reshaping the data model and losing
  CQL and portability. The persister is the only component that would change.
- **DataStax Astra.** Managed Cassandra with CQL intact, so the schema and the
  driver stay. Serverless pricing means it starts near zero and scales with
  use.

**If Cassandra's operational burden becomes the constraint rather than its
cost, either is the right answer.**

### Discounts

- **Committed use discounts** — 37% for one year, 55% for three, on Compute.
  On $3,200 of nodes that is $1,200–1,800/month. The obvious first move once
  the shape of the load is known.
- **Spot nodes for the stateless pool** — up to 70% off. Fine for services
  that tolerate a 30-second eviction notice; the dev environment already does
  this. Never for Cassandra.
- **Autopilot for the stateless tier** — pay per pod rather than per node. It
  wins when utilisation is low. It cannot host Cassandra (no local SSDs, no
  sysctls), so this means two clusters, and the cross-cluster networking
  usually eats the saving.

---

## What scales with what

Knowing which axis a cost moves on is more useful than the absolute number:

| Cost | Driven by | Notes |
|---|---|---|
| Realtime nodes | **Concurrent connections** | ~40k per pod. Idle connections still cost memory. |
| Stateless nodes | **Messages per second** | The only tier that tracks activity rather than population. |
| Cassandra nodes | **Total message volume, ever** | Append-only, so this only grows. Lifecycle tiering does not apply — it is all on SSD. |
| Cassandra disk | **Message volume × RF(3) × compaction headroom** | Budget 2× the raw data size. |
| Cloud SQL | **Registered users, chats** | Grows slowly. |
| Kafka | **Peak message rate** | Not total volume — retention is only 7 days. |
| Memorystore | **Concurrent users + active chats** | Presence and sequences. |
| Cloud Storage | **Media uploaded, ever** | Lifecycle tiering makes old media a third the price. |
| Egress | **Media downloaded** | The CDN is what keeps this small; every cache hit is egress not paid at origin. |
| SMS | **Signups** | The one cost an attacker can inflate. |

### Rough shape at scale

Very approximate, extrapolating the components above:

| Concurrent users | Messages/day | ~$/month |
|---|---|---|
| 10k | 1M | 2,000 |
| 100k | 20M | 6,000 |
| 1M | 300M | 25,000 |
| 10M | 5B | 150,000 |

It is sublinear because the fixed floor — regional cluster, HA database, Kafka
minimum — is a large share of the small deployment and a rounding error in the
large one.

---

## Watching it

Cost visibility is enabled on the cluster (`cost_management_config`), so GKE
usage is attributable per namespace. To see where the money goes:

```bash
gcloud billing accounts list
```

Then in the console: Billing → Cost table, grouped by label. Everything
Terraform creates carries `env` and `component` labels, which is what makes
"what does the realtime tier actually cost" answerable.

Set a budget alert. The failure mode is not a slow drift — it is a runaway
autoscaler or an egress spike, and both are visible within hours if something
is watching:

```bash
gcloud billing budgets create --billing-account=BILLING_ACCOUNT --display-name="messaging-prod" --budget-amount=8000USD --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1.0
```
