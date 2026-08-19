# Runbook

Procedures for the things that actually go wrong, and the routine work that
stops them going wrong.

Every alert in `deploy/terraform/modules/observability` links to a section
here.

---

## Orientation

```bash
gcloud container clusters get-credentials messaging-prod-cluster --region europe-west1 --project messaging-prod
```

```bash
kubectl get pods -n messaging -o wide
```

```bash
kubectl top pods -n messaging
```

Recent errors across the platform:

```bash
gcloud logging read 'resource.type="k8s_container" AND resource.labels.namespace_name="messaging" AND severity>=ERROR' --limit 50 --format json --project messaging-prod
```

---

## Alert: messages are reaching the dead-letter queue

**What it means.** A consumer exhausted its retries. This is data a user sent
that the platform accepted and then could not process.

**Urgency.** High. The DLQ retains for 30 days; after that the records are
gone.

1. Read the failures. Each record carries `source_topic`, `group` and the
   error:

   ```bash
   kubectl run -n messaging kafka-cli --rm -it --restart=Never --image=apache/kafka:3.9.0 -- /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server $KAFKA_BROKERS --topic platform.dlq --from-beginning --max-messages 20
   ```

2. The `error` field says why. Common causes:
   - **Schema mismatch** — a producer emitting a field a consumer rejects.
     Fix the consumer, redeploy, replay.
   - **Cassandra rejection** — usually a value exceeding a column limit.
   - **A genuine bug** — fix, deploy, replay.

3. Replay by producing the payloads back to `source_topic`. They are the
   original record bodies, so they can be produced verbatim.

---

## Alert: the persister is falling behind

**What it means.** Records arrive on `messages.raw` faster than they are
written to Cassandra.

**User impact.** Messages appear to send but are missing from history on
another device, and push notifications are delayed by the lag.

```bash
kubectl logs -n messaging -l app=persister --tail=100
```

Causes, in order of likelihood:

1. **Cassandra is slow.** Check compaction and write latency:

   ```bash
   kubectl exec -n data cassandra-0 -- nodetool tpstats
   ```

   ```bash
   kubectl exec -n data cassandra-0 -- nodetool compactionstats
   ```

   A large compaction backlog means the ring cannot keep up. Throttle
   compaction to give writes headroom:

   ```bash
   kubectl exec -n data cassandra-0 -- nodetool setcompactionthroughput 32
   ```

2. **Too few persister pods.** A pod can own at most one partition at a time,
   so replicas above the partition count do nothing and replicas below it mean
   partitions queue:

   ```bash
   kubectl scale -n messaging deployment/persister --replicas=16
   ```

3. **A poison record retrying.** Look for the same offset warning repeatedly.
   It will reach the DLQ after its retries; if it is blocking a partition
   badly, that is the DLQ working as designed.

---

## Alert: API error rate above 1%

1. Which backend, and which status:

   ```bash
   gcloud logging read 'resource.type="http_load_balancer" AND httpRequest.status>=500' --limit 20 --format json --project messaging-prod
   ```

2. Did a deploy just land?

   ```bash
   gcloud deploy rollouts list --delivery-pipeline=messaging-pipeline --region=europe-west1 --project=messaging-prod --limit=5
   ```

   If so, roll back — see below.

3. Is a dependency down? Readiness probes say so directly:

   ```bash
   kubectl get pods -n messaging -o custom-columns='NAME:.metadata.name,READY:.status.conditions[?(@.type=="Ready")].status'
   ```

   ```bash
   kubectl exec -n messaging deploy/chat-service -- wget -qO- localhost:9090/readyz
   ```

   The `/readyz` body names the failing dependency.

---

## Alert: realtime connections dropped sharply

A 30% fall in five minutes without a deploy.

**Rule out a deploy first.** A rolling update of the gateway moves connections
by design, and `Drain` makes it gradual.

Otherwise, in order:

1. **Cloud Armor blocking real users.** The most common cause of a sudden
   drop, usually after a rule change:

   ```bash
   gcloud logging read 'resource.type="http_load_balancer" AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"' --limit 20 --project messaging-prod
   ```

   If a rule is over-matching, set it to preview rather than deleting it, so
   you keep the signal:

   ```bash
   gcloud compute security-policies rules update 2000 --security-policy=messaging-prod-api-armor --preview --project=messaging-prod
   ```

2. **NAT port exhaustion.** Presents as intermittent failures that look like
   DNS:

   ```bash
   gcloud logging read 'resource.type="nat_gateway" AND jsonPayload.allocation_status="DROPPED"' --limit 20 --project messaging-prod
   ```

   Raise `max_ports_per_vm` or add a NAT IP in `modules/network`.

3. **The Network LB's backends are unhealthy:**

   ```bash
   gcloud compute backend-services get-health messaging-prod-mtproto-backend --region=europe-west1 --project=messaging-prod
   ```

---

## Alert: Cloud SQL connections near exhaustion

At 100% every service that touches Postgres fails to connect, which takes down
login and chat creation together.

**Immediate mitigation** — lower the per-pod pool on the highest-replica
service and restart it:

```bash
kubectl set env -n messaging deployment/chat-service POSTGRES_MAX_CONNS=10
```

**Then** work out which service grew. The arithmetic is pods × pool size:

```bash
kubectl get deploy -n messaging -o custom-columns='NAME:.metadata.name,REPLICAS:.status.replicas'
```

**Real fix:** either raise `max_connections` on the instance (a restart), or
put PgBouncer in front in transaction-pooling mode, which is the right answer
past a few dozen pods.

---

## Moderation: banning an account

Never with a direct database write. `UPDATE users SET banned = true` skips the
audit entry, skips the Redis mirror and skips session revocation — the account
stays logged in, keeps sending until its token expires, and nothing records
who did it or why.

Use the admin API:

```bash
curl -X POST "$ADMIN/admin/v1/users/12345/ban" -H 'Content-Type: application/json' -d '{"reason":"repeated unsolicited bulk messages to non-contacts, reports 881 and 902","revoke_sessions":true}'
```

The reason is mandatory and must be substantive. It is the record someone
reads during an appeal.

**If the ban does not take effect on the send path**, the Redis mirror is
stale. It reconciles every 15 minutes; to force it, restart the admin service
— reconciliation runs at startup:

```bash
kubectl rollout restart -n messaging deployment/admin-service
```

**After a Redis failover or flush**, send-path ban enforcement is silently off
until the next reconcile. Bans remain enforced at token issuance throughout,
so the exposure is bounded at one access-token lifetime, but forcing a
reconcile closes it sooner.

---

## Alert: the audit chain is broken

`messaging_audit_chain_breaks_total` is non-zero. **This is a security
incident, not an availability one.** The administrative audit trail can no
longer be trusted from the reported entry onwards.

Do not restart the auditor. Restarting loses the in-memory chain state and
makes the break harder, not easier, to characterise.

**First, read what it found.** The log line names the writer, the sequence
number and the kind:

```bash
kubectl logs -n messaging deployment/auditor --tail=200 | grep "AUDIT CHAIN BROKEN"
```

Three kinds, meaning different things:

| Kind | Meaning | Most likely cause |
|---|---|---|
| `altered` | An entry's content no longer matches its own hash | Someone rewrote a record in the topic |
| `sequence_gap` | Entries are missing between two records | Records deleted, or a writer's records lost |
| `linkage` | The hashes do not chain, but the sequence is contiguous | An entry was substituted for another |

**Second, confirm against the archive.** The bucket's retention policy is
locked in prod, so its copy cannot have been altered even by someone who could
alter the topic. If Kafka and the archive disagree, the archive is right.

```bash
gsutil ls "gs://messaging-prod-audit-archive/audit/$(date -u +%Y/%m/%d)/"
gsutil cat "gs://messaging-prod-audit-archive/audit/.../writer-1-500.jsonl" | jq -c 'select(.seq >= 40 and .seq <= 60)'
```

**Third, decide whether it is benign.** One case is: a pod restarted, its
successor began a new chain at seq 1, and the previous chain simply ended.
That is normal and the auditor does not report it. What it *does* report and
is still benign: reading a writer mid-chain after a Kafka retention expiry
drops the earlier records. The log says so explicitly ("starts mid-chain")
rather than raising a break.

Anything else is tampering or data loss, and both need the same first move:
preserve the evidence. Do not let retention expire on the affected window
while you investigate.

**What this cannot tell you.** Entries cut off the *end* of a chain leave a
chain that verifies perfectly. If you suspect a truncation rather than an
edit, compare the archive's highest sequence per writer against what the topic
holds — a writer that stops mid-sequence with no restart is the signature.

---

## Alert: audit entries are not reaching the archive

`messaging_audit_archive_failures_total` is climbing. Entries are buffered in
the auditor's memory and retried, so nothing is lost yet — but a pod restart
while the buffer is full loses whatever it held.

Check the bucket is reachable and the identity still has `objectCreator`:

```bash
kubectl logs -n messaging deployment/auditor --tail=50 | grep -i archiv
```

The most common cause after a working deploy is the retention lock doing its
job: an object cannot be overwritten before its retention expires, so a retry
that reuses an object name fails. Object names include the sequence range, so
this only happens if the same range is re-archived — which means the consumer
group offset was reset. If that is what happened, that is the thing to fix.

---

## Rolling back

Cloud Deploy keeps every release, so a rollback is a promotion, not a rebuild:

```bash
gcloud deploy targets rollback prod --delivery-pipeline=messaging-pipeline --region=europe-west1 --project=messaging-prod
```

To a specific release:

```bash
gcloud deploy releases promote --release=chat-service-abc1234 --delivery-pipeline=messaging-pipeline --to-target=prod --region=europe-west1 --project=messaging-prod
```

**If a canary is in flight**, abandon it rather than rolling back — the stable
subset is still serving:

```bash
gcloud deploy rollouts cancel ROLLOUT --release=RELEASE --delivery-pipeline=messaging-pipeline --region=europe-west1 --project=messaging-prod
```

**Emergency, no Cloud Deploy:**

```bash
kubectl rollout undo -n messaging deployment/chat-service
```

---

## Cassandra

### A node is down

```bash
kubectl exec -n data cassandra-0 -- nodetool status
```

With RF=3 and `LOCAL_QUORUM`, one node down is survivable and the ring keeps
serving. Two down in the same replica set fails writes.

1. Why did the pod die?

   ```bash
   kubectl describe pod -n data cassandra-2
   ```

   ```bash
   kubectl logs -n data cassandra-2 --previous --tail=200
   ```

2. **OOMKilled** — the JVM heap is capped at 8G against a 32Gi limit, so an
   OOM means off-heap growth: usually too many SSTables or a large partition.
   Check for a partition that has outgrown its bucket:

   ```bash
   kubectl exec -n data cassandra-0 -- nodetool tablehistograms messaging messages_by_chat
   ```

3. **Marked down but running** — almost always a GC pause longer than the
   failure detector's threshold. Confirm in the logs, then reduce the heap or
   the concurrent compactors.

### Replacing a dead node

Only if the node is permanently gone. The StatefulSet recreates the pod and
the PVC survives, so most of the time you do nothing.

If the data is genuinely lost:

```bash
kubectl delete pvc -n data cassandra-data-cassandra-2
```

```bash
kubectl delete pod -n data cassandra-2
```

The new pod bootstraps and streams from its replicas. Then:

```bash
kubectl exec -n data cassandra-0 -- nodetool cleanup messaging
```

### Repair is overdue

`gc_grace_seconds` is three days. If repair has not completed within that
window, **deleted data can resurrect**.

```bash
kubectl get cronjob -n data cassandra-repair
```

```bash
kubectl create job -n data --from=cronjob/cassandra-repair repair-manual
```

```bash
kubectl logs -n data -l job-name=repair-manual -f
```

Repair on a large ring takes hours. Do not run it alongside a bootstrap.

### Rebuilding Cassandra from Kafka

This is why `messages.raw` retains for seven days.

1. Stop the persister:

   ```bash
   kubectl scale -n messaging deployment/persister --replicas=0
   ```

2. Reset the consumer group to the earliest offset:

   ```bash
   kubectl run -n messaging kafka-cli --rm -it --restart=Never --image=apache/kafka:3.9.0 -- /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server $KAFKA_BROKERS --group persister --topic messages.raw --reset-offsets --to-earliest --execute
   ```

3. Scale back up. Every write is idempotent, so replaying is safe:

   ```bash
   kubectl scale -n messaging deployment/persister --replicas=16
   ```

---

## Redis

### A total Memorystore outage

**This is the one hard dependency.** Sequence allocation fails, so sends fail.

1. Confirm:

   ```bash
   gcloud redis clusters describe messaging-prod-redis --region=europe-west1 --project=messaging-prod
   ```

2. Presence and rate limiting degrade gracefully; sending does not. There is
   no application-level workaround — the recovery is the cluster recovering.

3. **After recovery**, sequence counters will be cold. This is handled: the
   allocator takes a short lock, reads the true maximum from Cassandra and
   seeds past it with headroom. Watch for the reseed in the chat service logs
   and confirm no chat's sequence went backwards:

   ```bash
   kubectl logs -n messaging -l app=chat-service --tail=200 | grep -i seq
   ```

### Memory pressure

`maxmemory-policy` is `noeviction`, so writes fail rather than silently
evicting a sequence counter. Failing loudly is the intended behaviour.

```bash
gcloud redis clusters describe messaging-prod-redis --region=europe-west1 --format='value(stateInfo)' --project=messaging-prod
```

Add a shard — an online reshard:

```bash
gcloud redis clusters update messaging-prod-redis --region=europe-west1 --shard-count=5 --project=messaging-prod
```

---

## Routine operations

### Rotating the JWT signing key

Zero downtime, because verifiers accept every key in the JWKS and select by
`kid`.

1. Generate a new key with a new id and add it as a Secret Manager version.
2. Deploy the auth service with the new `JWT_SIGNING_KEY_ID`. It now signs
   with the new key and serves both in the JWKS.
3. Wait for the longest access token TTL (15 minutes) plus the verifiers'
   JWKS refresh interval (15 minutes). Thirty minutes is safe.
4. Remove the old key version.

**Do not skip step 3.** Removing the old key while tokens signed with it are
still live rejects every one of them.

### Rotating the MTProto server key

**This is not routine.** Clients pin the public key, so rotating it means a
coordinated client release: ship a version that accepts both fingerprints,
wait for adoption, then rotate. Doing it without that leaves every un-updated
client unable to handshake.

### Scaling the gateway

The HPA scales on connection count, targeting 30k per pod against a 40k limit.
To change the ceiling:

```bash
kubectl set env -n messaging deployment/realtime-gateway MAX_CONNECTIONS_PER_POD=60000
```

Memory is the constraint — roughly 8KB of buffers per connection — so raise
the memory limit and `GOMEMLIMIT` together, and remember one gateway pod per
node because of the `hostPort`.

### Adding Kafka partitions

**One way only.** Partitions can be increased but never decreased, and
increasing them changes key-to-partition mapping — so messages for an existing
chat may land on a different partition than its history did, breaking ordering
across the change.

Plan for growth up front. If you must:

1. Drain the consumers.
2. Increase the count.
3. Accept that ordering is not guaranteed across the boundary for existing
   chats.

### Draining a node for maintenance

```bash
kubectl cordon NODE
```

```bash
kubectl drain NODE --ignore-daemonsets --delete-emptydir-data --grace-period=180
```

The PodDisruptionBudgets hold the line: one gateway pod at a time, one
Cassandra node at a time, 75% of the chat service available.

**Never drain a Cassandra node without checking the ring first** — if another
node is already down, draining a second fails `LOCAL_QUORUM`:

```bash
kubectl exec -n data cassandra-0 -- nodetool status
```
