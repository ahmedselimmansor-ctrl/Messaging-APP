-- Cassandra schema for message history.
--
-- Applied by the schema-migrate Job in deploy/k8s/jobs, and by
-- `make cassandra-schema` for local development.
--
-- Design principle: model the query, not the entity. Every table below exists
-- because exactly one access path needs it, and none of them requires a
-- secondary index, ALLOW FILTERING, or a multi-partition read.

-- ---------------------------------------------------------------------------
-- Keyspace
-- ---------------------------------------------------------------------------
--
-- NetworkTopologyStrategy with RF=3 across a single logical datacentre that
-- maps to a GCP region. The three replicas land in three zones because the
-- GossipingPropertyFileSnitch reads the zone from each node's rack
-- assignment (see the StatefulSet's topology.kubernetes.io/zone affinity), so
-- losing a zone leaves a LOCAL_QUORUM of 2 available.
--
-- SimpleStrategy is never correct here: it ignores topology entirely and will
-- happily put all three replicas in one zone.
CREATE KEYSPACE IF NOT EXISTS messaging
WITH replication = {
  'class': 'NetworkTopologyStrategy',
  'europe-west1': 3
} AND durable_writes = true;

USE messaging;

-- ---------------------------------------------------------------------------
-- messages_by_chat — the primary history table
-- ---------------------------------------------------------------------------
--
-- Partition key is (chat_id, bucket). A chat's history is unbounded, and an
-- unbounded partition is the classic way to kill a Cassandra cluster:
-- compaction, repair and reads all degrade past a few hundred megabytes.
-- Bucketing by seq/10000 keeps every partition at roughly 10k rows — about
-- 10MB at 1KB per message — which is comfortably inside the healthy range.
--
-- Clustering by seq DESC means "the newest N messages" is a contiguous slice
-- from the start of the partition: no sorting, no filtering, no seeking.
CREATE TABLE IF NOT EXISTS messages_by_chat (
    chat_id       bigint,
    bucket        bigint,
    seq           bigint,
    message_id    text,
    sender_id     bigint,
    msg_type      text,
    body          text,
    encrypted     boolean,
    media         text,     -- JSON MediaRef; opaque to Cassandra
    reply_to_seq  bigint,
    created_at    timestamp,
    edited_at     timestamp,
    deleted       boolean,
    PRIMARY KEY ((chat_id, bucket), seq)
) WITH CLUSTERING ORDER BY (seq DESC)
  -- TimeWindowCompactionStrategy, not SizeTiered: this is time-series data
  -- that is written once and never updated in bulk. TWCS groups each day's
  -- SSTables together, so old data stops being rewritten by compaction and a
  -- TTL expiry drops a whole SSTable instead of leaving tombstones behind.
  AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_unit': 'DAYS',
    'compaction_window_size': 1
  }
  -- Chat text compresses well and the CPU cost is trivial next to the disk
  -- and page-cache savings.
  AND compression = {'class': 'LZ4Compressor', 'chunk_length_in_kb': 16}
  -- Reads always specify the full partition key and a seq range, so the
  -- bloom filter earns its memory.
  AND bloom_filter_fp_chance = 0.01
  -- gc_grace_seconds defaults to 10 days, which is the window in which repair
  -- must run or deleted data can resurrect. We soft-delete instead of
  -- deleting, so tombstones are rare and a shorter window is safe.
  AND gc_grace_seconds = 259200  -- 3 days
  AND comment = 'Chat history, bucketed at 10k messages per partition';

-- ---------------------------------------------------------------------------
-- messages_by_chat_buckets — which partitions exist for a chat
-- ---------------------------------------------------------------------------
--
-- Answers "what is the newest bucket for this chat?" in one row read. Without
-- it, recovering the sequence high-water mark after a Redis loss would mean
-- guessing bucket numbers or scanning.
CREATE TABLE IF NOT EXISTS messages_by_chat_buckets (
    chat_id  bigint,
    bucket   bigint,
    PRIMARY KEY (chat_id, bucket)
) WITH CLUSTERING ORDER BY (bucket DESC)
  AND compaction = {'class': 'LeveledCompactionStrategy'}
  AND comment = 'Bucket index; tiny rows, read-heavy, hence LCS';

-- ---------------------------------------------------------------------------
-- message_by_id — lookup by the client-facing UUID
-- ---------------------------------------------------------------------------
--
-- A secondary index on message_id would be a global scan across every node.
-- A separate table keyed by message_id is one partition read.
CREATE TABLE IF NOT EXISTS message_by_id (
    message_id  text PRIMARY KEY,
    chat_id     bigint,
    bucket      bigint,
    seq         bigint
) WITH compaction = {'class': 'LeveledCompactionStrategy'}
  AND comment = 'message_id -> (chat_id, bucket, seq) for jump-to-message';

-- ---------------------------------------------------------------------------
-- message_dedupe — idempotent sends
-- ---------------------------------------------------------------------------
--
-- A client that retries a send after a network timeout presents the same
-- random_id. This table turns that retry into a lookup that returns the
-- original message instead of creating a duplicate — the single most visible
-- correctness bug a chat app can have.
--
-- TTL'd at 24 hours because the window in which a client can meaningfully
-- retry is minutes, and keeping these rows forever would double the write
-- volume of the whole platform.
CREATE TABLE IF NOT EXISTS message_dedupe (
    chat_id           bigint,
    sender_id         bigint,
    client_random_id  bigint,
    seq               bigint,
    message_id        text,
    PRIMARY KEY ((chat_id, sender_id), client_random_id)
) WITH default_time_to_live = 86400
  AND gc_grace_seconds = 3600
  -- TWCS again: every row expires on a fixed schedule, so whole SSTables age
  -- out together and expiry costs nothing.
  AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_unit': 'HOURS',
    'compaction_window_size': 6
  }
  AND comment = 'Send idempotency keys, 24h TTL';

-- ---------------------------------------------------------------------------
-- media_acl — which chat an uploaded object belongs to
-- ---------------------------------------------------------------------------
--
-- Without this table, media access is capability-based: possession of the
-- object path is sufficient, so a forwarded path grants access to anyone,
-- forever. The binding is written by the persister once the message is
-- durable, and the media service checks chat membership against it before
-- signing a download URL. Revoking someone from a chat now revokes the chat's
-- media with it.
--
-- The key is the object *stem* — the path with its extension and any
-- derivative suffix removed — so a thumbnail inherits its original's
-- permissions instead of needing a row of its own. See gcsx.ACLKey.
CREATE TABLE IF NOT EXISTS media_acl (
    acl_key     text PRIMARY KEY,
    chat_id     bigint,
    message_id  text,
    uploader_id bigint,
    bound_at    timestamp
) WITH compaction = {'class': 'LeveledCompactionStrategy'}
  -- LCS, not TWCS: these rows are read on every media download and deleted
  -- when a message is deleted, so read latency matters more than write
  -- amplification.
  AND comment = 'object stem -> chat, for media access control';

-- ---------------------------------------------------------------------------
-- message_reactions
-- ---------------------------------------------------------------------------
--
-- Reactions change far more often than messages do, so they live in their own
-- table: updating them in messages_by_chat would rewrite history rows and
-- fight TWCS.
CREATE TABLE IF NOT EXISTS message_reactions (
    chat_id    bigint,
    seq        bigint,
    user_id    bigint,
    reaction   text,
    created_at timestamp,
    PRIMARY KEY ((chat_id, seq), user_id)
) WITH compaction = {'class': 'LeveledCompactionStrategy'}
  AND comment = 'One row per user per message; LCS suits the update rate';

-- ---------------------------------------------------------------------------
-- message_edits — audit trail
-- ---------------------------------------------------------------------------
--
-- messages_by_chat holds only the current text. This table keeps the previous
-- versions, which matters for moderation and abuse reports: "they edited it
-- after I reported it" has to be answerable.
CREATE TABLE IF NOT EXISTS message_edits (
    chat_id     bigint,
    seq         bigint,
    edited_at   timestamp,
    editor_id   bigint,
    old_body    text,
    PRIMARY KEY ((chat_id, seq), edited_at)
) WITH CLUSTERING ORDER BY (edited_at DESC)
  AND default_time_to_live = 7776000  -- 90 days
  AND compaction = {
    'class': 'TimeWindowCompactionStrategy',
    'compaction_window_unit': 'DAYS',
    'compaction_window_size': 7
  }
  AND comment = 'Edit history for moderation; 90 day retention';

-- ---------------------------------------------------------------------------
-- Operational notes
-- ---------------------------------------------------------------------------
--
-- Repair: `nodetool repair -pr` weekly per node, staggered. It must complete
-- within gc_grace_seconds (3 days here) or deleted data can resurrect. The
-- CronJob in deploy/k8s/jobs/cassandra-repair.yaml runs it.
--
-- Backup: `nodetool snapshot` plus an upload of the snapshot directory to
-- GCS, per node, nightly. A snapshot is a hard link, so it is instant and
-- costs no space until compaction moves on — but it does pin disk, so the
-- upload must delete the snapshot when it finishes.
--
-- Adding a region: add the region to the keyspace replication map and run
-- `nodetool rebuild -- <source-dc>` on the new nodes. Do not change RF and
-- run repair at the same time.
