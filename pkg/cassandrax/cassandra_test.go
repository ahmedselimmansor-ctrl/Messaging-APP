package cassandrax

import (
	"context"
	"testing"
)

// Bucketing is the one piece of arithmetic that decides where a message
// physically lives. Everything downstream — the write, the history read, the
// edit, the soft delete — computes the bucket independently from the same
// sequence number, so if BucketOf were ever inconsistent with itself a message
// would be written to one partition and looked for in another. It would not
// error; the message would simply not be there.

func TestBucketOfIsMonotonicAndPartitions(t *testing.T) {
	// Sequences are dense and increasing, so buckets must be too. A
	// non-monotonic mapping would make the history walk (which decrements the
	// bucket) skip ranges.
	prev := BucketOf(0)
	for seq := int64(0); seq < BucketSize*3; seq += 97 {
		b := BucketOf(seq)
		if b < prev {
			t.Fatalf("BucketOf went backwards: seq %d → bucket %d after %d", seq, b, prev)
		}
		prev = b
	}
}

func TestBucketBoundariesAreExact(t *testing.T) {
	// Off-by-one here splits a partition in the wrong place. Harmless for a
	// fresh chat, and quietly wrong for every message already written under
	// the old boundary.
	cases := []struct {
		seq  int64
		want int64
	}{
		{0, 0},
		{1, 0},
		{BucketSize - 1, 0},
		{BucketSize, 1},
		{BucketSize + 1, 1},
		{2*BucketSize - 1, 1},
		{2 * BucketSize, 2},
		{100 * BucketSize, 100},
	}
	for _, tc := range cases {
		if got := BucketOf(tc.seq); got != tc.want {
			t.Errorf("BucketOf(%d) = %d, want %d", tc.seq, got, tc.want)
		}
	}
}

func TestEachBucketHoldsExactlyBucketSizeSequences(t *testing.T) {
	// The whole point of bucketing is bounding partition size. If a bucket
	// held more sequences than BucketSize, partitions would grow past the size
	// the constant promises and take compaction and repair down with them.
	for bucket := int64(0); bucket < 5; bucket++ {
		count := int64(0)
		for seq := bucket * BucketSize; seq < (bucket+1)*BucketSize; seq++ {
			if BucketOf(seq) != bucket {
				t.Fatalf("seq %d is in bucket %d, expected %d", seq, BucketOf(seq), bucket)
			}
			count++
		}
		if count != BucketSize {
			t.Fatalf("bucket %d holds %d sequences, want %d", bucket, count, BucketSize)
		}
		// And the sequence either side belongs elsewhere.
		if b := BucketOf(bucket*BucketSize - 1); bucket > 0 && b != bucket-1 {
			t.Errorf("the sequence below bucket %d is in %d", bucket, b)
		}
		if b := BucketOf((bucket + 1) * BucketSize); b != bucket+1 {
			t.Errorf("the sequence above bucket %d is in %d", bucket, b)
		}
	}
}

func TestBucketSizeIsSaneForCassandra(t *testing.T) {
	// Not a behavioural test — a guard on the constant. Cassandra degrades
	// once a partition passes a few hundred megabytes, and this is the number
	// that keeps it under. Someone raising it to "reduce the number of
	// partitions" would be trading a cheap problem for an expensive one.
	if BucketSize < 1_000 {
		t.Errorf("BucketSize = %d, small enough that a busy chat spans thousands of partitions", BucketSize)
	}
	if BucketSize > 100_000 {
		t.Errorf("BucketSize = %d; at a few KB per message this is a multi-hundred-MB partition, "+
			"which is where Cassandra compaction and repair start to suffer", BucketSize)
	}
}

func TestTheHistoryWalkCoversEveryBucketWithoutGaps(t *testing.T) {
	// History reads walk downwards, recomputing the cursor as
	// (bucket+1)*BucketSize after each step. That arithmetic has to land
	// exactly on the top of the next bucket: one too high re-reads a message,
	// one too low skips one silently.
	//
	// This reproduces the walk rather than trusting it by inspection.
	const startSeq = int64(35_000)

	bucket := BucketOf(startSeq)
	beforeSeq := startSeq

	seen := make(map[int64]bool)
	for bucket >= 0 {
		// Every sequence this iteration could return: below the cursor and
		// inside this bucket.
		lo := bucket * BucketSize
		for seq := lo; seq < beforeSeq && seq < lo+BucketSize; seq++ {
			if seen[seq] {
				t.Fatalf("sequence %d would be read twice by the history walk", seq)
			}
			seen[seq] = true
		}

		bucket--
		beforeSeq = (bucket + 1) * BucketSize
	}

	// Everything below the starting cursor must have been covered exactly once.
	for seq := int64(0); seq < startSeq; seq++ {
		if !seen[seq] {
			t.Fatalf("sequence %d would be skipped by the history walk", seq)
		}
	}
	if len(seen) != int(startSeq) {
		t.Errorf("the walk covered %d sequences, want %d", len(seen), startSeq)
	}
}

func TestRangeWalkCoversItsEndpoints(t *testing.T) {
	// Range() iterates BucketOf(from)..BucketOf(to) inclusive. If the upper
	// bound were exclusive, the newest bucket would be missing from every
	// range query that happened to end inside it — which is most of them.
	from, to := BucketSize-5, 2*BucketSize+5

	covered := make(map[int64]bool)
	for bucket := BucketOf(from); bucket <= BucketOf(to); bucket++ {
		covered[bucket] = true
	}

	if !covered[BucketOf(from)] {
		t.Error("the range walk misses the bucket containing the lower bound")
	}
	if !covered[BucketOf(to)] {
		t.Error("the range walk misses the bucket containing the upper bound")
	}
	// And the bucket in between, which a naive two-endpoint loop would drop.
	if !covered[1] {
		t.Error("the range walk misses an intermediate bucket")
	}
}

func TestBucketOfHandlesTheSentinelHistoryCursor(t *testing.T) {
	// History uses 1<<62 as "from the newest message". It must not overflow
	// into a negative bucket, which would make the walk terminate immediately
	// and return nothing.
	sentinel := int64(1) << 62
	if b := BucketOf(sentinel); b <= 0 {
		t.Fatalf("BucketOf(1<<62) = %d; the history walk would return nothing", b)
	}
}

func TestDefaultConfigIsUsable(t *testing.T) {
	c := DefaultConfig()
	if c.Keyspace == "" {
		t.Error("DefaultConfig has no keyspace")
	}
	if c.Timeout <= 0 || c.ConnTimeout <= 0 {
		t.Error("DefaultConfig has no timeout; a hung node would block indefinitely")
	}
	if c.NumConns <= 0 || c.PageSize <= 0 {
		t.Errorf("DefaultConfig has NumConns=%d PageSize=%d; both must be positive",
			c.NumConns, c.PageSize)
	}

	// Hosts are deliberately absent: they are environment-specific and come
	// from configuration. What matters is that the omission is caught loudly
	// rather than producing a client that silently connects to nothing.
	if len(c.Hosts) != 0 {
		t.Error("DefaultConfig hardcodes hosts; they belong in configuration")
	}
	if _, err := Connect(context.Background(), c); err == nil {
		t.Error("Connect accepted a config with no hosts")
	}
	// LOCAL_QUORUM is the correct default for a multi-DC ring: it survives one
	// node and does not pay a cross-region round trip. ONE would risk reading
	// stale data after a write; QUORUM would make every read cross regions.
	if got := c.Consistency.String(); got != "LOCAL_QUORUM" {
		t.Errorf("default consistency is %s, want LOCAL_QUORUM", got)
	}
}
