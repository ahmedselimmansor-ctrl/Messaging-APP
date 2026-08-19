// Command loadgen drives the realtime gateway with synthetic clients.
//
// It answers the questions capacity planning actually turns on:
//
//   - How many connections does one gateway pod hold before it degrades?
//   - What does the handshake cost, given it is a 2048-bit modular
//     exponentiation on both sides?
//   - What is the send latency distribution under N concurrent senders?
//
// It speaks the real protocol through pkg/mtclient, so it exercises the same
// code path a phone does — including the proof-of-work factorisation and the
// obfuscation layer, both of which are easy to accidentally make expensive.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pervagans/messaging-app/pkg/mtclient"
	"github.com/pervagans/messaging-app/pkg/mtproto"
)

func main() {
	var (
		addr       = flag.String("addr", "localhost:4443", "gateway TCP address")
		keyFile    = flag.String("key", "local/mtproto-server-key.pub", "server public key PEM (pinned)")
		clients    = flag.Int("clients", 100, "concurrent connections")
		duration   = flag.Duration("duration", 60*time.Second, "how long to run")
		rate       = flag.Float64("rate", 1.0, "messages per second per client")
		framing    = flag.String("framing", "intermediate", "abridged|intermediate|padded")
		obfuscated = flag.Bool("obfuscated", false, "use the obfuscation2 layer")
		rampUp     = flag.Duration("ramp", 10*time.Second, "spread connection setup over this window")
		token      = flag.String("token", "", "access token to bind sessions with (optional)")
		chatID     = flag.Int64("chat", 1, "chat id to send to")
	)
	flag.Parse()

	pubKey, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read the server public key %s: %v\n", *keyFile, err)
		fmt.Fprintln(os.Stderr, "generate one with: make keys && openssl rsa -in local/mtproto-server-key.pem -pubout -out local/mtproto-server-key.pub")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *duration+*rampUp+30*time.Second)
	defer cancel()

	s := &stats{}
	var wg sync.WaitGroup

	fmt.Printf("connecting %d clients to %s (framing=%s obfuscated=%v) over %s\n",
		*clients, *addr, *framing, *obfuscated, *rampUp)

	// Ramp rather than connecting all at once. A thundering herd of
	// handshakes measures the ramp, not the steady state — and each handshake
	// is a 2048-bit modexp on the server, so the burst is genuinely
	// expensive.
	stagger := time.Duration(0)
	if *clients > 0 {
		stagger = *rampUp / time.Duration(*clients)
	}

	for i := 0; i < *clients; i++ {
		select {
		case <-ctx.Done():
			break
		case <-time.After(stagger):
		}

		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			runClient(ctx, id, clientConfig{
				addr:       *addr,
				pubKey:     string(pubKey),
				framing:    *framing,
				obfuscated: *obfuscated,
				rate:       *rate,
				token:      *token,
				chatID:     *chatID,
				duration:   *duration,
			}, s)
		}(i)
	}

	// Report while running, so a run that is going wrong is visible without
	// waiting for it to finish.
	reportDone := make(chan struct{})
	go func() {
		defer close(reportDone)
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.snapshot()
			}
		}
	}()

	wg.Wait()
	cancel()
	<-reportDone

	s.final()
}

type clientConfig struct {
	addr       string
	pubKey     string
	framing    string
	obfuscated bool
	rate       float64
	token      string
	chatID     int64
	duration   time.Duration
}

func runClient(ctx context.Context, id int, cfg clientConfig, s *stats) {
	handshakeStart := time.Now()

	c, err := mtclient.Dial(ctx, mtclient.Options{
		Addr:               cfg.addr,
		ServerPublicKeyPEM: cfg.pubKey,
		Framing:            cfg.framing,
		Obfuscated:         cfg.obfuscated,
		DialTimeout:        30 * time.Second,
		RequestTimeout:     30 * time.Second,
		OnUpdate: func(mtproto.Update) {
			s.updates.Add(1)
		},
	})
	if err != nil {
		s.connectErrors.Add(1)
		return
	}
	defer c.Close()

	s.recordHandshake(time.Since(handshakeStart))
	s.connected.Add(1)
	defer s.connected.Add(-1)

	if cfg.token != "" {
		if _, err := c.Bind(ctx, cfg.token, "loadgen", "1.0"); err != nil {
			s.bindErrors.Add(1)
			return
		}
	}

	interval := time.Duration(float64(time.Second) / cfg.rate)
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	deadline := time.After(cfg.duration)
	randomID := int64(id) * 1_000_000

	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			return
		case <-ticker.C:
			randomID++
			start := time.Now()

			if cfg.token == "" {
				// Unbound sessions cannot send, so measure the ping path
				// instead. It still exercises the envelope, the framing and
				// the transport — everything except the upstream call.
				if err := c.Ping(ctx); err != nil {
					s.sendErrors.Add(1)
					continue
				}
			} else {
				_, err := c.SendMessage(ctx, mtproto.SendMessage{
					ChatID: cfg.chatID, Type: "text",
					Body:     fmt.Sprintf("loadgen %d/%d", id, randomID),
					RandomID: randomID,
				})
				if err != nil {
					s.sendErrors.Add(1)
					continue
				}
			}
			s.recordRequest(time.Since(start))
		}
	}
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

type stats struct {
	connected     atomic.Int64
	connectErrors atomic.Int64
	bindErrors    atomic.Int64
	sendErrors    atomic.Int64
	requests      atomic.Int64
	updates       atomic.Int64

	mu         sync.Mutex
	handshakes []time.Duration
	latencies  []time.Duration

	lastReport   time.Time
	lastRequests int64
}

func (s *stats) recordHandshake(d time.Duration) {
	s.mu.Lock()
	s.handshakes = append(s.handshakes, d)
	s.mu.Unlock()
}

func (s *stats) recordRequest(d time.Duration) {
	s.requests.Add(1)
	s.mu.Lock()
	// Cap the sample. A long run at high rate would otherwise accumulate
	// millions of durations and the process would die measuring itself.
	if len(s.latencies) < 1_000_000 {
		s.latencies = append(s.latencies, d)
	}
	s.mu.Unlock()
}

func (s *stats) snapshot() {
	now := time.Now()
	total := s.requests.Load()

	rate := float64(0)
	if !s.lastReport.IsZero() {
		elapsed := now.Sub(s.lastReport).Seconds()
		if elapsed > 0 {
			rate = float64(total-s.lastRequests) / elapsed
		}
	}
	s.lastReport = now
	s.lastRequests = total

	fmt.Printf("[%s] connected=%d requests=%d rate=%.0f/s updates=%d errors(connect=%d bind=%d send=%d)\n",
		now.Format("15:04:05"),
		s.connected.Load(), total, rate, s.updates.Load(),
		s.connectErrors.Load(), s.bindErrors.Load(), s.sendErrors.Load())
}

func (s *stats) final() {
	s.mu.Lock()
	handshakes := append([]time.Duration(nil), s.handshakes...)
	latencies := append([]time.Duration(nil), s.latencies...)
	s.mu.Unlock()

	fmt.Println()
	fmt.Println("=== results ===")
	fmt.Printf("connections established : %d\n", len(handshakes))
	fmt.Printf("connection failures     : %d\n", s.connectErrors.Load())
	fmt.Printf("bind failures           : %d\n", s.bindErrors.Load())
	fmt.Printf("requests                : %d\n", s.requests.Load())
	fmt.Printf("request failures        : %d\n", s.sendErrors.Load())
	fmt.Printf("updates received        : %d\n", s.updates.Load())

	if len(handshakes) > 0 {
		fmt.Println()
		fmt.Println("handshake latency (includes the 2048-bit DH on both sides):")
		printPercentiles(handshakes)
	}
	if len(latencies) > 0 {
		fmt.Println()
		fmt.Println("request latency:")
		printPercentiles(latencies)
	}
}

func printPercentiles(d []time.Duration) {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })

	at := func(p float64) time.Duration {
		if len(d) == 0 {
			return 0
		}
		i := int(float64(len(d)) * p)
		if i >= len(d) {
			i = len(d) - 1
		}
		return d[i]
	}

	var sum time.Duration
	for _, v := range d {
		sum += v
	}

	fmt.Printf("  n=%d  mean=%s\n", len(d), (sum / time.Duration(len(d))).Round(time.Microsecond))
	fmt.Printf("  p50=%s  p90=%s  p95=%s  p99=%s  max=%s\n",
		at(0.50).Round(time.Microsecond),
		at(0.90).Round(time.Microsecond),
		at(0.95).Round(time.Microsecond),
		at(0.99).Round(time.Microsecond),
		d[len(d)-1].Round(time.Microsecond),
	)
}
