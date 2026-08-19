package chat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// Region affinity.
//
// Every chat has a home region, fixed when it is created. Sequence allocation
// and message ordering happen there and only there, because both depend on a
// single writer: sequences are a Redis INCR, and Redis is regional; ordering
// comes from one Kafka partition, and Kafka is regional too. Two regions
// allocating sequences for one chat would produce duplicate numbers and
// silently overwrite history.
//
// So a send for a chat homed elsewhere is proxied to that region rather than
// handled locally. The user still connects to their nearest gateway — which
// is what latency they actually feel — and pays one cross-region round trip
// only when talking to a chat that lives somewhere else.
//
// Single-region deployments never take this path: HomeRegion equals the local
// region for every chat, and the proxy code is dead.

var crossRegionSend = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Namespace: "messaging",
	Name:      "cross_region_send_seconds",
	Help:      "Latency of a send proxied to the chat's home region.",
	// Buckets chosen around the expected cost: ~60-80ms between European
	// regions, more across continents. The tail above 500ms is what the
	// alert watches.
	Buckets: []float64{.05, .1, .2, .3, .5, 1, 2, 5},
}, []string{"home_region", "result"})

// isLocal reports whether this replica owns the chat.
func (s *Service) isLocal(homeRegion string) bool {
	// An empty home region means a chat created before regions existed, or a
	// single-region deployment. Treating it as local is correct in both:
	// there is nowhere else for it to be.
	return homeRegion == "" || homeRegion == s.Cfg.Base.Region
}

// proxyToHomeRegion forwards a request to the region that owns the chat.
//
// The request is replayed verbatim against the peer region's internal
// endpoint, carrying the same identity headers. The peer treats it exactly as
// it would a local call, which means there is one implementation of the send
// path rather than a local one and a remote one.
func (s *Service) proxyToHomeRegion(
	ctx context.Context,
	homeRegion, path string,
	userID, deviceID int64,
	body any,
	out any,
) error {
	peer, ok := s.Cfg.RegionEndpoints[homeRegion]
	if !ok {
		// A chat homed in a region we have no endpoint for. This is a
		// configuration error, not a user error, and silently handling it
		// locally would be far worse than failing: it would allocate a
		// duplicate sequence number.
		s.Log.Error("no endpoint configured for a chat's home region",
			"home_region", homeRegion, "configured", len(s.Cfg.RegionEndpoints))
		return httpx.ErrUnavailable("this chat's home region is unreachable")
	}

	started := time.Now()

	encoded, err := json.Marshal(body)
	if err != nil {
		return httpx.ErrInternal("could not encode the proxied request").WithCause(err)
	}

	// A generous but bounded timeout. Cross-region adds a round trip; it
	// should not add a hang.
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, peer+path, bytes.NewReader(encoded))
	if err != nil {
		return httpx.ErrInternal("could not build the proxied request").WithCause(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Id", fmt.Sprint(userID))
	req.Header.Set("X-Device-Id", fmt.Sprint(deviceID))
	// Marks the request as already proxied. Without it, a misconfiguration
	// where two regions each believe the other is the home would bounce a
	// request between them until something timed out.
	req.Header.Set("X-Proxied-From", s.Cfg.Base.Region)

	otel.GetTextMapPropagator().Inject(reqCtx, propagation.HeaderCarrier(req.Header))

	resp, err := s.regionClient.Do(req)
	if err != nil {
		crossRegionSend.WithLabelValues(homeRegion, "error").Observe(time.Since(started).Seconds())
		return httpx.ErrUnavailable("could not reach this chat's home region").WithCause(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		crossRegionSend.WithLabelValues(homeRegion, "error").Observe(time.Since(started).Seconds())

		// Pass the peer's error through rather than replacing it: the client
		// asked a question and the authoritative region answered it, so
		// "forbidden" should stay "forbidden" and not become "unavailable".
		var envelope struct {
			Error struct {
				Code       string `json:"code"`
				Message    string `json:"message"`
				RetryAfter int    `json:"retry_after"`
			} `json:"error"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		_ = json.Unmarshal(raw, &envelope)

		e := httpx.Err(resp.StatusCode, httpx.ErrorCode(envelope.Error.Code), "%s", envelope.Error.Message)
		if envelope.Error.RetryAfter > 0 {
			return httpx.ErrFloodWait(envelope.Error.RetryAfter)
		}
		return e
	}

	crossRegionSend.WithLabelValues(homeRegion, "ok").Observe(time.Since(started).Seconds())
	telemetry.MessagesDelivered.WithLabelValues("cross_region").Inc()

	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out); err != nil {
		return httpx.ErrInternal("could not decode the proxied response").WithCause(err)
	}
	return nil
}

// HomeRegionFor picks the home region for a new chat.
//
// The creator's region, always. A chat's traffic is overwhelmingly between
// people who know each other, who are usually in the same part of the world,
// so the creator's region is a good proxy for where the conversation will
// live — and any rule more clever than that would need to predict the member
// list before it exists.
func (s *Service) HomeRegionFor() string { return s.Cfg.Base.Region }

// newRegionClient builds the HTTP client used for cross-region calls.
//
// Separate from the general-purpose client because the connection
// characteristics differ: far fewer peers, much longer round trips, and
// connections worth keeping alive aggressively since establishing one costs a
// transcontinental handshake.
func newRegionClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        64,
			MaxIdleConnsPerHost: 32,
			// Long, because re-establishing a cross-region TLS connection is
			// expensive and these are low-volume.
			IdleConnTimeout:   10 * time.Minute,
			ForceAttemptHTTP2: true,
		},
	}
}
