// Command realtime-gateway terminates MTProto connections over TCP, UDP and
// WebSocket.
//
// All three listeners run in one process so a client can switch transport —
// dropping from TCP to WebSocket behind a restrictive proxy, or to UDP on a
// lossy link — without losing its negotiated auth key, which lives in Redis
// and is resolvable from any pod.
package main

import (
	"context"
	"fmt"

	"github.com/pervagans/messaging-app/pkg/app"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/mtproto"
	"github.com/pervagans/messaging-app/pkg/mtproto/transport"
	"github.com/pervagans/messaging-app/pkg/redisx"
	gateway "github.com/pervagans/messaging-app/services/realtime-gateway/internal"
)

func main() {
	app.Run("realtime-gateway", run)
}

func run(ctx context.Context, a *app.App) error {
	cfg, err := gateway.LoadConfig(a.Cfg)
	if err != nil {
		return err
	}

	serverKey, err := mtproto.LoadServerKey(cfg.ServerKeyPEM)
	if err != nil {
		return fmt.Errorf("mtproto server key: %w", err)
	}
	a.Log.Info("mtproto server key loaded", "fingerprint", serverKey.Fingerprint)

	rdb, err := redisx.Connect(ctx, cfg.Redis)
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	a.OnShutdown("redis", rdb.Close)
	a.Health.Register("redis", rdb.Ping)

	producer, err := kafkax.NewProducer(cfg.Kafka, kafkax.DefaultProducerOptions())
	if err != nil {
		return fmt.Errorf("kafka: %w", err)
	}
	a.OnShutdown("kafka", producer.Close)

	upstream := gateway.NewUpstream(cfg, a.Log)
	a.Health.Register("chat-service", upstream.Ping)

	g := gateway.New(cfg, a.Log, rdb, upstream, producer, serverKey)
	g.Start(ctx)
	a.OnShutdown("gateway", g.Close)

	// On SIGTERM, tell every live client to reconnect before the sockets go
	// away. Without this a rolling update produces a synchronised reconnect
	// storm against the new pods.
	a.OnDrain(g.Drain)

	// --- TCP ---
	tcpLn, err := transport.ListenTCP(cfg.TCPAddr, a.Log)
	if err != nil {
		return fmt.Errorf("tcp listener: %w", err)
	}
	tcpLn.MaxConnections = cfg.MaxConnectionsPerPod
	tcpLn.HandshakeTimeout = cfg.HandshakeTimeout
	a.OnShutdown("tcp-listener", func(context.Context) error { return tcpLn.Close() })
	go func() {
		if err := tcpLn.Serve(ctx, g.Handle); err != nil {
			a.Log.Error("tcp listener stopped", "error", err)
		}
	}()
	a.Log.Info("listening", "transport", "tcp", "addr", tcpLn.Addr().String())

	// --- UDP ---
	udpLn, err := transport.ListenUDP(cfg.UDPAddr, a.Log)
	if err != nil {
		return fmt.Errorf("udp listener: %w", err)
	}
	udpLn.MaxConnections = int(cfg.MaxConnectionsPerPod)
	a.OnShutdown("udp-listener", func(context.Context) error { return udpLn.Close() })
	go func() {
		if err := udpLn.Serve(ctx, g.Handle); err != nil {
			a.Log.Error("udp listener stopped", "error", err)
		}
	}()
	a.Log.Info("listening", "transport", "udp", "addr", udpLn.Addr().String())

	// --- WebSocket ---
	wsLn, err := transport.ListenWS(transport.WSOptions{
		Addr:           cfg.WSAddr,
		Path:           cfg.WSPath,
		AllowedOrigins: cfg.WSAllowedOrigins,
	}, a.Log)
	if err != nil {
		return fmt.Errorf("websocket listener: %w", err)
	}
	wsLn.MaxConnections = cfg.MaxConnectionsPerPod
	a.OnShutdown("ws-listener", func(context.Context) error { return wsLn.Close() })
	go func() {
		if err := wsLn.Serve(ctx, g.Handle); err != nil {
			a.Log.Error("websocket listener stopped", "error", err)
		}
	}()
	a.Log.Info("listening", "transport", "ws", "addr", wsLn.Addr().String(), "path", cfg.WSPath)

	// Readiness fails once the pod is at capacity so the load balancer sends
	// new connections elsewhere instead of having them refused at accept.
	a.Health.Register("capacity", func(context.Context) error {
		if n := g.Active(); n >= cfg.MaxConnectionsPerPod {
			return fmt.Errorf("at capacity: %d connections", n)
		}
		return nil
	})

	return nil
}
