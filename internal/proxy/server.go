// Package proxy implements a TLS multiplexer that routes incoming connections
// to separate SSH or HTTP backends based on the first bytes of each connection.
// A single TLS listener accepts all traffic; the initial 8-byte protocol header
// determines the destination.
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Vr00mm/ssh-over-tls/internal/handler"
)

const (
	defaultDialTimeout      = 10 * time.Second
	defaultHandshakeTimeout = 10 * time.Second
)

// Server is a TLS multiplexer that routes SSH and HTTP connections to separate backends.
type Server struct {
	sshAddr          string
	httpAddr         string
	port             string
	tlsConfig        *tls.Config
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	handler          *handler.Handler
}

// New creates a Server that listens on port and forwards SSH traffic to sshAddr
// and HTTP traffic to httpAddr. It loads TLS credentials from certFile and keyFile.
func New(sshAddr, httpAddr, port, certFile, keyFile string, opts ...Option) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load certificates: %w", err)
	}

	s := &Server{
		sshAddr:          sshAddr,
		httpAddr:         httpAddr,
		port:             port,
		dialTimeout:      defaultDialTimeout,
		handshakeTimeout: defaultHandshakeTimeout,
		tlsConfig:        defaultTLSConfig(cert),
	}

	for _, opt := range opts {
		opt(s)
	}

	s.handler = handler.New(handler.Config{
		SSHAddr:          sshAddr,
		HTTPAddr:         httpAddr,
		DialTimeout:      s.dialTimeout,
		HandshakeTimeout: s.handshakeTimeout,
	})

	return s, nil
}

// defaultTLSConfig returns a secure TLS configuration with modern defaults.
func defaultTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			// TLS 1.2 suites - ordered by preference (GCM and ChaCha20-Poly1305 only)
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
}

// Run starts the TLS listener, serves connections, and shuts down cleanly on SIGINT/SIGTERM.
func (s *Server) Run() error {
	listener, err := tls.Listen("tcp", ":"+s.port, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("listen on port %s: %w", s.port, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return s.serve(ctx, listener)
}

// serve accepts connections from listener until ctx is cancelled,
// then waits for all active connections to finish.
func (s *Server) serve(ctx context.Context, listener net.Listener) error {
	go s.shutdownOnSignal(ctx, listener)

	slog.Info("listening", "port", s.port)

	var wg sync.WaitGroup

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}

			slog.Error("accept", "err", err)

			continue
		}

		wg.Go(func() {
			s.handler.Handle(ctx, conn)
		})
	}

	slog.Info("waiting for active connections to finish")
	wg.Wait()

	return nil //nolint:nilerr // accept error triggers the break; returning nil signals clean shutdown
}

// shutdownOnSignal closes the listener when the context is cancelled.
func (s *Server) shutdownOnSignal(ctx context.Context, listener net.Listener) {
	<-ctx.Done()
	slog.Info("shutting down, closing listener")

	if err := listener.Close(); err != nil {
		slog.Error("close listener", "err", err)
	}
}
