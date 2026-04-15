// Package proxy implements a TLS multiplexer that routes incoming connections
// to separate SSH or HTTP backends based on the first bytes of each connection.
// A single TLS listener accepts all traffic; the initial 8-byte protocol header
// determines the destination.
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	defaultDialTimeout      = 10 * time.Second
	defaultHandshakeTimeout = 10 * time.Second
	// copyBufSize matches io.Copy's internal default to avoid under-utilising buffers.
	copyBufSize = 32 * 1024
)

// copyBufPool reuses 32 KiB copy buffers across connections.
// Each io.CopyBuffer call otherwise allocates one on the heap; at high
// connection rates this creates significant GC pressure.
var copyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, copyBufSize)
		return &buf
	},
}

// Server is a TLS multiplexer that routes SSH and HTTP connections to separate backends.
type Server struct {
	sshAddr          string
	httpAddr         string
	port             string
	tlsConfig        *tls.Config
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
}

// Option configures a Server.
type Option func(*Server)

// WithDialTimeout sets the timeout for dialing backend connections (default 10s).
func WithDialTimeout(d time.Duration) Option {
	return func(s *Server) { s.dialTimeout = d }
}

// WithHandshakeTimeout sets the deadline for TLS handshake + protocol header read (default 10s).
func WithHandshakeTimeout(d time.Duration) Option {
	return func(s *Server) { s.handshakeTimeout = d }
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
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
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
	go func() {
		<-ctx.Done()
		slog.Info("shutting down, closing listener")

		if err := listener.Close(); err != nil {
			slog.Error("close listener", "err", err)
		}
	}()

	slog.Info("listening", "port", s.port)

	var wg sync.WaitGroup

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break // listener closed by shutdown goroutine — drain active connections
			}

			slog.Error("accept", "err", err)

			continue
		}

		wg.Go(func() { s.handleConnection(ctx, conn) })
	}

	slog.Info("waiting for active connections to finish")
	wg.Wait()

	return nil //nolint:nilerr // accept error triggers the break; returning nil signals clean shutdown
}

// detectProtocol identifies the protocol from the first 8 bytes of a connection.
// Returns the protocol name ("SSH" or "HTTP") and whether it was recognized.
// All protocols are matched on their first 4 characters, which uniquely identify
// SSH and all supported HTTP verbs (GET, POST, HEAD, PUT, DELETE, OPTIONS, CONNECT).
func detectProtocol(header string) (string, bool) {
	switch header[:4] {
	case "SSH-":
		return "SSH", true
	case "GET ", "POST", "HEAD", "PUT ", "DELE", "OPTI", "CONN":
		return "HTTP", true
	}

	return "", false
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close() //nolint:errcheck // connection close in defer: error is not actionable

	logger := slog.With("remote_addr", conn.RemoteAddr().String())

	defer func() {
		if r := recover(); r != nil {
			logger.Error("panic in connection handler", "panic", r)
		}
	}()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		logger.Error("not a TLS connection")
		return
	}

	// Single deadline covers both the TLS handshake and the protocol header read.
	// Clear it once the connection is identified so the pipe can run indefinitely.
	if err := conn.SetDeadline(time.Now().Add(s.handshakeTimeout)); err != nil {
		logger.Error("set handshake deadline", "err", err)
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		logger.Error("TLS handshake", "err", err)
		return
	}

	state := tlsConn.ConnectionState()

	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err != nil {
		logger.Error("read protocol header", "err", err)
		return
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		logger.Error("clear deadline", "err", err)
		return
	}

	protocol, ok := detectProtocol(string(buf))
	if !ok {
		logger.Error("unknown protocol", "header", string(buf))
		return
	}

	var targetAddr string

	switch protocol {
	case "SSH":
		targetAddr = s.sshAddr
	case "HTTP":
		targetAddr = s.httpAddr
	}

	logger.Info("connection open",
		"protocol", protocol,
		"sni", state.ServerName,
		"tls_version", state.Version,
		"cipher_suite", state.CipherSuite,
	)
	defer logger.Info("connection close",
		"protocol", protocol,
		"sni", state.ServerName,
		"tls_version", state.Version,
		"cipher_suite", state.CipherSuite,
	)

	dialCtx, cancel := context.WithTimeout(ctx, s.dialTimeout)
	defer cancel()

	var dialer net.Dialer

	target, err := dialer.DialContext(dialCtx, "tcp", targetAddr)
	if err != nil {
		logger.Error("dial backend", "addr", targetAddr, "err", err)
		return
	}

	defer target.Close() //nolint:errcheck // connection close in defer: error is not actionable

	if _, err := target.Write(buf); err != nil {
		logger.Error("write header to backend", "err", err)
		return
	}

	// Buffer size 2 prevents goroutine leak: both goroutines can send even if
	// only one is received (we return as soon as either direction closes).
	done := make(chan struct{}, 2)

	buf1 := copyBufPool.Get().(*[]byte) //nolint:errcheck,forcetypeassert // pool stores only *[]byte, assertion is always safe
	buf2 := copyBufPool.Get().(*[]byte) //nolint:errcheck,forcetypeassert // pool stores only *[]byte, assertion is always safe

	go func() {
		defer copyBufPool.Put(buf1)

		io.CopyBuffer(target, conn, *buf1) // #nosec G104 -- best-effort pipe, error on one side causes the other to close

		done <- struct{}{}
	}()

	go func() {
		defer copyBufPool.Put(buf2)

		io.CopyBuffer(conn, target, *buf2) // #nosec G104 -- best-effort pipe, error on one side causes the other to close

		done <- struct{}{}
	}()

	<-done
}
