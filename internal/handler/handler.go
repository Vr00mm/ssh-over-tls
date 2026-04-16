package handler

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/Vr00mm/ssh-over-tls/internal/protocol"
	"github.com/Vr00mm/ssh-over-tls/internal/tlsutil"
)

// Config holds configuration for connection handling.
type Config struct {
	SSHAddr          string
	HTTPAddr         string
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
}

// Handler handles incoming TLS connections.
type Handler struct {
	cfg Config
}

// New creates a new connection handler with the given configuration.
func New(cfg Config) *Handler {
	return &Handler{cfg: cfg}
}

// Handle processes a single TLS connection.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) {
	start := time.Now()

	defer conn.Close() //nolint:errcheck // connection close in defer: error is not actionable

	logger := slog.With("remote_addr", conn.RemoteAddr().String())

	defer func() {
		if r := recover(); r != nil {
			logger.Error("panic in connection handler",
				"panic", r,
				"duration_ms", time.Since(start).Milliseconds())
		}
	}()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		logger.Error("not a TLS connection")
		return
	}

	if err := h.performHandshake(ctx, tlsConn, logger, start); err != nil {
		return
	}

	state := tlsConn.ConnectionState()

	header, err := h.readProtocolHeader(conn, logger, start)
	if err != nil {
		return
	}

	proto, ok := protocol.Detect(header)
	if !ok {
		h.logUnknownProtocol(logger, header, start)
		return
	}

	h.handleProtocol(ctx, conn, proto, state, header, logger, start)
}

// performHandshake performs the TLS handshake with timeout.
func (h *Handler) performHandshake(ctx context.Context, conn *tls.Conn, logger *slog.Logger, start time.Time) error {
	if err := conn.SetDeadline(time.Now().Add(h.cfg.HandshakeTimeout)); err != nil {
		logger.Error("set handshake deadline", "err", err)
		return err
	}

	if err := conn.Handshake(); err != nil {
		logLevel := categorizeError(err)
		logger.Log(ctx, logLevel, "TLS handshake",
			"err", err,
			"duration_ms", time.Since(start).Milliseconds())

		return err
	}

	return nil
}

// readProtocolHeader reads the protocol identification header.
func (h *Handler) readProtocolHeader(conn net.Conn, logger *slog.Logger, start time.Time) ([]byte, error) {
	buf := make([]byte, 8)

	_, err := io.ReadFull(conn, buf)
	if err != nil {
		logLevel := slog.LevelError
		if err == io.EOF {
			logLevel = slog.LevelWarn
		}

		logger.Log(context.Background(), logLevel, "read protocol header",
			"err", err,
			"duration_ms", time.Since(start).Milliseconds())

		return nil, err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		logger.Error("clear deadline", "err", err)
		return nil, err
	}

	return buf, nil
}

// logUnknownProtocol logs details about an unknown protocol.
func (h *Handler) logUnknownProtocol(logger *slog.Logger, header []byte, start time.Time) {
	logger.Warn("unknown protocol",
		"header", protocol.SanitizeHeader(header),
		"duration_ms", time.Since(start).Milliseconds())
}

// handleProtocol routes the connection to the appropriate backend.
func (h *Handler) handleProtocol(ctx context.Context, conn net.Conn, proto string, state tls.ConnectionState, header []byte, logger *slog.Logger, start time.Time) {
	targetAddr := h.selectBackend(proto)

	logger.Info("connection open",
		"protocol", proto,
		"sni", state.ServerName,
		"tls_version", tlsutil.VersionName(state.Version),
		"cipher_suite", tlsutil.CipherSuiteName(state.CipherSuite))

	defer h.logConnectionClose(logger, proto, state, start)

	backend, err := h.dialBackend(ctx, targetAddr, logger)
	if err != nil {
		return
	}

	defer backend.Close() //nolint:errcheck // connection close in defer: error is not actionable

	_ = BidirectionalCopy(conn, backend, header)
}

// selectBackend returns the backend address for a given protocol.
func (h *Handler) selectBackend(proto string) string {
	if proto == protocol.SSH {
		return h.cfg.SSHAddr
	}

	return h.cfg.HTTPAddr
}

// dialBackend dials the backend server with timeout.
func (h *Handler) dialBackend(ctx context.Context, addr string, logger *slog.Logger) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, h.cfg.DialTimeout)
	defer cancel()

	var dialer net.Dialer

	backend, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		logger.Error("dial backend", "addr", addr, "err", err)
		return nil, err
	}

	return backend, nil
}

// logConnectionClose logs connection close with full details.
func (h *Handler) logConnectionClose(logger *slog.Logger, proto string, state tls.ConnectionState, start time.Time) {
	logger.Info("connection close",
		"protocol", proto,
		"sni", state.ServerName,
		"tls_version", tlsutil.VersionName(state.Version),
		"cipher_suite", tlsutil.CipherSuiteName(state.CipherSuite),
		"duration_ms", time.Since(start).Milliseconds())
}
