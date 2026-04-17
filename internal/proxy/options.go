package proxy

import (
	"time"
)

// Option configures a Server.
type Option func(*Server)

// WithDialTimeout sets the timeout for dialing backend connections (default 10s).
func WithDialTimeout(d time.Duration) Option {
	return func(s *Server) {
		s.dialTimeout = d
	}
}

// WithHandshakeTimeout sets the deadline for TLS handshake + protocol header read (default 10s).
func WithHandshakeTimeout(d time.Duration) Option {
	return func(s *Server) {
		s.handshakeTimeout = d
	}
}

// WithCopyIdleTimeout sets the maximum idle time for data transfer (default 5m).
func WithCopyIdleTimeout(d time.Duration) Option {
	return func(s *Server) {
		s.copyIdleTimeout = d
	}
}

// WithTLSMinVersion sets the minimum TLS version to accept.
func WithTLSMinVersion(version uint16) Option {
	return func(s *Server) {
		if s.tlsConfig != nil {
			s.tlsConfig.MinVersion = version
		}
	}
}

// WithTLSCipherSuites sets the cipher suites to support.
func WithTLSCipherSuites(ciphers []uint16) Option {
	return func(s *Server) {
		if s.tlsConfig != nil && len(ciphers) > 0 {
			s.tlsConfig.CipherSuites = ciphers
		}
	}
}

// WithProxyProtocol enables or disables sending PROXY protocol v1 headers to HTTP backends.
func WithProxyProtocol(enabled bool) Option {
	return func(s *Server) {
		s.proxyProtocolEnabled = enabled
	}
}
