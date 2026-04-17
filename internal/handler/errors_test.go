package handler

import (
	"errors"
	"io"
	"log/slog"
	"testing"
)

func TestCategorizeError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected slog.Level
	}{
		{
			name:     "EOF should be WARN",
			err:      io.EOF,
			expected: slog.LevelWarn,
		},
		{
			name:     "unsupported versions should be WARN",
			err:      errors.New("tls: client offered only unsupported versions: [301]"),
			expected: slog.LevelWarn,
		},
		{
			name:     "no cipher suite should be WARN",
			err:      errors.New("tls: no cipher suite supported by both client and server"),
			expected: slog.LevelWarn,
		},
		{
			name:     "SSLv2 should be WARN",
			err:      errors.New("tls: unsupported SSLv2 handshake received"),
			expected: slog.LevelWarn,
		},
		{
			name:     "connection reset should be WARN",
			err:      errors.New("read tcp: connection reset by peer"),
			expected: slog.LevelWarn,
		},
		{
			name:     "generic error should be ERROR",
			err:      errors.New("some other error"),
			expected: slog.LevelError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := categorizeError(tt.err)
			if level != tt.expected {
				t.Errorf("categorizeError(%v) = %v, expected %v", tt.err, level, tt.expected)
			}
		})
	}
}

func TestBeautifyTLSError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains []string // strings that should be in the output
	}{
		{
			name: "hex cipher suites converted to names",
			err:  errors.New("tls: no cipher suite supported by both client and server; client offered: [c024 c023 c00a]"),
			contains: []string{
				"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
				"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			},
		},
		{
			name: "handles multiple cipher suites with truncation",
			err:  errors.New("tls: no cipher suite supported by both client and server; client offered: [ff c024 c023 c00a c009 c008 c028]"),
			contains: []string{
				"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
				"... (4 more)",
			},
		},
		{
			name:     "non-cipher error unchanged",
			err:      errors.New("tls: unsupported SSLv2 handshake received"),
			contains: []string{"unsupported SSLv2"},
		},
		{
			name: "TLS versions converted to names",
			err:  errors.New("tls: client offered only unsupported versions: [303 302 301]"),
			contains: []string{
				"TLS 1.2",
				"TLS 1.1",
				"TLS 1.0",
			},
		},
		{
			name: "single TLS version",
			err:  errors.New("tls: client offered only unsupported versions: [302]"),
			contains: []string{
				"TLS 1.1",
			},
		},
		{
			name: "empty version list",
			err:  errors.New("tls: client offered only unsupported versions: []"),
			contains: []string{
				"versions: [none]",
			},
		},
		{
			name:     "nil error returns empty string",
			err:      nil,
			contains: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BeautifyTLSError(tt.err)

			if tt.err == nil {
				if result != "" {
					t.Errorf("BeautifyTLSError(nil) = %q, expected empty string", result)
				}
				return
			}

			for _, expected := range tt.contains {
				if expected != "" && !containsSubstring(result, expected) {
					t.Errorf("BeautifyTLSError() result missing %q\nGot: %s", expected, result)
				}
			}
		})
	}
}
