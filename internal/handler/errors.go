// Package handler provides connection handling for the TLS multiplexer.
package handler

import (
	"log/slog"
	"strings"
)

// categorizeError returns the appropriate log level for TLS errors.
// Common scanner/bot errors are logged at WARN level to reduce noise,
// while genuine connection issues are logged at ERROR level.
func categorizeError(err error) slog.Level {
	if err == nil {
		return slog.LevelError
	}

	errMsg := err.Error()

	// Common scanner patterns that shouldn't trigger alerts
	scannerPatterns := []string{
		"unsupported versions",
		"no cipher suite supported",
		"first record does not look like a TLS handshake",
		"unsupported SSLv2 handshake",
	}

	for _, pattern := range scannerPatterns {
		if containsSubstring(errMsg, pattern) {
			return slog.LevelWarn
		}
	}

	return slog.LevelError
}

// containsSubstring checks if a string contains a substring.
func containsSubstring(s, substr string) bool {
	return strings.Contains(s, substr)
}
