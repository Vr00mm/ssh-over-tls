// Package handler provides connection handling for the TLS multiplexer.
package handler

import (
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/Vr00mm/ssh-over-tls/internal/tlsutil"
)

// categorizeError returns the appropriate log level for TLS errors.
// Common scanner/bot errors are logged at WARN level to reduce noise,
// while genuine connection issues are logged at ERROR level.
func categorizeError(err error) slog.Level {
	if err == nil {
		return slog.LevelError
	}

	// EOF during TLS handshake is normal for scanners/incompatible clients
	// They connect, probe, and disconnect without completing handshake
	if err == io.EOF {
		return slog.LevelWarn
	}

	errMsg := err.Error()

	// Common scanner patterns that shouldn't trigger alerts
	scannerPatterns := []string{
		"unsupported versions",
		"no cipher suite supported",
		"first record does not look like a TLS handshake",
		"unsupported SSLv2 handshake",
		"inappropriate protocol fallback", // Client falling back to weaker TLS
		"connection reset by peer",        // Scanner aborted connection
	}

	for _, pattern := range scannerPatterns {
		if containsSubstring(errMsg, pattern) {
			return slog.LevelWarn
		}
	}

	return slog.LevelError
}

// BeautifyTLSError converts hex cipher suite IDs and TLS version IDs in error messages to readable names.
// Transforms cipher suites: "client offered: [c024 c023 ...]" → "client offered: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, ..."
// Transforms versions: "unsupported versions: [303 302 301]" → "unsupported versions: [TLS 1.2, TLS 1.1, TLS 1.0]"
func BeautifyTLSError(err error) string {
	if err == nil {
		return ""
	}

	msg := err.Error()

	// First, replace TLS version lists
	// Matches patterns like: versions: [303 302 301] or versions: []
	versionRe := regexp.MustCompile(`versions: \[([0-9a-f\s]*)\]`)
	msg = versionRe.ReplaceAllStringFunc(msg, func(match string) string {
		submatch := versionRe.FindStringSubmatch(match)
		if len(submatch) < 2 {
			return match
		}

		hexValues := strings.Fields(submatch[1])
		if len(hexValues) == 0 {
			return "versions: [none]"
		}

		var versionNames []string
		for _, hex := range hexValues {
			val, err := strconv.ParseUint(hex, 16, 16)
			if err == nil {
				versionNames = append(versionNames, tlsutil.VersionName(uint16(val)))
			}
		}

		if len(versionNames) == 0 {
			return match
		}

		return fmt.Sprintf("versions: [%s]", strings.Join(versionNames, ", "))
	})

	// Second, replace cipher suite lists
	// Matches patterns like: [c024 c023 c00a ...] or [ff c024 c023 ...]
	cipherRe := regexp.MustCompile(`client offered: \[([0-9a-f\s]+)\]`)
	msg = cipherRe.ReplaceAllStringFunc(msg, func(match string) string {
		submatch := cipherRe.FindStringSubmatch(match)
		if len(submatch) < 2 {
			return match
		}

		hexValues := strings.Fields(submatch[1])
		var suiteIDs []uint16

		for _, hex := range hexValues {
			val, err := strconv.ParseUint(hex, 16, 16)
			if err == nil {
				suiteIDs = append(suiteIDs, uint16(val))
			}
		}

		if len(suiteIDs) == 0 {
			return match
		}

		return fmt.Sprintf("client offered: %s", tlsutil.FormatCipherSuites(suiteIDs))
	})

	return msg
}

// containsSubstring checks if a string contains a substring.
func containsSubstring(s, substr string) bool {
	return strings.Contains(s, substr)
}
