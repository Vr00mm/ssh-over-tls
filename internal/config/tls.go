package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
)

// parseTLSVersion converts a TLS version string to the corresponding constant.
// Supports formats like "TLS12", "TLS1.2", "TLSV1.2" (case-insensitive).
// Returns tls.VersionTLS12 for invalid/unknown versions.
func parseTLSVersion(version string) uint16 {
	normalized := strings.ToUpper(strings.ReplaceAll(version, ".", ""))
	normalized = strings.TrimPrefix(normalized, "V")

	switch normalized {
	case "TLS10":
		return tls.VersionTLS10
	case "TLS11":
		return tls.VersionTLS11
	case "TLS13":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

// parseCipherSuites parses a comma-separated list of cipher suite names.
// Returns the corresponding cipher suite IDs or an error if unknown names are found.
func parseCipherSuites(suites string) ([]uint16, error) {
	if suites == "" {
		return nil, nil
	}

	parts := strings.Split(suites, ",")
	result := make([]uint16, 0, len(parts))
	allSuites := buildCipherSuiteMap()

	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}

		value, ok := allSuites[strings.ToUpper(name)]
		if !ok {
			return nil, fmt.Errorf("unknown cipher suite: %q", name)
		}

		result = append(result, value)
	}

	if len(result) == 0 {
		return nil, errors.New("no valid cipher suites found")
	}

	return result, nil
}

// buildCipherSuiteMap returns a map of cipher suite names to their IDs.
// Includes both full names and shorter aliases.
func buildCipherSuiteMap() map[string]uint16 {
	return map[string]uint16{
		// TLS 1.2 suites - full names
		"TLS_RSA_WITH_AES_128_CBC_SHA":                  tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		"TLS_RSA_WITH_AES_256_CBC_SHA":                  tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":               tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":               tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		// Shorter aliases
		"TLS_ECDHE_RSA_WITH_AES_128_GCM":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}
