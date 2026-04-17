// Package tlsutil provides TLS-related utilities including human-readable
// names for TLS versions and cipher suites.
package tlsutil

import (
	"crypto/tls"
	"fmt"
)

// VersionName converts a TLS version number to a human-readable string.
// Returns the standard name (e.g., "TLS 1.2") for known versions,
// or a hex representation for unknown versions.
func VersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

// CipherSuiteName converts a cipher suite ID to its standard name.
// Returns the cipher suite name (e.g., "TLS_AES_128_GCM_SHA256") for known suites,
// or a hex representation for unknown suites.
func CipherSuiteName(id uint16) string {
	if name, ok := cipherSuiteNames[id]; ok {
		return name
	}

	return fmt.Sprintf("0x%04x", id)
}

// FormatCipherSuites converts a slice of cipher suite IDs to a compact,
// readable representation. Shows first 3 with names, then count of remaining.
// Example: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, ... (15 more)"
func FormatCipherSuites(ids []uint16) string {
	if len(ids) == 0 {
		return "none"
	}

	const maxShow = 3
	var names []string

	for i, id := range ids {
		if i >= maxShow {
			break
		}
		names = append(names, CipherSuiteName(id))
	}

	result := fmt.Sprintf("%v", names)
	if len(ids) > maxShow {
		result = fmt.Sprintf("%v ... (%d more)", names, len(ids)-maxShow)
	}

	return result
}

// cipherSuiteNames maps cipher suite IDs to their standard names.
// Includes modern and legacy suites for comprehensive error reporting.
var cipherSuiteNames = map[uint16]string{
	// TLS 1.3 cipher suites
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",

	// TLS 1.2 and earlier - ECDHE suites
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:          "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",

	// RSA key exchange suites
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:    "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:    "TLS_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x003d:                              "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x003c:                              "TLS_RSA_WITH_AES_128_CBC_SHA256",

	// Legacy weak ciphers (commonly sent by scanners)
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",

	// ECDHE-RSA with legacy ciphers
	0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xc002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
	0xc00c: "TLS_ECDH_RSA_WITH_RC4_128_SHA",
	0xc008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xc00d: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
	0xc004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
	0xc005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
	0xc00e: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
	0xc00f: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",

	// DHE-DSS (legacy)
	0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
	0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
	0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
	0x006a: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",

	// Additional ECDHE suites not in tls constants
	0xc025: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xc026: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xc029: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc02a: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",

	// Special values
	0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
	0x5600: "TLS_FALLBACK_SCSV",
}
