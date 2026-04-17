// Package protocol provides protocol detection utilities for identifying
// SSH and HTTP traffic based on connection headers.
package protocol

import "fmt"

const (
	// SSH represents the SSH protocol.
	SSH = "SSH"
	// HTTP represents the HTTP protocol.
	HTTP = "HTTP"
)

// Detect identifies the protocol from the first bytes of a connection.
// Returns the protocol name (SSH or HTTP) and whether it was recognized.
// SSH is matched on "SSH-" prefix, HTTP methods are matched on complete words.
func Detect(header []byte) (string, bool) {
	if len(header) < 4 {
		return "", false
	}

	// Check for SSH protocol identifier.
	if len(header) >= 4 && string(header[:4]) == "SSH-" {
		return SSH, true
	}

	// Check for HTTP methods (require full match with space or newline).
	// We match more precisely to avoid false positives.
	headerStr := string(header)
	if len(headerStr) >= 4 {
		prefix4 := headerStr[:4]
		switch prefix4 {
		case "GET ", "PUT ", "HEAD":
			return HTTP, true
		}
	}

	if len(headerStr) >= 5 {
		prefix5 := headerStr[:5]
		switch prefix5 {
		case "POST ", "PATCH":
			return HTTP, true
		}
	}

	if len(headerStr) >= 6 {
		prefix6 := headerStr[:6]
		switch prefix6 {
		case "DELETE", "TRACE ":
			return HTTP, true
		}
	}

	if len(headerStr) >= 7 {
		prefix7 := headerStr[:7]
		switch prefix7 {
		case "OPTIONS", "CONNECT":
			return HTTP, true
		}
	}

	if len(headerStr) >= 8 {
		prefix8 := headerStr[:8]
		if prefix8 == "OPTIONS " || prefix8 == "CONNECT " {
			return HTTP, true
		}
	}

	return "", false
}

// SanitizeHeader makes protocol headers safe for logging by replacing
// non-printable characters with their hex representation.
func SanitizeHeader(header []byte) string {
	result := make([]byte, 0, len(header)*2)

	for _, b := range header {
		if b >= 32 && b < 127 {
			result = append(result, b)
		} else {
			result = fmt.Appendf(result, "\\x%02x", b)
		}
	}

	return string(result)
}
