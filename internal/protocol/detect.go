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
// All protocols are matched on their first 4 characters, which uniquely identify
// SSH and all supported HTTP verbs.
func Detect(header []byte) (string, bool) {
	if len(header) < 4 {
		return "", false
	}

	prefix := string(header[:4])
	switch prefix {
	case "SSH-":
		return SSH, true
	case "GET ", "POST", "HEAD", "PUT ", "DELE", "OPTI", "CONN", "PATC", "TRAC":
		return HTTP, true
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
