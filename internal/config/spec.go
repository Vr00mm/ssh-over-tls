// Package config loads runtime configuration from a file and environment variables.
// Environment variables always take precedence over file values.
package config

import (
	"cmp"
	"fmt"
	"os"
	"strings"
	"time"
)

const defaultConfigFile = "/etc/ssh-over-tls/config"

// Spec holds the runtime configuration.
// Required: SSH_SERVER_ADDR, HTTP_SERVER_ADDR, LISTEN_PORT.
// Optional: TLS_CERT_FILE (default: cert.pem), TLS_KEY_FILE (default: key.pem),
//
//	TLS_MIN_VERSION (default: TLS12), TLS_CIPHER_SUITES (default: secure modern ciphers),
//	COPY_IDLE_TIMEOUT (default: 5m), PROXY_PROTOCOL_ENABLED (default: false).
type Spec struct {
	SSHAddr              string
	HTTPAddr             string
	Port                 string
	CertFile             string
	KeyFile              string
	TLSMinVersion        uint16
	TLSCipherSuites      []uint16
	CopyIdleTimeout      time.Duration
	ProxyProtocolEnabled bool
}

// Load reads configuration from a file then overlays environment variables.
// The config file path is taken from CONFIG_FILE (default: /etc/ssh-over-tls/config).
// A missing config file is silently ignored; any other read error is returned.
// SSH_SERVER_ADDR, HTTP_SERVER_ADDR, and LISTEN_PORT are required from either source.
func Load() (Spec, error) {
	filePath := cmp.Or(os.Getenv("CONFIG_FILE"), defaultConfigFile)

	fileVars, err := loadFile(filePath)
	if err != nil {
		return Spec{}, err
	}

	spec, err := buildSpec(fileVars)
	if err != nil {
		return Spec{}, err
	}

	return spec, nil
}

// buildSpec constructs a Spec from environment and file variables.
func buildSpec(fileVars map[string]string) (Spec, error) {
	lookup := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}

		if v := fileVars[key]; v != "" {
			return v
		}

		return fallback
	}

	spec := Spec{
		SSHAddr:              lookup("SSH_SERVER_ADDR", ""),
		HTTPAddr:             lookup("HTTP_SERVER_ADDR", ""),
		Port:                 lookup("LISTEN_PORT", ""),
		CertFile:             lookup("TLS_CERT_FILE", "cert.pem"),
		KeyFile:              lookup("TLS_KEY_FILE", "key.pem"),
		ProxyProtocolEnabled: lookup("PROXY_PROTOCOL_ENABLED", "false") == "true",
	}

	if err := validateRequiredFields(spec); err != nil {
		return Spec{}, err
	}

	if err := parseTLSConfig(&spec, lookup); err != nil {
		return Spec{}, err
	}

	if err := parseTimeouts(&spec, lookup); err != nil {
		return Spec{}, err
	}

	return spec, nil
}

// validateRequiredFields checks that all required fields are set.
func validateRequiredFields(spec Spec) error {
	required := []struct {
		field string
		value string
	}{
		{"SSH_SERVER_ADDR", spec.SSHAddr},
		{"HTTP_SERVER_ADDR", spec.HTTPAddr},
		{"LISTEN_PORT", spec.Port},
	}

	var missing []string

	for _, r := range required {
		if r.value == "" {
			missing = append(missing, r.field)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required config: %s", strings.Join(missing, ", "))
	}

	return nil
}

// parseTLSConfig parses TLS-related configuration.
func parseTLSConfig(spec *Spec, lookup func(string, string) string) error {
	tlsVersionStr := lookup("TLS_MIN_VERSION", "TLS12")
	spec.TLSMinVersion = parseTLSVersion(tlsVersionStr)

	cipherSuitesStr := lookup("TLS_CIPHER_SUITES", "")
	if cipherSuitesStr != "" {
		suites, err := parseCipherSuites(cipherSuitesStr)
		if err != nil {
			return fmt.Errorf("parse TLS_CIPHER_SUITES: %w", err)
		}

		spec.TLSCipherSuites = suites
	}

	return nil
}

// parseTimeouts parses timeout-related configuration.
func parseTimeouts(spec *Spec, lookup func(string, string) string) error {
	copyIdleTimeoutStr := lookup("COPY_IDLE_TIMEOUT", "5m")
	if copyIdleTimeoutStr != "" {
		d, err := time.ParseDuration(copyIdleTimeoutStr)
		if err != nil {
			return fmt.Errorf("parse COPY_IDLE_TIMEOUT: %w (expected format: 1s, 5m, 1h)", err)
		}
		spec.CopyIdleTimeout = d
	} else {
		spec.CopyIdleTimeout = 5 * time.Minute
	}

	return nil
}
