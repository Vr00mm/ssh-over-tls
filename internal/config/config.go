// Package config loads runtime configuration from a file and environment variables.
// Environment variables always take precedence over file values.
package config

import (
	"bufio"
	"cmp"
	"fmt"
	"os"
	"strings"
)

const defaultConfigFile = "/etc/ssh-over-tls/config"

// Spec holds the runtime configuration.
// Required: SSH_SERVER_ADDR, HTTP_SERVER_ADDR, LISTEN_PORT.
// Optional: TLS_CERT_FILE (default: cert.pem), TLS_KEY_FILE (default: key.pem).
type Spec struct {
	SSHAddr  string
	HTTPAddr string
	Port     string
	CertFile string
	KeyFile  string
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

	// lookup returns the env var if set, then the file value, then the fallback.
	lookup := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}

		if v := fileVars[key]; v != "" {
			return v
		}

		return fallback
	}

	var cfg Spec

	// Slice preserves declaration order so the missing-vars error is deterministic.
	required := []struct {
		key string
		dst *string
	}{
		{key: "SSH_SERVER_ADDR", dst: &cfg.SSHAddr},
		{key: "HTTP_SERVER_ADDR", dst: &cfg.HTTPAddr},
		{key: "LISTEN_PORT", dst: &cfg.Port},
	}

	var missing []string

	for _, r := range required {
		v := lookup(r.key, "")
		if v == "" {
			missing = append(missing, r.key)
			continue
		}

		*r.dst = v
	}

	if len(missing) > 0 {
		return Spec{}, fmt.Errorf("missing required configuration keys: %v", missing)
	}

	cfg.CertFile = lookup("TLS_CERT_FILE", "cert.pem")
	cfg.KeyFile = lookup("TLS_KEY_FILE", "key.pem")

	return cfg, nil
}

// loadFile parses a KEY=VALUE config file.
// Blank lines and lines starting with '#' are ignored.
// Returns an empty map if the file does not exist.
func loadFile(path string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is the operator-supplied config file location, not user input
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("open config file %q: %w", path, err)
	}

	defer f.Close() //nolint:errcheck // config file close: error is not actionable

	vars := map[string]string{}
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if key != "" {
			vars[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read config file %q: %w", path, err)
	}

	return vars, nil
}
