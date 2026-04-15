package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfigFile creates a temporary config file with the given content.
func writeConfigFile(t *testing.T, content string) string {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "config-*.conf")
	if err != nil {
		t.Fatalf("create temp config file: %v", err)
	}

	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("close config file: %v", err)
	}

	return f.Name()
}

// clearAllEnv sets all config-related env vars to "" for the duration of the test.
// t.Setenv restores the original values on cleanup.
// Our code treats "" as unset (all lookups check v != "").
func clearAllEnv(t *testing.T) {
	t.Helper()

	for _, k := range []string{
		"SSH_SERVER_ADDR", "HTTP_SERVER_ADDR", "LISTEN_PORT",
		"TLS_CERT_FILE", "TLS_KEY_FILE", "CONFIG_FILE",
	} {
		t.Setenv(k, "")
	}
}

// noConfigFile returns a path guaranteed not to exist so the default
// /etc/ssh-over-tls/config is never consulted.
func noConfigFile(t *testing.T) string {
	t.Helper()

	return filepath.Join(t.TempDir(), "nonexistent")
}

// --- loadFile ---

func TestLoadFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		content  string
		noFile   bool
		wantVars map[string]string
	}{
		{
			name:     "nonexistent file returns empty map",
			noFile:   true,
			wantVars: map[string]string{},
		},
		{
			name:    "parses key=value pairs",
			content: "FOO=bar\nBAZ=qux\n",
			wantVars: map[string]string{
				"FOO": "bar",
				"BAZ": "qux",
			},
		},
		{
			name:     "ignores blank lines",
			content:  "\nFOO=bar\n\nBAZ=qux\n",
			wantVars: map[string]string{"FOO": "bar", "BAZ": "qux"},
		},
		{
			name:     "ignores comment lines",
			content:  "# comment\nFOO=bar\n# another\n",
			wantVars: map[string]string{"FOO": "bar"},
		},
		{
			name:     "ignores lines without equals sign",
			content:  "NOEQUALS\nFOO=bar\n",
			wantVars: map[string]string{"FOO": "bar"},
		},
		{
			name:     "trims whitespace around key and value",
			content:  "  FOO  =  bar  \n",
			wantVars: map[string]string{"FOO": "bar"},
		},
		{
			name:     "preserves equals sign in value",
			content:  "KEY=val=ue\n",
			wantVars: map[string]string{"KEY": "val=ue"},
		},
		{
			name:     "ignores empty key after trim",
			content:  "  =value\nFOO=bar\n",
			wantVars: map[string]string{"FOO": "bar"},
		},
		{
			name:    "stores empty value in map",
			content: "FOO=\n",
			// empty value is stored; Load's lookup ignores it (v != "")
			wantVars: map[string]string{"FOO": ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var path string
			if tt.noFile {
				path = filepath.Join(t.TempDir(), "nonexistent")
			} else {
				path = writeConfigFile(t, tt.content)
			}

			got, err := loadFile(path)
			if err != nil {
				t.Fatalf("loadFile() unexpected error: %v", err)
			}

			if len(got) != len(tt.wantVars) {
				t.Fatalf("loadFile() returned %d entries, want %d: got %v", len(got), len(tt.wantVars), got)
			}

			for k, want := range tt.wantVars {
				if got[k] != want {
					t.Errorf("loadFile()[%q] = %q, want %q", k, got[k], want)
				}
			}
		})
	}
}

// --- Load ---

func TestLoad_RequiredFromEnv(t *testing.T) {
	clearAllEnv(t)
	t.Setenv("CONFIG_FILE", noConfigFile(t))
	t.Setenv("SSH_SERVER_ADDR", "localhost:22")
	t.Setenv("HTTP_SERVER_ADDR", "localhost:80")
	t.Setenv("LISTEN_PORT", "443")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.SSHAddr != "localhost:22" {
		t.Errorf("SSHAddr = %q, want %q", cfg.SSHAddr, "localhost:22")
	}

	if cfg.HTTPAddr != "localhost:80" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, "localhost:80")
	}

	if cfg.Port != "443" {
		t.Errorf("Port = %q, want %q", cfg.Port, "443")
	}
}

func TestLoad_RequiredFromFile(t *testing.T) {
	clearAllEnv(t)

	path := writeConfigFile(t,
		"SSH_SERVER_ADDR=localhost:2222\n"+
			"HTTP_SERVER_ADDR=localhost:8080\n"+
			"LISTEN_PORT=8443\n",
	)
	t.Setenv("CONFIG_FILE", path)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.SSHAddr != "localhost:2222" {
		t.Errorf("SSHAddr = %q, want %q", cfg.SSHAddr, "localhost:2222")
	}

	if cfg.HTTPAddr != "localhost:8080" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, "localhost:8080")
	}

	if cfg.Port != "8443" {
		t.Errorf("Port = %q, want %q", cfg.Port, "8443")
	}
}

func TestLoad_EnvOverridesFile(t *testing.T) {
	clearAllEnv(t)

	path := writeConfigFile(t,
		"SSH_SERVER_ADDR=file-ssh:22\n"+
			"HTTP_SERVER_ADDR=file-http:80\n"+
			"LISTEN_PORT=file-port\n",
	)
	t.Setenv("CONFIG_FILE", path)
	t.Setenv("SSH_SERVER_ADDR", "env-ssh:22")
	t.Setenv("HTTP_SERVER_ADDR", "env-http:80")
	// LISTEN_PORT not in env → taken from file

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.SSHAddr != "env-ssh:22" {
		t.Errorf("SSHAddr = %q, want env value", cfg.SSHAddr)
	}

	if cfg.HTTPAddr != "env-http:80" {
		t.Errorf("HTTPAddr = %q, want env value", cfg.HTTPAddr)
	}

	if cfg.Port != "file-port" {
		t.Errorf("Port = %q, want file value %q", cfg.Port, "file-port")
	}
}

func TestLoad_MissingConfigFileIgnored(t *testing.T) {
	clearAllEnv(t)
	t.Setenv("CONFIG_FILE", noConfigFile(t))
	t.Setenv("SSH_SERVER_ADDR", "localhost:22")
	t.Setenv("HTTP_SERVER_ADDR", "localhost:80")
	t.Setenv("LISTEN_PORT", "443")

	if _, err := Load(); err != nil {
		t.Fatalf("Load() with missing config file returned error: %v", err)
	}
}

func TestLoad_MissingAllRequired(t *testing.T) {
	clearAllEnv(t)
	t.Setenv("CONFIG_FILE", noConfigFile(t))

	_, err := Load()
	if err == nil {
		t.Fatal("Load() returned nil error, want error for missing required keys")
	}

	for _, key := range []string{"SSH_SERVER_ADDR", "HTTP_SERVER_ADDR", "LISTEN_PORT"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q does not mention missing key %q", err.Error(), key)
		}
	}
}

func TestLoad_MissingPartialRequired(t *testing.T) {
	clearAllEnv(t)
	t.Setenv("CONFIG_FILE", noConfigFile(t))
	t.Setenv("SSH_SERVER_ADDR", "localhost:22")
	// HTTP_SERVER_ADDR and LISTEN_PORT intentionally missing

	_, err := Load()
	if err == nil {
		t.Fatal("Load() returned nil error, want error")
	}

	msg := err.Error()

	if strings.Contains(msg, "SSH_SERVER_ADDR") {
		t.Errorf("error %q mentions SSH_SERVER_ADDR which was provided", msg)
	}

	if !strings.Contains(msg, "HTTP_SERVER_ADDR") {
		t.Errorf("error %q does not mention missing key HTTP_SERVER_ADDR", msg)
	}

	if !strings.Contains(msg, "LISTEN_PORT") {
		t.Errorf("error %q does not mention missing key LISTEN_PORT", msg)
	}
}

func TestLoad_DefaultOptionals(t *testing.T) {
	clearAllEnv(t)
	t.Setenv("CONFIG_FILE", noConfigFile(t))
	t.Setenv("SSH_SERVER_ADDR", "localhost:22")
	t.Setenv("HTTP_SERVER_ADDR", "localhost:80")
	t.Setenv("LISTEN_PORT", "443")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.CertFile != "cert.pem" {
		t.Errorf("CertFile = %q, want %q", cfg.CertFile, "cert.pem")
	}

	if cfg.KeyFile != "key.pem" {
		t.Errorf("KeyFile = %q, want %q", cfg.KeyFile, "key.pem")
	}
}

func TestLoad_OptionalFromEnv(t *testing.T) {
	clearAllEnv(t)
	t.Setenv("CONFIG_FILE", noConfigFile(t))
	t.Setenv("SSH_SERVER_ADDR", "localhost:22")
	t.Setenv("HTTP_SERVER_ADDR", "localhost:80")
	t.Setenv("LISTEN_PORT", "443")
	t.Setenv("TLS_CERT_FILE", "/etc/ssl/cert.pem")
	t.Setenv("TLS_KEY_FILE", "/etc/ssl/key.pem")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.CertFile != "/etc/ssl/cert.pem" {
		t.Errorf("CertFile = %q, want %q", cfg.CertFile, "/etc/ssl/cert.pem")
	}

	if cfg.KeyFile != "/etc/ssl/key.pem" {
		t.Errorf("KeyFile = %q, want %q", cfg.KeyFile, "/etc/ssl/key.pem")
	}
}

func TestLoad_OptionalEnvOverridesFile(t *testing.T) {
	clearAllEnv(t)

	path := writeConfigFile(t,
		"SSH_SERVER_ADDR=localhost:22\n"+
			"HTTP_SERVER_ADDR=localhost:80\n"+
			"LISTEN_PORT=443\n"+
			"TLS_CERT_FILE=/file/cert.pem\n"+
			"TLS_KEY_FILE=/file/key.pem\n",
	)
	t.Setenv("CONFIG_FILE", path)
	t.Setenv("TLS_CERT_FILE", "/env/cert.pem") // overrides file; KEY_FILE stays from file

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.CertFile != "/env/cert.pem" {
		t.Errorf("CertFile = %q, want env override %q", cfg.CertFile, "/env/cert.pem")
	}

	if cfg.KeyFile != "/file/key.pem" {
		t.Errorf("KeyFile = %q, want file value %q", cfg.KeyFile, "/file/key.pem")
	}
}

func TestLoadFile_UnreadableFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: chmod 000 does not restrict access")
	}

	path := writeConfigFile(t, "FOO=bar\n")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	t.Cleanup(func() { os.Chmod(path, 0o600) }) //nolint:errcheck,gosec // best-effort restore for cleanup

	_, err := loadFile(path)
	if err == nil {
		t.Fatal("loadFile() expected error for unreadable file, got nil")
	}
}

func TestLoad_UnreadableConfigFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: chmod 000 does not restrict access")
	}

	clearAllEnv(t)

	path := writeConfigFile(t, "FOO=bar\n")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	t.Cleanup(func() { os.Chmod(path, 0o600) }) //nolint:errcheck,gosec // best-effort restore for cleanup

	t.Setenv("CONFIG_FILE", path)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() expected error for unreadable config file, got nil")
	}
}

func TestLoad_EmptyFileValueTreatedAsUnset(t *testing.T) {
	clearAllEnv(t)

	// SSH_SERVER_ADDR= (empty) must be ignored; no env var either → should fail as missing
	path := writeConfigFile(t,
		"SSH_SERVER_ADDR=\n"+
			"HTTP_SERVER_ADDR=localhost:80\n"+
			"LISTEN_PORT=443\n",
	)
	t.Setenv("CONFIG_FILE", path)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() returned nil, want error for empty file value treated as unset")
	}

	if !strings.Contains(err.Error(), "SSH_SERVER_ADDR") {
		t.Errorf("error %q does not mention SSH_SERVER_ADDR", err.Error())
	}
}
