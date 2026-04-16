# ssh-over-tls

[![Go Version](https://img.shields.io/github/go-mod/go-version/Vr00mm/ssh-over-tls)](https://go.dev/)
[![License](https://img.shields.io/github/license/Vr00mm/ssh-over-tls)](./LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Vr00mm/ssh-over-tls/test.yml?branch=main)](https://github.com/Vr00mm/ssh-over-tls/actions)
[![Release](https://img.shields.io/github/v/release/Vr00mm/ssh-over-tls)](https://github.com/Vr00mm/ssh-over-tls/releases)

A TLS multiplexer that serves SSH and HTTP traffic on a single port. Incoming connections are identified by their first bytes and forwarded to the appropriate backend — no client-side changes required.

```
client ──TLS──► :443 ──► SSH_SERVER_ADDR  (SSH traffic)
                     └──► HTTP_SERVER_ADDR (HTTP traffic)
```

## Getting Started

### Debian / Ubuntu (apt)

```bash
# Add the apt repository
curl -fsSL https://vr00mm.github.io/apt/pubkey.gpg | sudo gpg --dearmor -o /usr/share/keyrings/vr00mm.gpg
echo "deb [signed-by=/usr/share/keyrings/vr00mm.gpg] https://vr00mm.github.io/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/vr00mm.list

sudo apt update && sudo apt install ssh-over-tls
```

### Pre-built binaries

Download `.deb` packages or raw binaries from [GitHub Releases](https://github.com/Vr00mm/ssh-over-tls/releases/latest).

| Platform | Architecture | Package |
|----------|-------------|---------|
| Linux | amd64 | `ssh-over-tls_<version>_linux_amd64.deb` |
| Linux | arm64 | `ssh-over-tls_<version>_linux_arm64.deb` |

### From source

```bash
go install github.com/Vr00mm/ssh-over-tls@latest
```

## Configuration

All configuration is via environment variables.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SSH_SERVER_ADDR` | Yes | — | Address of the SSH backend (e.g. `localhost:22`) |
| `HTTP_SERVER_ADDR` | Yes | — | Address of the HTTP backend (e.g. `localhost:80`) |
| `LISTEN_PORT` | Yes | — | Port to listen on (e.g. `443`) |
| `TLS_CERT_FILE` | No | `cert.pem` | Path to the TLS certificate file |
| `TLS_KEY_FILE` | No | `key.pem` | Path to the TLS private key file |
| `TLS_MIN_VERSION` | No | `TLS12` | Minimum TLS version (`TLS10`, `TLS11`, `TLS12`, `TLS13`) |
| `TLS_CIPHER_SUITES` | No | _(secure defaults)_ | Comma-separated list of allowed cipher suites |

### Example

```bash
export SSH_SERVER_ADDR=localhost:22
export HTTP_SERVER_ADDR=localhost:8080
export LISTEN_PORT=443
export TLS_CERT_FILE=/etc/ssl/cert.pem
export TLS_KEY_FILE=/etc/ssl/key.pem

ssh-over-tls
```

### TLS Security Configuration

By default, `ssh-over-tls` uses TLS 1.2+ with a secure set of modern cipher suites. You can customize this behavior for specific security requirements.

#### Setting Minimum TLS Version

Reject older TLS versions to reduce exposure to protocol vulnerabilities:

```bash
# Only accept TLS 1.3 (most secure, may reject some older clients)
export TLS_MIN_VERSION=TLS13

# Accept TLS 1.2 and above (default, good compatibility)
export TLS_MIN_VERSION=TLS12
```

**Supported values:** `TLS10`, `TLS11`, `TLS12`, `TLS13`

**Note:** Setting `TLS_MIN_VERSION=TLS13` will reduce scanner noise in logs by rejecting connections from bots using outdated TLS versions.

#### Configuring Cipher Suites

Limit allowed cipher suites for compliance or hardening:

```bash
# High security: only strongest ciphers
export TLS_CIPHER_SUITES="TLS_ECDHE_RSA_WITH_AES_256_GCM,TLS_ECDHE_ECDSA_WITH_AES_256_GCM,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"

# Maximum compatibility: include CBC mode ciphers
export TLS_CIPHER_SUITES="TLS_ECDHE_RSA_WITH_AES_128_GCM,TLS_ECDHE_RSA_WITH_AES_256_GCM,TLS_ECDHE_RSA_WITH_AES_128_CBC"
```

**Common cipher suite names:**
- `TLS_ECDHE_RSA_WITH_AES_128_GCM` or `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM` or `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM` or `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM` or `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305` or `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305` or `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`

If not specified, secure defaults are used (all modern ECDHE-based cipher suites).

#### Configuration File

Alternatively, use a configuration file at `/etc/ssh-over-tls/config`:

```bash
# /etc/ssh-over-tls/config
SSH_SERVER_ADDR=localhost:22
HTTP_SERVER_ADDR=localhost:8080
LISTEN_PORT=443
TLS_CERT_FILE=/etc/ssl/certs/ssh-over-tls.pem
TLS_KEY_FILE=/etc/ssl/private/ssh-over-tls.key

# Security settings
TLS_MIN_VERSION=TLS12
TLS_CIPHER_SUITES=TLS_ECDHE_RSA_WITH_AES_256_GCM,TLS_ECDHE_ECDSA_WITH_AES_256_GCM
```

Environment variables always override configuration file values.

## Connecting via SSH

The proxy expects the raw SSH protocol after the TLS handshake.
Use any tool that can wrap a TCP connection in TLS as a `ProxyCommand`.

### One-off connection

```bash
ssh -o ProxyCommand="openssl s_client -connect proxy.example.com:443 -quiet" user@proxy.example.com
```

`-quiet` suppresses `openssl`'s connection banner so only SSH traffic flows through stdin/stdout.

### Persistent SSH config

Add this to `~/.ssh/config` to make it transparent:

```
Host myserver
    HostName proxy.example.com
    User     myuser
    ProxyCommand openssl s_client -connect %h:%p -quiet
```

Then simply:

```bash
ssh myserver
```

### Using a self-signed certificate

Pass the certificate as a trusted CA so `openssl` verifies it correctly:

```bash
ssh -o ProxyCommand="openssl s_client -connect proxy.example.com:443 -quiet -CAfile /path/to/cert.pem" user@proxy.example.com
```

Or in `~/.ssh/config`:

```
Host myserver
    HostName proxy.example.com
    User     myuser
    ProxyCommand openssl s_client -connect %h:%p -quiet -CAfile /path/to/cert.pem
```

## How It Works

1. Clients connect and complete a TLS handshake.
2. The proxy reads the first 8 bytes to detect the protocol:
   - `SSH-` prefix → forwarded to `SSH_SERVER_ADDR`
   - HTTP verb (`GET`, `POST`, `HEAD`, …) → forwarded to `HTTP_SERVER_ADDR`
3. The 8-byte header is prepended back to the stream before forwarding.
4. Bidirectional proxying runs until either side closes the connection.

Both backends receive the original unencrypted traffic — TLS is terminated at the proxy.

## Development

### Project Structure

The codebase follows idiomatic Go organization with focused, modular packages:

```
internal/
├── config/          # Configuration loading (file.go, spec.go, tls.go)
├── handler/         # Connection handling (handler.go, copy.go, errors.go)
├── protocol/        # Protocol detection (SSH/HTTP)
├── proxy/           # TLS server and options
└── tlsutil/         # TLS helper utilities (version/cipher names)
```

**Code standards:**
- All files under 200 lines
- All functions under 50 lines
- Early returns instead of nested if statements
- Zero golangci-lint issues

### Building

```bash
go build ./cmd/ssh-over-tls
```

### Testing

```bash
go test ./...
golangci-lint run
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
