# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- PROXY protocol v1 support for HTTP backends: forwards real client IP to nginx/backends via `PROXY TCP4 ...` header
- New `PROXY_PROTOCOL_ENABLED` config option (default: `false`) — must be explicitly enabled to avoid breaking backends that don't expect it
- New `COPY_IDLE_TIMEOUT` config option (default: `5m`) — closes idle connections after inactivity to free resources
- TCP half-close support in bidirectional copy: signals end-of-stream to the peer when one direction finishes, allowing the other to drain cleanly
- TLS error beautification: hex cipher suite IDs and version codes in error messages are now translated to human-readable names (e.g. `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384`, `TLS 1.2`)
- Graceful shutdown with 30-second timeout: active connections are tracked and force-closed if they don't finish in time
- Expanded TLS cipher suite name map covering legacy, DHE, ECDH, and scanner-specific suites for better error diagnostics
- `FormatCipherSuites` helper to render lists of cipher suite IDs compactly in logs
- Unit tests for `categorizeError` and `BeautifyTLSError`
- `WithCopyIdleTimeout` and `WithProxyProtocol` functional options on `proxy.Server`

### Changed
- **Major refactoring**: Split monolithic files into focused packages
- `internal/proxy/server.go` reduced from 419 to 139 lines (67% reduction)
- `internal/config/config.go` split into `spec.go`, `file.go`, `tls.go`
- All source files now under 200 lines, all functions under 50 lines
- Improved code organization following idiomatic Go package structure
- HTTP method detection tightened to require a trailing space or exact word boundary, preventing false positives on binary payloads that happen to start with `POST`, `DELETE`, etc.
- Debian `postinst` now restarts the service on upgrade (instead of only enabling it)
- Debian `prerm` now only stops and disables the service on full removal, not on upgrade
- systemd service unit gains `TimeoutStopSec=35s`, `KillMode=mixed`, `KillSignal=SIGTERM` to align with the application's 30-second graceful shutdown

### Removed
- Weak CBC cipher suites from default TLS configuration
- Nested if statements in favor of early returns

### Fixed
- All golangci-lint issues (29 issues resolved)
- Error handling with proper nolint annotations
- Whitespace and formatting per Go best practices
- EOF during TLS handshake now logged as WARN instead of ERROR (normal scanner behaviour)
- `connection reset by peer` and `inappropriate protocol fallback` errors now classified as WARN (scanner noise, not actionable errors)

## [1.0.0] - 2026-04-15

### Added
- TLS multiplexer routing SSH and HTTP traffic on a single port
- Protocol detection via 8-byte header sniffing
- Graceful shutdown on SIGINT/SIGTERM with active-connection draining
- Configurable dial and TLS handshake timeouts via functional options
- Structured logging with `log/slog`
- TLS certificate and key paths configurable via `TLS_CERT_FILE` / `TLS_KEY_FILE` env vars
- Debian package with systemd service unit
- APT repository publishing via `deb-publish` action
