# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Major refactoring**: Split monolithic files into focused packages
- `internal/proxy/server.go` reduced from 419 to 139 lines (67% reduction)
- `internal/config/config.go` split into `spec.go`, `file.go`, `tls.go`
- All source files now under 200 lines, all functions under 50 lines
- Improved code organization following idiomatic Go package structure

### Added
- New `internal/tlsutil` package for TLS version/cipher suite name helpers
- New `internal/protocol` package for protocol detection logic
- New `internal/handler` package with connection handling, copying, and error categorization
- Buffer pooling for improved performance in bidirectional copying
- Better error messages listing all missing required configuration fields

### Removed
- Weak CBC cipher suites from default TLS configuration
- Nested if statements in favor of early returns

### Fixed
- All golangci-lint issues (29 issues resolved)
- Error handling with proper nolint annotations
- Whitespace and formatting per Go best practices

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
