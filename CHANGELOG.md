# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
