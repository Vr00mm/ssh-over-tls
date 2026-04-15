# Contributing

## Prerequisites

- Go 1.25+
- `golangci-lint` — `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`
- `govulncheck` — `go install golang.org/x/vuln/cmd/govulncheck@latest`

## Development

```bash
# Clone
git clone https://github.com/Vr00mm/ssh-over-tls.git
cd ssh-over-tls

# Install dependencies
make install

# Build
make build

# Run tests
make test

# Lint
make lint
```

## TLS certificates for local testing

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=localhost"
```

## Pull Request Process

1. Fork the repository and create a branch from `main`.
2. Make your changes with tests where applicable.
3. Run `make lint` and `make test` — both must pass.
4. Open a PR with a clear description of the change and why.
