BINARY_NAME=ssh-over-tls
GO=go

VERSION?=$(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

.PHONY: all build clean test lint lint-fix fmt audit help

all: lint test build

## build: Build the binary
build:
	$(GO) build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/$(BINARY_NAME)

## clean: Remove build artifacts
clean:
	rm -rf bin/ coverage.out coverage.html

## test: Run tests with race detector and coverage
test:
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

## lint: Run linter
lint:
	golangci-lint run ./...

## lint-fix: Run linter and auto-fix issues
lint-fix:
	golangci-lint run --fix ./...

## fmt: Format code
fmt:
	golangci-lint fmt ./...

## audit: Check dependencies for known vulnerabilities
audit:
	govulncheck ./...

## install: Download and tidy dependencies
install:
	$(GO) mod download
	$(GO) mod tidy

## help: Show this help
help:
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
