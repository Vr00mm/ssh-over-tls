// Package main is the entry point for the ssh-over-tls server.
package main

import (
	"log/slog"
	"os"

	"github.com/Vr00mm/ssh-over-tls/internal/config"
	"github.com/Vr00mm/ssh-over-tls/internal/proxy"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	// Build proxy options from configuration
	opts := []proxy.Option{
		proxy.WithTLSMinVersion(cfg.TLSMinVersion),
	}

	if len(cfg.TLSCipherSuites) > 0 {
		opts = append(opts, proxy.WithTLSCipherSuites(cfg.TLSCipherSuites))
	}

	s, err := proxy.New(cfg.SSHAddr, cfg.HTTPAddr, cfg.Port, cfg.CertFile, cfg.KeyFile, opts...)
	if err != nil {
		slog.Error("create proxy", "err", err)
		os.Exit(1)
	}

	if err := s.Run(); err != nil {
		slog.Error("proxy", "err", err)
		os.Exit(1)
	}
}
