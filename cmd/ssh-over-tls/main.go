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

	s, err := proxy.New(cfg.SSHAddr, cfg.HTTPAddr, cfg.Port, cfg.CertFile, cfg.KeyFile)
	if err != nil {
		slog.Error("create proxy", "err", err)
		os.Exit(1)
	}

	if err := s.Run(); err != nil {
		slog.Error("proxy", "err", err)
		os.Exit(1)
	}
}
