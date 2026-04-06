//go:build darwin || windows

package app

import (
	"context"

	gecitdns "github.com/boratanrikulu/gecit/pkg/dns"
	"github.com/boratanrikulu/gecit/pkg/engine"
	gecittun "github.com/boratanrikulu/gecit/pkg/tun"
	"github.com/sirupsen/logrus"
)

type tunEngine struct {
	mgr        *gecittun.Manager
	dns        *gecitdns.Server
	dohEnabled bool
	logger     *logrus.Logger
}

func newPlatformEngine(cfg engine.Config, logger *logrus.Logger) (engine.Engine, error) {
	dohUpstream := cfg.DoHUpstream
	if dohUpstream == "" {
		dohUpstream = "https://1.1.1.1/dns-query"
	}

	return &tunEngine{
		mgr: gecittun.NewManager(gecittun.Config{
			Ports:     cfg.Ports,
			FakeTTL:   cfg.FakeTTL,
			Interface: cfg.Interface,
		}, logger),
		dns:        gecitdns.NewServer(dohUpstream, logger),
		dohEnabled: cfg.DoHEnabled,
		logger:     logger,
	}, nil
}

func (e *tunEngine) Start(ctx context.Context) error {
	if e.dohEnabled {
		stopSystemDNS()

		if err := e.dns.Start(); err != nil {
			resumeSystemDNS()
			return err
		}
		if err := gecitdns.SetSystemDNS(); err != nil {
			e.dns.Stop()
			resumeSystemDNS()
			return err
		}
		e.logger.Info("DoH DNS active")
	}

	if err := e.mgr.Start(ctx); err != nil {
		if e.dohEnabled {
			gecitdns.RestoreSystemDNS()
			e.dns.Stop()
			resumeSystemDNS()
		}
		return err
	}

	return nil
}

func (e *tunEngine) Stop() error {
	e.mgr.Stop()
	if e.dohEnabled {
		gecitdns.RestoreSystemDNS()
		e.dns.Stop()
		resumeSystemDNS()
	}
	return nil
}

func (e *tunEngine) Mode() string { return "tun" }
