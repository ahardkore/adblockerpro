// Command adblockerpro is a network-wide DNS ad blocker for a Raspberry Pi.
//
// Point your router's DHCP at the Pi and every device on the LAN — phones,
// laptops, smart TVs and streaming sticks that have no way to run an
// extension — stops resolving ad and tracker hostnames.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ahardkore/adblockerpro/internal/api"
	"github.com/ahardkore/adblockerpro/internal/blocklist"
	"github.com/ahardkore/adblockerpro/internal/config"
	"github.com/ahardkore/adblockerpro/internal/devices"
	"github.com/ahardkore/adblockerpro/internal/dhcp"
	"github.com/ahardkore/adblockerpro/internal/history"
	"github.com/ahardkore/adblockerpro/internal/resolver"
	"github.com/ahardkore/adblockerpro/internal/schedule"
	"github.com/ahardkore/adblockerpro/internal/server"
	"github.com/ahardkore/adblockerpro/internal/stats"
)

// version is overridden at build time with -ldflags "-X main.version=…".
var version = "dev"

func main() {
	var (
		cfgPath  = flag.String("config", envOr("ABP_CONFIG", config.DefaultPath), "path to config.json")
		dnsPort  = flag.Int("dns-port", 0, "override the DNS port (default 53)")
		webPort  = flag.Int("web-port", 0, "override the dashboard port (default 8080)")
		listen   = flag.String("listen", "", "override the DNS listen address")
		dataDir  = flag.String("data-dir", "", "override the data directory")
		logLevel = flag.String("log-level", "", "debug, info, warn or error")
		check    = flag.String("check", "", "evaluate a domain against the lists and exit")
		noUpdate = flag.Bool("no-update", false, "do not download blocklists on start-up")
		showVer  = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("adblockerpro %s\n", version)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("config: %v", err)
	}
	if *dnsPort != 0 {
		cfg.DNS.Port = *dnsPort
	}
	if *webPort != 0 {
		cfg.Web.Port = *webPort
	}
	if *listen != "" {
		cfg.DNS.Listen = *listen
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if *logLevel != "" {
		cfg.Log.Level = *logLevel
	}
	if err := cfg.Validate(); err != nil {
		fatal("config: %v", err)
	}

	log := newLogger(cfg.Log.Level)
	api.Version = version

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		log.Warn("cannot create data dir", "dir", cfg.DataDir, "err", err)
	}

	// Filtering engine and blocklists.
	engine := blocklist.New(cfg.DNS.BlockSubdomains)
	engine.SetRules(cfg.Rules)
	updater := blocklist.NewUpdater(engine, cfg.DataDir+"/lists", log)
	updater.SetSources(cfg.Lists.Sources)
	updater.OnChange(func(src []blocklist.Source) {
		cfg.Lists.Sources = src
		if err := cfg.Save(); err != nil {
			log.Warn("save config", "err", err)
		}
	})
	if n := updater.LoadFromCache(); n > 0 {
		log.Info("loaded blocklists from cache", "domains", n)
	}

	// One-shot domain check for scripts and debugging.
	if *check != "" {
		if engine.Domains().Len() == 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			if _, err := updater.UpdateAll(ctx); err != nil {
				log.Warn("list download failed", "err", err)
			}
			cancel()
		}
		d := engine.Check(*check, "")
		if d.Blocked {
			fmt.Printf("BLOCKED  %s  (rule %q from %s)\n", *check, d.Rule, d.Source)
			os.Exit(1)
		}
		fmt.Printf("allowed  %s\n", *check)
		return
	}

	// Resolver plumbing.
	cache := resolver.NewCache(cfg.DNS.CacheSize,
		time.Duration(cfg.DNS.CacheMinTTL)*time.Second,
		time.Duration(cfg.DNS.CacheMaxTTL)*time.Second)
	pool := resolver.NewPool(buildUpstreams(cfg)...)
	registry := devices.New(cfg.Devices)

	collector := stats.New(cfg.Log.QueryLogSize, cfg.Log.AnonymizeClients)
	if cfg.Log.PersistStats {
		collector.SetPersistPath(cfg.DataDir)
		if err := collector.Load(cfg.DataDir); err == nil {
			log.Info("restored statistics from disk")
		}
	}

	// Long-term query history (Pi-hole keeps this in SQLite; we use
	// append-only daily shards and feed them from the stats collector).
	var hist *history.Store
	if cfg.History.Enabled {
		h, err := history.Open(filepath.Join(cfg.DataDir, "history"), cfg.History.RetentionDays)
		if err != nil {
			log.Warn("history disabled", "err", err)
		} else {
			hist = h
			collector.SetSink(func(e stats.Entry) {
				if err := hist.Append(e); err != nil {
					log.Debug("history append", "err", err)
				}
			})
			log.Info("query history enabled",
				"dir", filepath.Join(cfg.DataDir, "history"),
				"retention_days", cfg.History.RetentionDays)
		}
	}

	schedules := schedule.New()
	schedules.Set(cfg.Schedules)

	dnsSrv := server.NewDNS(cfg, server.Deps{
		Engine:    engine,
		Cache:     cache,
		Pool:      pool,
		Devices:   registry,
		Stats:     collector,
		Schedules: schedules,
		Log:       log,
	})

	// DHCP: optional, but when it is on we learn every device's hostname
	// and can guarantee clients use us for DNS.
	dhcpSrv := dhcp.New(cfg.DHCP, filepath.Join(cfg.DataDir, "leases.json"), log, func(l dhcp.Lease) {
		name := l.Hostname
		if name == "" {
			name = l.Vendor
		}
		registry.Learn(l.IP, name)
	})
	for _, l := range dhcpSrv.Leases() {
		if l.Hostname != "" {
			registry.Learn(l.IP, l.Hostname)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	apiSrv := api.New(api.Deps{
		Config:    cfg,
		Engine:    engine,
		Updater:   updater,
		Cache:     cache,
		Pool:      pool,
		Devices:   registry,
		Stats:     collector,
		DNS:       dnsSrv,
		History:   hist,
		Schedules: schedules,
		DHCP:      dhcpSrv,
		Log:       log,
		Reload: func(c *config.Config) error {
			if err := c.Validate(); err != nil {
				return err
			}
			engine.SetBlockSubdomains(c.DNS.BlockSubdomains)
			pool.Set(buildUpstreams(c)...)
			dnsSrv.ApplyConfig(c)
			schedules.Set(c.Schedules)
			dhcpSrv.SetConfig(c.DHCP)
			cache.Flush()
			log.Info("configuration reloaded")
			return nil
		},
	})

	errCh := make(chan error, 3)
	go func() { errCh <- dnsSrv.ListenAndServe(ctx) }()
	go func() { errCh <- apiSrv.ListenAndServe(ctx, cfg.WebAddr()) }()
	if cfg.DHCP.Enabled {
		go func() {
			if err := dhcpSrv.ListenAndServe(ctx); err != nil {
				// A DHCP failure must not take DNS down with it.
				log.Error("dhcp server stopped", "err", err)
			}
		}()
	}

	if !*noUpdate {
		go updater.Run(ctx, cfg.UpdateInterval())
	}
	if cfg.Log.PersistStats {
		stopPersist := make(chan struct{})
		defer close(stopPersist)
		go collector.RunPersist(time.Minute, stopPersist)
	}
	if hist != nil {
		stopHistory := make(chan struct{})
		defer close(stopHistory)
		go hist.RunFlush(5*time.Second, stopHistory)
		defer hist.Close()
	}

	log.Info("adblockerpro started",
		"version", version,
		"dns", cfg.DNSAddr(),
		"dashboard", "http://"+cfg.WebAddr(),
		"domains", engine.Domains().Len(),
		"schedules", len(cfg.Schedules),
		"dhcp", cfg.DHCP.Enabled,
		"history", hist != nil)

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errCh:
		if err != nil {
			stop()
			log.Error("server stopped", "err", err)
			// Give the other server a moment to unwind, then exit non-zero
			// so systemd restarts us.
			time.Sleep(250 * time.Millisecond)
			if cfg.Log.PersistStats {
				_ = collector.Save()
			}
			os.Exit(1)
		}
	}

	if cfg.Log.PersistStats {
		_ = collector.Save()
	}
	time.Sleep(200 * time.Millisecond)
}

func buildUpstreams(cfg *config.Config) []resolver.Upstream {
	timeout := cfg.UpstreamTimeout()
	var doh, plain []resolver.Upstream
	for _, u := range cfg.DNS.DoHUpstreams {
		if u = strings.TrimSpace(u); u != "" {
			doh = append(doh, resolver.NewDoHUpstream(u, timeout))
		}
	}
	for _, u := range cfg.DNS.Upstreams {
		if a := config.NormalizeUpstream(u); a != "" {
			plain = append(plain, &resolver.UDPUpstream{Addr: a, Timeout: timeout})
		}
	}
	if cfg.DNS.PreferDoH {
		return append(doh, plain...)
	}
	return append(plain, doh...)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})
	return slog.New(h)
}

// envOr returns the environment variable value, or def when it is unset.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "adblockerpro: "+format+"\n", args...)
	os.Exit(1)
}
