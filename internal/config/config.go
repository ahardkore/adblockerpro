// Package config loads, validates and persists the on-disk configuration.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ahardkore/adblockerpro/internal/blocklist"
	"github.com/ahardkore/adblockerpro/internal/dhcp"
	"github.com/ahardkore/adblockerpro/internal/schedule"
)

// DefaultPath is where the service looks for its configuration.
const DefaultPath = "/etc/adblockerpro/config.json"

// DNSConfig configures the resolver.
type DNSConfig struct {
	// Listen is the address the DNS server binds to. 0.0.0.0 serves the
	// whole LAN, which is the point of the box.
	Listen string `json:"listen"`
	// Port is normally 53.
	Port int `json:"port"`
	// Upstreams are plain DNS resolvers, host:port (port optional).
	Upstreams []string `json:"upstreams"`
	// DoHUpstreams are DNS-over-HTTPS endpoints. When non-empty and
	// PreferDoH is set they are tried first, so the ISP cannot see or
	// hijack lookups.
	DoHUpstreams []string `json:"doh_upstreams"`
	PreferDoH    bool     `json:"prefer_doh"`
	// Sinkhole is zero-ip, nxdomain, refused or custom-ip.
	Sinkhole   string `json:"sinkhole"`
	CustomIPv4 string `json:"custom_ipv4,omitempty"`
	CustomIPv6 string `json:"custom_ipv6,omitempty"`
	BlockTTL   uint32 `json:"block_ttl"`
	// BlockSubdomains makes a listed domain cover its subdomains too.
	BlockSubdomains bool `json:"block_subdomains"`
	// BlockCNAMECloaking re-checks CNAME targets of allowed answers.
	BlockCNAMECloaking bool `json:"block_cname_cloaking"`
	// BlockHTTPSRecords drops HTTPS/SVCB records, which forces clients that
	// would otherwise discover encrypted DNS or ECH to fall back to plain
	// connections we can still filter.
	BlockHTTPSRecords bool `json:"block_https_records"`
	CacheSize         int  `json:"cache_size"`
	CacheMinTTL       int  `json:"cache_min_ttl"`
	CacheMaxTTL       int  `json:"cache_max_ttl"`
	// ServeStale replays an expired cache entry when every upstream fails.
	ServeStale bool `json:"serve_stale"`
	// UpstreamTimeoutMS bounds a single upstream exchange.
	UpstreamTimeoutMS int `json:"upstream_timeout_ms"`
	// RateLimitPerClient caps queries per second per client (0 disables).
	RateLimitPerClient int `json:"rate_limit_per_client"`
	// AllowedClients restricts who may query, as IPs or CIDRs. Empty means
	// every private network, which keeps the resolver off the public net.
	AllowedClients []string `json:"allowed_clients"`
	// LocalRecords are static answers, e.g. "pi.hole": "192.168.1.2".
	LocalRecords map[string]string `json:"local_records,omitempty"`
	// ConditionalForward sends a domain suffix to a specific resolver,
	// typically your router for local hostnames.
	ConditionalForward []Forward `json:"conditional_forward,omitempty"`
	// RequestDNSSEC adds an EDNS0 OPT record with the DO bit so upstreams
	// validate and report authenticated data (the AD bit), which is then
	// tracked per query in the log.
	RequestDNSSEC bool `json:"request_dnssec"`
	// DoHServer exposes /dns-query on the dashboard port so phones and
	// laptops can keep using this resolver off the LAN.
	DoHServer bool `json:"doh_server"`
}

// Forward is one conditional-forwarding entry.
type Forward struct {
	// Domain is a suffix such as "home.arpa" or "1.168.192.in-addr.arpa".
	Domain string `json:"domain"`
	// Upstream is host[:port] of the resolver that owns it.
	Upstream string `json:"upstream"`
}

// WebConfig configures the dashboard and API.
type WebConfig struct {
	Listen string `json:"listen"`
	Port   int    `json:"port"`
	// AdminToken, when set, is required by the API and the dashboard login.
	AdminToken string `json:"admin_token,omitempty"`
}

// ListsConfig configures blocklist sources.
type ListsConfig struct {
	Sources             []blocklist.Source `json:"sources"`
	UpdateIntervalHours int                `json:"update_interval_hours"`
}

// Device is a known client on the LAN with its own policy.
type Device struct {
	// Match is an IP or CIDR, e.g. "192.168.1.42" or "192.168.5.0/24".
	Match string `json:"match"`
	Name  string `json:"name"`
	// Group selects which group-scoped rules apply.
	Group string `json:"group,omitempty"`
	// Paused disables filtering for this device entirely.
	Paused bool `json:"paused,omitempty"`
}

// HistoryConfig configures the long-term query store.
type HistoryConfig struct {
	Enabled       bool `json:"enabled"`
	RetentionDays int  `json:"retention_days"`
}

// LogConfig configures logging and the query log.
type LogConfig struct {
	Level string `json:"level"`
	// QueryLogSize is how many recent queries are kept in memory.
	QueryLogSize int `json:"query_log_size"`
	// AnonymizeClients stores only a hash of client addresses.
	AnonymizeClients bool `json:"anonymize_clients"`
	// PersistStats writes counters to disk so they survive a reboot.
	PersistStats bool `json:"persist_stats"`
}

// Config is the whole configuration document.
type Config struct {
	DataDir string           `json:"data_dir"`
	DNS     DNSConfig        `json:"dns"`
	Web     WebConfig        `json:"web"`
	Lists   ListsConfig      `json:"lists"`
	Rules   []blocklist.Rule `json:"rules"`
	Devices []Device         `json:"devices"`
	Log     LogConfig        `json:"log"`
	// History is the long-term query store.
	History HistoryConfig `json:"history"`
	// DHCP is the optional DHCPv4 server.
	DHCP dhcp.Config `json:"dhcp"`
	// Schedules are the time-based filtering windows.
	Schedules []schedule.Schedule `json:"schedules"`

	path string
	mu   sync.Mutex
}

// Default returns a configuration suitable for a fresh Raspberry Pi install.
func Default() *Config {
	c := &Config{
		DataDir: "/var/lib/adblockerpro",
		DNS: DNSConfig{
			Listen:    "0.0.0.0",
			Port:      53,
			Upstreams: []string{"1.1.1.1:53", "9.9.9.9:53", "8.8.8.8:53"},
			DoHUpstreams: []string{
				"https://cloudflare-dns.com/dns-query",
				"https://dns.quad9.net/dns-query",
			},
			PreferDoH:          true,
			Sinkhole:           "zero-ip",
			BlockTTL:           60,
			BlockSubdomains:    true,
			BlockCNAMECloaking: true,
			BlockHTTPSRecords:  false,
			CacheSize:          20000,
			CacheMinTTL:        30,
			CacheMaxTTL:        86400,
			ServeStale:         true,
			UpstreamTimeoutMS:  3500,
			RateLimitPerClient: 0,
			AllowedClients:     nil,
			LocalRecords:       map[string]string{},
		},
		Web: WebConfig{
			Listen: "0.0.0.0",
			Port:   8080,
		},
		Lists: ListsConfig{
			Sources:             blocklist.DefaultSources(),
			UpdateIntervalHours: 24,
		},
		Rules:   []blocklist.Rule{},
		Devices: []Device{},
		History: HistoryConfig{Enabled: true, RetentionDays: 30},
		DHCP: dhcp.Config{
			Enabled:    false,
			Netmask:    "255.255.255.0",
			LeaseHours: 12,
			DomainName: "lan",
		},
		Schedules: []schedule.Schedule{},
		Log: LogConfig{
			Level:        "info",
			QueryLogSize: 20000,
			PersistStats: true,
		},
	}
	return c
}

// Load reads the configuration at path, creating it with defaults when it
// does not exist yet.
func Load(path string) (*Config, error) {
	cfg := Default()
	cfg.path = path

	data, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		if err := cfg.Save(); err != nil {
			// A read-only location is fine for a dry run; carry on with the
			// defaults rather than refusing to start.
			return cfg, nil
		}
		return cfg, nil
	case err != nil:
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.path = path
	cfg.applyDefaults()
	return cfg, cfg.Validate()
}

func (c *Config) applyDefaults() {
	d := Default()
	if c.DataDir == "" {
		c.DataDir = d.DataDir
	}
	if c.DNS.Listen == "" {
		c.DNS.Listen = d.DNS.Listen
	}
	if c.DNS.Port == 0 {
		c.DNS.Port = d.DNS.Port
	}
	if len(c.DNS.Upstreams) == 0 {
		c.DNS.Upstreams = d.DNS.Upstreams
	}
	if c.DNS.Sinkhole == "" {
		c.DNS.Sinkhole = d.DNS.Sinkhole
	}
	if c.DNS.BlockTTL == 0 {
		c.DNS.BlockTTL = d.DNS.BlockTTL
	}
	if c.DNS.CacheSize == 0 {
		c.DNS.CacheSize = d.DNS.CacheSize
	}
	if c.DNS.CacheMaxTTL == 0 {
		c.DNS.CacheMaxTTL = d.DNS.CacheMaxTTL
	}
	if c.DNS.UpstreamTimeoutMS == 0 {
		c.DNS.UpstreamTimeoutMS = d.DNS.UpstreamTimeoutMS
	}
	if c.DNS.LocalRecords == nil {
		c.DNS.LocalRecords = map[string]string{}
	}
	if c.Web.Listen == "" {
		c.Web.Listen = d.Web.Listen
	}
	if c.Web.Port == 0 {
		c.Web.Port = d.Web.Port
	}
	if c.Lists.UpdateIntervalHours == 0 {
		c.Lists.UpdateIntervalHours = d.Lists.UpdateIntervalHours
	}
	if c.Log.Level == "" {
		c.Log.Level = d.Log.Level
	}
	if c.Log.QueryLogSize == 0 {
		c.Log.QueryLogSize = d.Log.QueryLogSize
	}
	if c.History.RetentionDays == 0 {
		c.History.RetentionDays = d.History.RetentionDays
	}
	if c.DHCP.LeaseHours == 0 {
		c.DHCP.LeaseHours = d.DHCP.LeaseHours
	}
	if c.DHCP.Netmask == "" {
		c.DHCP.Netmask = d.DHCP.Netmask
	}
	for i := range c.Lists.Sources {
		if c.Lists.Sources[i].ID == "" {
			c.Lists.Sources[i].ID = blocklist.SourceID(c.Lists.Sources[i].URL)
		}
	}
}

// Validate checks the values that would otherwise fail at runtime.
func (c *Config) Validate() error {
	if c.DNS.Port < 1 || c.DNS.Port > 65535 {
		return fmt.Errorf("dns.port %d out of range", c.DNS.Port)
	}
	if c.Web.Port < 1 || c.Web.Port > 65535 {
		return fmt.Errorf("web.port %d out of range", c.Web.Port)
	}
	switch c.DNS.Sinkhole {
	case "zero-ip", "nxdomain", "refused", "custom-ip":
	default:
		return fmt.Errorf("dns.sinkhole %q is not one of zero-ip, nxdomain, refused, custom-ip", c.DNS.Sinkhole)
	}
	if c.DNS.Sinkhole == "custom-ip" && c.DNS.CustomIPv4 == "" && c.DNS.CustomIPv6 == "" {
		return fmt.Errorf("dns.sinkhole custom-ip needs custom_ipv4 or custom_ipv6")
	}
	if len(c.DNS.Upstreams) == 0 && len(c.DNS.DoHUpstreams) == 0 {
		return fmt.Errorf("at least one upstream resolver is required")
	}
	if c.DHCP.Enabled {
		for _, field := range []struct{ name, value string }{
			{"dhcp.server_ip", c.DHCP.ServerIP},
			{"dhcp.range_start", c.DHCP.RangeStart},
			{"dhcp.range_end", c.DHCP.RangeEnd},
		} {
			if net.ParseIP(field.value) == nil {
				return fmt.Errorf("%s must be an IPv4 address", field.name)
			}
		}
	}
	for _, s := range c.Schedules {
		if err := schedule.Validate(s); err != nil {
			return err
		}
	}
	return nil
}

// Path is the file this configuration was loaded from.
func (c *Config) Path() string { return c.path }

// SetPath overrides the save location.
func (c *Config) SetPath(p string) { c.path = p }

// Save atomically writes the configuration back to disk.
func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.path == "" {
		return fmt.Errorf("config has no path")
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// UpdateInterval is the blocklist refresh period.
func (c *Config) UpdateInterval() time.Duration {
	return time.Duration(c.Lists.UpdateIntervalHours) * time.Hour
}

// UpstreamTimeout bounds one upstream exchange.
func (c *Config) UpstreamTimeout() time.Duration {
	return time.Duration(c.DNS.UpstreamTimeoutMS) * time.Millisecond
}

// DNSAddr is the host:port the resolver binds to.
func (c *Config) DNSAddr() string {
	return fmt.Sprintf("%s:%d", c.DNS.Listen, c.DNS.Port)
}

// WebAddr is the host:port the dashboard binds to.
func (c *Config) WebAddr() string {
	return fmt.Sprintf("%s:%d", c.Web.Listen, c.Web.Port)
}

// NormalizeUpstream appends the default DNS port when the entry has none.
func NormalizeUpstream(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, "[") { // [::1]:53
		if strings.Contains(addr, "]:") {
			return addr
		}
		return addr + ":53"
	}
	if strings.Count(addr, ":") == 1 {
		return addr
	}
	if strings.Contains(addr, ":") { // bare IPv6
		return "[" + addr + "]:53"
	}
	return addr + ":53"
}
