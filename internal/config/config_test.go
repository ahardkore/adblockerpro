package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ahardkore/adblockerpro/internal/schedule"
)

func TestDefaultsAreValid(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Errorf("default config rejected: %v", err)
	}
}

func TestLoadCreatesDefaultFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c == nil {
		t.Fatal("nil config")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("config file was not created: %v", err)
	}
	// A fresh file holds no secrets, but the config file gets the owner-only
	// perm because real deployments put tokens in it.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("config file mode = %o, want 600", fi.Mode().Perm())
	}
}

func TestSavePreservesModeAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	c := Default()
	c.SetPath(path)
	c.DNS.Port = 5353
	if err := c.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("config file mode = %o, want 600", fi.Mode().Perm())
	}

	back, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if back.DNS.Port != 5353 {
		t.Errorf("port = %d, want 5353", back.DNS.Port)
	}
}

func TestLoadRejectsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected an error for a malformed file")
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*Config)
		match string
	}{
		{"bad dns port", func(c *Config) { c.DNS.Port = 0 }, "dns.port"},
		{"bad web port", func(c *Config) { c.Web.Port = 70000 }, "web.port"},
		{"bad sinkhole", func(c *Config) { c.DNS.Sinkhole = "nope" }, "sinkhole"},
		{"custom-ip with no ip", func(c *Config) {
			c.DNS.Sinkhole = "custom-ip"
			c.DNS.CustomIPv4 = ""
			c.DNS.CustomIPv6 = ""
		}, "custom-ip"},
		{"udp empty", func(c *Config) {
			c.DNS.Upstreams = nil
			c.DNS.DoHUpstreams = nil
		}, "upstream"},
		{"bad tls port", func(c *Config) {
			c.Web.TLS.Enabled = true
			c.Web.TLS.Port = 0
		}, "tls"},
		{"tls same port", func(c *Config) {
			c.Web.TLS.Enabled = true
			c.Web.TLS.Port = c.Web.Port
		}, "differ"},
		{"tls half config", func(c *Config) {
			c.Web.TLS.Enabled = true
			c.Web.TLS.CertFile = "/etc/x.crt"
			c.Web.TLS.KeyFile = ""
		}, "both"},
		{"dhcp bad server", func(c *Config) {
			c.DHCP.Enabled = true
			c.DHCP.ServerIP = "not-an-ip"
		}, "server_ip"},
		{"dhcp bad range", func(c *Config) {
			c.DHCP.Enabled = true
			c.DHCP.ServerIP = "192.168.1.1"
			c.DHCP.RangeStart = "192.168.1.200"
			c.DHCP.RangeEnd = "192.168.1.100"
		}, "range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			tc.mut(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tc.match)
			}
			if !strings.Contains(err.Error(), tc.match) {
				t.Errorf("error = %q, want substring %q", err, tc.match)
			}
		})
	}
}

func TestNormalizeUpstream(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"1.1.1.1", "1.1.1.1:53"},
		{"1.1.1.1:5353", "1.1.1.1:5353"},
		{"example.com", "example.com:53"},
		{"[::1]", "[::1]:53"},
		{"[::1]:5353", "[::1]:5353"},
		{"2001:db8::1", "[2001:db8::1]:53"},
		{"example.com:53", "example.com:53"},
		{"", ""},
		{"   ", ""},
	}
	for _, tc := range cases {
		if got := NormalizeUpstream(tc.in); got != tc.want {
			t.Errorf("NormalizeUpstream(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUpdateIntervalAndTimeout(t *testing.T) {
	c := Default()
	c.Lists.UpdateIntervalHours = 6
	c.DNS.UpstreamTimeoutMS = 1200
	if got := c.UpdateInterval(); got != 6*time.Hour {
		t.Errorf("UpdateInterval = %v, want 6h", got)
	}
	if got := c.UpstreamTimeout(); got != time.Millisecond*1200 {
		t.Errorf("UpstreamTimeout = %v, want 1200ms", got)
	}
}

func TestSessionTTLDefaults(t *testing.T) {
	c := Default()
	if got := c.SessionTTL(); got != 7*24*time.Hour {
		t.Errorf("SessionTTL = %v", got)
	}
	c.Web.SessionHours = 0
	if got := c.SessionTTL(); got != 7*24*time.Hour {
		t.Errorf("SessionTTL default = %v", got)
	}
}

func TestApplyDefaultsFillsMissingValues(t *testing.T) {
	// A user config with only a few keys should still produce a valid box.
	c := &Config{path: filepath.Join(t.TempDir(), "config.json")}
	// Schedules written by hand without a mode get the default the API
	// applies — they must not fail validation on load.
	c.Schedules = []schedule.Schedule{{Name: "Hand-edited", Enabled: true, Start: "22:00", End: "07:00"}}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		t.Errorf("applyDefaults produced a config that fails validation: %v", err)
	}
	if got := c.Schedules[0].Mode; got != schedule.ModeBlockAll {
		t.Errorf("schedule mode = %q, want block-all", got)
	}
}

func TestConfigJSONShape(t *testing.T) {
	// Guards against a silent rename of the json tags: the config file is the
	// one user-editable file and the installer writes it by hand.
	c := Default()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		`"data_dir"`, `"dns"`, `"web"`, `"lists"`, `"rules"`, `"devices"`,
		`"log"`, `"history"`, `"dhcp"`, `"schedules"`,
	} {
		if !strings.Contains(string(data), key) {
			t.Errorf("config JSON missing %s", key)
		}
	}
}
