package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ahardkore/adblockerpro/internal/auth"
	"github.com/ahardkore/adblockerpro/internal/blocklist"
)

// This file backs the first-run wizard. The dashboard is useless if the
// person who bought the Pi cannot get past "now change your router", so the
// API hands the UI everything it needs to walk them through it: the address
// to type into the router, a blocklist preset, a password, and a self-test
// that says in plain words whether it is actually working.

// preset is a named bundle of blocklists.
type preset struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Summary string   `json:"summary"`
	Detail  string   `json:"detail"`
	Lists   []string `json:"-"`
}

func presets() []preset {
	return []preset{
		{
			ID:      "gentle",
			Title:   "Gentle",
			Summary: "Blocks obvious ads with the lowest risk of site breakage.",
			Detail:  "Two conservative lists, roughly 150 000 domains. Pick this if someone in the house will complain loudly the first time a page misbehaves.",
			Lists: []string{
				"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
				"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
			},
		},
		{
			ID:      "balanced",
			Title:   "Balanced",
			Summary: "Ads, trackers and smart-TV telemetry. Recommended.",
			Detail:  "Five well-maintained lists, around 300 000 domains, including one aimed specifically at smart TVs and streaming sticks. This is what most people should choose.",
			Lists: []string{
				"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
				"https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
				"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
				"https://small.oisd.nl/",
				"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
			},
		},
		{
			ID:      "strict",
			Title:   "Strict",
			Summary: "Everything above plus aggressive tracking lists.",
			Detail:  "Around a million domains. Expect to allow the occasional domain by hand — the Query log makes that one click.",
			Lists: []string{
				"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
				"https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
				"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
				"https://big.oisd.nl/",
				"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
				"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
			},
		},
	}
}

func presetTitle(url string) string {
	switch {
	case strings.Contains(url, "StevenBlack"):
		return "StevenBlack unified hosts"
	case strings.Contains(url, "adguardteam"):
		return "AdGuard DNS filter"
	case strings.Contains(url, "pgl.yoyo.org"):
		return "Peter Lowe's ad servers"
	case strings.Contains(url, "small.oisd"):
		return "OISD small"
	case strings.Contains(url, "big.oisd"):
		return "OISD big"
	case strings.Contains(url, "SmartTV"):
		return "Smart-TV & CTV trackers"
	case strings.Contains(url, "hagezi"):
		return "HaGeZi Pro"
	default:
		return url
	}
}

// LANAddress guesses the address people should type into their router: the
// first private IPv4 on a real interface.
func LANAddress() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var fallback string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip.IsPrivate() {
				// Prefer wired over wireless: a Pi acting as a resolver
				// should really be on Ethernet.
				if strings.HasPrefix(iface.Name, "eth") || strings.HasPrefix(iface.Name, "en") {
					return ip.String()
				}
				if fallback == "" {
					fallback = ip.String()
				}
			}
		}
	}
	return fallback
}

// handleSetup drives the first-run wizard.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.setupState(w)
	case http.MethodPost:
		var body struct {
			Action string `json:"action"`
			Preset string `json:"preset"`
			// Password is optional; an empty one leaves the box open.
			Password string `json:"password"`
		}
		if err := decode(r, &body); err != nil {
			badRequest(w, "invalid body")
			return
		}
		switch body.Action {
		case "preset":
			if err := s.applyPreset(body.Preset); err != nil {
				badRequest(w, err.Error())
				return
			}
			// Download in the background: the wizard polls the state.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				if n, err := s.Updater.UpdateAll(ctx); err != nil {
					s.Log.Warn("preset download failed", "err", err)
				} else {
					s.Log.Info("preset lists downloaded", "domains", n)
				}
			}()
		case "password":
			if body.Password == "" {
				s.Config.Web.AdminPasswordHash = ""
			} else {
				hash, err := auth.HashPassword(body.Password)
				if err != nil {
					badRequest(w, err.Error())
					return
				}
				s.Config.Web.AdminPasswordHash = hash
				s.sessions.RevokeAll()
			}
		case "complete":
			s.Config.SetupComplete = true
		case "reopen":
			s.Config.SetupComplete = false
		default:
			badRequest(w, "unknown action")
			return
		}
		if err := s.Config.Save(); err != nil {
			s.Log.Warn("save config", "err", err)
		}
		s.setupState(w)
	default:
		badRequest(w, "unsupported method")
	}
}

func (s *Server) applyPreset(id string) error {
	for _, p := range presets() {
		if p.ID != id {
			continue
		}
		sources := make([]blocklist.Source, 0, len(p.Lists))
		for _, u := range p.Lists {
			sources = append(sources, blocklist.Source{
				ID:      blocklist.SourceID(u),
				Title:   presetTitle(u),
				URL:     u,
				Enabled: true,
			})
		}
		s.Updater.SetSources(sources)
		s.Config.Lists.Sources = sources
		return nil
	}
	return errUnknownPreset
}

func (s *Server) setupState(w http.ResponseWriter) {
	summary := s.Stats.Summary(24)
	domains := s.Engine.Domains().Len()
	lan := LANAddress()

	// "Other devices are using it" is the only honest proof the router
	// change worked: a client that is not this Pi has asked us something.
	otherClients := 0
	for _, c := range summary.TopClients {
		if c.Name != "" && c.Name != "127.0.0.1" && c.Name != "::1" && c.Name != lan {
			otherClients++
		}
	}

	ps := presets()
	out := make([]map[string]any, 0, len(ps))
	current := currentPreset(s.Config.Lists.Sources)
	for _, p := range ps {
		out = append(out, map[string]any{
			"id": p.ID, "title": p.Title, "summary": p.Summary,
			"detail": p.Detail, "lists": len(p.Lists), "active": p.ID == current,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"completed": s.Config.SetupComplete,
		"lan_ip":    lan,
		"dns_port":  s.Config.DNS.Port,
		"web_port":  s.Config.Web.Port,
		"version":   Version,
		"uptime_s":  int(s.DNS.Uptime().Seconds()),
		"steps": map[string]any{
			"lists_ready":   domains > 1000,
			"domains":       domains,
			"last_update":   s.Updater.LastRun(),
			"password_set":  s.Config.Web.AdminPasswordHash != "",
			"other_clients": otherClients,
			"queries":       summary.Total,
			"blocked":       summary.Blocked,
			"dhcp_enabled":  s.Config.DHCP.Enabled,
			"https":         s.Config.Web.TLS.Enabled,
		},
		"presets": out,
	})
}

// currentPreset names the preset whose list set matches the configuration,
// so the wizard can tick the right radio button on a second visit.
func currentPreset(sources []blocklist.Source) string {
	have := map[string]bool{}
	for _, s := range sources {
		if s.Enabled {
			have[s.URL] = true
		}
	}
	for _, p := range presets() {
		if len(p.Lists) != len(have) {
			continue
		}
		match := true
		for _, u := range p.Lists {
			if !have[u] {
				match = false
				break
			}
		}
		if match {
			return p.ID
		}
	}
	return ""
}

// handleSetupTest is the "is it actually working?" button. Every check
// returns a sentence a non-technical person can act on.
func (s *Server) handleSetupTest(w http.ResponseWriter, r *http.Request) {
	type check struct {
		ID     string `json:"id"`
		Title  string `json:"title"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
		Hint   string `json:"hint,omitempty"`
	}
	checks := []check{}

	// 1. Are the blocklists loaded?
	domains := s.Engine.Domains().Len()
	checks = append(checks, check{
		ID: "lists", Title: "Blocklists loaded", OK: domains > 1000,
		Detail: plural(domains, "domain", "domains") + " in memory",
		Hint:   "Press “Update lists” — the Pi needs internet access for this.",
	})

	// 2. Does an upstream answer?
	up := s.Pool.Status()
	healthy := 0
	for _, u := range up {
		if u.Healthy {
			healthy++
		}
	}
	checks = append(checks, check{
		ID: "upstream", Title: "Internet lookups work", OK: healthy > 0,
		Detail: plural(healthy, "upstream resolver is", "upstream resolvers are") + " healthy",
		Hint:   "Check the Pi's own network connection and the upstreams in Settings.",
	})

	// 3. Would a known ad domain be blocked?
	dec := s.Engine.Check("doubleclick.net", "")
	checks = append(checks, check{
		ID: "blocking", Title: "Ad domains are blocked", OK: dec.Blocked,
		Detail: "test lookup of doubleclick.net",
		Hint:   "Your lists may still be downloading. Wait a minute and test again.",
	})

	// 4. Has anything else on the network used it yet?
	summary := s.Stats.Summary(24)
	lan := LANAddress()
	others := map[string]bool{}
	for _, c := range summary.TopClients {
		if c.Name != "" && c.Name != "127.0.0.1" && c.Name != "::1" && c.Name != lan {
			others[c.Name] = true
		}
	}
	checks = append(checks, check{
		ID: "clients", Title: "Your devices are using it", OK: len(others) > 0,
		Detail: plural(len(others), "device has", "devices have") + " sent lookups in the last 24 hours",
		Hint:   "Set your router's DNS server to " + lan + ", then reboot one device (or turn its Wi-Fi off and on) and test again.",
	})

	allOK := true
	for _, c := range checks {
		if !c.OK {
			allOK = false
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      allOK,
		"checks":  checks,
		"lan_ip":  lan,
		"checked": time.Now(),
	})
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// errUnknownPreset is returned when the wizard asks for a preset we do not
// know about.
var errUnknownPreset = errors.New("unknown blocklist preset")
