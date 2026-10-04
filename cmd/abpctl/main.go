// Command abpctl is the terminal companion to adblockerpro: a small client
// for the local API so you can check on the box over SSH without opening a
// browser.
//
//	abpctl status             # one-screen overview
//	abpctl top [-n 15]        # busiest and most-blocked domains
//	abpctl tail [-f]          # live query log
//	abpctl device 192.168.1.5 # per-device drill-down
//	abpctl pause 15m          # stop filtering for a while
//	abpctl resume
//	abpctl flush              # empty the DNS cache
//	abpctl check doubleclick.net
//	abpctl backup [file.json]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var version = "dev"

func main() {
	var (
		addr    = flag.String("addr", envOr("ABP_ADDR", "http://127.0.0.1:8080"), "dashboard base URL")
		token   = flag.String("token", os.Getenv("ABP_TOKEN"), "admin token (or ABP_TOKEN)")
		count   = flag.Int("n", 10, "number of rows for top/tail")
		follow  = flag.Bool("f", false, "follow the query log (tail)")
		days    = flag.Int("days", 7, "window in days for device reports")
		showVer = flag.Bool("version", false, "print the version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println("abpctl", version)
		return
	}
	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	c := &client{base: strings.TrimRight(*addr, "/"), token: *token}
	var err error
	switch args[0] {
	case "status":
		err = c.status()
	case "top":
		err = c.top(*count)
	case "tail":
		err = c.tail(*count, *follow)
	case "device":
		if len(args) < 2 {
			err = fmt.Errorf("usage: abpctl device <ip>")
		} else {
			err = c.device(args[1], *days)
		}
	case "pause":
		d := "15m"
		if len(args) > 1 {
			d = args[1]
		}
		err = c.pause(d)
	case "resume":
		err = c.resume()
	case "flush":
		err = c.flush()
	case "check":
		if len(args) < 2 {
			err = fmt.Errorf("usage: abpctl check <domain>")
		} else {
			err = c.check(args[1])
		}
	case "backup":
		out := ""
		if len(args) > 1 {
			out = args[1]
		}
		err = c.backup(out)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "abpctl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `abpctl — command line client for adblockerpro

Usage: abpctl [flags] <command> [args]

Commands:
  status             overview: queries, block rate, cache, upstreams
  top [-n 15]        busiest and most-blocked domains
  tail [-n 20] [-f]  recent queries, optionally following
  device <ip>        per-device drill-down (needs history enabled)
  pause [15m]        pause filtering everywhere
  resume             resume filtering
  flush              empty the DNS cache
  check <domain>     show whether a domain would be blocked, and why
  backup [file]      write a configuration backup (default: stdout)

Flags:
`)
	flag.PrintDefaults()
}

/* ------------------------------- client -------------------------------- */

type client struct {
	base  string
	token string
}

func (c *client) do(method, path string, body []byte, out any) error {
	req, err := http.NewRequest(method, c.base+path, bytesReader(body))
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("X-API-Key", c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", c.base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("unauthorized — pass -token or set ABP_TOKEN")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *client) get(path string, out any) error { return c.do(http.MethodGet, path, nil, out) }

func (c *client) post(path string, body any, out any) error {
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	return c.do(http.MethodPost, path, raw, out)
}

/* ------------------------------ commands ------------------------------- */

type summary struct {
	Summary struct {
		Total        int64   `json:"total"`
		Blocked      int64   `json:"blocked"`
		Cached       int64   `json:"cached"`
		Errors       int64   `json:"errors"`
		Validated    int64   `json:"validated"`
		BlockPercent float64 `json:"block_percent"`
		AvgMS        float64 `json:"avg_ms"`
		Clients      int     `json:"clients"`
		TopAllowed   []item  `json:"top_allowed"`
		TopBlocked   []item  `json:"top_blocked"`
		TopClients   []item  `json:"top_clients"`
	} `json:"summary"`
	Cache struct {
		Entries  int     `json:"entries"`
		HitRatio float64 `json:"hit_ratio"`
	} `json:"cache"`
	Upstreams []struct {
		Name    string `json:"name"`
		Healthy bool   `json:"healthy"`
		Queries uint64 `json:"queries"`
	} `json:"upstreams"`
	Lists struct {
		Domains int `json:"domains"`
		Sources int `json:"sources"`
	} `json:"lists"`
	Status struct {
		Version     string    `json:"version"`
		UptimeS     int       `json:"uptime_s"`
		DNSAddr     string    `json:"dns_addr"`
		Paused      bool      `json:"paused"`
		PausedUntil time.Time `json:"paused_until"`
	} `json:"status"`
}

type item struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

func (c *client) status() error {
	var s summary
	if err := c.get("/api/summary?hours=24", &s); err != nil {
		return err
	}
	fmt.Printf("adblockerpro %s — up %s, DNS on %s\n",
		s.Status.Version, human(time.Duration(s.Status.UptimeS)*time.Second), s.Status.DNSAddr)
	if s.Status.Paused {
		fmt.Printf("FILTERING PAUSED until %s\n", s.Status.PausedUntil.Local().Format("15:04:05"))
	}
	fmt.Printf("\nLast 24 hours\n")
	fmt.Printf("  queries   %d\n", s.Summary.Total)
	fmt.Printf("  blocked   %d (%.1f%%)\n", s.Summary.Blocked, s.Summary.BlockPercent)
	fmt.Printf("  cached    %d\n", s.Summary.Cached)
	fmt.Printf("  errors    %d\n", s.Summary.Errors)
	fmt.Printf("  clients   %d\n", s.Summary.Clients)
	fmt.Printf("  latency   %.1f ms average\n", s.Summary.AvgMS)
	fmt.Printf("\nBlocklist  %d domains from %d sources\n", s.Lists.Domains, s.Lists.Sources)
	fmt.Printf("Cache      %d entries, %.1f%% hit rate\n", s.Cache.Entries, s.Cache.HitRatio)
	fmt.Printf("Upstreams\n")
	for _, u := range s.Upstreams {
		state := "up"
		if !u.Healthy {
			state = "DOWN"
		}
		fmt.Printf("  %-40s %-4s %d queries\n", u.Name, state, u.Queries)
	}
	return nil
}

func (c *client) top(n int) error {
	var s summary
	if err := c.get("/api/summary?hours=24", &s); err != nil {
		return err
	}
	printItems("Most queried", s.Summary.TopAllowed, n)
	printItems("Most blocked", s.Summary.TopBlocked, n)
	printItems("Busiest clients", s.Summary.TopClients, n)
	return nil
}

func printItems(title string, items []item, n int) {
	fmt.Printf("\n%s\n", title)
	if len(items) == 0 {
		fmt.Println("  (nothing yet)")
		return
	}
	for i, it := range items {
		if i >= n {
			break
		}
		fmt.Printf("  %6d  %s\n", it.Count, it.Name)
	}
}

type queryPage struct {
	Queries []struct {
		Time   time.Time `json:"time"`
		Client string    `json:"client"`
		Device string    `json:"device"`
		Domain string    `json:"domain"`
		Type   string    `json:"type"`
		Status string    `json:"status"`
		Rule   string    `json:"rule"`
		MS     float64   `json:"ms"`
	} `json:"queries"`
}

func (c *client) tail(n int, follow bool) error {
	seen := map[string]bool{}
	for {
		var p queryPage
		if err := c.get(fmt.Sprintf("/api/queries?limit=%d", n), &p); err != nil {
			return err
		}
		// The API returns newest first; print oldest first so the log reads
		// downwards like tail -f.
		for i := len(p.Queries) - 1; i >= 0; i-- {
			e := p.Queries[i]
			key := fmt.Sprintf("%d|%s|%s", e.Time.UnixNano(), e.Client, e.Domain)
			if seen[key] {
				continue
			}
			seen[key] = true
			who := e.Client
			if e.Device != "" {
				who = e.Device
			}
			fmt.Printf("%s  %-18s %-6s %-9s %6.1fms  %s%s\n",
				e.Time.Local().Format("15:04:05"), who, e.Type, e.Status, e.MS, e.Domain,
				suffix(e.Rule))
		}
		if !follow {
			return nil
		}
		if len(seen) > 5000 {
			seen = map[string]bool{}
		}
		time.Sleep(2 * time.Second)
	}
}

func suffix(rule string) string {
	if rule == "" {
		return ""
	}
	return "  [" + rule + "]"
}

func (c *client) device(ip string, days int) error {
	var resp struct {
		Enabled bool   `json:"enabled"`
		Error   string `json:"error"`
		Report  struct {
			Client     string    `json:"client"`
			Device     string    `json:"device"`
			Total      int64     `json:"total"`
			Blocked    int64     `json:"blocked"`
			Cached     int64     `json:"cached"`
			BlockRatio float64   `json:"block_ratio"`
			AvgMS      float64   `json:"avg_ms"`
			FirstSeen  time.Time `json:"first_seen"`
			LastSeen   time.Time `json:"last_seen"`
			TopDomains []item    `json:"top_domains"`
			TopBlocked []item    `json:"top_blocked"`
		} `json:"report"`
	}
	path := fmt.Sprintf("/api/devices/report?client=%s&days=%d", url.QueryEscape(ip), days)
	if err := c.get(path, &resp); err != nil {
		return err
	}
	if !resp.Enabled {
		return fmt.Errorf("%s", resp.Error)
	}
	r := resp.Report
	name := r.Device
	if name == "" {
		name = "(unnamed)"
	}
	fmt.Printf("%s — %s, last %d days\n", r.Client, name, days)
	if r.Total == 0 {
		fmt.Println("  no queries recorded in this window")
		return nil
	}
	fmt.Printf("  queries %d, blocked %d (%.1f%%), cached %d, %.1f ms average\n",
		r.Total, r.Blocked, r.BlockRatio, r.Cached, r.AvgMS)
	fmt.Printf("  seen from %s to %s\n",
		r.FirstSeen.Local().Format("Jan 2 15:04"), r.LastSeen.Local().Format("Jan 2 15:04"))
	printItems("Most queried", r.TopDomains, 10)
	printItems("Most blocked", r.TopBlocked, 10)
	return nil
}

func (c *client) pause(dur string) error {
	d, err := time.ParseDuration(dur)
	if err != nil || d <= 0 {
		return fmt.Errorf("%q is not a duration like 15m or 2h", dur)
	}
	minutes := int(d.Minutes())
	if minutes < 1 {
		minutes = 1
	}
	if err := c.post("/api/control", map[string]any{"action": "pause", "minutes": minutes}, nil); err != nil {
		return err
	}
	fmt.Printf("filtering paused for %s\n", dur)
	return nil
}

func (c *client) resume() error {
	if err := c.post("/api/control", map[string]any{"action": "resume"}, nil); err != nil {
		return err
	}
	fmt.Println("filtering resumed")
	return nil
}

func (c *client) flush() error {
	if err := c.post("/api/control", map[string]any{"action": "flush-cache"}, nil); err != nil {
		return err
	}
	fmt.Println("cache flushed")
	return nil
}

func (c *client) check(domain string) error {
	var resp struct {
		Domain   string `json:"domain"`
		Sinkhole string `json:"sinkhole"`
		Decision struct {
			Blocked       bool   `json:"blocked"`
			Rule          string `json:"rule"`
			Source        string `json:"source"`
			MatchedDomain string `json:"matched_domain"`
		} `json:"decision"`
	}
	if err := c.get("/api/check?domain="+url.QueryEscape(domain), &resp); err != nil {
		return err
	}
	verdict := "allowed"
	if resp.Decision.Blocked {
		verdict = "BLOCKED (" + resp.Sinkhole + ")"
	}
	fmt.Printf("%s: %s", resp.Domain, verdict)
	if resp.Decision.MatchedDomain != "" && resp.Decision.MatchedDomain != resp.Domain {
		fmt.Printf(" via %s", resp.Decision.MatchedDomain)
	}
	if resp.Decision.Rule != "" {
		fmt.Printf(" rule=%s", resp.Decision.Rule)
	}
	if resp.Decision.Source != "" {
		fmt.Printf(" source=%q", resp.Decision.Source)
	}
	fmt.Println()
	return nil
}

func (c *client) backup(path string) error {
	var raw json.RawMessage
	if err := c.get("/api/backup", &raw); err != nil {
		return err
	}
	pretty, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		pretty = raw
	}
	if path == "" {
		fmt.Println(string(pretty))
		return nil
	}
	if err := os.WriteFile(path, append(pretty, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Printf("backup written to %s (%d bytes)\n", path, len(pretty))
	return nil
}

/* ------------------------------- helpers ------------------------------- */

func bytesReader(b []byte) *strings.Reader {
	if b == nil {
		return strings.NewReader("")
	}
	return strings.NewReader(string(b))
}

func human(d time.Duration) string {
	d = d.Round(time.Minute)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
