package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ahardkore/adblockerpro/internal/blocklist"
	"github.com/ahardkore/adblockerpro/internal/config"
	"github.com/ahardkore/adblockerpro/internal/dhcp"
	"github.com/ahardkore/adblockerpro/internal/dnsmsg"
	"github.com/ahardkore/adblockerpro/internal/history"
	"github.com/ahardkore/adblockerpro/internal/schedule"
	"github.com/ahardkore/adblockerpro/internal/stats"
)

/* ------------------------------ history ------------------------------- */

func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0)
	}
	return time.Time{}
}

// handleHistory is the paginated, searchable long-term query log — the
// feature Pi-hole uses SQLite for.
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if s.History == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"records": []any{}, "total": 0, "enabled": false,
		})
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	page, err := s.History.Query(history.Filter{
		From:   parseTime(q.Get("from")),
		To:     parseTime(q.Get("to")),
		Search: q.Get("search"),
		Status: stats.Status(q.Get("status")),
		Client: q.Get("client"),
		Domain: q.Get("domain"),
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"records":  page.Records,
		"total":    page.Total,
		"offset":   page.Offset,
		"limit":    page.Limit,
		"has_more": page.HasMore,
		"enabled":  true,
		"days":     s.History.Days(),
		"bytes":    s.History.DiskUsage(),
	})
}

func (s *Server) handleHistoryDaily(w http.ResponseWriter, r *http.Request) {
	if s.History == nil {
		writeJSON(w, http.StatusOK, map[string]any{"days": []any{}})
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 {
		days = 30
	}
	since := time.Now().AddDate(0, 0, -days)
	writeJSON(w, http.StatusOK, map[string]any{
		"days":        s.History.Daily(days),
		"top_blocked": s.History.TopDomains(since, true, 15),
		"top_allowed": s.History.TopDomains(since, false, 15),
		"bytes":       s.History.DiskUsage(),
	})
}

func (s *Server) handleHistoryExport(w http.ResponseWriter, r *http.Request) {
	if s.History == nil {
		badRequest(w, "history is disabled")
		return
	}
	since := parseTime(r.URL.Query().Get("from"))
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=adblockerpro-history-%s.jsonl", time.Now().Format("2006-01-02")))
	if err := s.History.Export(w, since); err != nil {
		s.Log.Warn("history export", "err", err)
	}
}

/* ----------------------------- schedules ------------------------------ */

func (s *Server) handleSchedules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		now := time.Now()
		active := s.Schedules.Active("", now)
		next, hasNext := s.Schedules.NextChange("", now)
		resp := map[string]any{
			"schedules": s.Schedules.All(),
			"active":    active,
			"now":       now.Format(time.RFC3339),
		}
		if hasNext {
			resp["next_change"] = next.Format(time.RFC3339)
		}
		writeJSON(w, http.StatusOK, resp)

	case http.MethodPost:
		var sc schedule.Schedule
		if err := decode(r, &sc); err != nil {
			badRequest(w, "invalid body")
			return
		}
		if sc.Mode == "" {
			sc.Mode = schedule.ModeBlockAll
		}
		if err := schedule.Validate(sc); err != nil {
			badRequest(w, err.Error())
			return
		}
		if sc.ID == "" {
			sc.ID = fmt.Sprintf("s%d", time.Now().UnixNano()/1e6)
		}
		list := s.Config.Schedules
		replaced := false
		for i := range list {
			if list[i].ID == sc.ID {
				list[i] = sc
				replaced = true
				break
			}
		}
		if !replaced {
			list = append(list, sc)
		}
		s.Config.Schedules = list
		s.Schedules.Set(list)
		s.saveConfig()
		s.Cache.Flush()
		writeJSON(w, http.StatusOK, sc)

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		list := s.Config.Schedules
		for i := range list {
			if list[i].ID == id {
				s.Config.Schedules = append(list[:i], list[i+1:]...)
				s.Schedules.Set(s.Config.Schedules)
				s.saveConfig()
				s.Cache.Flush()
				writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
				return
			}
		}
		badRequest(w, "schedule not found")
	default:
		badRequest(w, "unsupported method")
	}
}

/* -------------------------------- DHCP -------------------------------- */

func (s *Server) handleDHCP(w http.ResponseWriter, r *http.Request) {
	if s.DHCP == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "leases": []any{}})
		return
	}
	switch r.Method {
	case http.MethodGet:
		leases := s.DHCP.Leases()
		writeJSON(w, http.StatusOK, map[string]any{
			"config":  s.DHCP.Config(),
			"leases":  leases,
			"enabled": s.DHCP.Enabled(),
			"count":   len(leases),
		})
	case http.MethodPost, http.MethodPut:
		var cfg dhcp.Config
		if err := decode(r, &cfg); err != nil {
			badRequest(w, "invalid body")
			return
		}
		// Reservations are managed through their own endpoint.
		cfg.Reservations = s.Config.DHCP.Reservations
		old := s.Config.DHCP
		s.Config.DHCP = cfg
		if err := s.Config.Validate(); err != nil {
			s.Config.DHCP = old
			badRequest(w, err.Error())
			return
		}
		s.DHCP.SetConfig(cfg)
		s.saveConfig()
		msg := map[string]any{"status": "ok", "config": s.DHCP.Config()}
		if cfg.Enabled != old.Enabled {
			msg["restart_required"] = true
			msg["note"] = "restart adblockerpro to start or stop the DHCP listener"
		}
		writeJSON(w, http.StatusOK, msg)
	default:
		badRequest(w, "unsupported method")
	}
}

func (s *Server) handleDHCPReservation(w http.ResponseWriter, r *http.Request) {
	if s.DHCP == nil {
		badRequest(w, "dhcp is not available")
		return
	}
	switch r.Method {
	case http.MethodPost:
		var res dhcp.Reservation
		if err := decode(r, &res); err != nil {
			badRequest(w, "invalid body")
			return
		}
		if _, err := net.ParseMAC(strings.TrimSpace(res.MAC)); err != nil {
			badRequest(w, "mac must look like aa:bb:cc:dd:ee:ff")
			return
		}
		if net.ParseIP(res.IP) == nil {
			badRequest(w, "ip must be an IPv4 address")
			return
		}
		list := s.Config.DHCP.Reservations
		replaced := false
		for i := range list {
			if strings.EqualFold(list[i].MAC, res.MAC) {
				list[i] = res
				replaced = true
				break
			}
		}
		if !replaced {
			list = append(list, res)
		}
		s.Config.DHCP.Reservations = list
		s.DHCP.SetConfig(s.Config.DHCP)
		s.saveConfig()
		writeJSON(w, http.StatusOK, res)
	case http.MethodDelete:
		mac := r.URL.Query().Get("mac")
		list := s.Config.DHCP.Reservations
		for i := range list {
			if strings.EqualFold(list[i].MAC, mac) {
				s.Config.DHCP.Reservations = append(list[:i], list[i+1:]...)
				s.DHCP.SetConfig(s.Config.DHCP)
				s.saveConfig()
				writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
				return
			}
		}
		badRequest(w, "reservation not found")
	default:
		badRequest(w, "unsupported method")
	}
}

/* ------------------------- DNS-over-HTTPS server ----------------------- */

// handleDoH serves RFC 8484 so phones and laptops can use this resolver from
// anywhere (behind a reverse proxy with TLS) and so Android's "Private DNS"
// has something to talk to. Pi-hole cannot do this without a sidecar.
func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	if !s.Config.DNS.DoHServer {
		http.Error(w, "DoH server is disabled", http.StatusNotFound)
		return
	}
	var query []byte
	switch r.Method {
	case http.MethodGet:
		raw := r.URL.Query().Get("dns")
		if raw == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(raw, "="))
		if err != nil {
			http.Error(w, "bad base64url", http.StatusBadRequest)
			return
		}
		query = decoded
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "application/dns-message") {
			http.Error(w, "expected application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, dnsmsg.MaxMessageSize))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		query = body
	default:
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
		return
	}

	clientIP := net.ParseIP(clientHost(r))
	if clientIP == nil {
		clientIP = net.IPv4(127, 0, 0, 1)
	}
	resp := s.DNS.Handle(r.Context(), query, clientIP, "doh")
	if len(resp) == 0 {
		http.Error(w, "no answer", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(resp)))
	_, _ = w.Write(resp)
}

func clientHost(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if i := strings.IndexByte(fwd, ','); i > 0 {
			return strings.TrimSpace(fwd[:i])
		}
		return strings.TrimSpace(fwd)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

/* ------------------------------ metrics -------------------------------- */

// handleMetrics exposes Prometheus text format, so the Pi can feed Grafana
// without a third-party exporter.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	sum := s.Stats.Summary(1)
	cache := s.Cache.Stats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var b strings.Builder
	metric := func(name, help, typ string, value float64, labels ...string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		if len(labels) == 0 {
			fmt.Fprintf(&b, "%s %g\n", name, value)
			return
		}
		fmt.Fprintf(&b, "%s{%s} %g\n", name, strings.Join(labels, ","), value)
	}

	metric("adblockerpro_queries_total", "Total DNS queries answered", "counter", float64(sum.Total))
	metric("adblockerpro_blocked_total", "Queries sinkholed", "counter", float64(sum.Blocked))
	metric("adblockerpro_cached_total", "Queries answered from cache", "counter", float64(sum.Cached))
	metric("adblockerpro_errors_total", "Queries that failed", "counter", float64(sum.Errors))
	metric("adblockerpro_dnssec_validated_total", "Answers with the AD bit set", "counter", float64(sum.Validated))
	metric("adblockerpro_block_ratio", "Share of queries blocked", "gauge", sum.BlockPercent/100)
	metric("adblockerpro_response_ms", "Mean response time in milliseconds", "gauge", sum.AvgMS)
	metric("adblockerpro_clients", "Distinct clients seen", "gauge", float64(sum.Clients))
	metric("adblockerpro_blocklist_domains", "Domains on the blocklists", "gauge", float64(s.Engine.Domains().Len()))
	metric("adblockerpro_cache_entries", "Entries in the DNS cache", "gauge", float64(cache.Entries))
	metric("adblockerpro_cache_hit_ratio", "Cache hit ratio", "gauge", cache.HitRate/100)
	metric("adblockerpro_uptime_seconds", "Seconds since the resolver started", "gauge", s.DNS.Uptime().Seconds())

	fmt.Fprintf(&b, "# HELP adblockerpro_upstream_queries_total Queries sent to each upstream\n# TYPE adblockerpro_upstream_queries_total counter\n")
	for _, u := range s.Pool.Status() {
		fmt.Fprintf(&b, "adblockerpro_upstream_queries_total{upstream=%q,healthy=%q} %d\n",
			u.Name, strconv.FormatBool(u.Healthy), u.Queries)
	}
	if s.DHCP != nil && s.DHCP.Enabled() {
		metric("adblockerpro_dhcp_leases", "Active DHCP leases", "gauge", float64(len(s.DHCP.Leases())))
	}
	if s.History != nil {
		metric("adblockerpro_history_bytes", "History on disk", "gauge", float64(s.History.DiskUsage()))
	}
	_, _ = io.WriteString(w, b.String())
}

/* --------------------------- backup / restore -------------------------- */

// backupDocument is the Teleporter equivalent: everything needed to rebuild
// this box, in one JSON file.
type backupDocument struct {
	Version   string              `json:"version"`
	Exported  time.Time           `json:"exported"`
	Config    *config.Config      `json:"config"`
	Rules     []blocklist.Rule    `json:"rules"`
	Schedules []schedule.Schedule `json:"schedules"`
	Devices   []config.Device     `json:"devices"`
	Leases    []dhcp.Lease        `json:"dhcp_leases,omitempty"`
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	doc := backupDocument{
		Version:   Version,
		Exported:  time.Now(),
		Config:    s.Config,
		Rules:     s.Engine.Rules(),
		Schedules: s.Schedules.All(),
		Devices:   s.Config.Devices,
	}
	if s.DHCP != nil {
		doc.Leases = s.DHCP.Leases()
	}
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=adblockerpro-backup-%s.json", time.Now().Format("2006-01-02")))
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		badRequest(w, "POST a backup document")
		return
	}
	var doc backupDocument
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<20)).Decode(&doc); err != nil {
		badRequest(w, "invalid backup file: "+err.Error())
		return
	}
	if doc.Config == nil {
		badRequest(w, "backup has no config section")
		return
	}
	incoming := doc.Config
	// Never let a backup move the listeners out from under the running
	// process, or lock the operator out.
	incoming.DNS.Listen, incoming.DNS.Port = s.Config.DNS.Listen, s.Config.DNS.Port
	incoming.Web = s.Config.Web
	incoming.DataDir = s.Config.DataDir
	if err := incoming.Validate(); err != nil {
		badRequest(w, err.Error())
		return
	}

	s.Config.DNS = incoming.DNS
	s.Config.Lists = incoming.Lists
	s.Config.Rules = incoming.Rules
	s.Config.Devices = incoming.Devices
	s.Config.Schedules = incoming.Schedules
	s.Config.DHCP = incoming.DHCP
	s.Config.Log = incoming.Log
	s.Config.History = incoming.History

	s.Engine.SetRules(s.Config.Rules)
	s.Devices.Set(s.Config.Devices)
	s.Schedules.Set(s.Config.Schedules)
	s.Updater.SetSources(s.Config.Lists.Sources)
	if s.DHCP != nil {
		s.DHCP.SetConfig(s.Config.DHCP)
	}
	if s.Reload != nil {
		if err := s.Reload(s.Config); err != nil {
			badRequest(w, err.Error())
			return
		}
	}
	s.saveConfig()
	s.Updater.LoadFromCache()

	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "restored",
		"rules":     len(s.Config.Rules),
		"devices":   len(s.Config.Devices),
		"schedules": len(s.Config.Schedules),
		"lists":     len(s.Config.Lists.Sources),
	})
}

/* -------------------------------- misc --------------------------------- */

func (s *Server) saveConfig() {
	if err := s.Config.Save(); err != nil {
		s.Log.Warn("save config", "err", err)
	}
}

// handleDevicesSuggest offers names the resolver has learned from DHCP for
// clients that are not named yet — one click to adopt them.
func (s *Server) handleDevicesSuggest(w http.ResponseWriter, r *http.Request) {
	type suggestion struct {
		IP       string `json:"ip"`
		MAC      string `json:"mac,omitempty"`
		Name     string `json:"name"`
		Vendor   string `json:"vendor,omitempty"`
		Queries  int64  `json:"queries"`
		Blocked  int64  `json:"blocked"`
		FromDHCP bool   `json:"from_dhcp"`
	}
	known := map[string]bool{}
	for _, d := range s.Config.Devices {
		known[strings.ToLower(d.Match)] = true
	}
	byIP := map[string]suggestion{}
	if s.DHCP != nil {
		for _, l := range s.DHCP.Leases() {
			if l.IP == "" || known[strings.ToLower(l.IP)] {
				continue
			}
			name := l.Hostname
			if name == "" {
				name = l.Vendor
			}
			if name == "" {
				continue
			}
			byIP[l.IP] = suggestion{IP: l.IP, MAC: l.MAC, Name: name, Vendor: l.Vendor, FromDHCP: true}
		}
	}
	for _, seen := range s.Devices.Seen() {
		if known[strings.ToLower(seen.IP)] {
			continue
		}
		sg := byIP[seen.IP]
		sg.IP = seen.IP
		sg.Queries, sg.Blocked = seen.Queries, seen.Blocked
		if sg.Name == "" {
			sg.Name = seen.Name
		}
		byIP[seen.IP] = sg
	}
	out := make([]suggestion, 0, len(byIP))
	for _, v := range byIP {
		if v.Name == "" && v.Queries == 0 {
			continue
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Queries > out[j].Queries })
	writeJSON(w, http.StatusOK, map[string]any{"suggestions": out})
}
