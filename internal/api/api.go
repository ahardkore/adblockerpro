// Package api exposes the REST API and serves the dashboard.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ahardkore/adblockerpro/internal/blocklist"
	"github.com/ahardkore/adblockerpro/internal/config"
	"github.com/ahardkore/adblockerpro/internal/devices"
	"github.com/ahardkore/adblockerpro/internal/dhcp"
	"github.com/ahardkore/adblockerpro/internal/dnsmsg"
	"github.com/ahardkore/adblockerpro/internal/history"
	"github.com/ahardkore/adblockerpro/internal/resolver"
	"github.com/ahardkore/adblockerpro/internal/schedule"
	"github.com/ahardkore/adblockerpro/internal/server"
	"github.com/ahardkore/adblockerpro/internal/stats"
	"github.com/ahardkore/adblockerpro/web"
)

// Version is stamped at build time.
var Version = "dev"

// Deps are the collaborators the API needs.
type Deps struct {
	Config  *config.Config
	Engine  *blocklist.Engine
	Updater *blocklist.Updater
	Cache   *resolver.Cache
	Pool    *resolver.Pool
	Devices *devices.Registry
	Stats   *stats.Collector
	DNS     *server.DNS
	// History is the long-term query store (nil when disabled).
	History *history.Store
	// Schedules holds the time-based filtering windows.
	Schedules *schedule.Engine
	// DHCP is the optional DHCPv4 server (nil when not built in).
	DHCP *dhcp.Server
	Log  *slog.Logger
	// Reload re-applies configuration to the running resolver.
	Reload func(*config.Config) error
}

// Server is the HTTP server for the dashboard and API.
type Server struct {
	Deps
	mux  *http.ServeMux
	http *http.Server
}

// New wires up the routes.
func New(d Deps) *Server {
	s := &Server{Deps: d, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	// Unauthenticated: health and login.
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/login", s.handleLogin)

	// DNS-over-HTTPS is authenticated by nothing on purpose: it is a
	// resolver endpoint, protected by the same client checks as UDP DNS.
	s.mux.HandleFunc("/dns-query", s.handleDoH)
	s.mux.HandleFunc("/metrics", s.handleMetrics)

	api := map[string]http.HandlerFunc{
		"/api/summary":          s.handleSummary,
		"/api/history":          s.handleHistory,
		"/api/history/daily":    s.handleHistoryDaily,
		"/api/history/export":   s.handleHistoryExport,
		"/api/schedules":        s.handleSchedules,
		"/api/dhcp":             s.handleDHCP,
		"/api/dhcp/reservation": s.handleDHCPReservation,
		"/api/devices/suggest":  s.handleDevicesSuggest,
		"/api/backup":           s.handleBackup,
		"/api/restore":          s.handleRestore,
		"/api/queries":          s.handleQueries,
		"/api/lists":            s.handleLists,
		"/api/lists/update":     s.handleListsUpdate,
		"/api/lists/toggle":     s.handleListsToggle,
		"/api/rules":            s.handleRules,
		"/api/devices":          s.handleDevices,
		"/api/settings":         s.handleSettings,
		"/api/control":          s.handleControl,
		"/api/check":            s.handleCheck,
	}
	for path, h := range api {
		s.mux.Handle(path, s.auth(h))
	}

	static, err := fs.Sub(web.FS, "static")
	if err != nil {
		panic(fmt.Sprintf("embed static: %v", err))
	}
	fileServer := http.FileServer(http.FS(static))
	s.mux.Handle("/", noCacheHTML(fileServer))
}

func noCacheHTML(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") || strings.HasSuffix(r.URL.Path, ".html") {
			w.Header().Set("Cache-Control", "no-store")
		}
		h.ServeHTTP(w, r)
	})
}

// ListenAndServe runs the HTTP server until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	s.http = &http.Server{
		Addr:              addr,
		Handler:           s.logRequests(s.mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		s.Log.Info("dashboard listening", "addr", addr)
		err := s.http.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.http.Shutdown(shutdownCtx)
	}
}

func (s *Server) logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != http.MethodGet {
			s.Log.Debug("api", "method", r.Method, "path", r.URL.Path,
				"ms", time.Since(start).Milliseconds())
		}
	})
}

// auth enforces the admin token when one is configured.
func (s *Server) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := s.Config.Web.AdminToken
		if token == "" {
			h(w, r)
			return
		}
		provided := r.Header.Get("X-API-Key")
		if provided == "" {
			if b := r.Header.Get("Authorization"); strings.HasPrefix(b, "Bearer ") {
				provided = strings.TrimPrefix(b, "Bearer ")
			}
		}
		if provided == "" {
			if c, err := r.Cookie("abp_token"); err == nil {
				provided = c.Value
			}
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		h(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func badRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"version":  Version,
		"uptime_s": int(s.DNS.Uptime().Seconds()),
		"domains":  s.Engine.Domains().Len(),
		"auth":     s.Config.Web.AdminToken != "",
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		badRequest(w, "POST required")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := decode(r, &body); err != nil {
		badRequest(w, "invalid body")
		return
	}
	token := s.Config.Web.AdminToken
	if token == "" || subtle.ConstantTimeCompare([]byte(body.Token), []byte(token)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "abp_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((30 * 24 * time.Hour).Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours == 0 {
		hours = 24
	}
	pausedUntil := s.Devices.PausedUntil()
	resp := map[string]any{
		"summary":   s.Stats.Summary(hours),
		"cache":     s.Cache.Stats(),
		"upstreams": s.Pool.Status(),
		"lists": map[string]any{
			"domains":     s.Engine.Domains().Len(),
			"sources":     len(s.Updater.Sources()),
			"last_update": s.Updater.LastRun(),
		},
		"schedules": map[string]any{
			"count":  len(s.Schedules.All()),
			"active": s.Schedules.Active("", time.Now()),
		},
		"dhcp":    s.dhcpSummary(),
		"history": s.historySummary(),
		"status": map[string]any{
			"version":      Version,
			"uptime_s":     int(s.DNS.Uptime().Seconds()),
			"dns_addr":     s.DNS.Addr(),
			"paused":       !pausedUntil.IsZero(),
			"paused_until": pausedUntil,
			"sinkhole":     s.Config.DNS.Sinkhole,
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) dhcpSummary() map[string]any {
	if s.DHCP == nil {
		return map[string]any{"enabled": false, "leases": 0}
	}
	active := 0
	for _, l := range s.DHCP.Leases() {
		if l.Active() {
			active++
		}
	}
	return map[string]any{"enabled": s.DHCP.Enabled(), "leases": active}
}

func (s *Server) historySummary() map[string]any {
	if s.History == nil {
		return map[string]any{"enabled": false}
	}
	return map[string]any{
		"enabled": true,
		"days":    len(s.History.Days()),
		"bytes":   s.History.DiskUsage(),
		"writes":  s.History.Writes(),
	}
}

func (s *Server) handleQueries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	entries := s.Stats.Recent(stats.QueryFilter{
		Limit:  limit,
		Search: q.Get("search"),
		Status: stats.Status(q.Get("status")),
		Client: q.Get("client"),
	})
	writeJSON(w, http.StatusOK, map[string]any{"queries": entries, "count": len(entries)})
}

func (s *Server) handleLists(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"sources": s.Updater.Sources(),
			"domains": s.Engine.Domains().Len(),
		})
	case http.MethodPost:
		var body struct {
			Title string `json:"title"`
			URL   string `json:"url"`
		}
		if err := decode(r, &body); err != nil || strings.TrimSpace(body.URL) == "" {
			badRequest(w, "url is required")
			return
		}
		src := s.Updater.AddSource(strings.TrimSpace(body.Title), strings.TrimSpace(body.URL))
		s.persistSources()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if _, err := s.Updater.UpdateAll(ctx); err != nil {
				s.Log.Warn("list update after add failed", "err", err)
			}
		}()
		writeJSON(w, http.StatusOK, src)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if !s.Updater.RemoveSource(id) {
			badRequest(w, "unknown list id")
			return
		}
		s.persistSources()
		s.Updater.LoadFromCache()
		writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
	default:
		badRequest(w, "unsupported method")
	}
}

func (s *Server) handleListsToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := decode(r, &body); err != nil || body.ID == "" {
		badRequest(w, "id is required")
		return
	}
	if !s.Updater.ToggleSource(body.ID, body.Enabled) {
		badRequest(w, "unknown list id")
		return
	}
	s.persistSources()
	n := s.Updater.LoadFromCache()
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "domains": n})
}

func (s *Server) handleListsUpdate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	n, err := s.Updater.UpdateAll(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "domains": n})
		return
	}
	s.persistSources()
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "domains": n})
}

func (s *Server) persistSources() {
	s.Config.Lists.Sources = s.Updater.Sources()
	if err := s.Config.Save(); err != nil {
		s.Log.Warn("save config", "err", err)
	}
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"rules": s.Engine.Rules()})
	case http.MethodPost:
		var rule blocklist.Rule
		if err := decode(r, &rule); err != nil {
			badRequest(w, "invalid body")
			return
		}
		rule.Pattern = strings.TrimSpace(strings.ToLower(rule.Pattern))
		if rule.Pattern == "" {
			badRequest(w, "pattern is required")
			return
		}
		if rule.Action != blocklist.ActionAllow && rule.Action != blocklist.ActionBlock {
			rule.Action = blocklist.ActionBlock
		}
		if rule.Created == "" {
			rule.Created = time.Now().Format(time.RFC3339)
		}
		s.Engine.AddRule(rule)
		s.Config.Rules = s.Engine.Rules()
		if err := s.Config.Save(); err != nil {
			s.Log.Warn("save config", "err", err)
		}
		s.Cache.Flush()
		writeJSON(w, http.StatusOK, rule)
	case http.MethodDelete:
		q := r.URL.Query()
		if !s.Engine.RemoveRule(q.Get("pattern"), blocklist.Action(q.Get("action")), q.Get("group")) {
			badRequest(w, "rule not found")
			return
		}
		s.Config.Rules = s.Engine.Rules()
		if err := s.Config.Save(); err != nil {
			s.Log.Warn("save config", "err", err)
		}
		s.Cache.Flush()
		writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
	default:
		badRequest(w, "unsupported method")
	}
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"devices": s.Config.Devices,
			"seen":    s.Devices.Seen(),
		})
	case http.MethodPost:
		var dev config.Device
		if err := decode(r, &dev); err != nil || strings.TrimSpace(dev.Match) == "" {
			badRequest(w, "match (ip or cidr) is required")
			return
		}
		dev.Match = strings.TrimSpace(dev.Match)
		replaced := false
		for i := range s.Config.Devices {
			if strings.EqualFold(s.Config.Devices[i].Match, dev.Match) {
				s.Config.Devices[i] = dev
				replaced = true
				break
			}
		}
		if !replaced {
			s.Config.Devices = append(s.Config.Devices, dev)
		}
		s.Devices.Set(s.Config.Devices)
		if err := s.Config.Save(); err != nil {
			s.Log.Warn("save config", "err", err)
		}
		writeJSON(w, http.StatusOK, dev)
	case http.MethodDelete:
		match := r.URL.Query().Get("match")
		for i := range s.Config.Devices {
			if strings.EqualFold(s.Config.Devices[i].Match, match) {
				s.Config.Devices = append(s.Config.Devices[:i], s.Config.Devices[i+1:]...)
				s.Devices.Set(s.Config.Devices)
				if err := s.Config.Save(); err != nil {
					s.Log.Warn("save config", "err", err)
				}
				writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
				return
			}
		}
		badRequest(w, "device not found")
	default:
		badRequest(w, "unsupported method")
	}
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"dns":   s.Config.DNS,
			"lists": map[string]any{"update_interval_hours": s.Config.Lists.UpdateIntervalHours},
			"log":   s.Config.Log,
			"path":  s.Config.Path(),
		})
	case http.MethodPut, http.MethodPost:
		var body struct {
			DNS                 *config.DNSConfig `json:"dns"`
			UpdateIntervalHours *int              `json:"update_interval_hours"`
		}
		if err := decode(r, &body); err != nil {
			badRequest(w, "invalid body")
			return
		}
		old := s.Config.DNS
		if body.DNS != nil {
			// The listen address and port only take effect on restart; keep
			// the running values so the API cannot silently lie.
			listen, port := old.Listen, old.Port
			s.Config.DNS = *body.DNS
			s.Config.DNS.Listen, s.Config.DNS.Port = listen, port
		}
		if body.UpdateIntervalHours != nil && *body.UpdateIntervalHours > 0 {
			s.Config.Lists.UpdateIntervalHours = *body.UpdateIntervalHours
		}
		if err := s.Config.Validate(); err != nil {
			s.Config.DNS = old
			badRequest(w, err.Error())
			return
		}
		if s.Reload != nil {
			if err := s.Reload(s.Config); err != nil {
				s.Config.DNS = old
				badRequest(w, err.Error())
				return
			}
		}
		if err := s.Config.Save(); err != nil {
			s.Log.Warn("save config", "err", err)
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "dns": s.Config.DNS})
	default:
		badRequest(w, "unsupported method")
	}
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action  string `json:"action"`
		Minutes int    `json:"minutes"`
	}
	if err := decode(r, &body); err != nil {
		badRequest(w, "invalid body")
		return
	}
	switch body.Action {
	case "pause":
		d := time.Duration(body.Minutes) * time.Minute
		if d <= 0 {
			d = 5 * time.Minute
		}
		until := s.Devices.PauseAll(d)
		s.Cache.Flush()
		writeJSON(w, http.StatusOK, map[string]any{"status": "paused", "until": until})
	case "resume":
		s.Devices.Resume()
		writeJSON(w, http.StatusOK, map[string]string{"status": "filtering"})
	case "flush-cache":
		n := s.Cache.Flush()
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "flushed": n})
	case "reset-stats":
		s.Stats.Reset()
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		badRequest(w, "unknown action")
	}
}

// handleCheck explains what the filter would do with a domain, which is the
// fastest way to debug "is adblockerpro breaking this app?".
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	clientIP := strings.TrimSpace(r.URL.Query().Get("client"))
	if domain == "" {
		var body struct {
			Domain string `json:"domain"`
			Client string `json:"client"`
		}
		if err := decode(r, &body); err == nil {
			domain = strings.TrimSpace(body.Domain)
			if clientIP == "" {
				clientIP = strings.TrimSpace(body.Client)
			}
		}
	}
	if domain == "" {
		badRequest(w, "domain is required")
		return
	}
	group := ""
	if clientIP != "" {
		if ip := net.ParseIP(clientIP); ip != nil {
			group = s.Devices.Lookup(ip).Group
		}
	}
	d := s.Engine.Check(domain, group)
	writeJSON(w, http.StatusOK, map[string]any{
		"domain":   blocklist.Normalize(domain),
		"group":    group,
		"decision": d,
		"sinkhole": s.Config.DNS.Sinkhole,
		"type":     dnsmsg.TypeString(dnsmsg.TypeA),
	})
}
