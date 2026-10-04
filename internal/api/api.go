// Package api exposes the REST API and serves the dashboard.
package api

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
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

	"github.com/ahardkore/adblockerpro/internal/auth"
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
	"github.com/ahardkore/adblockerpro/internal/tlsutil"
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
	mux   *http.ServeMux
	http  *http.Server
	https *http.Server
	// sessions holds dashboard logins; throttle slows password guessing.
	sessions *auth.Sessions
	throttle *auth.Throttle
	// certFingerprint is shown in the UI when HTTPS is on.
	certFingerprint string
}

// New wires up the routes.
func New(d Deps) *Server {
	s := &Server{
		Deps:     d,
		mux:      http.NewServeMux(),
		sessions: auth.NewSessions(d.Config.SessionTTL()),
		throttle: auth.NewThrottle(5, 5*time.Minute),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	// Unauthenticated: health and login.
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/login", s.handleLogin)
	s.mux.HandleFunc("/api/logout", s.handleLogout)

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
		"/api/devices/report":   s.handleDeviceReport,
		"/api/devices/clients":  s.handleDeviceClients,
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
		"/api/password":         s.handlePassword,
		"/api/sessions":         s.handleSessions,
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
		Handler:           s.redirectToTLS(s.logRequests(s.mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	errCh := make(chan error, 2)

	if s.Config.Web.TLS.Enabled {
		if err := s.startTLS(errCh); err != nil {
			return err
		}
	}

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
		if s.https != nil {
			_ = s.https.Shutdown(shutdownCtx)
		}
		return s.http.Shutdown(shutdownCtx)
	}
}

// startTLS brings up the HTTPS listener, generating a self-signed
// certificate in DataDir when none was supplied.
func (s *Server) startTLS(errCh chan error) error {
	cert, key := s.Config.Web.TLS.CertFile, s.Config.Web.TLS.KeyFile
	if cert == "" || key == "" {
		var err error
		cert, key, err = tlsutil.EnsureSelfSigned(s.Config.DataDir, nil)
		if err != nil {
			return fmt.Errorf("generate certificate: %w", err)
		}
		s.Log.Info("using self-signed dashboard certificate", "cert", cert)
	}
	if fp, err := tlsutil.Fingerprint(cert); err == nil {
		s.certFingerprint = fp
	}

	handler := http.Handler(s.logRequests(s.mux))
	s.https = &http.Server{
		Addr:              s.Config.WebTLSAddr(),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	go func() {
		s.Log.Info("dashboard listening (https)", "addr", s.https.Addr, "fingerprint", s.certFingerprint)
		err := s.https.ListenAndServeTLS(cert, key)
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	return nil
}

// redirectToTLS sends plain HTTP browsers to the HTTPS port. API clients
// using a token are left alone so scripts do not break.
func (s *Server) redirectToTLS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Config.Web.TLS.Enabled || !s.Config.Web.TLS.RedirectHTTP ||
			r.TLS != nil || strings.HasPrefix(r.URL.Path, "/dns-query") {
			h.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		port := s.Config.Web.TLS.Port
		if port == 0 {
			port = 8443
		}
		target := fmt.Sprintf("https://%s:%d%s", host, port, r.URL.RequestURI())
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	})
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

// authRequired reports whether any credential is configured. With neither a
// token nor a password the box is open, which is the out-of-the-box state on
// a trusted home LAN.
func (s *Server) authRequired() bool {
	return s.Config.Web.AdminToken != "" || s.Config.Web.AdminPasswordHash != ""
}

// authenticated accepts either the machine token (header or query) or a
// dashboard session cookie.
func (s *Server) authenticated(r *http.Request) bool {
	if !s.authRequired() {
		return true
	}
	if c, err := r.Cookie(sessionCookie); err == nil && s.sessions.Valid(c.Value) {
		return true
	}
	if token := s.Config.Web.AdminToken; token != "" {
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
		if provided != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1 {
			return true
		}
	}
	return false
}

// auth enforces credentials when any are configured.
func (s *Server) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated(r) {
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
		"auth":     s.authRequired(),
		"tls":      s.Config.Web.TLS.Enabled,
	})
}

const sessionCookie = "abp_session"

// clientIP is the throttling key: the peer address without its port.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		badRequest(w, "POST required")
		return
	}
	var body struct {
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	if err := decode(r, &body); err != nil {
		badRequest(w, "invalid body")
		return
	}
	ip := clientIP(r)
	if ok, wait := s.throttle.Allowed(ip); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":     "too many attempts",
			"retry_in_s": int(wait.Seconds()) + 1,
		})
		return
	}

	ok := false
	if hash := s.Config.Web.AdminPasswordHash; hash != "" && body.Password != "" {
		ok = auth.VerifyPassword(hash, body.Password)
	}
	if !ok {
		if token := s.Config.Web.AdminToken; token != "" {
			supplied := body.Token
			if supplied == "" {
				supplied = body.Password
			}
			ok = supplied != "" && subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) == 1
		}
	}
	if !ok {
		s.throttle.Fail(ip)
		s.Log.Warn("failed dashboard login", "client", ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	s.throttle.Succeed(ip)
	id, expires, err := s.sessions.Create(ip)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(time.Until(expires).Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "expires": expires})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Revoke(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "abp_token", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handlePassword sets or clears the dashboard password. Changing it logs
// every other browser out.
func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		badRequest(w, "POST required")
		return
	}
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decode(r, &body); err != nil {
		badRequest(w, "invalid body")
		return
	}
	cur := s.Config.Web.AdminPasswordHash
	if cur != "" && !auth.VerifyPassword(cur, body.Current) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password is wrong"})
		return
	}
	if body.New == "" {
		s.Config.Web.AdminPasswordHash = ""
	} else {
		hash, err := auth.HashPassword(body.New)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		s.Config.Web.AdminPasswordHash = hash
	}
	if err := s.Config.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.sessions.RevokeAll()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"password_set": s.Config.Web.AdminPasswordHash != "",
	})
}

// handleSessions reports and optionally clears dashboard logins.
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		s.sessions.RevokeAll()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions":     s.sessions.Count(),
		"password_set": s.Config.Web.AdminPasswordHash != "",
		"token_set":    s.Config.Web.AdminToken != "",
		"tls":          s.Config.Web.TLS.Enabled,
		"fingerprint":  s.certFingerprint,
	})
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
			// Never echo the token or the password hash.
			"web": map[string]any{
				"listen":        s.Config.Web.Listen,
				"port":          s.Config.Web.Port,
				"session_hours": s.Config.Web.SessionHours,
				"password_set":  s.Config.Web.AdminPasswordHash != "",
				"token_set":     s.Config.Web.AdminToken != "",
				"tls":           s.Config.Web.TLS,
			},
		})
	case http.MethodPut, http.MethodPost:
		var body struct {
			DNS                 *config.DNSConfig `json:"dns"`
			UpdateIntervalHours *int              `json:"update_interval_hours"`
			Web                 *struct {
				SessionHours *int               `json:"session_hours"`
				TLS          *config.TLSConfig  `json:"tls"`
			} `json:"web"`
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
		oldWeb := s.Config.Web
		if body.Web != nil {
			// Credentials are changed through /api/password only; the
			// listen address needs a restart, so neither is editable here.
			if body.Web.SessionHours != nil && *body.Web.SessionHours > 0 {
				s.Config.Web.SessionHours = *body.Web.SessionHours
			}
			if body.Web.TLS != nil {
				s.Config.Web.TLS = *body.Web.TLS
			}
		}
		if err := s.Config.Validate(); err != nil {
			s.Config.DNS = old
			s.Config.Web = oldWeb
			badRequest(w, err.Error())
			return
		}
		if s.Reload != nil {
			if err := s.Reload(s.Config); err != nil {
				s.Config.DNS = old
				s.Config.Web = oldWeb
				badRequest(w, err.Error())
				return
			}
		}
		if err := s.Config.Save(); err != nil {
			s.Log.Warn("save config", "err", err)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "ok",
			"dns":          s.Config.DNS,
			"tls":          s.Config.Web.TLS,
			"needs_restart": s.Config.Web.TLS != oldWeb.TLS,
		})
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
