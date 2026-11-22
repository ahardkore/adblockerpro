package api

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ahardkore/adblockerpro/internal/auth"
	"github.com/ahardkore/adblockerpro/internal/blocklist"
	"github.com/ahardkore/adblockerpro/internal/config"
	"github.com/ahardkore/adblockerpro/internal/devices"
	"github.com/ahardkore/adblockerpro/internal/schedule"
	"github.com/ahardkore/adblockerpro/internal/server"
	"github.com/ahardkore/adblockerpro/internal/stats"
)

// newTestServer builds a Server with a real engine, devices, stats, schedules
// and DNS — nothing is stubbed — so the routes answer against real
// collaborators. There is no network: the DNS listener is never started.
func newTestServer(t *testing.T, mutate func(*config.Config)) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.SetPath(filepath.Join(dir, "config.json"))
	cfg.DataDir = dir
	if mutate != nil {
		mutate(cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := blocklist.New(true)
	registry := devices.New(nil)
	collector := stats.New(100, false)
	schedules := schedule.New()
	dnsSrv := server.NewDNS(cfg, server.Deps{
		Engine:    engine,
		Devices:   registry,
		Stats:     collector,
		Schedules: schedules,
		Log:       log,
	})
	return New(Deps{
		Config:    cfg,
		Engine:    engine,
		Updater:   blocklist.NewUpdater(engine, dir, log),
		Devices:   registry,
		Stats:     collector,
		DNS:       dnsSrv,
		Schedules: schedules,
		Log:       log,
	})
}

func do(t *testing.T, s *Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req, _ = http.NewRequest(method, path, strings.NewReader(body))
	} else {
		req, _ = http.NewRequest(method, path, nil)
	}
	if headers != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	return w
}

// randomToken returns a fresh, unguessable token. Captured here rather than
// relying on a fixed constant so tests cannot collide with a real token.
func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestHealthNeedsNoAuth(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) { c.Web.AdminToken = randomToken() })
	w := do(t, s, http.MethodGet, "/api/health", "", nil)
	if w.Code != http.StatusOK {
		t.Errorf("health = %d, want 200", w.Code)
	}
}

func TestProtectedRouteRequiresAuth(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) { c.Web.AdminToken = "secret-token" })
	w := do(t, s, http.MethodGet, "/api/settings", "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated /api/settings = %d, want 401", w.Code)
	}
}

func TestProtectedRouteAcceptsToken(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) { c.Web.AdminToken = "secret-token" })
	w := do(t, s, http.MethodGet, "/api/settings", "", map[string]string{"X-API-Key": "secret-token"})
	if w.Code != http.StatusOK {
		t.Errorf("token-auth /api/settings = %d, want 200: %s", w.Code, w.Body.String())
	}
}

func TestProtectedRouteAcceptsBearerToken(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) { c.Web.AdminToken = "secret-token" })
	w := do(t, s, http.MethodGet, "/api/settings", "", map[string]string{"Authorization": "Bearer secret-token"})
	if w.Code != http.StatusOK {
		t.Errorf("bearer /api/settings = %d, want 200", w.Code)
	}
}

func TestWrongTokenRejected(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) { c.Web.AdminToken = "secret-token" })
	w := do(t, s, http.MethodGet, "/api/settings", "", map[string]string{"X-API-Key": "wrong"})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong-token /api/settings = %d, want 401", w.Code)
	}
}

func TestLoginWithTokenGivesSession(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) { c.Web.AdminToken = "secret-token" })
	w := do(t, s, http.MethodPost, "/api/login", `{"token":"secret-token"}`, map[string]string{"Content-Type": "application/json"})
	if w.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", w.Code, w.Body.String())
	}
	cookies := w.Header()["Set-Cookie"]
	found := false
	for _, c := range cookies {
		if strings.Contains(c, "abp_session=") {
			found = true
		}
	}
	if !found {
		t.Errorf("abp_session cookie missing from %v", cookies)
	}
}

func TestLoginWithWrongTokenIsRejected(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) { c.Web.AdminToken = "secret-token" })
	w := do(t, s, http.MethodPost, "/api/login", `{"token":"wrong"}`, map[string]string{"Content-Type": "application/json"})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong login = %d, want 401", w.Code)
	}
}

func TestLoginWithPassword(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) {
		hash, err := auth.HashPassword("hunter22")
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		c.Web.AdminPasswordHash = hash
	})
	w := do(t, s, http.MethodPost, "/api/login", `{"password":"hunter22"}`, map[string]string{"Content-Type": "application/json"})
	if w.Code != http.StatusOK {
		t.Fatalf("password login = %d: %s", w.Code, w.Body.String())
	}
}

func TestLoginWithWrongPasswordIsRejected(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) {
		hash, _ := auth.HashPassword("hunter22")
		c.Web.AdminPasswordHash = hash
	})
	w := do(t, s, http.MethodPost, "/api/login", `{"password":"hunter23"}`, map[string]string{"Content-Type": "application/json"})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong password login = %d, want 401", w.Code)
	}
}

func TestStaticDashboardIsCacheNoStore(t *testing.T) {
	s := newTestServer(t, nil)
	w := do(t, s, http.MethodGet, "/", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("dashboard = %d", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
	if body := w.Body.String(); !strings.Contains(body, "<") || len(body) < 100 {
		t.Errorf("dashboard body looks wrong (%d bytes)", len(body))
	}
}

func TestSettingsResponseNeverLeaksSecrets(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) {
		c.Web.AdminToken = "secret-token"
		hash, _ := auth.HashPassword("hunter22")
		c.Web.AdminPasswordHash = hash
	})
	w := do(t, s, http.MethodGet, "/api/settings", "", map[string]string{"X-API-Key": "secret-token"})
	if w.Code != http.StatusOK {
		t.Fatalf("settings = %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "secret-token") {
		t.Error("API response leaked the token")
	}
	if strings.Contains(body, "pbkdf2") || strings.Contains(body, "$2a$") {
		t.Error("API response leaked a password hash")
	}
}

func TestSettingsPutAppliesAndValidates(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) { c.Web.AdminToken = "secret-token" })
	body := `{"dns":{"listen":"0.0.0.0","port":5353,"upstreams":["1.1.1.1:53"],"sinkhole":"nxdomain","block_ttl":30,"block_subdomains":true,"block_cname_cloaking":true,"cache_size":100,"cache_min_ttl":30,"cache_max_ttl":86400,"serve_stale":true,"upstream_timeout_ms":1000,"rate_limit_per_client":0,"allowed_clients":null,"local_records":{},"conditional_forward":null,"prefetch":true,"request_dnssec":true,"doh_server":false,"block_https_records":false,"prefer_doh":true,"custom_ipv4":""}}`
	w := do(t, s, http.MethodPut, "/api/settings", body, map[string]string{"X-API-Key": "secret-token"})
	if w.Code != http.StatusOK {
		t.Fatalf("settings PUT = %d: %s", w.Code, w.Body.String())
	}
	// The running config reflects the change.
	saved := s.Config.DNS
	if saved.Sinkhole != "nxdomain" {
		t.Errorf("sinkhole = %q, want nxdomain", saved.Sinkhole)
	}
	// Listen/port are pinned: the running listener only changes on restart.
	if saved.Port != 53 {
		t.Errorf("port = %d, want 53 (the running value)", saved.Port)
	}
}

func TestSettingsPutRejectsInvalidValues(t *testing.T) {
	s := newTestServer(t, func(c *config.Config) { c.Web.AdminToken = "secret-token" })
	// sinkhole must be one of the known modes.
	body := `{"dns":{"sinkhole":"bogus-mode"}}`
	w := do(t, s, http.MethodPut, "/api/settings", body, map[string]string{"X-API-Key": "secret-token"})
	if w.Code == http.StatusOK {
		t.Fatalf("bogus sinkhole accepted: %s", w.Body.String())
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("bogus sinkhole status = %d, want 400", w.Code)
	}
}
