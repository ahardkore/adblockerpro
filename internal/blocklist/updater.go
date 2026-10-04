package blocklist

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Source is one upstream blocklist.
type Source struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
	// Kind is "block" (default) or "allow". An allow list overrides the
	// blocklists, the way Pi-hole v6's subscribed allowlists do — handy for
	// "do not break my smart TV" lists.
	Kind string `json:"kind,omitempty"`

	// Populated by the updater.
	Domains     int       `json:"domains"`
	Bytes       int64     `json:"bytes"`
	LastUpdated time.Time `json:"last_updated,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}

// SourceID derives a stable id from a URL.
func SourceID(url string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(strings.ToLower(url))))
	return hex.EncodeToString(sum[:8])
}

// DefaultSources are the lists a fresh install starts with: solid ad and
// tracker coverage without the false positives that break streaming apps.
func DefaultSources() []Source {
	urls := []struct{ title, url string }{
		{"StevenBlack unified hosts", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
		{"AdGuard DNS filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"},
		{"Peter Lowe's ad servers", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"},
		{"OISD small", "https://small.oisd.nl/"},
		{"Smart-TV & CTV trackers", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt"},
	}
	out := make([]Source, 0, len(urls))
	for _, u := range urls {
		out = append(out, Source{
			ID:      SourceID(u.url),
			Title:   u.title,
			URL:     u.url,
			Enabled: true,
		})
	}
	return out
}

// Updater downloads sources, caches them on disk and rebuilds the engine's
// domain set.
type Updater struct {
	engine *Engine
	dir    string
	client *http.Client
	log    *slog.Logger

	mu       sync.Mutex
	sources  []Source
	lastRun  time.Time
	running  bool
	onChange func([]Source)
}

// NewUpdater creates an updater that caches downloads under dir.
func NewUpdater(e *Engine, dir string, log *slog.Logger) *Updater {
	return &Updater{
		engine: e,
		dir:    dir,
		log:    log,
		client: &http.Client{
			Timeout: 90 * time.Second,
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConns:        8,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 15 * time.Second,
			},
		},
	}
}

// OnChange registers a callback fired after every successful rebuild, used to
// persist updated source metadata.
func (u *Updater) OnChange(fn func([]Source)) { u.onChange = fn }

// SetSources replaces the configured sources.
func (u *Updater) SetSources(s []Source) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.sources = append([]Source(nil), s...)
	for i := range u.sources {
		if u.sources[i].ID == "" {
			u.sources[i].ID = SourceID(u.sources[i].URL)
		}
	}
}

// Sources returns a copy of the current sources with their statistics.
func (u *Updater) Sources() []Source {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]Source(nil), u.sources...)
}

// IsAllow reports whether this is a subscribed allowlist.
func (s Source) IsAllow() bool { return strings.EqualFold(s.Kind, "allow") }

// AddSource adds a list (or re-enables it if the URL is already present).
func (u *Updater) AddSource(title, url string) Source {
	return u.AddSourceKind(title, url, "block")
}

// AddSourceKind adds a list of the given kind ("block" or "allow").
func (u *Updater) AddSourceKind(title, url, kind string) Source {
	if kind == "" {
		kind = "block"
	}
	u.mu.Lock()
	id := SourceID(url)
	for i := range u.sources {
		if u.sources[i].ID == id {
			u.sources[i].Enabled = true
			u.sources[i].Kind = kind
			if title != "" {
				u.sources[i].Title = title
			}
			s := u.sources[i]
			u.mu.Unlock()
			return s
		}
	}
	if title == "" {
		title = url
	}
	s := Source{ID: id, Title: title, URL: url, Enabled: true, Kind: kind}
	u.sources = append(u.sources, s)
	u.mu.Unlock()
	return s
}

// RemoveSource deletes a list by id and drops its cache file.
func (u *Updater) RemoveSource(id string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for i := range u.sources {
		if u.sources[i].ID == id {
			u.sources = append(u.sources[:i], u.sources[i+1:]...)
			_ = os.Remove(u.cachePath(id))
			return true
		}
	}
	return false
}

// ToggleSource enables or disables a list by id.
func (u *Updater) ToggleSource(id string, enabled bool) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for i := range u.sources {
		if u.sources[i].ID == id {
			u.sources[i].Enabled = enabled
			return true
		}
	}
	return false
}

// LastRun reports when the last update finished.
func (u *Updater) LastRun() time.Time {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastRun
}

func (u *Updater) cachePath(id string) string {
	return filepath.Join(u.dir, id+".list")
}

// LoadFromCache rebuilds the domain set from previously downloaded files so
// the resolver starts blocking immediately, before any network is available.
func (u *Updater) LoadFromCache() int {
	sources := u.Sources()
	merged := make(map[string]string, 1<<16)
	allow := make(map[string]string, 1024)
	for _, s := range sources {
		if !s.Enabled {
			continue
		}
		f, err := os.Open(u.cachePath(s.ID))
		if err != nil {
			continue
		}
		domains := ParseList(f)
		f.Close()
		target := merged
		if s.IsAllow() {
			target = allow
		}
		for _, d := range domains {
			if _, exists := target[d]; !exists {
				target[d] = s.Title
			}
		}
	}
	u.engine.SetDomains(NewDomainSet(merged))
	u.engine.SetAllowDomains(NewDomainSet(allow))
	return len(merged)
}

// UpdateAll downloads every enabled source and rebuilds the domain set.
// Sources that fail keep their cached copy.
func (u *Updater) UpdateAll(ctx context.Context) (int, error) {
	u.mu.Lock()
	if u.running {
		u.mu.Unlock()
		return u.engine.Domains().Len(), fmt.Errorf("update already in progress")
	}
	u.running = true
	sources := append([]Source(nil), u.sources...)
	u.mu.Unlock()

	defer func() {
		u.mu.Lock()
		u.running = false
		u.mu.Unlock()
	}()

	if err := os.MkdirAll(u.dir, 0o755); err != nil {
		return 0, fmt.Errorf("create cache dir: %w", err)
	}

	type result struct {
		idx     int
		domains []string
		bytes   int64
		err     error
	}

	results := make(chan result, len(sources))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, s := range sources {
		if !s.Enabled {
			continue
		}
		wg.Add(1)
		go func(i int, s Source) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			domains, n, err := u.fetch(ctx, s)
			results <- result{idx: i, domains: domains, bytes: n, err: err}
		}(i, s)
	}
	wg.Wait()
	close(results)

	merged := make(map[string]string, 1<<17)
	allow := make(map[string]string, 1024)
	now := time.Now()
	for r := range results {
		s := &sources[r.idx]
		if r.err != nil {
			s.LastError = r.err.Error()
			u.log.Warn("blocklist update failed, using cache",
				"list", s.Title, "err", r.err)
			if f, err := os.Open(u.cachePath(s.ID)); err == nil {
				r.domains = ParseList(f)
				f.Close()
			}
		} else {
			s.LastError = ""
			s.LastUpdated = now
			s.Bytes = r.bytes
		}
		s.Domains = len(r.domains)
		target := merged
		if s.IsAllow() {
			target = allow
		}
		for _, d := range r.domains {
			if _, exists := target[d]; !exists {
				target[d] = s.Title
			}
		}
	}

	u.engine.SetDomains(NewDomainSet(merged))
	u.engine.SetAllowDomains(NewDomainSet(allow))

	u.mu.Lock()
	// Preserve any sources added while the update was running.
	byID := map[string]Source{}
	for _, s := range sources {
		byID[s.ID] = s
	}
	for i := range u.sources {
		if s, ok := byID[u.sources[i].ID]; ok {
			u.sources[i] = s
		}
	}
	u.lastRun = now
	snapshot := append([]Source(nil), u.sources...)
	u.mu.Unlock()

	if u.onChange != nil {
		u.onChange(snapshot)
	}
	u.log.Info("blocklists updated", "domains", len(merged), "lists", len(snapshot))
	return len(merged), nil
}

func (u *Updater) fetch(ctx context.Context, s Source) ([]string, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	var reader io.ReadCloser
	var size int64

	if strings.HasPrefix(s.URL, "file://") || strings.HasPrefix(s.URL, "/") {
		path := strings.TrimPrefix(s.URL, "file://")
		f, err := os.Open(path)
		if err != nil {
			return nil, 0, err
		}
		reader = f
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", "adblockerpro/1.0 (+https://github.com/ahardkore/adblockerpro)")
		req.Header.Set("Accept", "text/plain, */*")
		resp, err := u.client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, 0, fmt.Errorf("http %s", resp.Status)
		}
		reader = resp.Body
	}
	defer reader.Close()

	tmp := u.cachePath(s.ID) + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return nil, 0, err
	}
	// Cap a single list at 128 MiB of raw text.
	size, err = io.Copy(f, io.LimitReader(reader, 128<<20))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return nil, 0, err
	}
	if err := os.Rename(tmp, u.cachePath(s.ID)); err != nil {
		os.Remove(tmp)
		return nil, 0, err
	}

	cached, err := os.Open(u.cachePath(s.ID))
	if err != nil {
		return nil, 0, err
	}
	defer cached.Close()
	domains := ParseList(cached)
	sort.Strings(domains)
	return domains, size, nil
}

// Run updates on start-up (unless the cache is fresh) and then on an
// interval, until ctx is cancelled.
func (u *Updater) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	// Give the network a moment to come up after boot.
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if _, err := u.UpdateAll(ctx); err != nil {
				u.log.Warn("blocklist update cycle failed", "err", err)
			}
			timer.Reset(interval)
		}
	}
}
