// Package stats keeps the in-memory query log and the counters the
// dashboard renders.
package stats

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Status describes how a query was answered.
type Status string

const (
	// StatusAllowed was forwarded upstream and answered.
	StatusAllowed Status = "allowed"
	// StatusBlocked was sinkholed.
	StatusBlocked Status = "blocked"
	// StatusCached was answered from the local cache.
	StatusCached Status = "cached"
	// StatusLocal was answered from a static local record.
	StatusLocal Status = "local"
	// StatusError could not be answered.
	StatusError Status = "error"
)

// Entry is one line of the query log.
type Entry struct {
	Time     time.Time `json:"time"`
	Client   string    `json:"client"`
	Device   string    `json:"device,omitempty"`
	Domain   string    `json:"domain"`
	Type     string    `json:"type"`
	Status   Status    `json:"status"`
	Rule     string    `json:"rule,omitempty"`
	Source   string    `json:"source,omitempty"`
	Upstream string    `json:"upstream,omitempty"`
	Answer   string    `json:"answer,omitempty"`
	Rcode    string    `json:"rcode,omitempty"`
	MS       float64   `json:"ms"`
	// Validated means the upstream set the AD bit: the answer's DNSSEC
	// signatures were checked.
	Validated bool `json:"validated,omitempty"`
	// Schedule names the time window that caused a block, if any.
	Schedule string `json:"schedule,omitempty"`
}

// Blocked reports whether this query was sinkholed.
func (e Entry) Blocked() bool { return e.Status == StatusBlocked }

type counterSnapshot struct {
	Total   int64             `json:"total"`
	Blocked int64             `json:"blocked"`
	Cached  int64             `json:"cached"`
	Errors  int64             `json:"errors"`
	Domains map[string]int64  `json:"domains"`
	Blocks  map[string]int64  `json:"blocks"`
	Clients map[string]int64  `json:"clients"`
	Buckets map[string]bucket `json:"buckets"`
	Saved   time.Time         `json:"saved"`
}

type bucket struct {
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
}

// Collector aggregates query activity.
type Collector struct {
	mu sync.RWMutex

	ring      []Entry
	head      int
	size      int
	filled    bool
	anonymize bool

	total, blocked, cached, errors int64
	validated                      int64
	domains                        map[string]int64
	blocks                         map[string]int64
	clients                        map[string]int64
	types                          map[string]int64
	buckets                        map[string]bucket // "2006-01-02T15:04" in 10 min steps
	latencySum                     float64
	latencyN                       int64
	started                        time.Time
	path                           string
	sink                           func(Entry)
}

// SetSink registers a callback invoked for every recorded query, outside the
// collector's lock. The long-term history store uses it.
func (c *Collector) SetSink(fn func(Entry)) {
	c.mu.Lock()
	c.sink = fn
	c.mu.Unlock()
}

// New creates a collector keeping size recent queries.
func New(size int, anonymize bool) *Collector {
	if size <= 0 {
		size = 1000
	}
	return &Collector{
		ring:      make([]Entry, size),
		size:      size,
		anonymize: anonymize,
		domains:   map[string]int64{},
		blocks:    map[string]int64{},
		clients:   map[string]int64{},
		types:     map[string]int64{},
		buckets:   map[string]bucket{},
		started:   time.Now(),
	}
}

func bucketKey(t time.Time) string {
	t = t.UTC().Truncate(10 * time.Minute)
	return t.Format("2006-01-02T15:04")
}

// AnonymizeClient hashes a client address when privacy mode is on.
func (c *Collector) AnonymizeClient(ip string) string {
	if !c.anonymize {
		return ip
	}
	sum := sha256.Sum256([]byte(ip))
	return "anon-" + hex.EncodeToString(sum[:4])
}

// Record adds an entry to the log and updates counters.
func (c *Collector) Record(e Entry) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Client = c.AnonymizeClient(e.Client)
	e.Domain = strings.ToLower(e.Domain)

	sink := c.record(e)
	if sink != nil {
		sink(e)
	}
}

// record updates the counters and returns the sink to notify, if any.
func (c *Collector) record(e Entry) func(Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.ring[c.head] = e
	c.head = (c.head + 1) % c.size
	if c.head == 0 {
		c.filled = true
	}

	c.total++
	c.domains[e.Domain]++
	c.clients[e.Client]++
	c.types[e.Type]++
	c.latencySum += e.MS
	c.latencyN++
	if e.Validated {
		c.validated++
	}

	key := bucketKey(e.Time)
	b := c.buckets[key]
	b.Total++

	switch e.Status {
	case StatusBlocked:
		c.blocked++
		c.blocks[e.Domain]++
		b.Blocked++
	case StatusCached:
		c.cached++
	case StatusError:
		c.errors++
	}
	c.buckets[key] = b

	// Keep the maps from growing without bound on long uptimes.
	if len(c.domains) > 50000 {
		c.trimLocked(c.domains, 20000)
	}
	if len(c.blocks) > 20000 {
		c.trimLocked(c.blocks, 10000)
	}
	if len(c.buckets) > 24*6*8 {
		c.trimBucketsLocked(24 * 6 * 7)
	}
	return c.sink
}

func (c *Collector) trimLocked(m map[string]int64, keep int) {
	type kv struct {
		k string
		v int64
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	for _, e := range all[min(keep, len(all)):] {
		delete(m, e.k)
	}
}

func (c *Collector) trimBucketsLocked(keep int) {
	keys := make([]string, 0, len(c.buckets))
	for k := range c.buckets {
		keys = append(keys, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	for _, k := range keys[min(keep, len(keys)):] {
		delete(c.buckets, k)
	}
}

// QueryFilter narrows a query-log read.
type QueryFilter struct {
	Limit  int
	Search string
	Status Status
	Client string
}

// Recent returns the newest entries matching f, newest first.
func (c *Collector) Recent(f QueryFilter) []Entry {
	if f.Limit <= 0 {
		f.Limit = 200
	}
	search := strings.ToLower(strings.TrimSpace(f.Search))

	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]Entry, 0, f.Limit)
	n := c.size
	if !c.filled {
		n = c.head
	}
	for i := 0; i < n && len(out) < f.Limit; i++ {
		idx := (c.head - 1 - i + c.size*2) % c.size
		e := c.ring[idx]
		if e.Time.IsZero() {
			continue
		}
		if f.Status != "" && e.Status != f.Status {
			continue
		}
		if f.Client != "" && e.Client != f.Client {
			continue
		}
		if search != "" &&
			!strings.Contains(e.Domain, search) &&
			!strings.Contains(strings.ToLower(e.Client), search) &&
			!strings.Contains(strings.ToLower(e.Device), search) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// TopItem is a name/count pair.
type TopItem struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// Point is one bar of the activity chart.
type Point struct {
	Time    string `json:"time"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
}

// Summary is everything the dashboard header needs.
type Summary struct {
	Total        int64     `json:"total"`
	Blocked      int64     `json:"blocked"`
	Cached       int64     `json:"cached"`
	Errors       int64     `json:"errors"`
	Validated    int64     `json:"validated"`
	BlockPercent float64   `json:"block_percent"`
	AvgMS        float64   `json:"avg_ms"`
	Clients      int       `json:"clients"`
	Since        time.Time `json:"since"`
	TopAllowed   []TopItem `json:"top_allowed"`
	TopBlocked   []TopItem `json:"top_blocked"`
	TopClients   []TopItem `json:"top_clients"`
	Types        []TopItem `json:"types"`
	Timeline     []Point   `json:"timeline"`
}

func topN(m map[string]int64, n int) []TopItem {
	out := make([]TopItem, 0, len(m))
	for k, v := range m {
		out = append(out, TopItem{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Summary builds a snapshot for the API. hours controls the timeline span.
func (c *Collector) Summary(hours int) Summary {
	if hours <= 0 {
		hours = 24
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	s := Summary{
		Total:      c.total,
		Blocked:    c.blocked,
		Cached:     c.cached,
		Errors:     c.errors,
		Validated:  c.validated,
		Clients:    len(c.clients),
		Since:      c.started,
		TopAllowed: topN(c.domains, 10),
		TopBlocked: topN(c.blocks, 10),
		TopClients: topN(c.clients, 10),
		Types:      topN(c.types, 8),
	}
	if c.total > 0 {
		s.BlockPercent = float64(c.blocked) / float64(c.total) * 100
	}
	if c.latencyN > 0 {
		s.AvgMS = c.latencySum / float64(c.latencyN)
	}

	now := time.Now().UTC().Truncate(10 * time.Minute)
	steps := hours * 6
	s.Timeline = make([]Point, 0, steps)
	for i := steps - 1; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * 10 * time.Minute)
		k := t.Format("2006-01-02T15:04")
		b := c.buckets[k]
		s.Timeline = append(s.Timeline, Point{
			Time:    t.Format(time.RFC3339),
			Total:   b.Total,
			Blocked: b.Blocked,
		})
	}
	return s
}

// Reset clears every counter and the query log.
func (c *Collector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ring = make([]Entry, c.size)
	c.head, c.filled = 0, false
	c.total, c.blocked, c.cached, c.errors, c.validated = 0, 0, 0, 0, 0
	c.domains = map[string]int64{}
	c.blocks = map[string]int64{}
	c.clients = map[string]int64{}
	c.types = map[string]int64{}
	c.buckets = map[string]bucket{}
	c.latencySum, c.latencyN = 0, 0
	c.started = time.Now()
}

// SetPersistPath enables saving counters to dir/stats.json.
func (c *Collector) SetPersistPath(dir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.path = filepath.Join(dir, "stats.json")
}

// Save writes the counters (not the query log) to disk.
func (c *Collector) Save() error {
	c.mu.RLock()
	if c.path == "" {
		c.mu.RUnlock()
		return nil
	}
	snap := counterSnapshot{
		Total:   c.total,
		Blocked: c.blocked,
		Cached:  c.cached,
		Errors:  c.errors,
		Domains: map[string]int64{},
		Blocks:  map[string]int64{},
		Clients: map[string]int64{},
		Buckets: map[string]bucket{},
		Saved:   time.Now(),
	}
	for _, t := range topN(c.domains, 500) {
		snap.Domains[t.Name] = t.Count
	}
	for _, t := range topN(c.blocks, 500) {
		snap.Blocks[t.Name] = t.Count
	}
	for k, v := range c.clients {
		snap.Clients[k] = v
	}
	for k, v := range c.buckets {
		snap.Buckets[k] = v
	}
	path := c.path
	c.mu.RUnlock()

	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load restores counters saved by a previous run.
func (c *Collector) Load(dir string) error {
	path := filepath.Join(dir, "stats.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var snap counterSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total, c.blocked, c.cached, c.errors = snap.Total, snap.Blocked, snap.Cached, snap.Errors
	for k, v := range snap.Domains {
		c.domains[k] += v
	}
	for k, v := range snap.Blocks {
		c.blocks[k] += v
	}
	for k, v := range snap.Clients {
		c.clients[k] += v
	}
	for k, v := range snap.Buckets {
		c.buckets[k] = v
	}
	c.path = path
	return nil
}

// RunPersist saves counters every interval until stop is closed.
func (c *Collector) RunPersist(interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			_ = c.Save()
			return
		case <-t.C:
			_ = c.Save()
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
