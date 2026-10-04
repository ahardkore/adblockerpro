// Package history is the long-term query store: every lookup is appended to
// a compact binary log, one file per UTC day, with daily rollups for charts
// and a paginated reader for the dashboard.
//
// Pi-hole keeps its history in SQLite. We keep ours in append-only shards so
// the binary stays dependency-free and a cheap SD card is not asked to do
// random writes all day — a day shard is written sequentially, rolled over
// at midnight and deleted wholesale when it ages out.
package history

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ahardkore/adblockerpro/internal/stats"
)

// fileMagic marks a shard and carries the format version.
var fileMagic = [8]byte{'A', 'B', 'P', 'H', 'I', 'S', 'T', 1}

// Record is one stored query.
type Record struct {
	Time     time.Time    `json:"time"`
	Client   string       `json:"client"`
	Device   string       `json:"device,omitempty"`
	Domain   string       `json:"domain"`
	Type     string       `json:"type"`
	Status   stats.Status `json:"status"`
	Rule     string       `json:"rule,omitempty"`
	Source   string       `json:"source,omitempty"`
	Upstream string       `json:"upstream,omitempty"`
	MS       float64      `json:"ms"`
}

// Filter narrows a history query.
type Filter struct {
	From   time.Time
	To     time.Time
	Search string
	Status stats.Status
	Client string
	Domain string
	Limit  int
	Offset int
}

// Page is a slice of results, newest first.
type Page struct {
	Records []Record `json:"records"`
	Total   int      `json:"total"`
	Offset  int      `json:"offset"`
	Limit   int      `json:"limit"`
	HasMore bool     `json:"has_more"`
}

// DayStat is a daily rollup.
type DayStat struct {
	Day     string `json:"day"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
	Cached  int64  `json:"cached"`
	Clients int    `json:"clients"`
	Bytes   int64  `json:"bytes"`
}

// Store writes and reads the history shards.
type Store struct {
	dir       string
	retention int

	mu      sync.Mutex
	day     string
	file    *os.File
	w       *bufio.Writer
	pending int
	closed  bool

	// writes counts records appended since start-up, for the dashboard.
	writes int64
}

// Open prepares the store. retentionDays <= 0 keeps shards for 30 days.
func Open(dir string, retentionDays int) (*Store, error) {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("history dir: %w", err)
	}
	s := &Store{dir: dir, retention: retentionDays}
	if err := s.rollover(time.Now().UTC()); err != nil {
		return nil, err
	}
	go s.Prune()
	return s, nil
}

func dayKey(t time.Time) string { return t.UTC().Format("2006-01-02") }

func (s *Store) shardPath(day string) string {
	return filepath.Join(s.dir, day+".log")
}

// rollover opens the shard for t, closing the previous one. Caller must not
// hold the mutex.
func (s *Store) rollover(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rolloverLocked(t)
}

func (s *Store) rolloverLocked(t time.Time) error {
	day := dayKey(t)
	if s.day == day && s.file != nil {
		return nil
	}
	if s.w != nil {
		_ = s.w.Flush()
	}
	if s.file != nil {
		_ = s.file.Close()
	}
	path := s.shardPath(day)
	newFile := false
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		newFile = true
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open shard %s: %w", day, err)
	}
	s.file, s.day = f, day
	s.w = bufio.NewWriterSize(f, 32*1024)
	if newFile {
		if _, err := s.w.Write(fileMagic[:]); err != nil {
			return err
		}
	}
	return nil
}

// Append stores one query. It is safe for concurrent use and never blocks on
// disk for long: writes are buffered and flushed by Flush or at 256 records.
func (s *Store) Append(e stats.Entry) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if dayKey(e.Time) != s.day {
		if err := s.rolloverLocked(e.Time); err != nil {
			return err
		}
	}
	rec := encode(e)
	if err := binary.Write(s.w, binary.BigEndian, uint32(len(rec))); err != nil {
		return err
	}
	if _, err := s.w.Write(rec); err != nil {
		return err
	}
	s.writes++
	s.pending++
	if s.pending >= 256 {
		s.pending = 0
		return s.w.Flush()
	}
	return nil
}

// Flush pushes buffered records to disk.
func (s *Store) Flush() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil || s.closed {
		return nil
	}
	s.pending = 0
	return s.w.Flush()
}

// Close flushes and closes the current shard.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.w != nil {
		_ = s.w.Flush()
	}
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// Writes reports how many records have been appended since start-up.
func (s *Store) Writes() int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

// RunFlush flushes periodically until stop is closed.
func (s *Store) RunFlush(every time.Duration, stop <-chan struct{}) {
	if every <= 0 {
		every = 5 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	daily := time.NewTicker(time.Hour)
	defer daily.Stop()
	for {
		select {
		case <-stop:
			_ = s.Flush()
			return
		case <-t.C:
			_ = s.Flush()
		case <-daily.C:
			_ = s.rollover(time.Now().UTC())
			_ = s.Prune()
		}
	}
}

/* ----------------------------- encoding ------------------------------ */

func putString(buf []byte, s string) []byte {
	if len(s) > 255 {
		s = s[:255]
	}
	buf = append(buf, byte(len(s)))
	return append(buf, s...)
}

func statusCode(s stats.Status) byte {
	switch s {
	case stats.StatusBlocked:
		return 1
	case stats.StatusCached:
		return 2
	case stats.StatusLocal:
		return 3
	case stats.StatusError:
		return 4
	default:
		return 0
	}
}

func codeStatus(b byte) stats.Status {
	switch b {
	case 1:
		return stats.StatusBlocked
	case 2:
		return stats.StatusCached
	case 3:
		return stats.StatusLocal
	case 4:
		return stats.StatusError
	default:
		return stats.StatusAllowed
	}
}

func encode(e stats.Entry) []byte {
	buf := make([]byte, 0, 96)
	buf = binary.BigEndian.AppendUint64(buf, uint64(e.Time.UnixMilli()))
	buf = append(buf, statusCode(e.Status))
	ms := e.MS * 10
	if ms < 0 {
		ms = 0
	}
	if ms > 65535 {
		ms = 65535
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(ms))
	buf = putString(buf, e.Client)
	buf = putString(buf, e.Device)
	buf = putString(buf, e.Domain)
	buf = putString(buf, e.Type)
	buf = putString(buf, e.Rule)
	buf = putString(buf, e.Source)
	buf = putString(buf, e.Upstream)
	return buf
}

func decode(b []byte) (Record, error) {
	if len(b) < 11 {
		return Record{}, io.ErrUnexpectedEOF
	}
	r := Record{
		Time:   time.UnixMilli(int64(binary.BigEndian.Uint64(b[0:8]))),
		Status: codeStatus(b[8]),
		MS:     float64(binary.BigEndian.Uint16(b[9:11])) / 10,
	}
	off := 11
	next := func() (string, error) {
		if off >= len(b) {
			return "", io.ErrUnexpectedEOF
		}
		n := int(b[off])
		off++
		if off+n > len(b) {
			return "", io.ErrUnexpectedEOF
		}
		s := string(b[off : off+n])
		off += n
		return s, nil
	}
	var err error
	if r.Client, err = next(); err != nil {
		return r, err
	}
	if r.Device, err = next(); err != nil {
		return r, err
	}
	if r.Domain, err = next(); err != nil {
		return r, err
	}
	if r.Type, err = next(); err != nil {
		return r, err
	}
	if r.Rule, err = next(); err != nil {
		return r, err
	}
	if r.Source, err = next(); err != nil {
		return r, err
	}
	if r.Upstream, err = next(); err != nil {
		return r, err
	}
	return r, nil
}

/* ------------------------------ reading ------------------------------- */

// readShard returns every record in a day file, oldest first.
func (s *Store) readShard(day string) ([]Record, error) {
	data, err := os.ReadFile(s.shardPath(day))
	if err != nil {
		return nil, err
	}
	if len(data) < len(fileMagic) {
		return nil, nil
	}
	if string(data[:7]) != string(fileMagic[:7]) {
		return nil, fmt.Errorf("history: %s is not a shard", day)
	}
	out := make([]Record, 0, 1024)
	off := len(fileMagic)
	for off+4 <= len(data) {
		n := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if n <= 0 || off+n > len(data) {
			break // torn write at the tail: stop, keep what we have
		}
		rec, err := decode(data[off : off+n])
		off += n
		if err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

// Days lists the shards present, newest first.
func (s *Store) Days() []string {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	days := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".log") {
			days = append(days, strings.TrimSuffix(name, ".log"))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(days)))
	return days
}

func (f Filter) matches(r Record) bool {
	if !f.From.IsZero() && r.Time.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && r.Time.After(f.To) {
		return false
	}
	if f.Status != "" && r.Status != f.Status {
		return false
	}
	if f.Client != "" && r.Client != f.Client && !strings.EqualFold(r.Device, f.Client) {
		return false
	}
	if f.Domain != "" && !strings.EqualFold(r.Domain, f.Domain) {
		return false
	}
	if f.Search != "" {
		q := strings.ToLower(f.Search)
		if !strings.Contains(strings.ToLower(r.Domain), q) &&
			!strings.Contains(strings.ToLower(r.Client), q) &&
			!strings.Contains(strings.ToLower(r.Device), q) &&
			!strings.Contains(strings.ToLower(r.Rule), q) {
			return false
		}
	}
	return true
}

// Query searches the history, newest first, with offset/limit paging.
func (s *Store) Query(f Filter) (Page, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	_ = s.Flush()

	page := Page{Records: []Record{}, Offset: f.Offset, Limit: f.Limit}
	skipped := 0
	for _, day := range s.Days() {
		// Skip whole shards that fall outside the range.
		if !f.From.IsZero() && day < dayKey(f.From) {
			continue
		}
		if !f.To.IsZero() && day > dayKey(f.To) {
			continue
		}
		recs, err := s.readShard(day)
		if err != nil {
			continue
		}
		for i := len(recs) - 1; i >= 0; i-- {
			if !f.matches(recs[i]) {
				continue
			}
			page.Total++
			if skipped < f.Offset {
				skipped++
				continue
			}
			if len(page.Records) < f.Limit {
				page.Records = append(page.Records, recs[i])
			} else {
				page.HasMore = true
			}
		}
	}
	return page, nil
}

// Daily returns rollups for the last n days, oldest first.
func (s *Store) Daily(n int) []DayStat {
	if n <= 0 {
		n = 30
	}
	days := s.Days()
	if len(days) > n {
		days = days[:n]
	}
	out := make([]DayStat, 0, len(days))
	for _, day := range days {
		st := DayStat{Day: day}
		if fi, err := os.Stat(s.shardPath(day)); err == nil {
			st.Bytes = fi.Size()
		}
		recs, err := s.readShard(day)
		if err != nil {
			continue
		}
		clients := map[string]struct{}{}
		for _, r := range recs {
			st.Total++
			switch r.Status {
			case stats.StatusBlocked:
				st.Blocked++
			case stats.StatusCached:
				st.Cached++
			}
			clients[r.Client] = struct{}{}
		}
		st.Clients = len(clients)
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Day < out[j].Day })
	return out
}

// TopDomains aggregates the busiest (or most blocked) domains over a window.
func (s *Store) TopDomains(since time.Time, blockedOnly bool, n int) []stats.TopItem {
	counts := map[string]int64{}
	for _, day := range s.Days() {
		if !since.IsZero() && day < dayKey(since) {
			continue
		}
		recs, err := s.readShard(day)
		if err != nil {
			continue
		}
		for _, r := range recs {
			if r.Time.Before(since) {
				continue
			}
			if blockedOnly && r.Status != stats.StatusBlocked {
				continue
			}
			counts[r.Domain]++
		}
	}
	out := make([]stats.TopItem, 0, len(counts))
	for k, v := range counts {
		out = append(out, stats.TopItem{Name: k, Count: v})
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

// Prune deletes shards older than the retention window.
func (s *Store) Prune() error {
	cutoff := dayKey(time.Now().UTC().AddDate(0, 0, -s.retention))
	for _, day := range s.Days() {
		if day < cutoff {
			_ = os.Remove(s.shardPath(day))
		}
	}
	return nil
}

// DiskUsage reports the total size of the history on disk.
func (s *Store) DiskUsage() int64 {
	var total int64
	for _, day := range s.Days() {
		if fi, err := os.Stat(s.shardPath(day)); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// Export writes the history as JSON lines, for backups or analysis.
func (s *Store) Export(w io.Writer, since time.Time) error {
	_ = s.Flush()
	enc := json.NewEncoder(w)
	days := s.Days()
	sort.Strings(days)
	for _, day := range days {
		if !since.IsZero() && day < dayKey(since) {
			continue
		}
		recs, err := s.readShard(day)
		if err != nil {
			continue
		}
		for _, r := range recs {
			if r.Time.Before(since) {
				continue
			}
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
	}
	return nil
}

// ClientReport is a per-device drill-down over a window of history.
type ClientReport struct {
	Client       string          `json:"client"`
	Device       string          `json:"device,omitempty"`
	From         time.Time       `json:"from"`
	To           time.Time       `json:"to"`
	Total        int64           `json:"total"`
	Blocked      int64           `json:"blocked"`
	Cached       int64           `json:"cached"`
	Errors       int64           `json:"errors"`
	BlockRatio   float64         `json:"block_ratio"`
	AvgMS        float64         `json:"avg_ms"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
	TopDomains   []stats.TopItem `json:"top_domains"`
	TopBlocked   []stats.TopItem `json:"top_blocked"`
	Types        []stats.TopItem `json:"types"`
	Hourly       []int64         `json:"hourly"`
	BlockedHours []int64         `json:"blocked_hourly"`
}

// ClientReport builds the drill-down for one client address.
func (s *Store) ClientReport(client string, since time.Time, topN int) ClientReport {
	if topN <= 0 {
		topN = 10
	}
	rep := ClientReport{
		Client:       client,
		From:         since,
		To:           time.Now().UTC(),
		Hourly:       make([]int64, 24),
		BlockedHours: make([]int64, 24),
	}
	domains := map[string]int64{}
	blocked := map[string]int64{}
	types := map[string]int64{}
	var totalMS float64

	for _, day := range s.Days() {
		if !since.IsZero() && day < dayKey(since) {
			continue
		}
		recs, err := s.readShard(day)
		if err != nil {
			continue
		}
		for _, r := range recs {
			if r.Client != client || r.Time.Before(since) {
				continue
			}
			rep.Total++
			totalMS += r.MS
			domains[r.Domain]++
			types[r.Type]++
			hour := r.Time.UTC().Hour()
			rep.Hourly[hour]++
			switch r.Status {
			case stats.StatusBlocked:
				rep.Blocked++
				rep.BlockedHours[hour]++
				blocked[r.Domain]++
			case stats.StatusCached:
				rep.Cached++
			case stats.StatusError:
				rep.Errors++
			}
			if r.Device != "" {
				rep.Device = r.Device
			}
			if rep.FirstSeen.IsZero() || r.Time.Before(rep.FirstSeen) {
				rep.FirstSeen = r.Time
			}
			if r.Time.After(rep.LastSeen) {
				rep.LastSeen = r.Time
			}
		}
	}
	if rep.Total > 0 {
		rep.BlockRatio = float64(rep.Blocked) / float64(rep.Total) * 100
		rep.AvgMS = totalMS / float64(rep.Total)
	}
	rep.TopDomains = topItems(domains, topN)
	rep.TopBlocked = topItems(blocked, topN)
	rep.Types = topItems(types, 8)
	return rep
}

// Clients lists every address seen in the window, busiest first.
func (s *Store) Clients(since time.Time) []stats.TopItem {
	counts := map[string]int64{}
	for _, day := range s.Days() {
		if !since.IsZero() && day < dayKey(since) {
			continue
		}
		recs, err := s.readShard(day)
		if err != nil {
			continue
		}
		for _, r := range recs {
			if r.Time.Before(since) {
				continue
			}
			counts[r.Client]++
		}
	}
	return topItems(counts, 0)
}

// topItems sorts a counter map, biggest first; n <= 0 keeps everything.
func topItems(counts map[string]int64, n int) []stats.TopItem {
	out := make([]stats.TopItem, 0, len(counts))
	for k, v := range counts {
		if k == "" {
			continue
		}
		out = append(out, stats.TopItem{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
