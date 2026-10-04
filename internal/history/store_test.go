package history

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ahardkore/adblockerpro/internal/stats"
)

func entry(domain, client string, status stats.Status, t time.Time) stats.Entry {
	return stats.Entry{
		Time: t, Client: client, Device: "TV", Domain: domain, Type: "A",
		Status: status, Rule: domain, Source: "TestList", Upstream: "stub", MS: 1.5,
	}
}

func TestAppendAndQuery(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 7)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Now()
	for i := 0; i < 10; i++ {
		st := stats.StatusAllowed
		if i%2 == 0 {
			st = stats.StatusBlocked
		}
		if err := s.Append(entry("d"+string(rune('a'+i))+".example", "192.168.1.5", st, now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	page, err := s.Query(Filter{Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if page.Total != 10 || len(page.Records) != 10 {
		t.Fatalf("total=%d returned=%d, want 10/10", page.Total, len(page.Records))
	}
	// Newest first.
	if !page.Records[0].Time.After(page.Records[9].Time) {
		t.Error("records are not newest-first")
	}
	if page.Records[0].Domain != "dj.example" {
		t.Errorf("first record = %q", page.Records[0].Domain)
	}
	if page.Records[0].Device != "TV" || page.Records[0].Source != "TestList" {
		t.Errorf("fields did not round-trip: %+v", page.Records[0])
	}

	blocked, _ := s.Query(Filter{Status: stats.StatusBlocked, Limit: 100})
	if blocked.Total != 5 {
		t.Errorf("blocked total = %d, want 5", blocked.Total)
	}

	search, _ := s.Query(Filter{Search: "da.example", Limit: 100})
	if search.Total != 1 {
		t.Errorf("search total = %d, want 1", search.Total)
	}
}

func TestQueryPagination(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 7)
	defer s.Close()

	now := time.Now()
	for i := 0; i < 25; i++ {
		_ = s.Append(entry("x.example", "10.0.0.1", stats.StatusAllowed, now.Add(time.Duration(i)*time.Second)))
	}
	first, _ := s.Query(Filter{Limit: 10})
	if len(first.Records) != 10 || !first.HasMore {
		t.Fatalf("page 1: %d records, hasMore=%v", len(first.Records), first.HasMore)
	}
	second, _ := s.Query(Filter{Limit: 10, Offset: 20})
	if len(second.Records) != 5 {
		t.Errorf("page 3: %d records, want 5", len(second.Records))
	}
	if second.Total != 25 {
		t.Errorf("total = %d, want 25", second.Total)
	}
}

func TestTimeRangeFilter(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 7)
	defer s.Close()

	now := time.Now()
	_ = s.Append(entry("old.example", "10.0.0.1", stats.StatusAllowed, now.Add(-2*time.Hour)))
	_ = s.Append(entry("new.example", "10.0.0.1", stats.StatusAllowed, now))

	page, _ := s.Query(Filter{From: now.Add(-time.Hour), Limit: 10})
	if page.Total != 1 || page.Records[0].Domain != "new.example" {
		t.Errorf("range filter returned %+v", page.Records)
	}
}

func TestDailyRollup(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 7)
	defer s.Close()

	now := time.Now()
	_ = s.Append(entry("a.example", "10.0.0.1", stats.StatusBlocked, now))
	_ = s.Append(entry("b.example", "10.0.0.2", stats.StatusCached, now))
	_ = s.Append(entry("c.example", "10.0.0.2", stats.StatusAllowed, now))
	_ = s.Flush()

	days := s.Daily(7)
	if len(days) == 0 {
		t.Fatal("no daily rollups")
	}
	today := days[len(days)-1]
	if today.Total != 3 || today.Blocked != 1 || today.Cached != 1 || today.Clients != 2 {
		t.Errorf("rollup = %+v", today)
	}

	top := s.TopDomains(now.Add(-time.Hour), true, 5)
	if len(top) != 1 || top[0].Name != "a.example" {
		t.Errorf("top blocked = %+v", top)
	}
}

func TestPruneRemovesOldShards(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 2)
	defer s.Close()

	old := filepath.Join(dir, "2000-01-01.log")
	if err := os.WriteFile(old, fileMagic[:], 0o644); err != nil {
		t.Fatal(err)
	}
	_ = s.Append(entry("today.example", "10.0.0.1", stats.StatusAllowed, time.Now()))
	if err := s.Prune(); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("an out-of-retention shard survived the prune")
	}
	if page, _ := s.Query(Filter{Limit: 10}); page.Total != 1 {
		t.Errorf("today's records should survive, got %d", page.Total)
	}
}

func TestReopenKeepsRecords(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 7)
	_ = s.Append(entry("persist.example", "10.0.0.1", stats.StatusBlocked, time.Now()))
	_ = s.Close()

	s2, err := Open(dir, 7)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	_ = s2.Append(entry("second.example", "10.0.0.1", stats.StatusAllowed, time.Now()))

	page, _ := s2.Query(Filter{Limit: 10})
	if page.Total != 2 {
		t.Errorf("total after reopen = %d, want 2", page.Total)
	}
}

func TestTruncatedTailIsTolerated(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 7)
	_ = s.Append(entry("good.example", "10.0.0.1", stats.StatusAllowed, time.Now()))
	_ = s.Flush()
	day := dayKey(time.Now())
	path := s.shardPath(day)
	_ = s.Close()

	// Simulate a power cut mid-write.
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(data, 0, 0, 1, 200, 'x'), 0o644); err != nil {
		t.Fatal(err)
	}

	s2, _ := Open(dir, 7)
	defer s2.Close()
	page, _ := s2.Query(Filter{Limit: 10})
	if page.Total != 1 {
		t.Errorf("total = %d, want the one intact record", page.Total)
	}
}

func TestExportJSONL(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 7)
	defer s.Close()
	_ = s.Append(entry("export.example", "10.0.0.1", stats.StatusBlocked, time.Now()))

	var buf bytes.Buffer
	if err := s.Export(&buf, time.Time{}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if !strings.Contains(buf.String(), "export.example") {
		t.Errorf("export missing the record: %s", buf.String())
	}
	if lines := strings.Count(strings.TrimSpace(buf.String()), "\n"); lines != 0 {
		t.Errorf("expected exactly one JSON line, got %d extra newlines", lines)
	}
}
