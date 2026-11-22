package stats

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHashClientIsDeterministicAndStable(t *testing.T) {
	a := HashClient("192.168.1.10")
	b := HashClient("192.168.1.10")
	c := HashClient("192.168.1.11")
	if a != b {
		t.Error("HashClient is not deterministic")
	}
	if a == c {
		t.Error("distinct client addresses hash identically")
	}
	if len(a) != len("anon-")+8 {
		t.Errorf("hash = %q, want anon-<8 hex chars>", a)
	}
}

func TestRecordAnonymizesClients(t *testing.T) {
	c := New(10, true)
	c.Record(Entry{Time: time.Now(), Client: "192.168.1.42", Domain: "ads.example", Type: "A", Status: StatusBlocked})
	entries := c.Recent(QueryFilter{Limit: 1})
	if len(entries) != 1 {
		t.Fatal("no entries returned")
	}
	if entries[0].Client == "192.168.1.42" {
		t.Error("client was stored verbatim with privacy mode on")
	}
	if entries[0].Client != HashClient("192.168.1.42") {
		t.Errorf("client = %q, want pseudonym %q", entries[0].Client, HashClient("192.168.1.42"))
	}
}

func TestRecordKeepsClientsWhenNotAnonymized(t *testing.T) {
	c := New(10, false)
	c.Record(Entry{Time: time.Now(), Client: "192.168.1.42", Domain: "ads.example", Type: "A", Status: StatusAllowed})
	entries := c.Recent(QueryFilter{Limit: 1})
	if entries[0].Client != "192.168.1.42" {
		t.Errorf("client = %q, want verbatim address", entries[0].Client)
	}
}

func TestRecentMatchesRawOrPseudonym(t *testing.T) {
	c := New(10, true)
	c.Record(Entry{Time: time.Now(), Client: "192.168.1.42", Domain: "ads.example", Type: "A", Status: StatusBlocked})

	// Querying by the raw address must match the stored pseudonym.
	hit := c.Recent(QueryFilter{Limit: 1, Client: "192.168.1.42"})
	if len(hit) != 1 {
		t.Error("raw client address did not match the stored pseudonym")
	}
	// Querying by the pseudonym directly must also match.
	hit = c.Recent(QueryFilter{Limit: 1, Client: HashClient("192.168.1.42")})
	if len(hit) != 1 {
		t.Error("pseudonym did not match its own entry")
	}
	// Unrelated clients must not match.
	hit = c.Recent(QueryFilter{Limit: 1, Client: "192.168.1.99"})
	if len(hit) != 0 {
		t.Error("unrelated client matched")
	}
}

func TestCountersAndSummary(t *testing.T) {
	c := New(10, false)
	for i := 0; i < 3; i++ {
		c.Record(Entry{Time: time.Now(), Client: "1.2.3.4", Domain: "ads.example", Type: "A", Status: StatusBlocked})
	}
	c.Record(Entry{Time: time.Now(), Client: "5.6.7.8", Domain: "example.com", Type: "A", Status: StatusCached})
	s := c.Summary(24)
	if s.Total != 4 || s.Blocked != 3 || s.Cached != 1 || s.Errors != 0 {
		t.Errorf("summary = %+v", s)
	}
	if s.Clients != 2 {
		t.Errorf("clients = %d, want 2", s.Clients)
	}
	if len(s.Timeline) == 0 {
		t.Error("timeline is empty")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := New(100, false)
	c.SetPersistPath(dir)
	c.Record(Entry{Time: time.Now(), Client: "1.2.3.4", Domain: "ads.example", Type: "A", Status: StatusBlocked})
	c.Record(Entry{Time: time.Now(), Client: "5.6.7.8", Domain: "example.com", Type: "A", Status: StatusCached})
	if err := c.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// The stats file holds client addresses, so it must be owner-only.
	fi, err := os.Stat(filepath.Join(dir, "stats.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("stats.json mode = %o, want 600", fi.Mode().Perm())
	}

	d := New(100, false)
	if err := d.Load(dir); err != nil {
		t.Fatalf("load: %v", err)
	}
	s := d.Summary(24)
	if s.Total != 2 {
		t.Errorf("restored Total = %d, want 2", s.Total)
	}
}

func TestLoadMissingFileIsNotFatal(t *testing.T) {
	d := New(10, false)
	if err := d.Load(t.TempDir()); err == nil {
		t.Error("Load of a missing file should return an error")
	}
}

func TestResetClearsCounters(t *testing.T) {
	c := New(10, false)
	c.Record(Entry{Time: time.Now(), Client: "1.2.3.4", Domain: "ads.example", Type: "A", Status: StatusBlocked})
	c.Reset()
	if s := c.Summary(24); s.Total != 0 || len(c.Recent(QueryFilter{Limit: 10})) != 0 {
		t.Errorf("after reset, summary = %+v", s)
	}
}

func TestRingBufferWraps(t *testing.T) {
	c := New(3, false)
	for i := 0; i < 10; i++ {
		c.Record(Entry{Time: time.Now(), Client: "1.2.3.4", Domain: "domain.example", Type: "A", Status: StatusAllowed})
	}
	if got := len(c.Recent(QueryFilter{Limit: 10})); got != 3 {
		t.Errorf("recent = %d entries, want 3", got)
	}
}
