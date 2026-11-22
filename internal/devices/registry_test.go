package devices

import (
	"net"
	"testing"
	"time"

	"github.com/ahardkore/adblockerpro/internal/config"
)

func dev(match, name, group string, paused bool) config.Device {
	return config.Device{Match: match, Name: name, Group: group, Paused: paused}
}

func TestLookupExactAddr(t *testing.T) {
	r := New([]config.Device{dev("192.168.1.42", "pi", "server", false)})
	p := r.Lookup(net.ParseIP("192.168.1.42"))
	if p.Name != "pi" || p.Group != "server" || !p.Known {
		t.Errorf("policy = %+v", p)
	}
}

func TestLookupPrefix(t *testing.T) {
	r := New([]config.Device{dev("192.168.1.0/24", "office", "iot", false)})
	p := r.Lookup(net.ParseIP("192.168.1.123"))
	if p.Name != "office" {
		t.Errorf("policy = %+v", p)
	}
	p = r.Lookup(net.ParseIP("10.0.0.1"))
	if p.Name != "" {
		t.Errorf("unexpected match: %+v", p)
	}
}

func TestMostSpecificWins(t *testing.T) {
	r := New([]config.Device{
		dev("192.168.1.0/24", "office", "all", false),
		dev("192.168.1.42", "printer", "printers", false),
	})
	p := r.Lookup(net.ParseIP("192.168.1.42"))
	if p.Name != "printer" {
		t.Errorf("policy = %+v, want exact match", p)
	}
	p = r.Lookup(net.ParseIP("192.168.1.99"))
	if p.Name != "office" {
		t.Errorf("policy = %+v, want prefix match", p)
	}
}

func TestUnparsableMatchSkipped(t *testing.T) {
	r := New([]config.Device{dev("not-an-ip", "bad", "", false)})
	p := r.Lookup(net.ParseIP("192.168.1.42"))
	if p.Known {
		t.Errorf("unparsable match should be skipped, got %+v", p)
	}
}

func TestLearnedNamesUsedWhenUnknown(t *testing.T) {
	r := New(nil)
	r.Learn("192.168.1.42", "living-room")
	p := r.Lookup(net.ParseIP("192.168.1.42"))
	if p.Name != "living-room" {
		t.Errorf("policy = %+v", p)
	}
}

func TestLearnedNameNeverOverridesExplicit(t *testing.T) {
	r := New([]config.Device{dev("192.168.1.42", "explicit", "", false)})
	r.Learn("192.168.1.42", "learned")
	p := r.Lookup(net.ParseIP("192.168.1.42"))
	if p.Name != "explicit" {
		t.Errorf("policy = %+v, explicit entry must win", p)
	}
}

func TestObserveCountsAndLearnsNames(t *testing.T) {
	r := New(nil)
	r.Observe("192.168.1.42", true)
	r.Observe("192.168.1.42", false)
	r.Learn("192.168.1.42", "tv")
	r.Observe("192.168.1.42", true)
	seen := r.Seen()
	if len(seen) != 1 {
		t.Fatalf("seen = %+v", seen)
	}
	if seen[0].Queries != 3 || seen[0].Blocked != 2 {
		t.Errorf("queries/blocked = %d/%d", seen[0].Queries, seen[0].Blocked)
	}
	if seen[0].Name != "tv" {
		t.Errorf("name = %q, want learned name", seen[0].Name)
	}
}

func TestGlobalPausePausesEverything(t *testing.T) {
	r := New([]config.Device{dev("192.168.1.0/24", "office", "", false)})
	r.PauseAll(time.Minute)
	p := r.Lookup(net.ParseIP("192.168.1.42"))
	if !p.Paused {
		t.Error("global pause should pause filters")
	}
	r.Resume()
	p = r.Lookup(net.ParseIP("192.168.1.42"))
	if p.Paused {
		t.Error("resume should clear the global pause")
	}
}

func TestPausedUntilClearsAfterExpiry(t *testing.T) {
	r := New(nil)
	r.PauseAll(time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	if until := r.PausedUntil(); !until.IsZero() {
		t.Errorf("PausedUntil = %v, want zero after expiry", until)
	}
}
