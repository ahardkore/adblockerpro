// Package devices maps client IP addresses to the policy that applies to
// them: which rule group they belong to and whether filtering is paused.
package devices

import (
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ahardkore/adblockerpro/internal/config"
)

// Policy is the resolved policy for a client.
type Policy struct {
	Name     string
	Group    string
	Paused   bool
	Known    bool
	MatchedBy string
}

type entry struct {
	prefix netip.Prefix
	addr   netip.Addr
	dev    config.Device
}

// Seen records activity for a client we have not been told about, which
// powers the "discovered devices" view in the dashboard.
type Seen struct {
	IP      string    `json:"ip"`
	First   time.Time `json:"first_seen"`
	Last    time.Time `json:"last_seen"`
	Queries int64     `json:"queries"`
	Blocked int64     `json:"blocked"`
	Name    string    `json:"name,omitempty"`
	Group   string    `json:"group,omitempty"`
	Paused  bool      `json:"paused"`
}

// Registry resolves client addresses to policies and tracks what it sees.
type Registry struct {
	mu      sync.RWMutex
	entries []entry
	seen    map[string]*Seen
	// globalPauseUntil pauses filtering for every client.
	globalPauseUntil time.Time
}

// New builds a registry from the configured devices.
func New(devs []config.Device) *Registry {
	r := &Registry{seen: map[string]*Seen{}}
	r.Set(devs)
	return r
}

// Set replaces the device table.
func (r *Registry) Set(devs []config.Device) {
	entries := make([]entry, 0, len(devs))
	for _, d := range devs {
		m := strings.TrimSpace(d.Match)
		if m == "" {
			continue
		}
		if strings.Contains(m, "/") {
			if p, err := netip.ParsePrefix(m); err == nil {
				entries = append(entries, entry{prefix: p, dev: d})
			}
			continue
		}
		if a, err := netip.ParseAddr(m); err == nil {
			entries = append(entries, entry{addr: a, dev: d})
		}
	}
	// Most specific first: exact addresses, then longer prefixes.
	sort.SliceStable(entries, func(i, j int) bool {
		bi, bj := entries[i].prefix.Bits(), entries[j].prefix.Bits()
		if entries[i].addr.IsValid() {
			bi = 129
		}
		if entries[j].addr.IsValid() {
			bj = 129
		}
		return bi > bj
	})

	r.mu.Lock()
	r.entries = entries
	// Refresh names on anything already seen.
	for ip, s := range r.seen {
		if a, err := netip.ParseAddr(ip); err == nil {
			if p, ok := lookup(entries, a); ok {
				s.Name, s.Group, s.Paused = p.Name, p.Group, p.Paused
			} else {
				s.Name, s.Group, s.Paused = "", "", false
			}
		}
	}
	r.mu.Unlock()
}

func lookup(entries []entry, a netip.Addr) (Policy, bool) {
	a = a.Unmap()
	for _, e := range entries {
		switch {
		case e.addr.IsValid() && e.addr.Unmap() == a:
			return Policy{Name: e.dev.Name, Group: e.dev.Group, Paused: e.dev.Paused, Known: true, MatchedBy: e.dev.Match}, true
		case e.prefix.IsValid() && e.prefix.Contains(a):
			return Policy{Name: e.dev.Name, Group: e.dev.Group, Paused: e.dev.Paused, Known: true, MatchedBy: e.dev.Match}, true
		}
	}
	return Policy{}, false
}

// Lookup resolves the policy for a client address.
func (r *Registry) Lookup(ip net.IP) Policy {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return Policy{}
	}
	r.mu.RLock()
	entries := r.entries
	paused := time.Now().Before(r.globalPauseUntil)
	r.mu.RUnlock()

	p, _ := lookup(entries, a.Unmap())
	if paused {
		p.Paused = true
	}
	return p
}

// Observe records a query from a client for the discovered-devices view.
func (r *Registry) Observe(ip string, blocked bool) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.seen[ip]
	if !ok {
		s = &Seen{IP: ip, First: now}
		if a, err := netip.ParseAddr(ip); err == nil {
			if p, found := lookup(r.entries, a); found {
				s.Name, s.Group, s.Paused = p.Name, p.Group, p.Paused
			}
		}
		// Keep the table bounded on busy networks.
		if len(r.seen) > 4096 {
			oldest, oldestTime := "", now
			for k, v := range r.seen {
				if v.Last.Before(oldestTime) {
					oldest, oldestTime = k, v.Last
				}
			}
			delete(r.seen, oldest)
		}
		r.seen[ip] = s
	}
	s.Last = now
	s.Queries++
	if blocked {
		s.Blocked++
	}
}

// Seen returns every client observed since start-up, busiest first.
func (r *Registry) Seen() []Seen {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Seen, 0, len(r.seen))
	for _, s := range r.seen {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Queries > out[j].Queries })
	return out
}

// PauseAll disables filtering network-wide for d.
func (r *Registry) PauseAll(d time.Duration) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.globalPauseUntil = time.Now().Add(d)
	return r.globalPauseUntil
}

// Resume re-enables filtering network-wide.
func (r *Registry) Resume() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.globalPauseUntil = time.Time{}
}

// PausedUntil reports the global pause deadline, zero when filtering is on.
func (r *Registry) PausedUntil() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if time.Now().After(r.globalPauseUntil) {
		return time.Time{}
	}
	return r.globalPauseUntil
}
