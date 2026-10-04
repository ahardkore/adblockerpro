package resolver

import (
	"context"
	"sync"
	"sync/atomic"
)

// Group coalesces identical in-flight lookups.
//
// When a TV, a phone and a laptop all ask for the same CDN hostname inside
// the same 20 ms — which is exactly what happens when a household starts
// streaming — only the first query goes upstream and the others wait for
// that answer. On a busy LAN this cuts upstream traffic noticeably and
// removes a whole class of duplicate-query latency.
type Group struct {
	mu    sync.Mutex
	calls map[string]*call

	shared  atomic.Uint64
	started atomic.Uint64
}

type call struct {
	done chan struct{}
	resp []byte
	name string
	err  error
}

// NewGroup returns an empty coalescing group.
func NewGroup() *Group { return &Group{calls: map[string]*call{}} }

// Do runs fn for key, or waits for an identical call already in flight.
// The returned bool reports whether this caller shared someone else's work.
//
// The response is copied for every waiter, so callers may rewrite the
// transaction id in place without stepping on each other.
func (g *Group) Do(ctx context.Context, key string, fn func() ([]byte, string, error)) ([]byte, string, bool, error) {
	g.mu.Lock()
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		g.shared.Add(1)
		select {
		case <-c.done:
			if c.err != nil {
				return nil, c.name, true, c.err
			}
			return append([]byte(nil), c.resp...), c.name, true, nil
		case <-ctx.Done():
			return nil, "", true, ctx.Err()
		}
	}
	c := &call{done: make(chan struct{})}
	g.calls[key] = c
	g.mu.Unlock()
	g.started.Add(1)

	c.resp, c.name, c.err = fn()

	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()
	close(c.done)

	if c.err != nil {
		return nil, c.name, false, c.err
	}
	return append([]byte(nil), c.resp...), c.name, false, nil
}

// InFlight reports how many distinct lookups are running right now.
func (g *Group) InFlight() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.calls)
}

// Stats returns how many lookups were started and how many were served by
// piggybacking on another caller's lookup.
func (g *Group) Stats() (started, shared uint64) {
	return g.started.Load(), g.shared.Load()
}
