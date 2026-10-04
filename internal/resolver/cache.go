package resolver

import (
	"container/list"
	"strconv"
	"sync"
	"time"

	"github.com/ahardkore/adblockerpro/internal/dnsmsg"
)

// CacheKey identifies a cached answer.
func CacheKey(name string, qtype uint16) string {
	return name + "|" + strconv.Itoa(int(qtype))
}

type cacheEntry struct {
	key     string
	msg     []byte
	ttls    dnsmsg.TTLInfo
	stored  time.Time
	expires time.Time
	rcode   uint16
}

// Cache is a bounded LRU of raw DNS responses. Entries are stored verbatim
// and aged on the way out, so replays carry honest TTLs.
type Cache struct {
	mu      sync.Mutex
	max     int
	minTTL  time.Duration
	maxTTL  time.Duration
	items   map[string]*list.Element
	order   *list.List
	hits    uint64
	misses  uint64
	stale   uint64
	evicted uint64
}

// NewCache builds a cache holding at most max entries, clamping TTLs into
// [minTTL, maxTTL].
func NewCache(max int, minTTL, maxTTL time.Duration) *Cache {
	if max <= 0 {
		max = 1
	}
	return &Cache{
		max:    max,
		minTTL: minTTL,
		maxTTL: maxTTL,
		items:  make(map[string]*list.Element, max/4+8),
		order:  list.New(),
	}
}

// Put stores a response. Responses with no TTL-bearing records (or an
// unparseable body) are not cached.
func (c *Cache) Put(key string, msg []byte) {
	info, err := dnsmsg.ScanTTLs(msg)
	if err != nil || info.Records == 0 {
		return
	}
	h, err := dnsmsg.ParseHeader(msg)
	if err != nil {
		return
	}
	ttl := time.Duration(info.MinTTL) * time.Second
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	if c.maxTTL > 0 && ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	if ttl <= 0 {
		return
	}

	stored := append([]byte(nil), msg...)
	now := time.Now()
	e := &cacheEntry{
		key:     key,
		msg:     stored,
		ttls:    info,
		stored:  now,
		expires: now.Add(ttl),
		rcode:   h.Rcode(),
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value = e
		c.order.MoveToFront(el)
		return
	}
	c.items[key] = c.order.PushFront(e)
	for c.order.Len() > c.max {
		last := c.order.Back()
		if last == nil {
			break
		}
		c.order.Remove(last)
		delete(c.items, last.Value.(*cacheEntry).key)
		c.evicted++
	}
}

// Get returns a fresh copy of the cached response with TTLs aged. When
// allowStale is true an expired entry may still be returned (flagged by the
// second result) so the LAN keeps working while upstreams are down.
func (c *Cache) Get(key string, allowStale bool) (msg []byte, stale bool, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, found := c.items[key]
	if !found {
		c.misses++
		return nil, false, false
	}
	e := el.Value.(*cacheEntry)
	now := time.Now()
	expired := now.After(e.expires)
	if expired && !allowStale {
		c.order.Remove(el)
		delete(c.items, key)
		c.misses++
		return nil, false, false
	}
	c.order.MoveToFront(el)
	out := append([]byte(nil), e.msg...)
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	dnsmsg.AgeTTLs(out, e.ttls, elapsed)
	if expired {
		// Stale answers get a short TTL so clients come back soon.
		dnsmsg.SetTTLs(out, e.ttls, 30)
		c.stale++
		return out, true, true
	}
	c.hits++
	return out, false, true
}

// Delete drops one entry.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
}

// Flush empties the cache.
func (c *Cache) Flush() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.order.Len()
	c.items = make(map[string]*list.Element, c.max/4+8)
	c.order.Init()
	return n
}

// CacheStats is a snapshot of cache counters.
type CacheStats struct {
	Entries int     `json:"entries"`
	Max     int     `json:"max"`
	Hits    uint64  `json:"hits"`
	Misses  uint64  `json:"misses"`
	Stale   uint64  `json:"stale"`
	Evicted uint64  `json:"evicted"`
	HitRate float64 `json:"hit_rate"`
}

// Stats returns the current counters.
func (c *Cache) Stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := CacheStats{
		Entries: c.order.Len(),
		Max:     c.max,
		Hits:    c.hits,
		Misses:  c.misses,
		Stale:   c.stale,
		Evicted: c.evicted,
	}
	if total := s.Hits + s.Misses; total > 0 {
		s.HitRate = float64(s.Hits) / float64(total) * 100
	}
	return s
}
