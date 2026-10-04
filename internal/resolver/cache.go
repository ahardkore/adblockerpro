package resolver

import (
	"container/list"
	"strconv"
	"strings"
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
	// hits counts how often this entry has been served, which is what
	// makes it a candidate for prefetching before it expires.
	hits int
	// prefetching guards against queuing the same refresh twice.
	prefetching bool
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
	hits       uint64
	misses     uint64
	stale      uint64
	evicted    uint64
	prefetched uint64
}

// CountPrefetch records a successful background refresh.
func (c *Cache) CountPrefetch() {
	c.mu.Lock()
	c.prefetched++
	c.mu.Unlock()
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
		// Keep the entry: if every upstream turns out to be down the caller
		// comes straight back with allowStale set, and an expired answer
		// beats no answer at all. The LRU reclaims it eventually.
		c.misses++
		return nil, false, false
	}
	c.order.MoveToFront(el)
	e.hits++
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

// ExpiringSoon returns the keys of popular entries that are about to
// expire, so they can be refreshed before anyone notices. Each key is
// returned at most once per refresh cycle.
func (c *Cache) ExpiringSoon(window time.Duration, minHits, max int) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	out := make([]string, 0, max)
	for el := c.order.Front(); el != nil && len(out) < max; el = el.Next() {
		e := el.Value.(*cacheEntry)
		if e.prefetching || e.hits < minHits {
			continue
		}
		if e.expires.After(now) && e.expires.Sub(now) <= window {
			e.prefetching = true
			out = append(out, e.key)
		}
	}
	return out
}

// FinishPrefetch clears the in-progress marker for a key.
func (c *Cache) FinishPrefetch(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value.(*cacheEntry).prefetching = false
	}
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
	Entries   int    `json:"entries"`
	Prefetched uint64 `json:"prefetched"`
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
		Entries:    c.order.Len(),
		Prefetched: c.prefetched,
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

// SplitCacheKey reverses CacheKey.
func SplitCacheKey(key string) (name string, qtype uint16, ok bool) {
	i := strings.LastIndexByte(key, '|')
	if i <= 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(key[i+1:])
	if err != nil || n < 0 || n > 65535 {
		return "", 0, false
	}
	return key[:i], uint16(n), true
}
