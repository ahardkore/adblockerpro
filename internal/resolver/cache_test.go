package resolver

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ahardkore/adblockerpro/internal/dnsmsg"
)

func answer(t *testing.T, name, ip string, ttl uint32) []byte {
	t.Helper()
	enc, err := dnsmsg.EncodeName(name)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg := make([]byte, dnsmsg.HeaderLen)
	binary.BigEndian.PutUint16(msg[0:2], 1)
	binary.BigEndian.PutUint16(msg[2:4], dnsmsg.FlagQR|dnsmsg.FlagRD|dnsmsg.FlagRA)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	binary.BigEndian.PutUint16(msg[6:8], 1)
	msg = append(msg, enc...)
	msg = binary.BigEndian.AppendUint16(msg, dnsmsg.TypeA)
	msg = binary.BigEndian.AppendUint16(msg, dnsmsg.ClassINET)
	msg = append(msg, 0xC0, 0x0C)
	msg = binary.BigEndian.AppendUint16(msg, dnsmsg.TypeA)
	msg = binary.BigEndian.AppendUint16(msg, dnsmsg.ClassINET)
	msg = binary.BigEndian.AppendUint32(msg, ttl)
	msg = binary.BigEndian.AppendUint16(msg, 4)
	msg = append(msg, net.ParseIP(ip).To4()...)
	return msg
}

func TestCachePutGet(t *testing.T) {
	c := NewCache(10, time.Second, time.Hour)
	key := CacheKey("example.com", dnsmsg.TypeA)
	c.Put(key, answer(t, "example.com", "93.184.216.34", 300))

	got, stale, ok := c.Get(key, false)
	if !ok || stale {
		t.Fatalf("expected a fresh hit, ok=%v stale=%v", ok, stale)
	}
	if ip := dnsmsg.FirstAnswer(got); ip != "93.184.216.34" {
		t.Errorf("answer = %q", ip)
	}
	if _, _, ok := c.Get(CacheKey("other.com", dnsmsg.TypeA), false); ok {
		t.Error("unexpected hit for a different key")
	}
	if s := c.Stats(); s.Hits != 1 || s.Misses != 1 {
		t.Errorf("stats = %+v", s)
	}
}

func TestCacheEviction(t *testing.T) {
	c := NewCache(2, time.Second, time.Hour)
	for _, n := range []string{"a.example", "b.example", "c.example"} {
		c.Put(CacheKey(n, dnsmsg.TypeA), answer(t, n, "1.2.3.4", 300))
	}
	if s := c.Stats(); s.Entries != 2 || s.Evicted != 1 {
		t.Errorf("stats = %+v, want 2 entries and 1 eviction", s)
	}
	if _, _, ok := c.Get(CacheKey("a.example", dnsmsg.TypeA), false); ok {
		t.Error("the oldest entry should have been evicted")
	}
}

func TestCacheExpiryAndStale(t *testing.T) {
	c := NewCache(10, 0, time.Hour)
	key := CacheKey("short.example", dnsmsg.TypeA)
	// A zero TTL answer is clamped to the minimum, so build it expired by
	// using a 1 second TTL and waiting it out.
	c.Put(key, answer(t, "short.example", "1.2.3.4", 1))
	time.Sleep(1100 * time.Millisecond)

	if _, _, ok := c.Get(key, false); ok {
		t.Error("expired entry should be a miss")
	}
	c.Put(key, answer(t, "short.example", "1.2.3.4", 1))
	time.Sleep(1100 * time.Millisecond)
	got, stale, ok := c.Get(key, true)
	if !ok || !stale {
		t.Fatalf("expected a stale hit, ok=%v stale=%v", ok, stale)
	}
	info, _ := dnsmsg.ScanTTLs(got)
	if info.MinTTL != 30 {
		t.Errorf("stale TTL = %d, want 30", info.MinTTL)
	}
}

func TestCacheFlush(t *testing.T) {
	c := NewCache(10, time.Second, time.Hour)
	c.Put(CacheKey("a.example", dnsmsg.TypeA), answer(t, "a.example", "1.2.3.4", 300))
	if n := c.Flush(); n != 1 {
		t.Errorf("flushed %d, want 1", n)
	}
	if c.Stats().Entries != 0 {
		t.Error("cache should be empty")
	}
}

func TestCacheKey(t *testing.T) {
	if CacheKey("a.example", dnsmsg.TypeA) == CacheKey("a.example", dnsmsg.TypeAAAA) {
		t.Error("key must include the query type")
	}
}
