package resolver

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ahardkore/adblockerpro/internal/dnsmsg"
)

// answer builds a minimal A response for name with the given TTL, which is
// enough for the cache to consider it storable.
func persistAnswer(t *testing.T, name string, ttl uint32) []byte {
	t.Helper()
	enc, err := dnsmsg.EncodeName(name)
	if err != nil {
		t.Fatalf("encode %q: %v", name, err)
	}
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180) // response, recursion
	binary.BigEndian.PutUint16(msg[4:6], 1)      // qdcount
	binary.BigEndian.PutUint16(msg[6:8], 1)      // ancount
	msg = append(msg, enc...)
	msg = binary.BigEndian.AppendUint16(msg, 1) // A
	msg = binary.BigEndian.AppendUint16(msg, 1) // IN
	msg = append(msg, enc...)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	msg = binary.BigEndian.AppendUint32(msg, ttl)
	msg = binary.BigEndian.AppendUint16(msg, 4)
	msg = append(msg, 93, 184, 216, 34)
	return msg
}

func TestCacheSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.bin")

	src := NewCache(100, time.Second, time.Hour)
	src.Put(CacheKey("example.com", 1), persistAnswer(t, "example.com", 300))
	src.Put(CacheKey("example.org", 1), persistAnswer(t, "example.org", 300))
	if err := src.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	dst := NewCache(100, time.Second, time.Hour)
	n, err := dst.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n != 2 {
		t.Fatalf("restored %d entries, want 2", n)
	}
	for _, name := range []string{"example.com", "example.org"} {
		if _, ok, _ := dst.Get(CacheKey(name, 1), false); !ok {
			t.Errorf("%s was not restored", name)
		}
	}
}

// TestCacheSaveSkipsExpired: a cache file written before a long power cut
// must not resurrect stale answers.
func TestCacheLoadDropsExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.bin")

	c := NewCache(10, time.Second, time.Hour)
	key := CacheKey("gone.example", 1)
	c.PutUntil(key, persistAnswer(t, "gone.example", 300), time.Now().Add(-time.Minute))
	if err := c.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	dst := NewCache(10, time.Second, time.Hour)
	n, err := dst.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n != 0 {
		t.Errorf("restored %d expired entries, want 0", n)
	}
}

func TestCacheLoadRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.bin")
	if err := os.WriteFile(path, []byte("this is not a cache file at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewCache(10, time.Second, time.Hour)
	if _, err := c.Load(path); err == nil {
		t.Error("expected an error for a non-cache file")
	}

	// A truncated but otherwise valid file must not panic.
	good := NewCache(10, time.Second, time.Hour)
	good.Put(CacheKey("example.com", 1), persistAnswer(t, "example.com", 300))
	if err := good.Save(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data[:len(data)-5], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCache(10, time.Second, time.Hour).Load(path); err != nil {
		t.Errorf("truncated file should load what it can: %v", err)
	}
}

func TestCacheLoadMissingFile(t *testing.T) {
	c := NewCache(10, time.Second, time.Hour)
	if _, err := c.Load(filepath.Join(t.TempDir(), "nope.bin")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestPutUntilKeepsExpiry(t *testing.T) {
	c := NewCache(10, time.Second, time.Hour)
	key := CacheKey("example.com", 1)
	want := time.Now().Add(42 * time.Second).Truncate(time.Millisecond)
	c.PutUntil(key, persistAnswer(t, "example.com", 300), want)

	keys := c.ExpiringSoon(time.Minute, 0, 10)
	if len(keys) != 1 || keys[0] != key {
		t.Fatalf("ExpiringSoon = %v, want [%s]", keys, key)
	}
	// The marker must stop a second pass from returning the same key.
	if again := c.ExpiringSoon(time.Minute, 0, 10); len(again) != 0 {
		t.Errorf("key returned twice: %v", again)
	}
	c.FinishPrefetch(key)
	if again := c.ExpiringSoon(time.Minute, 0, 10); len(again) != 1 {
		t.Error("FinishPrefetch did not clear the marker")
	}
}

func TestExpiringSoonRespectsHits(t *testing.T) {
	c := NewCache(10, time.Second, time.Hour)
	key := CacheKey("example.com", 1)
	c.PutUntil(key, persistAnswer(t, "example.com", 300), time.Now().Add(10*time.Second))

	if got := c.ExpiringSoon(time.Minute, 3, 10); len(got) != 0 {
		t.Fatalf("unpopular entry queued for prefetch: %v", got)
	}
	for i := 0; i < 3; i++ {
		c.Get(key, false)
	}
	if got := c.ExpiringSoon(time.Minute, 3, 10); len(got) != 1 {
		t.Errorf("popular entry not queued: %v", got)
	}
}

func TestSplitCacheKey(t *testing.T) {
	name, qtype, ok := SplitCacheKey(CacheKey("example.com", 28))
	if !ok || name != "example.com" || qtype != 28 {
		t.Errorf("SplitCacheKey = (%q,%d,%v)", name, qtype, ok)
	}
	if _, _, ok := SplitCacheKey("nonsense"); ok {
		t.Error("expected failure for a key with no separator")
	}
	if _, _, ok := SplitCacheKey("example.com|notanumber"); ok {
		t.Error("expected failure for a non-numeric qtype")
	}
}
