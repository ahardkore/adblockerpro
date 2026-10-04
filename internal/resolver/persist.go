package resolver

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Cache persistence: a reboot normally throws away everything the resolver
// learned, and the first minutes afterwards are slow for every device in the
// house. We write the live cache to disk on shutdown and read it back on
// start-up, dropping anything that expired while the box was off.

var cacheMagic = [8]byte{'A', 'B', 'P', 'C', 'A', 'C', 'H', 1}

// Save writes unexpired entries to path.
func (c *Cache) Save(path string) error {
	type snapshot struct {
		key     string
		msg     []byte
		expires int64
	}
	c.mu.Lock()
	items := make([]snapshot, 0, c.order.Len())
	now := time.Now()
	for el := c.order.Front(); el != nil; el = el.Next() {
		e := el.Value.(*cacheEntry)
		if now.After(e.expires) {
			continue
		}
		items = append(items, snapshot{key: e.key, msg: e.msg, expires: e.expires.UnixMilli()})
	}
	c.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	buf := make([]byte, 0, 1<<16)
	buf = append(buf, cacheMagic[:]...)
	for _, it := range items {
		if len(it.key) > 65535 || len(it.msg) > 65535 {
			continue
		}
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(it.key)))
		buf = append(buf, it.key...)
		buf = binary.BigEndian.AppendUint64(buf, uint64(it.expires))
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(it.msg)))
		buf = append(buf, it.msg...)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load restores entries written by Save, skipping any that have expired.
// It returns how many entries were restored.
func (c *Cache) Load(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(data) < len(cacheMagic) || string(data[:7]) != string(cacheMagic[:7]) {
		return 0, errors.New("resolver: not a cache file")
	}
	off := len(cacheMagic)
	now := time.Now()
	restored := 0
	for off+10 <= len(data) {
		klen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if off+klen+10 > len(data) {
			break
		}
		key := string(data[off : off+klen])
		off += klen
		expires := time.UnixMilli(int64(binary.BigEndian.Uint64(data[off : off+8])))
		off += 8
		mlen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if off+mlen > len(data) {
			break
		}
		msg := append([]byte(nil), data[off:off+mlen]...)
		off += mlen
		if now.After(expires) {
			continue
		}
		c.PutUntil(key, msg, expires)
		restored++
	}
	return restored, nil
}

// PutUntil stores a response with an explicit expiry, used when restoring a
// saved cache so entries keep their original lifetime.
func (c *Cache) PutUntil(key string, msg []byte, expires time.Time) {
	c.Put(key, msg)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*cacheEntry)
		e.expires = expires
	}
}
