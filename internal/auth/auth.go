// Package auth handles dashboard credentials: PBKDF2 password hashing,
// server-side sessions and brute-force throttling.
//
// The first version of this project kept a plaintext token in the config
// file and compared it on every request. That is fine on a trusted LAN and
// bad everywhere else, so passwords are now stored hashed and the browser
// gets an opaque session cookie instead of the secret itself.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultIterations is the PBKDF2 work factor. 210 000 is the OWASP
// recommendation for PBKDF2-HMAC-SHA256 and takes ~120 ms on a Pi 4, which
// is a fine price for a login that happens once a month.
const DefaultIterations = 210000

// ErrBadHash means the stored hash is not in our format.
var ErrBadHash = errors.New("auth: malformed password hash")

// pbkdf2 implements PBKDF2-HMAC-SHA256 (RFC 8018) on top of the standard
// library, so the binary keeps its zero-dependency promise.
func pbkdf2(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)

	buf := make([]byte, 4)
	u := make([]byte, hashLen)
	t := make([]byte, hashLen)

	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(block))
		prf.Write(buf)
		u = prf.Sum(u[:0])
		copy(t, u)

		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// HashPassword returns an encoded hash of the form
// pbkdf2-sha256$iterations$salt$key, all base64 raw-std encoded.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("auth: password must be at least 8 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2([]byte(password), salt, DefaultIterations, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s",
		DefaultIterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against an encoded hash in constant time.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1000 || iterations > 5_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := pbkdf2([]byte(password), salt, iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NewToken returns a URL-safe random secret, used for API tokens and
// session identifiers.
func NewToken(nbytes int) (string, error) {
	if nbytes <= 0 {
		nbytes = 32
	}
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

/* ------------------------------ sessions ------------------------------ */

type session struct {
	expires time.Time
	client  string
}

// Sessions is an in-memory session store. Sessions do not survive a restart,
// which for a home appliance is the right trade: no session secrets on disk.
type Sessions struct {
	mu   sync.Mutex
	ttl  time.Duration
	byID map[string]session
}

// NewSessions creates a store whose sessions live for ttl.
func NewSessions(ttl time.Duration) *Sessions {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	return &Sessions{ttl: ttl, byID: map[string]session{}}
}

// Create issues a new session for a client address.
func (s *Sessions) Create(client string) (string, time.Time, error) {
	id, err := NewToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expires := time.Now().Add(s.ttl)
	s.mu.Lock()
	s.sweepLocked()
	s.byID[id] = session{expires: expires, client: client}
	s.mu.Unlock()
	return id, expires, nil
}

// Valid reports whether a session id is live, refreshing its deadline.
func (s *Sessions) Valid(id string) bool {
	if id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return false
	}
	if time.Now().After(sess.expires) {
		delete(s.byID, id)
		return false
	}
	sess.expires = time.Now().Add(s.ttl)
	s.byID[id] = sess
	return true
}

// Revoke ends one session.
func (s *Sessions) Revoke(id string) {
	s.mu.Lock()
	delete(s.byID, id)
	s.mu.Unlock()
}

// RevokeAll ends every session, e.g. after a password change.
func (s *Sessions) RevokeAll() {
	s.mu.Lock()
	s.byID = map[string]session{}
	s.mu.Unlock()
}

// Count returns the number of live sessions.
func (s *Sessions) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	return len(s.byID)
}

func (s *Sessions) sweepLocked() {
	now := time.Now()
	for id, sess := range s.byID {
		if now.After(sess.expires) {
			delete(s.byID, id)
		}
	}
}

/* ----------------------------- throttling ------------------------------ */

type attempt struct {
	count int
	until time.Time
}

// Throttle slows down password guessing: after a handful of failures from
// one address, that address is locked out for a while.
type Throttle struct {
	mu       sync.Mutex
	attempts map[string]*attempt
	max      int
	window   time.Duration
}

// NewThrottle allows max failures per window per client.
func NewThrottle(max int, window time.Duration) *Throttle {
	if max <= 0 {
		max = 5
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &Throttle{attempts: map[string]*attempt{}, max: max, window: window}
}

// Allowed reports whether a client may try again, and how long it must wait
// if not.
func (t *Throttle) Allowed(client string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.attempts[client]
	if !ok {
		return true, 0
	}
	if time.Now().After(a.until) {
		delete(t.attempts, client)
		return true, 0
	}
	if a.count >= t.max {
		return false, time.Until(a.until)
	}
	return true, 0
}

// Fail records a failed attempt.
func (t *Throttle) Fail(client string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.attempts[client]
	if !ok || time.Now().After(a.until) {
		a = &attempt{}
		t.attempts[client] = a
	}
	a.count++
	a.until = time.Now().Add(t.window)
}

// Succeed clears the failure count for a client.
func (t *Throttle) Succeed(client string) {
	t.mu.Lock()
	delete(t.attempts, client)
	t.mu.Unlock()
}
