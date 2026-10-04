package auth

import (
	"encoding/hex"
	"testing"
	"time"
)

// TestPBKDF2Vectors checks our hand-rolled PBKDF2 against the published
// RFC 6070-style vectors for HMAC-SHA256, because a wrong KDF would still
// "work" while silently being weak.
func TestPBKDF2Vectors(t *testing.T) {
	cases := []struct {
		password, salt string
		iter, keyLen   int
		want           string
	}{
		{"password", "salt", 1, 32,
			"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{"password", "salt", 2, 32,
			"ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{"password", "salt", 4096, 32,
			"c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
		{"passwd", "salt", 1, 64,
			"55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
				"49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(pbkdf2([]byte(c.password), []byte(c.salt), c.iter, c.keyLen))
		if got != c.want {
			t.Errorf("pbkdf2(%q,%q,%d,%d)\n got %s\nwant %s",
				c.password, c.salt, c.iter, c.keyLen, got, c.want)
		}
	}
}

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !VerifyPassword(hash, "correct horse battery") {
		t.Error("the right password was rejected")
	}
	if VerifyPassword(hash, "correct horse batter") {
		t.Error("a wrong password was accepted")
	}
	if VerifyPassword("not-a-hash", "correct horse battery") {
		t.Error("a malformed hash verified")
	}
	// Two hashes of the same password must differ: the salt is random.
	other, _ := HashPassword("correct horse battery")
	if other == hash {
		t.Error("hashes are not salted")
	}
}

func TestHashPasswordRejectsShort(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("expected an error for a 5 character password")
	}
}

func TestSessions(t *testing.T) {
	s := NewSessions(50 * time.Millisecond)
	id, expires, err := s.Create("192.168.1.5")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if time.Until(expires) <= 0 {
		t.Error("session expires in the past")
	}
	if !s.Valid(id) {
		t.Fatal("fresh session is not valid")
	}
	if s.Valid("nonsense") {
		t.Error("an unknown session id validated")
	}
	if n := s.Count(); n != 1 {
		t.Errorf("Count = %d, want 1", n)
	}
	s.Revoke(id)
	if s.Valid(id) {
		t.Error("revoked session still valid")
	}

	id2, _, _ := s.Create("10.0.0.1")
	time.Sleep(80 * time.Millisecond)
	if s.Valid(id2) {
		t.Error("expired session still valid")
	}

	s.Create("10.0.0.2")
	s.RevokeAll()
	if n := s.Count(); n != 0 {
		t.Errorf("after RevokeAll Count = %d, want 0", n)
	}
}

func TestSessionsRefresh(t *testing.T) {
	s := NewSessions(120 * time.Millisecond)
	id, _, _ := s.Create("1.2.3.4")
	for i := 0; i < 3; i++ {
		time.Sleep(50 * time.Millisecond)
		if !s.Valid(id) {
			t.Fatalf("session expired despite activity at step %d", i)
		}
	}
}

func TestThrottle(t *testing.T) {
	th := NewThrottle(3, 100*time.Millisecond)
	const ip = "192.168.1.9"
	for i := 0; i < 3; i++ {
		if ok, _ := th.Allowed(ip); !ok {
			t.Fatalf("locked out after %d attempts, want 3 allowed", i)
		}
		th.Fail(ip)
	}
	ok, wait := th.Allowed(ip)
	if ok {
		t.Fatal("expected lockout after three failures")
	}
	if wait <= 0 {
		t.Error("lockout reported no wait time")
	}
	// Another address is unaffected.
	if ok, _ := th.Allowed("10.0.0.7"); !ok {
		t.Error("lockout leaked to a different client")
	}
	time.Sleep(120 * time.Millisecond)
	if ok, _ := th.Allowed(ip); !ok {
		t.Error("lockout did not expire")
	}

	th.Fail(ip)
	th.Succeed(ip)
	if ok, _ := th.Allowed(ip); !ok {
		t.Error("Succeed did not clear the failure count")
	}
}

func TestNewToken(t *testing.T) {
	a, err := NewToken(32)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	b, _ := NewToken(32)
	if a == b {
		t.Error("tokens repeat")
	}
	if len(a) < 40 {
		t.Errorf("token %q is shorter than expected", a)
	}
}
