package blocklist

import (
	"strings"
	"testing"
)

func TestParseListFormats(t *testing.T) {
	input := `
# a comment
! another comment
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.net  # trailing comment
0.0.0.0 localhost
plain-domain.example
||adblock-style.example^
||has-path.example/path
::1 ipv6host.example
192.168.1.1 multi-a.example multi-b.example
not_a_domain
8.8.8.8
`
	got := ParseList(strings.NewReader(input))
	want := map[string]bool{
		"ads.example.com":       true,
		"tracker.example.net":   true,
		"plain-domain.example":  true,
		"adblock-style.example": true,
		"ipv6host.example":      true,
		"multi-a.example":       true,
		"multi-b.example":       true,
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %d entries", got, len(want))
	}
	for _, d := range got {
		if !want[d] {
			t.Errorf("unexpected domain %q", d)
		}
	}
}

func TestParseListDeduplicates(t *testing.T) {
	got := ParseList(strings.NewReader("0.0.0.0 a.example\n0.0.0.0 a.example\nA.EXAMPLE\n"))
	if len(got) != 1 {
		t.Fatalf("got %v, want one entry", got)
	}
}

func TestValidDomain(t *testing.T) {
	ok := []string{"example.com", "a-b.example.co.uk", "sub_domain.example.org"}
	bad := []string{"", "localhost", "-bad.example", "exa mple.com", "1.2.3.4", "example.123", "a..b"}
	for _, d := range ok {
		if !ValidDomain(d) {
			t.Errorf("%q should be valid", d)
		}
	}
	for _, d := range bad {
		if ValidDomain(d) {
			t.Errorf("%q should be invalid", d)
		}
	}
}
