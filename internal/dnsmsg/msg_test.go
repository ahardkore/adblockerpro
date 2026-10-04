package dnsmsg

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildQuery assembles a minimal query message for tests.
func buildQuery(t *testing.T, name string, qtype uint16, id uint16) []byte {
	t.Helper()
	enc, err := EncodeName(name)
	if err != nil {
		t.Fatalf("encode %q: %v", name, err)
	}
	msg := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], FlagRD)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, enc...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, ClassINET)
	return msg
}

func TestParseQuestion(t *testing.T) {
	q := buildQuery(t, "Ads.Example.COM", TypeA, 0x1234)
	got, off, err := ParseQuestion(q)
	if err != nil {
		t.Fatalf("ParseQuestion: %v", err)
	}
	if got.Name != "ads.example.com" {
		t.Errorf("name = %q, want ads.example.com", got.Name)
	}
	if got.Type != TypeA || got.Class != ClassINET {
		t.Errorf("type/class = %d/%d", got.Type, got.Class)
	}
	if off != len(q) {
		t.Errorf("offset = %d, want %d", off, len(q))
	}
	if ID(q) != 0x1234 {
		t.Errorf("id = %x", ID(q))
	}
}

func TestParseQuestionShort(t *testing.T) {
	if _, _, err := ParseQuestion([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected an error for a truncated message")
	}
}

func TestBlockZeroIP(t *testing.T) {
	q := buildQuery(t, "tracker.example.com", TypeA, 7)
	_, off, _ := ParseQuestion(q)
	question, _, _ := ParseQuestion(q)
	resp := Block(q, off, question, SinkZeroIP, nil, nil, 60)

	h, err := ParseHeader(resp)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	if !h.IsResponse() {
		t.Error("QR bit not set")
	}
	if h.ID != 7 {
		t.Errorf("id = %d, want 7", h.ID)
	}
	if h.ANCount != 1 {
		t.Fatalf("ancount = %d, want 1", h.ANCount)
	}
	if h.Rcode() != RcodeSuccess {
		t.Errorf("rcode = %s", RcodeString(h.Rcode()))
	}
	if got := FirstAnswer(resp); got != "0.0.0.0" {
		t.Errorf("answer = %q, want 0.0.0.0", got)
	}
}

func TestBlockCustomIP(t *testing.T) {
	q := buildQuery(t, "ads.example.com", TypeA, 9)
	question, off, _ := ParseQuestion(q)
	resp := Block(q, off, question, SinkCustomIP, net.ParseIP("192.168.1.2"), nil, 30)
	if got := FirstAnswer(resp); got != "192.168.1.2" {
		t.Errorf("answer = %q, want 192.168.1.2", got)
	}
}

func TestBlockNXDomain(t *testing.T) {
	q := buildQuery(t, "ads.example.com", TypeA, 11)
	question, off, _ := ParseQuestion(q)
	resp := Block(q, off, question, SinkNXDomain, nil, nil, 60)
	h, _ := ParseHeader(resp)
	if h.Rcode() != RcodeNXDomain {
		t.Errorf("rcode = %s, want NXDOMAIN", RcodeString(h.Rcode()))
	}
	if h.ANCount != 0 {
		t.Errorf("ancount = %d, want 0", h.ANCount)
	}
}

func TestBlockUnsupportedTypeIsNodata(t *testing.T) {
	q := buildQuery(t, "ads.example.com", TypeTXT, 13)
	question, off, _ := ParseQuestion(q)
	resp := Block(q, off, question, SinkZeroIP, nil, nil, 60)
	h, _ := ParseHeader(resp)
	if h.Rcode() != RcodeSuccess || h.ANCount != 0 {
		t.Errorf("want NODATA, got rcode=%s ancount=%d", RcodeString(h.Rcode()), h.ANCount)
	}
}

// buildResponse appends an A record answer to a query, for TTL tests.
func buildResponse(t *testing.T, name string, ip string, ttl uint32) []byte {
	t.Helper()
	q := buildQuery(t, name, TypeA, 42)
	question, off, _ := ParseQuestion(q)
	resp := Block(q, off, question, SinkCustomIP, net.ParseIP(ip), nil, ttl)
	return resp
}

func TestScanAndAgeTTLs(t *testing.T) {
	resp := buildResponse(t, "example.com", "93.184.216.34", 300)
	info, err := ScanTTLs(resp)
	if err != nil {
		t.Fatalf("ScanTTLs: %v", err)
	}
	if info.Records != 1 || info.MinTTL != 300 {
		t.Fatalf("records=%d minTTL=%d, want 1/300", info.Records, info.MinTTL)
	}
	AgeTTLs(resp, info, 100)
	info2, _ := ScanTTLs(resp)
	if info2.MinTTL != 200 {
		t.Errorf("aged TTL = %d, want 200", info2.MinTTL)
	}
	AgeTTLs(resp, info, 10_000)
	info3, _ := ScanTTLs(resp)
	if info3.MinTTL != 0 {
		t.Errorf("clamped TTL = %d, want 0", info3.MinTTL)
	}
	SetTTLs(resp, info, 30)
	info4, _ := ScanTTLs(resp)
	if info4.MinTTL != 30 {
		t.Errorf("set TTL = %d, want 30", info4.MinTTL)
	}
}

func TestEncodeNameRejectsBadLabels(t *testing.T) {
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := EncodeName(string(long) + ".com"); err == nil {
		t.Error("expected an error for a 64 byte label")
	}
	if _, err := EncodeName("a..b"); err == nil {
		t.Error("expected an error for an empty label")
	}
}

func TestErrorResponse(t *testing.T) {
	q := buildQuery(t, "example.com", TypeA, 5)
	resp := Error(q, RcodeServFail)
	h, err := ParseHeader(resp)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	if h.Rcode() != RcodeServFail || !h.IsResponse() || h.ID != 5 {
		t.Errorf("unexpected header %+v", h)
	}
}

func TestSetID(t *testing.T) {
	q := buildQuery(t, "example.com", TypeA, 1)
	SetID(q, 0xBEEF)
	if ID(q) != 0xBEEF {
		t.Errorf("id = %x", ID(q))
	}
}

func TestTypeString(t *testing.T) {
	cases := map[uint16]string{TypeA: "A", TypeAAAA: "AAAA", TypeHTTPS: "HTTPS", 999: "TYPE999"}
	for in, want := range cases {
		if got := TypeString(in); got != want {
			t.Errorf("TypeString(%d) = %q, want %q", in, got, want)
		}
	}
}
