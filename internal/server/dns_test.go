package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/ahardkore/adblockerpro/internal/blocklist"
	"github.com/ahardkore/adblockerpro/internal/config"
	"github.com/ahardkore/adblockerpro/internal/devices"
	"github.com/ahardkore/adblockerpro/internal/dnsmsg"
	"github.com/ahardkore/adblockerpro/internal/resolver"
	"github.com/ahardkore/adblockerpro/internal/stats"
)

type stubUpstream struct {
	ip      string
	ttl     uint32
	err     error
	calls   int
	cname   string
}

func (s *stubUpstream) Name() string { return "stub" }

func (s *stubUpstream) Exchange(_ context.Context, query []byte) ([]byte, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	q, qend, err := dnsmsg.ParseQuestion(query)
	if err != nil {
		return nil, err
	}
	resp := append([]byte(nil), query[:qend]...)
	binary.BigEndian.PutUint16(resp[2:4], dnsmsg.FlagQR|dnsmsg.FlagRD|dnsmsg.FlagRA)
	answers := 1
	body := []byte{}
	if s.cname != "" {
		enc, _ := dnsmsg.EncodeName(s.cname)
		body = append(body, 0xC0, 0x0C)
		body = binary.BigEndian.AppendUint16(body, dnsmsg.TypeCNAME)
		body = binary.BigEndian.AppendUint16(body, dnsmsg.ClassINET)
		body = binary.BigEndian.AppendUint32(body, s.ttl)
		body = binary.BigEndian.AppendUint16(body, uint16(len(enc)))
		body = append(body, enc...)
		answers++
	}
	body = append(body, 0xC0, 0x0C)
	body = binary.BigEndian.AppendUint16(body, q.Type)
	body = binary.BigEndian.AppendUint16(body, dnsmsg.ClassINET)
	body = binary.BigEndian.AppendUint32(body, s.ttl)
	body = binary.BigEndian.AppendUint16(body, 4)
	body = append(body, net.ParseIP(s.ip).To4()...)

	binary.BigEndian.PutUint16(resp[6:8], uint16(answers))
	return append(resp, body...), nil
}

type fixture struct {
	dns    *DNS
	engine *blocklist.Engine
	up     *stubUpstream
	stats  *stats.Collector
	cfg    *config.Config
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	cfg := config.Default()
	cfg.DNS.Port = 15353
	cfg.DNS.CacheSize = 100

	engine := blocklist.New(true)
	engine.SetDomains(blocklist.NewDomainSet(map[string]string{
		"doubleclick.net": "TestList",
		"ads.tracker.net": "TestList",
	}))
	up := &stubUpstream{ip: "93.184.216.34", ttl: 300}
	collector := stats.New(100, false)

	d := NewDNS(cfg, Deps{
		Engine:  engine,
		Cache:   resolver.NewCache(100, time.Second, time.Hour),
		Pool:    resolver.NewPool(up),
		Devices: devices.New(cfg.Devices),
		Stats:   collector,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return &fixture{dns: d, engine: engine, up: up, stats: collector, cfg: cfg}
}

func query(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	enc, err := dnsmsg.EncodeName(name)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg := make([]byte, dnsmsg.HeaderLen)
	binary.BigEndian.PutUint16(msg[0:2], 0x4242)
	binary.BigEndian.PutUint16(msg[2:4], dnsmsg.FlagRD)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, enc...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, dnsmsg.ClassINET)
	return msg
}

func TestHandleBlocksListedDomain(t *testing.T) {
	f := newFixture(t)
	resp := f.dns.Handle(context.Background(), query(t, "stats.g.doubleclick.net", dnsmsg.TypeA), net.ParseIP("192.168.1.50"), "udp")
	if resp == nil {
		t.Fatal("no response")
	}
	if got := dnsmsg.FirstAnswer(resp); got != "0.0.0.0" {
		t.Errorf("answer = %q, want the sinkhole address", got)
	}
	if f.up.calls != 0 {
		t.Errorf("upstream was queried %d times for a blocked name", f.up.calls)
	}
	if e := f.stats.Recent(stats.QueryFilter{Limit: 1}); len(e) != 1 || e[0].Status != stats.StatusBlocked {
		t.Errorf("query log = %+v", e)
	}
}

func TestHandleForwardsAndCaches(t *testing.T) {
	f := newFixture(t)
	q := query(t, "example.com", dnsmsg.TypeA)

	resp := f.dns.Handle(context.Background(), q, net.ParseIP("192.168.1.50"), "udp")
	if got := dnsmsg.FirstAnswer(resp); got != "93.184.216.34" {
		t.Fatalf("answer = %q", got)
	}
	if dnsmsg.ID(resp) != 0x4242 {
		t.Errorf("transaction id not preserved: %x", dnsmsg.ID(resp))
	}

	resp2 := f.dns.Handle(context.Background(), q, net.ParseIP("192.168.1.50"), "udp")
	if dnsmsg.FirstAnswer(resp2) != "93.184.216.34" {
		t.Error("cached answer differs")
	}
	if f.up.calls != 1 {
		t.Errorf("upstream called %d times, want 1 (second answer should be cached)", f.up.calls)
	}
	entries := f.stats.Recent(stats.QueryFilter{Limit: 2})
	if len(entries) != 2 || entries[0].Status != stats.StatusCached {
		t.Errorf("second query status = %+v", entries)
	}
}

func TestHandleRefusesPublicClients(t *testing.T) {
	f := newFixture(t)
	resp := f.dns.Handle(context.Background(), query(t, "example.com", dnsmsg.TypeA), net.ParseIP("8.8.4.4"), "udp")
	h, err := dnsmsg.ParseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.Rcode() != dnsmsg.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dnsmsg.RcodeString(h.Rcode()))
	}
}

func TestHandleServfailOnUpstreamFailure(t *testing.T) {
	f := newFixture(t)
	f.up.err = errors.New("boom")
	resp := f.dns.Handle(context.Background(), query(t, "example.com", dnsmsg.TypeA), net.ParseIP("192.168.1.50"), "udp")
	h, _ := dnsmsg.ParseHeader(resp)
	if h.Rcode() != dnsmsg.RcodeServFail {
		t.Errorf("rcode = %s, want SERVFAIL", dnsmsg.RcodeString(h.Rcode()))
	}
}

func TestHandleStaleCacheWhenUpstreamDies(t *testing.T) {
	f := newFixture(t)
	f.up.ttl = 1
	q := query(t, "example.com", dnsmsg.TypeA)
	f.dns.Handle(context.Background(), q, net.ParseIP("192.168.1.50"), "udp")
	time.Sleep(1100 * time.Millisecond)
	f.up.err = errors.New("network down")

	resp := f.dns.Handle(context.Background(), q, net.ParseIP("192.168.1.50"), "udp")
	if got := dnsmsg.FirstAnswer(resp); got != "93.184.216.34" {
		t.Errorf("answer = %q, want the stale cached address", got)
	}
}

func TestDevicePolicyPausesFiltering(t *testing.T) {
	f := newFixture(t)
	f.cfg.Devices = []config.Device{{Match: "192.168.1.77", Name: "Work laptop", Paused: true}}
	f.dns.Devices.Set(f.cfg.Devices)

	resp := f.dns.Handle(context.Background(), query(t, "doubleclick.net", dnsmsg.TypeA), net.ParseIP("192.168.1.77"), "udp")
	if got := dnsmsg.FirstAnswer(resp); got != "93.184.216.34" {
		t.Errorf("answer = %q, filtering should be off for this device", got)
	}
	resp = f.dns.Handle(context.Background(), query(t, "doubleclick.net", dnsmsg.TypeA), net.ParseIP("192.168.1.78"), "udp")
	if got := dnsmsg.FirstAnswer(resp); got != "0.0.0.0" {
		t.Errorf("answer = %q, other devices must still be filtered", got)
	}
}

func TestGlobalPause(t *testing.T) {
	f := newFixture(t)
	f.dns.Devices.PauseAll(time.Minute)
	resp := f.dns.Handle(context.Background(), query(t, "doubleclick.net", dnsmsg.TypeA), net.ParseIP("192.168.1.50"), "udp")
	if got := dnsmsg.FirstAnswer(resp); got != "93.184.216.34" {
		t.Errorf("answer = %q, global pause should let everything through", got)
	}
	f.dns.Devices.Resume()
	resp = f.dns.Handle(context.Background(), query(t, "doubleclick.net", dnsmsg.TypeA), net.ParseIP("192.168.1.50"), "udp")
	if got := dnsmsg.FirstAnswer(resp); got != "0.0.0.0" {
		t.Errorf("answer = %q, filtering should be back on", got)
	}
}

func TestCNAMECloakingIsBlocked(t *testing.T) {
	f := newFixture(t)
	f.up.cname = "shim.ads.tracker.net"
	resp := f.dns.Handle(context.Background(), query(t, "metrics.first-party.example", dnsmsg.TypeA), net.ParseIP("192.168.1.50"), "udp")
	if got := dnsmsg.FirstAnswer(resp); got != "0.0.0.0" {
		t.Errorf("answer = %q, cloaked CNAME should be sinkholed", got)
	}
}

func TestLocalRecords(t *testing.T) {
	f := newFixture(t)
	f.cfg.DNS.LocalRecords = map[string]string{"pi.hole": "192.168.1.2"}
	f.dns.ApplyConfig(f.cfg)
	resp := f.dns.Handle(context.Background(), query(t, "pi.hole", dnsmsg.TypeA), net.ParseIP("192.168.1.50"), "udp")
	if got := dnsmsg.FirstAnswer(resp); got != "192.168.1.2" {
		t.Errorf("answer = %q, want the static local record", got)
	}
}

func TestRateLimit(t *testing.T) {
	f := newFixture(t)
	f.cfg.DNS.RateLimitPerClient = 2
	f.dns.ApplyConfig(f.cfg)
	client := net.ParseIP("192.168.1.90")
	var refused int
	for i := 0; i < 5; i++ {
		resp := f.dns.Handle(context.Background(), query(t, "example.com", dnsmsg.TypeA), client, "udp")
		if h, _ := dnsmsg.ParseHeader(resp); h.Rcode() == dnsmsg.RcodeRefused {
			refused++
		}
	}
	if refused != 3 {
		t.Errorf("refused %d of 5 queries, want 3", refused)
	}
}

func TestSinkholeModes(t *testing.T) {
	f := newFixture(t)
	f.cfg.DNS.Sinkhole = "nxdomain"
	f.dns.ApplyConfig(f.cfg)
	resp := f.dns.Handle(context.Background(), query(t, "doubleclick.net", dnsmsg.TypeA), net.ParseIP("192.168.1.50"), "udp")
	if h, _ := dnsmsg.ParseHeader(resp); h.Rcode() != dnsmsg.RcodeNXDomain {
		t.Errorf("rcode = %s, want NXDOMAIN", dnsmsg.RcodeString(h.Rcode()))
	}
}
