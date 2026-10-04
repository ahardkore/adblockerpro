package dhcp

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	cfg := Config{
		Enabled:    true,
		ServerIP:   "192.168.1.2",
		Netmask:    "255.255.255.0",
		Gateway:    "192.168.1.1",
		RangeStart: "192.168.1.100",
		RangeEnd:   "192.168.1.110",
		LeaseHours: 12,
		DomainName: "lan",
	}
	return New(cfg, filepath.Join(t.TempDir(), "leases.json"),
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
}

func request(msgType byte, mac string, hostname string, requested net.IP) *Packet {
	hw, _ := net.ParseMAC(mac)
	p := &Packet{
		Op: opRequest, HType: 1, HLen: 6, XID: 0xDEADBEEF,
		CIAddr: net.IPv4zero, YIAddr: net.IPv4zero, SIAddr: net.IPv4zero, GIAddr: net.IPv4zero,
		CHAddr: hw, Options: map[byte][]byte{OptMessageType: {msgType}},
	}
	if hostname != "" {
		p.SetOptionString(OptHostname, hostname)
	}
	if requested != nil {
		p.SetOptionIP(OptRequestedIP, requested)
	}
	return p
}

func TestPacketRoundTrip(t *testing.T) {
	p := request(Discover, "aa:bb:cc:dd:ee:ff", "living-room-tv", net.ParseIP("192.168.1.105"))
	p.SetOptionString(OptVendorClass, "Roku")

	parsed, err := Parse(p.Marshal())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.MessageType() != Discover {
		t.Errorf("type = %d", parsed.MessageType())
	}
	if parsed.MACString() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac = %q", parsed.MACString())
	}
	if parsed.Hostname() != "living-room-tv" {
		t.Errorf("hostname = %q", parsed.Hostname())
	}
	if parsed.VendorClass() != "Roku" {
		t.Errorf("vendor = %q", parsed.VendorClass())
	}
	if got := parsed.RequestedIP().String(); got != "192.168.1.105" {
		t.Errorf("requested ip = %s", got)
	}
	if parsed.XID != 0xDEADBEEF {
		t.Errorf("xid = %x", parsed.XID)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse([]byte("not dhcp")); err == nil {
		t.Error("expected an error for a short packet")
	}
	buf := make([]byte, 300) // right size, no magic cookie
	if _, err := Parse(buf); err == nil {
		t.Error("expected an error for a missing magic cookie")
	}
}

func TestDiscoverOffersAnAddress(t *testing.T) {
	s := testServer(t)
	resp := s.Handle(request(Discover, "aa:bb:cc:dd:ee:01", "tv", nil))
	if resp == nil {
		t.Fatal("no OFFER")
	}
	if resp.MessageType() != Offer {
		t.Fatalf("type = %d, want OFFER", resp.MessageType())
	}
	if !inPool(resp.YIAddr) {
		t.Errorf("offered %s, outside the pool", resp.YIAddr)
	}
	// The DNS option must point at us, or the whole product is pointless.
	dns := resp.Options[OptDNS]
	if len(dns) != 4 || net.IP(dns).String() != "192.168.1.2" {
		t.Errorf("dns option = %v, want 192.168.1.2", dns)
	}
	if gw := resp.Options[OptRouter]; len(gw) != 4 || net.IP(gw).String() != "192.168.1.1" {
		t.Errorf("router option = %v", gw)
	}
	lease := binary.BigEndian.Uint32(resp.Options[OptLeaseTime])
	if lease != 12*3600 {
		t.Errorf("lease time = %d", lease)
	}
}

func inPool(ip net.IP) bool {
	v := ipToUint(ip)
	return v >= ipToUint(net.ParseIP("192.168.1.100")) && v <= ipToUint(net.ParseIP("192.168.1.110"))
}

func TestRequestAcksAndRecordsLease(t *testing.T) {
	s := testServer(t)
	offer := s.Handle(request(Discover, "aa:bb:cc:dd:ee:02", "fire-stick", nil))
	ack := s.Handle(request(Request, "aa:bb:cc:dd:ee:02", "fire-stick", offer.YIAddr))
	if ack == nil || ack.MessageType() != ACK {
		t.Fatalf("expected ACK, got %+v", ack)
	}
	if !ack.YIAddr.Equal(offer.YIAddr) {
		t.Errorf("ACK address %s != offered %s", ack.YIAddr, offer.YIAddr)
	}
	leases := s.Leases()
	if len(leases) != 1 {
		t.Fatalf("leases = %d, want 1", len(leases))
	}
	l := leases[0]
	if l.Hostname != "fire-stick" {
		t.Errorf("hostname not learned: %q", l.Hostname)
	}
	if !l.Active() {
		t.Error("lease should be active")
	}
	if l.IP != offer.YIAddr.String() {
		t.Errorf("lease ip = %s", l.IP)
	}
}

func TestSameClientKeepsItsAddress(t *testing.T) {
	s := testServer(t)
	first := s.Handle(request(Discover, "aa:bb:cc:dd:ee:03", "xbox", nil))
	s.Handle(request(Request, "aa:bb:cc:dd:ee:03", "xbox", first.YIAddr))
	again := s.Handle(request(Discover, "aa:bb:cc:dd:ee:03", "xbox", nil))
	if !again.YIAddr.Equal(first.YIAddr) {
		t.Errorf("address changed on renewal: %s -> %s", first.YIAddr, again.YIAddr)
	}
}

func TestDistinctClientsGetDistinctAddresses(t *testing.T) {
	s := testServer(t)
	seen := map[string]bool{}
	for _, mac := range []string{"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"} {
		offer := s.Handle(request(Discover, mac, "", nil))
		s.Handle(request(Request, mac, "", offer.YIAddr))
		ip := offer.YIAddr.String()
		if seen[ip] {
			t.Fatalf("address %s handed out twice", ip)
		}
		seen[ip] = true
	}
}

func TestReservationWins(t *testing.T) {
	s := testServer(t)
	cfg := s.Config()
	cfg.Reservations = []Reservation{{MAC: "aa:bb:cc:dd:ee:04", IP: "192.168.1.50", Hostname: "nas"}}
	s.SetConfig(cfg)

	offer := s.Handle(request(Discover, "aa:bb:cc:dd:ee:04", "", nil))
	if offer.YIAddr.String() != "192.168.1.50" {
		t.Errorf("reserved client got %s, want 192.168.1.50", offer.YIAddr)
	}
}

func TestPoolExhaustion(t *testing.T) {
	s := testServer(t)
	cfg := s.Config()
	cfg.RangeStart, cfg.RangeEnd = "192.168.1.100", "192.168.1.101"
	s.SetConfig(cfg)

	for _, mac := range []string{"aa:bb:cc:00:01:01", "aa:bb:cc:00:01:02"} {
		offer := s.Handle(request(Discover, mac, "", nil))
		if offer == nil {
			t.Fatalf("%s got no offer", mac)
		}
		s.Handle(request(Request, mac, "", offer.YIAddr))
	}
	if resp := s.Handle(request(Discover, "aa:bb:cc:00:01:03", "", nil)); resp != nil {
		t.Errorf("pool is full, expected silence, got %s", resp.YIAddr)
	}
}

func TestRequestForWrongServerIsIgnored(t *testing.T) {
	s := testServer(t)
	req := request(Request, "aa:bb:cc:dd:ee:05", "", net.ParseIP("192.168.1.100"))
	req.SetOptionIP(OptServerID, net.ParseIP("192.168.1.250"))
	if resp := s.Handle(req); resp != nil {
		t.Error("a REQUEST aimed at another server must be ignored")
	}
}

func TestDisabledServerStaysQuiet(t *testing.T) {
	s := testServer(t)
	cfg := s.Config()
	cfg.Enabled = false
	s.SetConfig(cfg)
	if resp := s.Handle(request(Discover, "aa:bb:cc:dd:ee:06", "", nil)); resp != nil {
		t.Error("a disabled server must not answer")
	}
}

func TestReleaseFreesTheAddress(t *testing.T) {
	s := testServer(t)
	offer := s.Handle(request(Discover, "aa:bb:cc:dd:ee:07", "", nil))
	s.Handle(request(Request, "aa:bb:cc:dd:ee:07", "", offer.YIAddr))
	s.Handle(request(Release, "aa:bb:cc:dd:ee:07", "", nil))

	leases := s.Leases()
	if len(leases) != 1 || leases[0].Active() {
		t.Errorf("lease should be expired after RELEASE: %+v", leases)
	}
}

func TestLeasePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases.json")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{
		Enabled: true, ServerIP: "192.168.1.2", Netmask: "255.255.255.0",
		RangeStart: "192.168.1.100", RangeEnd: "192.168.1.110", LeaseHours: 12,
	}
	s := New(cfg, path, log, nil)
	offer := s.Handle(request(Discover, "aa:bb:cc:dd:ee:08", "roku", nil))
	s.Handle(request(Request, "aa:bb:cc:dd:ee:08", "roku", offer.YIAddr))
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	s2 := New(cfg, path, log, nil)
	leases := s2.Leases()
	if len(leases) != 1 || leases[0].Hostname != "roku" {
		t.Fatalf("leases after reload = %+v", leases)
	}
	if _, ok := s2.LeaseByIP(offer.YIAddr.String()); !ok {
		t.Error("LeaseByIP did not find the restored lease")
	}
}

func TestOnLeaseCallbackFires(t *testing.T) {
	got := make(chan Lease, 1)
	cfg := Config{
		Enabled: true, ServerIP: "192.168.1.2", Netmask: "255.255.255.0",
		RangeStart: "192.168.1.100", RangeEnd: "192.168.1.110", LeaseHours: 12,
	}
	s := New(cfg, filepath.Join(t.TempDir(), "l.json"),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(l Lease) { got <- l })

	offer := s.Handle(request(Discover, "aa:bb:cc:dd:ee:09", "ipad", nil))
	s.Handle(request(Request, "aa:bb:cc:dd:ee:09", "ipad", offer.YIAddr))

	select {
	case l := <-got:
		if l.Hostname != "ipad" {
			t.Errorf("callback lease = %+v", l)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onLease callback never fired")
	}
}

func TestBroadcastAddress(t *testing.T) {
	got := broadcastAddr(net.ParseIP("192.168.1.105"), net.ParseIP("255.255.255.0"))
	if got.String() != "192.168.1.255" {
		t.Errorf("broadcast = %s", got)
	}
}
