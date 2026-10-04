package dhcp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Config describes the pool the server hands out.
type Config struct {
	Enabled bool `json:"enabled"`
	// Interface to serve on; empty means every interface.
	Interface string `json:"interface,omitempty"`
	// ServerIP is this Pi's address: it is announced as both the DHCP
	// server and (by default) the DNS server, which is the whole point.
	ServerIP   string `json:"server_ip"`
	Netmask    string `json:"netmask"`
	Gateway    string `json:"gateway"`
	RangeStart string `json:"range_start"`
	RangeEnd   string `json:"range_end"`
	LeaseHours int    `json:"lease_hours"`
	DomainName string `json:"domain_name,omitempty"`
	// DNS overrides the advertised resolvers. Empty means "this Pi", which
	// is what you want; setting a second public resolver here would let
	// clients bypass filtering.
	DNS []string `json:"dns,omitempty"`
	// Reservations pin a MAC to an address.
	Reservations []Reservation `json:"reservations,omitempty"`
}

// Reservation is a static lease.
type Reservation struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
}

// Lease is a handed-out (or reserved) address.
type Lease struct {
	IP       string    `json:"ip"`
	MAC      string    `json:"mac"`
	Hostname string    `json:"hostname,omitempty"`
	Vendor   string    `json:"vendor,omitempty"`
	Start    time.Time `json:"start"`
	Expires  time.Time `json:"expires"`
	Static   bool      `json:"static"`
	LastSeen time.Time `json:"last_seen"`
}

// Active reports whether the lease is still valid.
func (l Lease) Active() bool { return l.Static || time.Now().Before(l.Expires) }

// Server is the DHCPv4 server.
type Server struct {
	log      *slog.Logger
	path     string
	onLease  func(Lease)
	listenFn func(ctx context.Context) (net.PacketConn, error)

	mu     sync.RWMutex
	cfg    Config
	leases map[string]*Lease // keyed by MAC

	conn net.PacketConn
}

// New creates a server. leasePath is where leases are persisted, onLease is
// called whenever a lease is created or renewed (used to name devices in the
// dashboard).
func New(cfg Config, leasePath string, log *slog.Logger, onLease func(Lease)) *Server {
	s := &Server{
		log:     log,
		path:    leasePath,
		onLease: onLease,
		leases:  map[string]*Lease{},
	}
	s.SetConfig(cfg)
	s.load()
	return s
}

// SetConfig swaps the pool configuration (and refreshes reservations).
func (s *Server) SetConfig(cfg Config) {
	if cfg.LeaseHours <= 0 {
		cfg.LeaseHours = 12
	}
	if cfg.Netmask == "" {
		cfg.Netmask = "255.255.255.0"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
	for _, r := range cfg.Reservations {
		mac := normalizeMAC(r.MAC)
		if mac == "" || net.ParseIP(r.IP) == nil {
			continue
		}
		l, ok := s.leases[mac]
		if !ok {
			l = &Lease{MAC: mac, Start: time.Now()}
			s.leases[mac] = l
		}
		l.IP = r.IP
		l.Static = true
		if r.Hostname != "" {
			l.Hostname = r.Hostname
		}
	}
}

// Config returns the current pool configuration.
func (s *Server) Config() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Enabled reports whether DHCP service is switched on.
func (s *Server) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Enabled
}

func normalizeMAC(s string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return hw.String()
}

/* ------------------------------- leases ------------------------------- */

// Leases returns every known lease, newest activity first.
func (s *Server) Leases() []Lease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Lease, 0, len(s.leases))
	for _, l := range s.leases {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// LeaseByIP looks up the lease currently holding an address.
func (s *Server) LeaseByIP(ip string) (Lease, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, l := range s.leases {
		if l.IP == ip {
			return *l, true
		}
	}
	return Lease{}, false
}

func (s *Server) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var leases []Lease
	if err := json.Unmarshal(data, &leases); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range leases {
		l := leases[i]
		if l.MAC == "" {
			continue
		}
		existing, ok := s.leases[l.MAC]
		if ok && existing.Static {
			existing.Hostname = firstNonEmpty(existing.Hostname, l.Hostname)
			existing.Vendor = firstNonEmpty(existing.Vendor, l.Vendor)
			continue
		}
		copied := l
		s.leases[l.MAC] = &copied
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Save persists leases to disk.
func (s *Server) Save() error {
	s.mu.RLock()
	out := make([]Lease, 0, len(s.leases))
	for _, l := range s.leases {
		out = append(out, *l)
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

/* ---------------------------- allocation ------------------------------ */

func ipToUint(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}

func uintToIP(v uint32) net.IP {
	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, v)
	return out
}

// Allocate picks an address for a client. Caller must hold the lock.
func (s *Server) allocateLocked(mac string, requested net.IP) (net.IP, error) {
	if l, ok := s.leases[mac]; ok && l.IP != "" {
		if ip := net.ParseIP(l.IP); ip != nil && (l.Static || s.inRangeLocked(ip)) {
			return ip.To4(), nil
		}
	}
	start := net.ParseIP(s.cfg.RangeStart).To4()
	end := net.ParseIP(s.cfg.RangeEnd).To4()
	if start == nil || end == nil {
		return nil, fmt.Errorf("dhcp: pool range is not configured")
	}
	taken := map[uint32]struct{}{}
	now := time.Now()
	for m, l := range s.leases {
		if m == mac {
			continue
		}
		if ip := net.ParseIP(l.IP); ip != nil && (l.Static || now.Before(l.Expires)) {
			taken[ipToUint(ip)] = struct{}{}
		}
	}
	if requested != nil {
		if v := ipToUint(requested); v >= ipToUint(start) && v <= ipToUint(end) {
			if _, used := taken[v]; !used {
				return requested.To4(), nil
			}
		}
	}
	for v := ipToUint(start); v <= ipToUint(end); v++ {
		if _, used := taken[v]; used {
			continue
		}
		if v == ipToUint(net.ParseIP(s.cfg.ServerIP)) {
			continue
		}
		return uintToIP(v), nil
	}
	return nil, errors.New("dhcp: address pool exhausted")
}

func (s *Server) inRangeLocked(ip net.IP) bool {
	start := net.ParseIP(s.cfg.RangeStart)
	end := net.ParseIP(s.cfg.RangeEnd)
	if start == nil || end == nil {
		return false
	}
	v := ipToUint(ip)
	return v >= ipToUint(start) && v <= ipToUint(end)
}

/* ----------------------------- handling ------------------------------- */

// Handle processes a request and returns the reply to send, or nil when the
// message needs no answer. Exported so it can be tested without sockets.
func (s *Server) Handle(req *Packet) *Packet {
	if req.Op != opRequest || req.MessageType() == 0 {
		return nil
	}
	mac := req.MACString()
	if mac == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cfg.Enabled {
		return nil
	}
	serverIP := net.ParseIP(s.cfg.ServerIP).To4()
	if serverIP == nil {
		return nil
	}

	switch req.MessageType() {
	case Discover:
		ip, err := s.allocateLocked(mac, req.RequestedIP())
		if err != nil {
			s.log.Warn("dhcp discover", "mac", mac, "err", err)
			return nil
		}
		s.touchLocked(mac, ip, req, false)
		return s.reply(req, Offer, ip, serverIP)

	case Request:
		// A REQUEST aimed at a different server means the client picked
		// someone else; drop our tentative offer.
		if sid := req.ServerID(); sid != nil && !sid.Equal(serverIP) {
			return nil
		}
		wanted := req.RequestedIP()
		if wanted == nil && req.CIAddr != nil && !req.CIAddr.Equal(net.IPv4zero) {
			wanted = req.CIAddr.To4()
		}
		ip, err := s.allocateLocked(mac, wanted)
		if err != nil {
			return s.reply(req, NAK, net.IPv4zero, serverIP)
		}
		if wanted != nil && !wanted.Equal(ip) {
			// We cannot honour the address it asked for.
			return s.reply(req, NAK, net.IPv4zero, serverIP)
		}
		lease := s.touchLocked(mac, ip, req, true)
		if s.onLease != nil && lease != nil {
			l := *lease
			go s.onLease(l)
		}
		return s.reply(req, ACK, ip, serverIP)

	case Release, Decline:
		if l, ok := s.leases[mac]; ok && !l.Static {
			l.Expires = time.Now()
		}
		return nil

	case Inform:
		return s.reply(req, ACK, net.IPv4zero, serverIP)
	}
	return nil
}

func (s *Server) touchLocked(mac string, ip net.IP, req *Packet, commit bool) *Lease {
	l, ok := s.leases[mac]
	if !ok {
		l = &Lease{MAC: mac, Start: time.Now()}
		s.leases[mac] = l
	}
	l.IP = ip.String()
	l.LastSeen = time.Now()
	if h := req.Hostname(); h != "" {
		l.Hostname = h
	}
	if v := req.VendorClass(); v != "" {
		l.Vendor = v
	}
	if commit && !l.Static {
		l.Expires = time.Now().Add(time.Duration(s.cfg.LeaseHours) * time.Hour)
	}
	return l
}

func (s *Server) reply(req *Packet, msgType byte, yiaddr, serverIP net.IP) *Packet {
	p := &Packet{
		Op:      opReply,
		HType:   req.HType,
		HLen:    req.HLen,
		XID:     req.XID,
		Flags:   req.Flags,
		CIAddr:  req.CIAddr,
		YIAddr:  yiaddr,
		GIAddr:  req.GIAddr,
		CHAddr:  req.CHAddr,
		Options: map[byte][]byte{OptMessageType: {msgType}},
	}
	p.SetOptionIP(OptServerID, serverIP)
	if msgType == NAK {
		return p
	}

	lease := uint32(s.cfg.LeaseHours) * 3600
	p.SetOptionUint32(OptLeaseTime, lease)
	p.SetOptionUint32(OptRenewalTime, lease/2)
	p.SetOptionUint32(OptRebindingTime, lease*7/8)
	if mask := net.ParseIP(s.cfg.Netmask); mask != nil {
		p.SetOptionIP(OptSubnetMask, mask)
	}
	if gw := net.ParseIP(s.cfg.Gateway); gw != nil {
		p.SetOptionIP(OptRouter, gw)
	}
	dns := []net.IP{serverIP}
	if len(s.cfg.DNS) > 0 {
		dns = dns[:0]
		for _, d := range s.cfg.DNS {
			if ip := net.ParseIP(d); ip != nil {
				dns = append(dns, ip)
			}
		}
	}
	p.SetOptionIPs(OptDNS, dns)
	p.SetOptionString(OptDomainName, s.cfg.DomainName)
	if mask := net.ParseIP(s.cfg.Netmask); mask != nil && yiaddr != nil {
		p.SetOptionIP(OptBroadcast, broadcastAddr(yiaddr, mask))
	}
	return p
}

func broadcastAddr(ip, mask net.IP) net.IP {
	v4, m4 := ip.To4(), mask.To4()
	if v4 == nil || m4 == nil {
		return net.IPv4bcast
	}
	out := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		out[i] = v4[i] | ^m4[i]
	}
	return out
}

/* ------------------------------ serving -------------------------------- */

// ListenAndServe binds UDP/67 and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if !s.Enabled() {
		s.log.Info("dhcp server disabled")
		<-ctx.Done()
		return nil
	}
	conn, err := listenDHCP(ctx, s.Config().Interface)
	if err != nil {
		return fmt.Errorf("dhcp listen: %w", err)
	}
	s.conn = conn
	s.log.Info("dhcp listening", "addr", ":67",
		"pool", s.Config().RangeStart+"-"+s.Config().RangeEnd)

	go func() {
		<-ctx.Done()
		_ = conn.Close()
		_ = s.Save()
	}()

	saveTicker := time.NewTicker(time.Minute)
	defer saveTicker.Stop()
	go func() {
		for range saveTicker.C {
			_ = s.Save()
		}
	}()

	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Warn("dhcp read", "err", err)
			continue
		}
		req, err := Parse(buf[:n])
		if err != nil {
			continue
		}
		resp := s.Handle(req)
		if resp == nil {
			continue
		}
		s.log.Debug("dhcp", "in", req.String(), "out", typeName(resp.MessageType()),
			"ip", resp.YIAddr.String(), "host", req.Hostname())
		if err := s.send(conn, req, resp, addr); err != nil {
			s.log.Warn("dhcp write", "err", err)
		}
	}
}

func (s *Server) send(conn net.PacketConn, req, resp *Packet, from net.Addr) error {
	data := resp.Marshal()

	// Relayed requests go back to the relay agent on port 67.
	if req.GIAddr != nil && !req.GIAddr.Equal(net.IPv4zero) {
		_, err := conn.WriteTo(data, &net.UDPAddr{IP: req.GIAddr, Port: 67})
		return err
	}
	// A client that already has an address and did not ask for broadcast
	// can be answered directly.
	if !req.Broadcast() && req.CIAddr != nil && !req.CIAddr.Equal(net.IPv4zero) {
		if _, err := conn.WriteTo(data, &net.UDPAddr{IP: req.CIAddr, Port: 68}); err == nil {
			return nil
		}
	}
	_, err := conn.WriteTo(data, &net.UDPAddr{IP: net.IPv4bcast, Port: 68})
	if err != nil && from != nil {
		_, err = conn.WriteTo(data, from)
	}
	return err
}
