// Package server contains the DNS listeners that answer the LAN.
package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ahardkore/adblockerpro/internal/blocklist"
	"github.com/ahardkore/adblockerpro/internal/config"
	"github.com/ahardkore/adblockerpro/internal/devices"
	"github.com/ahardkore/adblockerpro/internal/dnsmsg"
	"github.com/ahardkore/adblockerpro/internal/resolver"
	"github.com/ahardkore/adblockerpro/internal/schedule"
	"github.com/ahardkore/adblockerpro/internal/stats"
)

// Deps are the collaborators the DNS server needs.
type Deps struct {
	Engine  *blocklist.Engine
	Cache   *resolver.Cache
	Pool    *resolver.Pool
	Devices *devices.Registry
	Stats   *stats.Collector
	// Schedules applies time-of-day policy (bedtime, homework hours).
	Schedules *schedule.Engine
	Log       *slog.Logger
}

// DNS serves DNS over UDP and TCP, filtering as it goes.
type DNS struct {
	Deps

	mu         sync.RWMutex
	sink       dnsmsg.SinkholeMode
	sinkV4     net.IP
	sinkV6     net.IP
	blockTTL   uint32
	blockHTTPS bool
	cnameCheck bool
	serveStale bool
	timeout    time.Duration
	allowed    []netip.Prefix
	local      map[string]net.IP
	forwards   []forward
	dnssec     bool

	limiter *rateLimiter
	// group coalesces identical concurrent lookups.
	group *resolver.Group
	// prefetch refreshes popular entries before they expire.
	prefetch bool

	udp     *net.UDPConn
	tcpLn   net.Listener
	addr    string
	started time.Time
	wg      sync.WaitGroup
}

// forward is one conditional-forwarding route.
type forward struct {
	suffix string
	pool   *resolver.Pool
	name   string
}

// NewDNS builds a server from configuration.
func NewDNS(cfg *config.Config, deps Deps) *DNS {
	s := &DNS{Deps: deps, addr: cfg.DNSAddr(), group: resolver.NewGroup()}
	s.ApplyConfig(cfg)
	return s
}

// ApplyConfig applies runtime-changeable settings without a restart. The
// listen address is fixed for the life of the process.
func (s *DNS) ApplyConfig(cfg *config.Config) {
	allowed := parsePrefixes(cfg.DNS.AllowedClients)
	local := map[string]net.IP{}
	for name, ip := range cfg.DNS.LocalRecords {
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
			local[blocklist.Normalize(name)] = parsed
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sink = dnsmsg.SinkholeMode(cfg.DNS.Sinkhole)
	s.sinkV4 = net.ParseIP(cfg.DNS.CustomIPv4)
	s.sinkV6 = net.ParseIP(cfg.DNS.CustomIPv6)
	s.blockTTL = cfg.DNS.BlockTTL
	s.blockHTTPS = cfg.DNS.BlockHTTPSRecords
	s.cnameCheck = cfg.DNS.BlockCNAMECloaking
	s.serveStale = cfg.DNS.ServeStale
	s.timeout = cfg.UpstreamTimeout()
	s.allowed = allowed
	s.local = local
	s.dnssec = cfg.DNS.RequestDNSSEC
	s.prefetch = cfg.DNS.Prefetch
	fwds := make([]forward, 0, len(cfg.DNS.ConditionalForward))
	for _, f := range cfg.DNS.ConditionalForward {
		suffix := blocklist.Normalize(f.Domain)
		addr := config.NormalizeUpstream(f.Upstream)
		if suffix == "" || addr == "" {
			continue
		}
		fwds = append(fwds, forward{
			suffix: suffix,
			name:   "forward:" + addr,
			pool:   resolver.NewPool(&resolver.UDPUpstream{Addr: addr, Timeout: cfg.UpstreamTimeout()}),
		})
	}
	s.forwards = fwds
	if cfg.DNS.RateLimitPerClient > 0 {
		if s.limiter == nil {
			s.limiter = newRateLimiter(cfg.DNS.RateLimitPerClient)
		} else {
			s.limiter.setRate(cfg.DNS.RateLimitPerClient)
		}
	} else {
		s.limiter = nil
	}
}

func parsePrefixes(in []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(in))
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			if p, err := netip.ParsePrefix(raw); err == nil {
				out = append(out, p)
			}
			continue
		}
		if a, err := netip.ParseAddr(raw); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// clientAllowed keeps the resolver from being used as an open relay. With no
// explicit allow list we accept loopback plus RFC1918/ULA/link-local, which
// covers every home network and nothing on the public internet.
func (s *DNS) clientAllowed(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	s.mu.RLock()
	allowed := s.allowed
	s.mu.RUnlock()
	if len(allowed) > 0 {
		for _, p := range allowed {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast()
}

// ListenAndServe starts the UDP and TCP listeners and blocks until ctx is
// cancelled.
func (s *DNS) ListenAndServe(ctx context.Context) error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", s.addr, err)
	}
	uc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w (port 53 needs root or CAP_NET_BIND_SERVICE; is systemd-resolved still bound?)", s.addr, err)
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		uc.Close()
		return fmt.Errorf("listen tcp %s: %w", s.addr, err)
	}

	s.udp, s.tcpLn, s.started = uc, ln, time.Now()
	s.Log.Info("dns listening", "addr", s.addr, "proto", "udp+tcp")

	s.wg.Add(3)
	go func() { defer s.wg.Done(); s.serveUDP(ctx) }()
	go func() { defer s.wg.Done(); s.serveTCP(ctx) }()
	go func() { defer s.wg.Done(); s.runPrefetch(ctx) }()

	<-ctx.Done()
	_ = uc.Close()
	_ = ln.Close()
	s.wg.Wait()
	return nil
}

// Addr reports the listen address.
func (s *DNS) Addr() string { return s.addr }

// Uptime since the listeners came up.
func (s *DNS) Uptime() time.Duration {
	if s.started.IsZero() {
		return 0
	}
	return time.Since(s.started)
}

func (s *DNS) serveUDP(ctx context.Context) {
	buf := make([]byte, dnsmsg.MaxMessageSize)
	for {
		n, addr, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.Log.Warn("udp read", "err", err)
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go func(query []byte, addr *net.UDPAddr) {
			resp := s.Handle(ctx, query, addr.IP, "udp")
			if len(resp) == 0 {
				return
			}
			// UDP answers must fit the client's buffer; signal truncation
			// so well-behaved clients retry over TCP.
			if len(resp) > 512 {
				if h, err := dnsmsg.ParseHeader(resp); err == nil && h.ANCount > 0 {
					if trunc := truncate(resp); trunc != nil {
						resp = trunc
					}
				}
			}
			if _, err := s.udp.WriteToUDP(resp, addr); err != nil && ctx.Err() == nil {
				s.Log.Debug("udp write", "err", err, "client", addr.IP.String())
			}
		}(query, addr)
	}
}

// truncate returns a header-only response with the TC bit set.
func truncate(resp []byte) []byte {
	_, qend, err := dnsmsg.ParseQuestion(resp)
	if err != nil {
		return nil
	}
	out := append([]byte(nil), resp[:qend]...)
	flags := binary.BigEndian.Uint16(out[2:4]) | dnsmsg.FlagTC
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[6:8], 0)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	return out
}

func (s *DNS) serveTCP(ctx context.Context) {
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.Log.Warn("tcp accept", "err", err)
			continue
		}
		go s.handleTCPConn(ctx, conn)
	}
}

func (s *DNS) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ip := net.IP{}
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = ta.IP
	}
	for {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		if n == 0 || n > dnsmsg.MaxMessageSize*8 {
			return
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		resp := s.Handle(ctx, query, ip, "tcp")
		if len(resp) == 0 {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// runPrefetch keeps popular entries warm: anything that has been asked for
// repeatedly is refreshed in the background a few seconds before its TTL
// runs out, so clients never pay for the upstream round trip.
func (s *DNS) runPrefetch(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.RLock()
			enabled, timeout := s.prefetch, s.timeout
			s.mu.RUnlock()
			if !enabled {
				continue
			}
			for _, key := range s.Cache.ExpiringSoon(20*time.Second, 2, 32) {
				s.prefetchOne(ctx, key, timeout)
			}
		}
	}
}

func (s *DNS) prefetchOne(ctx context.Context, key string, timeout time.Duration) {
	defer s.Cache.FinishPrefetch(key)

	name, qtype, ok := resolver.SplitCacheKey(key)
	if !ok {
		return
	}
	query, err := dnsmsg.BuildQuery(name, qtype, uint16(time.Now().UnixNano()))
	if err != nil {
		return
	}
	exchangeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, _, err := s.Pool.Exchange(exchangeCtx, query)
	if err != nil {
		s.Log.Debug("prefetch failed", "domain", name, "err", err)
		return
	}
	if h, err := dnsmsg.ParseHeader(resp); err != nil || h.Rcode() != dnsmsg.RcodeSuccess {
		return
	}
	s.Cache.Put(key, resp)
	s.Cache.CountPrefetch()
}

// Handle filters and answers a single query. It is exported so tests (and
// the API's "test a domain" tool) can drive it directly.
func (s *DNS) Handle(ctx context.Context, query []byte, client net.IP, proto string) []byte {
	start := time.Now()

	if len(query) < dnsmsg.HeaderLen {
		return nil
	}
	h, err := dnsmsg.ParseHeader(query)
	if err != nil || h.IsResponse() {
		return nil
	}
	if !s.clientAllowed(client) {
		s.Log.Debug("refused non-local client", "client", client.String())
		return dnsmsg.Error(query, dnsmsg.RcodeRefused)
	}

	q, qend, err := dnsmsg.ParseQuestion(query)
	if err != nil {
		return dnsmsg.Error(query, dnsmsg.RcodeFormErr)
	}

	s.mu.RLock()
	limiter := s.limiter
	blockHTTPS, cnameCheck, serveStale := s.blockHTTPS, s.cnameCheck, s.serveStale
	timeout := s.timeout
	local := s.local
	forwards := s.forwards
	wantDNSSEC := s.dnssec
	blockTTL := s.blockTTL
	s.mu.RUnlock()

	clientStr := client.String()
	if limiter != nil && !limiter.allow(clientStr) {
		return dnsmsg.Error(query, dnsmsg.RcodeRefused)
	}

	policy := s.Devices.Lookup(client)
	entry := stats.Entry{
		Time:   start,
		Client: clientStr,
		Device: policy.Name,
		Domain: q.Name,
		Type:   dnsmsg.TypeString(q.Type),
	}

	finish := func(resp []byte, st stats.Status) []byte {
		entry.Status = st
		entry.MS = float64(time.Since(start).Microseconds()) / 1000
		if resp != nil {
			if rh, err := dnsmsg.ParseHeader(resp); err == nil {
				entry.Rcode = dnsmsg.RcodeString(rh.Rcode())
			}
			if entry.Answer == "" {
				entry.Answer = dnsmsg.FirstAnswer(resp)
			}
		}
		s.Stats.Record(entry)
		s.Devices.Observe(clientStr, st == stats.StatusBlocked)
		return resp
	}

	// Static local names (router, NAS, the Pi itself).
	if ip, ok := local[q.Name]; ok {
		if resp := localAnswer(query, qend, q, ip); resp != nil {
			return finish(resp, stats.StatusLocal)
		}
	}

	if !policy.Paused {
		if d := s.Engine.Check(q.Name, policy.Group); d.Blocked {
			entry.Rule, entry.Source = d.Rule, d.Source
			return finish(s.sinkhole(query, qend, q), stats.StatusBlocked)
		}
		if blockHTTPS && (q.Type == dnsmsg.TypeHTTPS || q.Type == dnsmsg.TypeSVCB) {
			entry.Source = "https-records-disabled"
			return finish(dnsmsg.Block(query, qend, q, dnsmsg.SinkZeroIP, nil, nil, blockTTL), stats.StatusBlocked)
		}
		// Time-of-day policy: bedtime, homework hours, dinner.
		if s.Schedules != nil {
			if blocked, name := s.Schedules.Decision(policy.Group, q.Name, start); blocked {
				entry.Schedule, entry.Source = name, "schedule:"+name
				entry.Rule = name
				return finish(s.sinkhole(query, qend, q), stats.StatusBlocked)
			}
		}
	}

	key := resolver.CacheKey(q.Name, q.Type)
	if cached, stale, ok := s.Cache.Get(key, false); ok && !stale {
		dnsmsg.SetID(cached, h.ID)
		entry.Upstream = "cache"
		return finish(cached, stats.StatusCached)
	}

	exchangeCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		exchangeCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	pool := s.Pool
	outbound := query
	for _, f := range forwards {
		if q.Name == f.suffix || strings.HasSuffix(q.Name, "."+f.suffix) {
			pool = f.pool
			break
		}
	}
	if wantDNSSEC {
		outbound = dnsmsg.WithDNSSEC(query, 1232)
	}

	resp, upstream, shared, err := s.group.Do(exchangeCtx, key, func() ([]byte, string, error) {
		return pool.Exchange(exchangeCtx, outbound)
	})
	if shared {
		entry.Source = "coalesced"
	}
	if err != nil {
		if serveStale {
			if cached, _, ok := s.Cache.Get(key, true); ok {
				dnsmsg.SetID(cached, h.ID)
				entry.Upstream = "cache (stale)"
				entry.Source = "upstream failure: " + err.Error()
				return finish(cached, stats.StatusCached)
			}
		}
		s.Log.Warn("upstream failed", "domain", q.Name, "err", err)
		entry.Source = err.Error()
		return finish(dnsmsg.Error(query, dnsmsg.RcodeServFail), stats.StatusError)
	}
	entry.Upstream = upstream
	entry.Validated = dnsmsg.Authenticated(resp)

	// CNAME cloaking: a first-party hostname that resolves into an ad
	// network's zone. Catch it on the way back.
	if cnameCheck && !policy.Paused {
		if targets := dnsmsg.CNAMETargets(resp); len(targets) > 0 {
			if d := s.Engine.CheckCNAMEs(targets, policy.Group); d.Blocked {
				entry.Rule, entry.Source = d.Rule, d.Source
				return finish(s.sinkhole(query, qend, q), stats.StatusBlocked)
			}
		}
	}

	s.Cache.Put(key, resp)
	dnsmsg.SetID(resp, h.ID)
	return finish(resp, stats.StatusAllowed)
}

func (s *DNS) sinkhole(query []byte, qend int, q dnsmsg.Question) []byte {
	s.mu.RLock()
	mode, v4, v6, ttl := s.sink, s.sinkV4, s.sinkV6, s.blockTTL
	s.mu.RUnlock()
	return dnsmsg.Block(query, qend, q, mode, v4, v6, ttl)
}

func localAnswer(query []byte, qend int, q dnsmsg.Question, ip net.IP) []byte {
	isV4 := ip.To4() != nil
	if (q.Type == dnsmsg.TypeA && isV4) || (q.Type == dnsmsg.TypeAAAA && !isV4) {
		return dnsmsg.Block(query, qend, q, dnsmsg.SinkCustomIP, ip, ip, 300)
	}
	if q.Type == dnsmsg.TypeA || q.Type == dnsmsg.TypeAAAA {
		// Right name, wrong family: NODATA rather than leaking upstream.
		return dnsmsg.Block(query, qend, q, dnsmsg.SinkCustomIP, nil, nil, 300)
	}
	return nil
}

// rateLimiter is a coarse per-client token bucket, refilled every second.
type rateLimiter struct {
	mu      sync.Mutex
	rate    int
	buckets map[string]int
	last    time.Time
}

func newRateLimiter(rate int) *rateLimiter {
	return &rateLimiter{rate: rate, buckets: map[string]int{}, last: time.Now()}
}

func (r *rateLimiter) setRate(rate int) {
	r.mu.Lock()
	r.rate = rate
	r.mu.Unlock()
}

func (r *rateLimiter) allow(client string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.last) >= time.Second {
		r.buckets = make(map[string]int, len(r.buckets))
		r.last = time.Now()
	}
	r.buckets[client]++
	return r.buckets[client] <= r.rate
}
