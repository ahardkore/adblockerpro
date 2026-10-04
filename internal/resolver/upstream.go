package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ahardkore/adblockerpro/internal/dnsmsg"
)

// Upstream is a resolver we can forward raw DNS messages to.
type Upstream interface {
	// Exchange sends a wire-format query and returns the wire-format reply.
	Exchange(ctx context.Context, query []byte) ([]byte, error)
	// Name identifies the upstream in logs and the dashboard.
	Name() string
}

// UDPUpstream talks plain DNS over UDP, retrying over TCP when the answer is
// truncated.
type UDPUpstream struct {
	Addr    string
	Timeout time.Duration
}

// Name implements Upstream.
func (u *UDPUpstream) Name() string { return "udp://" + u.Addr }

// Exchange implements Upstream.
func (u *UDPUpstream) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	d := net.Dialer{Timeout: u.Timeout}
	conn, err := d.DialContext(ctx, "udp", u.Addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(u.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, dnsmsg.MaxMessageSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < dnsmsg.HeaderLen {
			continue
		}
		if dnsmsg.ID(buf[:n]) != dnsmsg.ID(query) {
			continue // late reply from a previous exchange
		}
		resp := append([]byte(nil), buf[:n]...)
		h, err := dnsmsg.ParseHeader(resp)
		if err == nil && h.Flags&dnsmsg.FlagTC != 0 {
			if tcpResp, terr := u.exchangeTCP(ctx, query, deadline); terr == nil {
				return tcpResp, nil
			}
		}
		return resp, nil
	}
}

func (u *UDPUpstream) exchangeTCP(ctx context.Context, query []byte, deadline time.Time) ([]byte, error) {
	d := net.Dialer{Timeout: u.Timeout}
	conn, err := d.DialContext(ctx, "tcp", u.Addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 || n > dnsmsg.MaxMessageSize*8 {
		return nil, fmt.Errorf("upstream tcp: bad length %d", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// DoHUpstream talks RFC 8484 DNS-over-HTTPS, which hides lookups from the
// ISP and defeats DNS hijacking on the way out of the house.
type DoHUpstream struct {
	URL    string
	Client *http.Client
}

// NewDoHUpstream builds a DoH client with sane connection reuse.
func NewDoHUpstream(url string, timeout time.Duration) *DoHUpstream {
	return &DoHUpstream{
		URL: url,
		Client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConns:        16,
				MaxIdleConnsPerHost: 8,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
	}
}

// Name implements Upstream.
func (d *DoHUpstream) Name() string { return d.URL }

// Exchange implements Upstream.
func (d *DoHUpstream) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	// DoH caches on message id, so send id 0 and restore it afterwards.
	body := append([]byte(nil), query...)
	origID := dnsmsg.ID(body)
	dnsmsg.SetID(body, 0)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("doh %s: http %s", d.URL, resp.Status)
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, dnsmsg.MaxMessageSize*8))
	if err != nil {
		return nil, err
	}
	if len(out) < dnsmsg.HeaderLen {
		return nil, fmt.Errorf("doh %s: short response", d.URL)
	}
	dnsmsg.SetID(out, origID)
	return out, nil
}

type poolMember struct {
	up        Upstream
	failures  atomic.Int32
	downUntil atomic.Int64 // unix nanos
	queries   atomic.Uint64
	errors    atomic.Uint64
	totalNS   atomic.Uint64
}

func (m *poolMember) healthy() bool {
	return time.Now().UnixNano() >= m.downUntil.Load()
}

// Pool forwards to a list of upstreams in order, skipping ones that are in a
// failure cool-down. A resolver on a home network should degrade quietly
// rather than take the whole LAN offline.
type Pool struct {
	mu      sync.RWMutex
	members []*poolMember
}

// NewPool builds a pool over the given upstreams, highest priority first.
func NewPool(ups ...Upstream) *Pool {
	p := &Pool{}
	p.Set(ups...)
	return p
}

// Set replaces the upstream list.
func (p *Pool) Set(ups ...Upstream) {
	members := make([]*poolMember, 0, len(ups))
	for _, u := range ups {
		if u == nil {
			continue
		}
		members = append(members, &poolMember{up: u})
	}
	p.mu.Lock()
	p.members = members
	p.mu.Unlock()
}

// Len is the number of configured upstreams.
func (p *Pool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.members)
}

// Exchange tries each upstream in turn and returns the first good reply plus
// the name of the upstream that produced it.
func (p *Pool) Exchange(ctx context.Context, query []byte) ([]byte, string, error) {
	p.mu.RLock()
	members := p.members
	p.mu.RUnlock()
	if len(members) == 0 {
		return nil, "", fmt.Errorf("no upstreams configured")
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		// First pass skips unhealthy members; the second pass ignores health
		// so a total outage still gets one real try.
		for _, m := range members {
			if attempt == 0 && !m.healthy() {
				continue
			}
			start := time.Now()
			resp, err := m.up.Exchange(ctx, query)
			m.queries.Add(1)
			m.totalNS.Add(uint64(time.Since(start)))
			if err != nil {
				m.errors.Add(1)
				lastErr = err
				if f := m.failures.Add(1); f >= 3 {
					backoff := time.Duration(min(int(f), 10)) * 5 * time.Second
					m.downUntil.Store(time.Now().Add(backoff).UnixNano())
				}
				continue
			}
			m.failures.Store(0)
			m.downUntil.Store(0)
			return resp, m.up.Name(), nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all upstreams unavailable")
	}
	return nil, "", lastErr
}

// UpstreamStatus is a dashboard view of one upstream.
type UpstreamStatus struct {
	Name      string  `json:"name"`
	Healthy   bool    `json:"healthy"`
	Queries   uint64  `json:"queries"`
	Errors    uint64  `json:"errors"`
	AvgMS     float64 `json:"avg_ms"`
	DownUntil string  `json:"down_until,omitempty"`
}

// Status reports per-upstream health and latency.
func (p *Pool) Status() []UpstreamStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]UpstreamStatus, 0, len(p.members))
	for _, m := range p.members {
		s := UpstreamStatus{
			Name:    m.up.Name(),
			Healthy: m.healthy(),
			Queries: m.queries.Load(),
			Errors:  m.errors.Load(),
		}
		if s.Queries > 0 {
			s.AvgMS = float64(m.totalNS.Load()) / float64(s.Queries) / 1e6
		}
		if !s.Healthy {
			s.DownUntil = time.Unix(0, m.downUntil.Load()).Format(time.RFC3339)
		}
		out = append(out, s)
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
