// Package dhcp implements a small DHCPv4 server so the Pi can hand out
// addresses itself — which means it learns every device's hostname and MAC,
// and can force itself as the DNS server even on routers that will not let
// you change it.
package dhcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Message types (option 53).
const (
	Discover byte = 1
	Offer    byte = 2
	Request  byte = 3
	Decline  byte = 4
	ACK      byte = 5
	NAK      byte = 6
	Release  byte = 7
	Inform   byte = 8
)

// Option codes we read or write.
const (
	OptSubnetMask    byte = 1
	OptRouter        byte = 3
	OptDNS           byte = 6
	OptHostname      byte = 12
	OptDomainName    byte = 15
	OptBroadcast     byte = 28
	OptRequestedIP   byte = 50
	OptLeaseTime     byte = 51
	OptMessageType   byte = 53
	OptServerID      byte = 54
	OptParamRequest  byte = 55
	OptRenewalTime   byte = 58
	OptRebindingTime byte = 59
	OptVendorClass   byte = 60
	OptClientID      byte = 61
	OptClientFQDN    byte = 81
	OptEnd           byte = 255
)

const (
	opRequest byte = 1
	opReply   byte = 2
)

var magicCookie = [4]byte{99, 130, 83, 99}

// ErrNotDHCP is returned for packets that are not DHCP at all.
var ErrNotDHCP = errors.New("dhcp: not a DHCP packet")

// Packet is a parsed DHCPv4 message.
type Packet struct {
	Op      byte
	HType   byte
	HLen    byte
	Hops    byte
	XID     uint32
	Secs    uint16
	Flags   uint16
	CIAddr  net.IP // client's current address
	YIAddr  net.IP // address we are giving it
	SIAddr  net.IP // next server
	GIAddr  net.IP // relay agent
	CHAddr  net.HardwareAddr
	Options map[byte][]byte
}

// Broadcast reports whether the client asked for a broadcast reply.
func (p *Packet) Broadcast() bool { return p.Flags&0x8000 != 0 }

// MessageType returns option 53.
func (p *Packet) MessageType() byte {
	if v, ok := p.Options[OptMessageType]; ok && len(v) > 0 {
		return v[0]
	}
	return 0
}

// Hostname returns the client-supplied hostname, cleaned up for display.
func (p *Packet) Hostname() string {
	if v, ok := p.Options[OptHostname]; ok {
		return sanitizeName(string(v))
	}
	if v, ok := p.Options[OptClientFQDN]; ok && len(v) > 3 {
		return sanitizeName(string(v[3:]))
	}
	return ""
}

// VendorClass returns option 60, which is often the only clue about what a
// no-hostname streaming stick actually is.
func (p *Packet) VendorClass() string {
	if v, ok := p.Options[OptVendorClass]; ok {
		return sanitizeName(string(v))
	}
	return ""
}

// RequestedIP returns option 50.
func (p *Packet) RequestedIP() net.IP {
	if v, ok := p.Options[OptRequestedIP]; ok && len(v) == 4 {
		return net.IP(v).To4()
	}
	return nil
}

// ServerID returns option 54.
func (p *Packet) ServerID() net.IP {
	if v, ok := p.Options[OptServerID]; ok && len(v) == 4 {
		return net.IP(v).To4()
	}
	return nil
}

func sanitizeName(s string) string {
	s = strings.TrimSpace(strings.Trim(s, "\x00"))
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r >= 32 && r < 127 {
			out = append(out, r)
		}
	}
	if len(out) > 63 {
		out = out[:63]
	}
	return strings.TrimSpace(string(out))
}

// Parse decodes a DHCPv4 message.
func Parse(b []byte) (*Packet, error) {
	if len(b) < 240 {
		return nil, ErrNotDHCP
	}
	if b[236] != magicCookie[0] || b[237] != magicCookie[1] ||
		b[238] != magicCookie[2] || b[239] != magicCookie[3] {
		return nil, ErrNotDHCP
	}
	p := &Packet{
		Op:      b[0],
		HType:   b[1],
		HLen:    b[2],
		Hops:    b[3],
		XID:     binary.BigEndian.Uint32(b[4:8]),
		Secs:    binary.BigEndian.Uint16(b[8:10]),
		Flags:   binary.BigEndian.Uint16(b[10:12]),
		CIAddr:  net.IP(append([]byte(nil), b[12:16]...)),
		YIAddr:  net.IP(append([]byte(nil), b[16:20]...)),
		SIAddr:  net.IP(append([]byte(nil), b[20:24]...)),
		GIAddr:  net.IP(append([]byte(nil), b[24:28]...)),
		Options: map[byte][]byte{},
	}
	hlen := int(p.HLen)
	if hlen == 0 || hlen > 16 {
		hlen = 6
	}
	p.CHAddr = net.HardwareAddr(append([]byte(nil), b[28:28+hlen]...))

	off := 240
	for off < len(b) {
		code := b[off]
		if code == 0 { // pad
			off++
			continue
		}
		if code == OptEnd {
			break
		}
		if off+2 > len(b) {
			break
		}
		n := int(b[off+1])
		if off+2+n > len(b) {
			break
		}
		p.Options[code] = append([]byte(nil), b[off+2:off+2+n]...)
		off += 2 + n
	}
	return p, nil
}

func ip4(ip net.IP) []byte {
	if ip == nil {
		return []byte{0, 0, 0, 0}
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return []byte{0, 0, 0, 0}
}

// Marshal encodes the packet. Options are emitted in ascending code order so
// the output is deterministic and easy to test.
func (p *Packet) Marshal() []byte {
	b := make([]byte, 240, 548)
	b[0] = p.Op
	b[1] = p.HType
	if b[1] == 0 {
		b[1] = 1 // ethernet
	}
	b[2] = p.HLen
	if b[2] == 0 {
		b[2] = byte(len(p.CHAddr))
	}
	b[3] = p.Hops
	binary.BigEndian.PutUint32(b[4:8], p.XID)
	binary.BigEndian.PutUint16(b[8:10], p.Secs)
	binary.BigEndian.PutUint16(b[10:12], p.Flags)
	copy(b[12:16], ip4(p.CIAddr))
	copy(b[16:20], ip4(p.YIAddr))
	copy(b[20:24], ip4(p.SIAddr))
	copy(b[24:28], ip4(p.GIAddr))
	copy(b[28:44], p.CHAddr)
	copy(b[236:240], magicCookie[:])

	// Message type first, as most clients expect.
	if v, ok := p.Options[OptMessageType]; ok {
		b = append(b, OptMessageType, byte(len(v)))
		b = append(b, v...)
	}
	for code := 1; code < 255; code++ {
		c := byte(code)
		if c == OptMessageType {
			continue
		}
		v, ok := p.Options[c]
		if !ok {
			continue
		}
		if len(v) > 255 {
			v = v[:255]
		}
		b = append(b, c, byte(len(v)))
		b = append(b, v...)
	}
	b = append(b, OptEnd)
	// Pad to the 300 byte minimum some clients insist on.
	for len(b) < 300 {
		b = append(b, 0)
	}
	return b
}

// SetOptionIP stores a single IPv4 option value.
func (p *Packet) SetOptionIP(code byte, ip net.IP) {
	p.Options[code] = append([]byte(nil), ip4(ip)...)
}

// SetOptionIPs stores a list of IPv4 addresses (e.g. DNS servers).
func (p *Packet) SetOptionIPs(code byte, ips []net.IP) {
	if len(ips) == 0 {
		return
	}
	buf := make([]byte, 0, 4*len(ips))
	for _, ip := range ips {
		buf = append(buf, ip4(ip)...)
	}
	p.Options[code] = buf
}

// SetOptionUint32 stores a 32 bit option (lease times).
func (p *Packet) SetOptionUint32(code byte, v uint32) {
	p.Options[code] = binary.BigEndian.AppendUint32(nil, v)
}

// SetOptionString stores a text option.
func (p *Packet) SetOptionString(code byte, s string) {
	if s == "" {
		return
	}
	p.Options[code] = []byte(s)
}

// MACString renders the hardware address.
func (p *Packet) MACString() string {
	if len(p.CHAddr) == 0 {
		return ""
	}
	return p.CHAddr.String()
}

// String is a short description for logs.
func (p *Packet) String() string {
	return fmt.Sprintf("dhcp %s from %s xid=%08x", typeName(p.MessageType()), p.MACString(), p.XID)
}

func typeName(t byte) string {
	switch t {
	case Discover:
		return "DISCOVER"
	case Offer:
		return "OFFER"
	case Request:
		return "REQUEST"
	case Decline:
		return "DECLINE"
	case ACK:
		return "ACK"
	case NAK:
		return "NAK"
	case Release:
		return "RELEASE"
	case Inform:
		return "INFORM"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}
