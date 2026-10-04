// Package dnsmsg implements the small slice of DNS wire-format handling that
// adblockerpro needs: reading the header and question of an incoming query,
// synthesising sinkhole answers, and walking resource records so cached
// responses can have their TTLs aged correctly.
//
// We deliberately avoid a full message parser. Allowed queries are forwarded
// upstream as raw bytes, so only the question section ever has to be decoded.
package dnsmsg

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
)

// Record types we care about by name.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeOPT   uint16 = 41
	TypeDS    uint16 = 43
	TypeSVCB  uint16 = 64
	TypeHTTPS uint16 = 65
	TypeANY   uint16 = 255
)

// Classes.
const (
	ClassINET uint16 = 1
)

// Response codes.
const (
	RcodeSuccess  uint16 = 0
	RcodeFormErr  uint16 = 1
	RcodeServFail uint16 = 2
	RcodeNXDomain uint16 = 3
	RcodeNotImp   uint16 = 4
	RcodeRefused  uint16 = 5
)

// Header flag bits.
const (
	FlagQR uint16 = 1 << 15 // response
	FlagAA uint16 = 1 << 10 // authoritative
	FlagTC uint16 = 1 << 9  // truncated
	FlagRD uint16 = 1 << 8  // recursion desired
	FlagRA uint16 = 1 << 7  // recursion available
)

// HeaderLen is the fixed size of a DNS message header.
const HeaderLen = 12

// MaxMessageSize is the largest message we will ever read or relay.
const MaxMessageSize = 4096

var (
	// ErrShort means the buffer ended before a complete structure was read.
	ErrShort = errors.New("dnsmsg: message too short")
	// ErrNoQuestion means the header claimed zero questions.
	ErrNoQuestion = errors.New("dnsmsg: message has no question")
	// ErrBadName means a label was malformed or compression looped.
	ErrBadName = errors.New("dnsmsg: malformed domain name")
)

// Header is the 12 byte DNS message header.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Rcode returns the response code carried in the flags.
func (h Header) Rcode() uint16 { return h.Flags & 0x000F }

// IsResponse reports whether the QR bit is set.
func (h Header) IsResponse() bool { return h.Flags&FlagQR != 0 }

// Question is a single entry of the question section.
type Question struct {
	// Name is the lower-cased, dot-separated name without a trailing dot.
	// The root is reported as ".".
	Name  string
	Type  uint16
	Class uint16
}

// String renders the question for logging.
func (q Question) String() string { return q.Name + " " + TypeString(q.Type) }

// ParseHeader decodes the fixed header at the start of msg.
func ParseHeader(msg []byte) (Header, error) {
	if len(msg) < HeaderLen {
		return Header{}, ErrShort
	}
	return Header{
		ID:      binary.BigEndian.Uint16(msg[0:2]),
		Flags:   binary.BigEndian.Uint16(msg[2:4]),
		QDCount: binary.BigEndian.Uint16(msg[4:6]),
		ANCount: binary.BigEndian.Uint16(msg[6:8]),
		NSCount: binary.BigEndian.Uint16(msg[8:10]),
		ARCount: binary.BigEndian.Uint16(msg[10:12]),
	}, nil
}

// ID returns the transaction id of a message.
func ID(msg []byte) uint16 {
	if len(msg) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(msg[0:2])
}

// SetID rewrites the transaction id in place. Used when replaying a cached
// response to a new client.
func SetID(msg []byte, id uint16) {
	if len(msg) >= 2 {
		binary.BigEndian.PutUint16(msg[0:2], id)
	}
}

// ParseQuestion decodes the first question of msg and returns the offset of
// the first byte after the question section entry.
func ParseQuestion(msg []byte) (Question, int, error) {
	h, err := ParseHeader(msg)
	if err != nil {
		return Question{}, 0, err
	}
	if h.QDCount == 0 {
		return Question{}, 0, ErrNoQuestion
	}
	name, off, err := readName(msg, HeaderLen)
	if err != nil {
		return Question{}, 0, err
	}
	if off+4 > len(msg) {
		return Question{}, 0, ErrShort
	}
	q := Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(msg[off : off+2]),
		Class: binary.BigEndian.Uint16(msg[off+2 : off+4]),
	}
	return q, off + 4, nil
}

// readName decodes a (possibly compressed) domain name starting at off and
// returns the name plus the offset just past the name as it appears in the
// message (i.e. past the pointer, if one was used).
func readName(msg []byte, off int) (string, int, error) {
	var (
		sb       strings.Builder
		jumped   bool
		next     int
		budget   = 255
		maxJumps = 16
		jumps    int
	)
	for {
		if off >= len(msg) {
			return "", 0, ErrShort
		}
		l := int(msg[off])
		switch {
		case l == 0:
			off++
			if !jumped {
				next = off
			}
			if sb.Len() == 0 {
				return ".", next, nil
			}
			return sb.String(), next, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, ErrShort
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)
			if !jumped {
				next = off + 2
				jumped = true
			}
			jumps++
			if jumps > maxJumps || ptr >= len(msg) {
				return "", 0, ErrBadName
			}
			off = ptr
		case l&0xC0 != 0:
			return "", 0, ErrBadName
		default:
			start := off + 1
			end := start + l
			if end > len(msg) {
				return "", 0, ErrShort
			}
			budget -= l + 1
			if budget <= 0 {
				return "", 0, ErrBadName
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			for _, c := range msg[start:end] {
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				sb.WriteByte(c)
			}
			off = end
		}
	}
}

// skipName advances past a name without decoding it.
func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, ErrShort
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return 0, ErrShort
			}
			return off + 2, nil
		case l&0xC0 != 0:
			return 0, ErrBadName
		default:
			off += l + 1
		}
	}
}

// EncodeName writes name in wire format.
func EncodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return []byte{0}, nil
	}
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, ErrBadName
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	if len(out) > 255 {
		return nil, ErrBadName
	}
	return out, nil
}

// TypeString renders a record type for humans.
func TypeString(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	case TypeOPT:
		return "OPT"
	case TypeDS:
		return "DS"
	case TypeSVCB:
		return "SVCB"
	case TypeHTTPS:
		return "HTTPS"
	case TypeANY:
		return "ANY"
	default:
		return "TYPE" + strconv.Itoa(int(t))
	}
}

// RcodeString renders a response code for humans.
func RcodeString(r uint16) string {
	switch r {
	case RcodeSuccess:
		return "NOERROR"
	case RcodeFormErr:
		return "FORMERR"
	case RcodeServFail:
		return "SERVFAIL"
	case RcodeNXDomain:
		return "NXDOMAIN"
	case RcodeNotImp:
		return "NOTIMP"
	case RcodeRefused:
		return "REFUSED"
	default:
		return "RCODE" + strconv.Itoa(int(r))
	}
}

// response builds the common prefix of a reply: header plus an echo of the
// question section entry taken verbatim from the query.
func response(query []byte, qend int, rcode uint16, answers uint16) []byte {
	h, _ := ParseHeader(query)
	out := make([]byte, 0, qend+32)
	out = append(out, query[:qend]...)
	binary.BigEndian.PutUint16(out[2:4], FlagQR|FlagRA|(h.Flags&FlagRD)|rcode)
	binary.BigEndian.PutUint16(out[4:6], 1)       // QDCOUNT
	binary.BigEndian.PutUint16(out[6:8], answers) // ANCOUNT
	binary.BigEndian.PutUint16(out[8:10], 0)      // NSCOUNT
	binary.BigEndian.PutUint16(out[10:12], 0)     // ARCOUNT
	return out
}

// Error builds a reply to query carrying only the given response code.
func Error(query []byte, rcode uint16) []byte {
	_, qend, err := ParseQuestion(query)
	if err != nil {
		if len(query) < HeaderLen {
			return nil
		}
		out := make([]byte, HeaderLen)
		copy(out, query[:HeaderLen])
		binary.BigEndian.PutUint16(out[2:4], FlagQR|FlagRA|rcode)
		binary.BigEndian.PutUint16(out[4:6], 0)
		binary.BigEndian.PutUint16(out[6:8], 0)
		binary.BigEndian.PutUint16(out[8:10], 0)
		binary.BigEndian.PutUint16(out[10:12], 0)
		return out
	}
	return response(query, qend, rcode, 0)
}

// SinkholeMode selects what a blocked client receives.
type SinkholeMode string

const (
	// SinkZeroIP answers A/AAAA with the unspecified address. Fastest failure
	// for most clients and the default.
	SinkZeroIP SinkholeMode = "zero-ip"
	// SinkNXDomain answers NXDOMAIN. Smallest response, but some apps retry
	// aggressively against their hard-coded fallback resolvers.
	SinkNXDomain SinkholeMode = "nxdomain"
	// SinkRefused answers REFUSED.
	SinkRefused SinkholeMode = "refused"
	// SinkCustomIP answers A/AAAA with a configured address, e.g. the Pi
	// itself serving a 1x1 pixel.
	SinkCustomIP SinkholeMode = "custom-ip"
)

// Block builds the sinkhole reply for a blocked query.
//
// ttl is the TTL advertised on synthesised records. For modes that cannot
// carry an address (or question types other than A/AAAA) a NODATA style
// NOERROR answer is produced, which clients treat as "no such record".
func Block(query []byte, qend int, q Question, mode SinkholeMode, v4, v6 net.IP, ttl uint32) []byte {
	switch mode {
	case SinkNXDomain:
		return response(query, qend, RcodeNXDomain, 0)
	case SinkRefused:
		return response(query, qend, RcodeRefused, 0)
	}

	var rdata []byte
	switch q.Type {
	case TypeA:
		ip := v4
		if mode != SinkCustomIP || ip == nil {
			ip = net.IPv4zero
		}
		if v4 := ip.To4(); v4 != nil {
			rdata = append(rdata, v4...)
		}
	case TypeAAAA:
		ip := v6
		if mode != SinkCustomIP || ip == nil {
			ip = net.IPv6unspecified
		}
		if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
			rdata = append(rdata, v6...)
		}
	}
	if len(rdata) == 0 {
		// NODATA: NOERROR with an empty answer section.
		return response(query, qend, RcodeSuccess, 0)
	}

	out := response(query, qend, RcodeSuccess, 1)
	out = append(out, 0xC0, 0x0C) // pointer to the question name
	out = binary.BigEndian.AppendUint16(out, q.Type)
	out = binary.BigEndian.AppendUint16(out, ClassINET)
	out = binary.BigEndian.AppendUint32(out, ttl)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
	out = append(out, rdata...)
	return out
}

// TTLInfo describes the TTLs found in a response, so a cached copy can be
// aged before it is replayed.
type TTLInfo struct {
	// MinTTL is the smallest TTL across all records (0 if there are none).
	MinTTL uint32
	// Offsets are byte positions of each 32 bit TTL field in the message.
	Offsets []int
	// Records is the number of resource records walked.
	Records int
}

// ScanTTLs walks every resource record in msg and records TTL positions.
func ScanTTLs(msg []byte) (TTLInfo, error) {
	h, err := ParseHeader(msg)
	if err != nil {
		return TTLInfo{}, err
	}
	off := HeaderLen
	for i := 0; i < int(h.QDCount); i++ {
		off, err = skipName(msg, off)
		if err != nil {
			return TTLInfo{}, err
		}
		off += 4
		if off > len(msg) {
			return TTLInfo{}, ErrShort
		}
	}
	info := TTLInfo{MinTTL: ^uint32(0)}
	total := int(h.ANCount) + int(h.NSCount) + int(h.ARCount)
	for i := 0; i < total; i++ {
		off, err = skipName(msg, off)
		if err != nil {
			return TTLInfo{}, err
		}
		if off+10 > len(msg) {
			return TTLInfo{}, ErrShort
		}
		rrType := binary.BigEndian.Uint16(msg[off : off+2])
		ttlOff := off + 4
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		if rrType != TypeOPT { // OPT reuses the TTL field for flags
			ttl := binary.BigEndian.Uint32(msg[ttlOff : ttlOff+4])
			if ttl < info.MinTTL {
				info.MinTTL = ttl
			}
			info.Offsets = append(info.Offsets, ttlOff)
			info.Records++
		}
		off += 10 + rdlen
		if off > len(msg) {
			return TTLInfo{}, ErrShort
		}
	}
	if info.Records == 0 {
		info.MinTTL = 0
	}
	return info, nil
}

// AgeTTLs subtracts elapsed seconds from every TTL recorded in info,
// clamping at zero. msg is modified in place.
func AgeTTLs(msg []byte, info TTLInfo, elapsed uint32) {
	for _, off := range info.Offsets {
		if off+4 > len(msg) {
			continue
		}
		ttl := binary.BigEndian.Uint32(msg[off : off+4])
		if ttl > elapsed {
			ttl -= elapsed
		} else {
			ttl = 0
		}
		binary.BigEndian.PutUint32(msg[off:off+4], ttl)
	}
}

// FirstAnswer returns a short, human readable rendering of the first A, AAAA
// or CNAME record in the answer section. It is best effort and used only for
// the query log.
func FirstAnswer(msg []byte) string {
	h, err := ParseHeader(msg)
	if err != nil || h.ANCount == 0 {
		return ""
	}
	off := HeaderLen
	for i := 0; i < int(h.QDCount); i++ {
		if off, err = skipName(msg, off); err != nil {
			return ""
		}
		off += 4
	}
	for i := 0; i < int(h.ANCount); i++ {
		if off, err = skipName(msg, off); err != nil {
			return ""
		}
		if off+10 > len(msg) {
			return ""
		}
		rrType := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		rdStart := off + 10
		rdEnd := rdStart + rdlen
		if rdEnd > len(msg) {
			return ""
		}
		switch {
		case rrType == TypeA && rdlen == 4:
			return net.IP(msg[rdStart:rdEnd]).String()
		case rrType == TypeAAAA && rdlen == 16:
			return net.IP(msg[rdStart:rdEnd]).String()
		case rrType == TypeCNAME:
			if name, _, err := readName(msg, rdStart); err == nil {
				return name
			}
		}
		off = rdEnd
	}
	return ""
}

// CNAMETargets returns every CNAME target in the answer section. The blocking
// engine re-checks these so that CNAME-cloaked trackers (a first-party
// hostname aliased to an ad network) are still caught.
func CNAMETargets(msg []byte) []string {
	h, err := ParseHeader(msg)
	if err != nil || h.ANCount == 0 {
		return nil
	}
	off := HeaderLen
	for i := 0; i < int(h.QDCount); i++ {
		if off, err = skipName(msg, off); err != nil {
			return nil
		}
		off += 4
	}
	var out []string
	for i := 0; i < int(h.ANCount); i++ {
		if off, err = skipName(msg, off); err != nil {
			return out
		}
		if off+10 > len(msg) {
			return out
		}
		rrType := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		rdStart := off + 10
		if rdStart+rdlen > len(msg) {
			return out
		}
		if rrType == TypeCNAME {
			if name, _, err := readName(msg, rdStart); err == nil {
				out = append(out, name)
			}
		}
		off = rdStart + rdlen
	}
	return out
}

// SetTTLs overwrites every TTL recorded in info with ttl. Used when serving
// a stale cache entry, so clients re-ask soon.
func SetTTLs(msg []byte, info TTLInfo, ttl uint32) {
	for _, off := range info.Offsets {
		if off+4 > len(msg) {
			continue
		}
		binary.BigEndian.PutUint32(msg[off:off+4], ttl)
	}
}

// Additional header flag bits.
const (
	FlagAD uint16 = 1 << 5 // authenticated data (upstream validated DNSSEC)
	FlagCD uint16 = 1 << 4 // checking disabled
)

// Authenticated reports whether the AD bit is set, i.e. a validating
// upstream vouched for the answer's DNSSEC signatures.
func Authenticated(msg []byte) bool {
	h, err := ParseHeader(msg)
	if err != nil {
		return false
	}
	return h.Flags&FlagAD != 0
}

// HasOPT reports whether the message already carries an EDNS0 OPT record.
func HasOPT(msg []byte) bool {
	h, err := ParseHeader(msg)
	if err != nil || h.ARCount == 0 {
		return false
	}
	off := HeaderLen
	for i := 0; i < int(h.QDCount); i++ {
		if off, err = skipName(msg, off); err != nil {
			return false
		}
		off += 4
	}
	total := int(h.ANCount) + int(h.NSCount) + int(h.ARCount)
	for i := 0; i < total; i++ {
		if off, err = skipName(msg, off); err != nil {
			return false
		}
		if off+10 > len(msg) {
			return false
		}
		if binary.BigEndian.Uint16(msg[off:off+2]) == TypeOPT {
			return true
		}
		off += 10 + int(binary.BigEndian.Uint16(msg[off+8:off+10]))
	}
	return false
}

// WithDNSSEC returns a copy of query carrying an EDNS0 OPT record with the
// DO bit set, so a validating upstream signs off on the answer (the AD bit
// comes back in the reply). Queries that already have an OPT record are
// returned unchanged — rewriting a client's own EDNS options would be rude.
func WithDNSSEC(query []byte, udpSize uint16) []byte {
	if len(query) < HeaderLen || HasOPT(query) {
		return query
	}
	if udpSize < 512 {
		udpSize = 1232 // the DNS flag day recommendation
	}
	h, err := ParseHeader(query)
	if err != nil {
		return query
	}
	out := make([]byte, 0, len(query)+11)
	out = append(out, query...)
	out = append(out,
		0x00, // root name
	)
	out = binary.BigEndian.AppendUint16(out, TypeOPT)
	out = binary.BigEndian.AppendUint16(out, udpSize)    // class = UDP payload size
	out = binary.BigEndian.AppendUint32(out, 0x00008000) // extended rcode/version + DO
	out = binary.BigEndian.AppendUint16(out, 0)          // rdlength
	binary.BigEndian.PutUint16(out[10:12], h.ARCount+1)
	return out
}

// BuildQuery assembles a standard recursive query, used by the prefetcher
// and by the command line tools.
func BuildQuery(name string, qtype uint16, id uint16) ([]byte, error) {
	enc, err := EncodeName(name)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, HeaderLen, HeaderLen+len(enc)+4)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], FlagRD)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, enc...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, ClassINET)
	return msg, nil
}
