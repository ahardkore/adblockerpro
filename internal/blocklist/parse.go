package blocklist

import (
	"bufio"
	"io"
	"strings"
)

// ParseList reads a blocklist in any of the common formats and returns the
// domains it contains.
//
// Accepted syntax, line by line:
//
//	0.0.0.0 ads.example.com      hosts format (any sink address)
//	127.0.0.1 ads.example.com    hosts format
//	ads.example.com              plain domain list
//	||ads.example.com^           Adblock Plus style host rule
//
// Comments (# or !), blank lines, localhost boilerplate and anything that is
// not a plausible hostname are skipped.
func ParseList(r io.Reader) []string {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	seen := make(map[string]struct{}, 1024)
	out := make([]string, 0, 1024)

	add := func(d string) {
		d = Normalize(d)
		if !ValidDomain(d) || isLocalhostName(d) {
			return
		}
		if _, dup := seen[d]; dup {
			return
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if i := strings.IndexAny(line, "#!"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}

		// Adblock Plus host rules: ||domain^ (ignore ones with modifiers,
		// element hiding or path components, which DNS cannot express).
		if strings.HasPrefix(line, "||") {
			rest := strings.TrimPrefix(line, "||")
			end := strings.IndexAny(rest, "^$/*")
			if end >= 0 {
				if strings.ContainsAny(rest[end:], "/*") {
					continue
				}
				rest = rest[:end]
			}
			add(rest)
			continue
		}
		if strings.ContainsAny(line, "/*@|$") {
			continue
		}

		fields := strings.Fields(line)
		switch len(fields) {
		case 1:
			add(fields[0])
		default:
			// hosts format: first field is the sink address, the rest hosts.
			if looksLikeIP(fields[0]) {
				for _, h := range fields[1:] {
					add(h)
				}
			} else {
				add(fields[0])
			}
		}
	}
	return out
}

func looksLikeIP(s string) bool {
	if strings.Contains(s, ":") {
		return true
	}
	dots := 0
	for _, c := range s {
		switch {
		case c == '.':
			dots++
		case c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return dots == 3
}

func isLocalhostName(d string) bool {
	switch d {
	case "localhost", "localhost.localdomain", "local", "broadcasthost",
		"ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
		"ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0":
		return true
	}
	return false
}

// ValidDomain reports whether d is a syntactically plausible hostname.
func ValidDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	if looksLikeIP(d) {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return false
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	// The TLD must not be purely numeric.
	tld := labels[len(labels)-1]
	allDigits := true
	for i := 0; i < len(tld); i++ {
		if tld[i] < '0' || tld[i] > '9' {
			allDigits = false
			break
		}
	}
	return !allDigits
}
