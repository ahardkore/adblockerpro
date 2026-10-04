// Package blocklist holds the matching engine: the compiled set of domains
// pulled from upstream lists plus the user's own allow/deny rules.
package blocklist

import (
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// Action is what a rule does when it matches.
type Action string

const (
	// ActionBlock sinkholes the query.
	ActionBlock Action = "block"
	// ActionAllow lets the query through even if a list blocks it.
	ActionAllow Action = "allow"
)

// Rule is a single user-authored pattern.
//
// Supported pattern forms:
//
//	example.com     exact host (and its subdomains when BlockSubdomains is on)
//	*.example.com   the domain and every subdomain, always
//	/^ads?[0-9]*\./ regular expression, delimited by slashes
type Rule struct {
	Pattern string `json:"pattern"`
	Action  Action `json:"action"`
	Comment string `json:"comment,omitempty"`
	Group   string `json:"group,omitempty"` // empty = applies to every device
	Created string `json:"created,omitempty"`
}

// Decision is the outcome of evaluating a domain.
type Decision struct {
	Blocked bool `json:"blocked"`
	// Rule is the pattern or list entry that matched.
	Rule string `json:"rule,omitempty"`
	// Source names where the match came from: "allowlist", "denylist",
	// "regex", or the title of an upstream blocklist.
	Source string `json:"source,omitempty"`
	// MatchedDomain is the name that actually matched, which can differ from
	// the queried name when a parent domain or CNAME target is blocked.
	MatchedDomain string `json:"matched_domain,omitempty"`
}

type compiledRules struct {
	exact    map[string]Rule
	wildcard map[string]Rule // suffix label set, e.g. "example.com"
	regex    []compiledRegex
}

type compiledRegex struct {
	re   *regexp.Regexp
	rule Rule
}

func compile(rules []Rule, action Action, group string) compiledRules {
	c := compiledRules{
		exact:    make(map[string]Rule),
		wildcard: make(map[string]Rule),
	}
	for _, r := range rules {
		if r.Action != action {
			continue
		}
		if !strings.EqualFold(r.Group, group) {
			// group == "" keeps only global rules; a named group keeps only
			// that group's rules (globals are evaluated separately).
			continue
		}
		p := strings.TrimSpace(strings.ToLower(r.Pattern))
		switch {
		case p == "":
			continue
		case len(p) > 2 && strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/"):
			re, err := regexp.Compile(p[1 : len(p)-1])
			if err != nil {
				continue
			}
			c.regex = append(c.regex, compiledRegex{re: re, rule: r})
		case strings.HasPrefix(p, "*."):
			c.wildcard[strings.TrimSuffix(p[2:], ".")] = r
		default:
			c.exact[strings.TrimSuffix(p, ".")] = r
		}
	}
	return c
}

func (c compiledRules) match(domain string) (Rule, bool) {
	if r, ok := c.exact[domain]; ok {
		return r, true
	}
	for i := 0; i < len(domain); i++ {
		if domain[i] != '.' {
			continue
		}
		if r, ok := c.wildcard[domain[i+1:]]; ok {
			return r, true
		}
	}
	if r, ok := c.wildcard[domain]; ok {
		return r, true
	}
	for _, cr := range c.regex {
		if cr.re.MatchString(domain) {
			return cr.rule, true
		}
	}
	return Rule{}, false
}

// Engine evaluates domains against the aggregated blocklists and user rules.
// It is safe for concurrent use; list reloads swap an immutable snapshot in.
type Engine struct {
	// BlockSubdomains makes a listed domain also cover every subdomain.
	blockSubdomains atomic.Bool

	domains      atomic.Pointer[DomainSet] // blocked domains from subscribed lists
	allowDomains atomic.Pointer[DomainSet] // subscribed allowlists ("antigravity")

	mu     sync.RWMutex
	rules  []Rule
	global struct {
		allow compiledRules
		deny  compiledRules
	}
	groups map[string]*groupRules
}

type groupRules struct {
	allow compiledRules
	deny  compiledRules
}

// DomainSet is an immutable set of blocked domains with the list each came
// from, produced by the updater.
type DomainSet struct {
	domains map[string]string // domain -> list title
	count   int
}

// NewDomainSet builds a set from a domain -> source map.
func NewDomainSet(m map[string]string) *DomainSet {
	if m == nil {
		m = map[string]string{}
	}
	return &DomainSet{domains: m, count: len(m)}
}

// Len is the number of domains in the set.
func (d *DomainSet) Len() int {
	if d == nil {
		return 0
	}
	return d.count
}

// Contains reports whether domain is listed verbatim.
func (d *DomainSet) Contains(domain string) (string, bool) {
	if d == nil {
		return "", false
	}
	src, ok := d.domains[domain]
	return src, ok
}

// New returns an engine with an empty list set.
func New(blockSubdomains bool) *Engine {
	e := &Engine{groups: map[string]*groupRules{}}
	e.blockSubdomains.Store(blockSubdomains)
	e.domains.Store(NewDomainSet(nil))
	e.allowDomains.Store(NewDomainSet(nil))
	e.SetRules(nil)
	return e
}

// SetBlockSubdomains toggles subdomain coverage for list entries.
func (e *Engine) SetBlockSubdomains(v bool) { e.blockSubdomains.Store(v) }

// SetDomains swaps in a freshly downloaded domain set.
func (e *Engine) SetDomains(d *DomainSet) { e.domains.Store(d) }

// Domains returns the current set.
func (e *Engine) Domains() *DomainSet { return e.domains.Load() }

// SetRules replaces every user rule and recompiles the matchers.
func (e *Engine) SetRules(rules []Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append([]Rule(nil), rules...)
	e.global.allow = compile(e.rules, ActionAllow, "")
	e.global.deny = compile(e.rules, ActionBlock, "")
	groups := map[string]*groupRules{}
	for _, r := range e.rules {
		if r.Group == "" {
			continue
		}
		g := strings.ToLower(r.Group)
		if _, ok := groups[g]; !ok {
			groups[g] = &groupRules{
				allow: compile(e.rules, ActionAllow, g),
				deny:  compile(e.rules, ActionBlock, g),
			}
		}
	}
	e.groups = groups
}

// Rules returns a copy of the current rule list.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Rule(nil), e.rules...)
}

// AddRule appends a rule, replacing an existing one with the same pattern,
// action and group.
func (e *Engine) AddRule(r Rule) {
	rules := e.Rules()
	for i, existing := range rules {
		if strings.EqualFold(existing.Pattern, r.Pattern) &&
			existing.Action == r.Action &&
			strings.EqualFold(existing.Group, r.Group) {
			rules[i] = r
			e.SetRules(rules)
			return
		}
	}
	e.SetRules(append(rules, r))
}

// RemoveRule deletes the first rule matching pattern (and action/group when
// they are non-empty). It reports whether anything was removed.
func (e *Engine) RemoveRule(pattern string, action Action, group string) bool {
	rules := e.Rules()
	for i, r := range rules {
		if !strings.EqualFold(r.Pattern, pattern) {
			continue
		}
		if action != "" && r.Action != action {
			continue
		}
		if group != "" && !strings.EqualFold(r.Group, group) {
			continue
		}
		e.SetRules(append(rules[:i], rules[i+1:]...))
		return true
	}
	return false
}

// Normalize lower-cases a queried name and strips the trailing dot.
func Normalize(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// Check evaluates domain for a device in the given group ("" for the default
// group). Allow rules always win over block rules.
func (e *Engine) Check(domain, group string) Decision {
	domain = Normalize(domain)
	if domain == "" || domain == "." {
		return Decision{}
	}

	e.mu.RLock()
	globalAllow, globalDeny := e.global.allow, e.global.deny
	var gr *groupRules
	if group != "" {
		gr = e.groups[strings.ToLower(group)]
	}
	e.mu.RUnlock()

	if gr != nil {
		if r, ok := gr.allow.match(domain); ok {
			return Decision{Rule: r.Pattern, Source: "allowlist:" + group, MatchedDomain: domain}
		}
	}
	if r, ok := globalAllow.match(domain); ok {
		return Decision{Rule: r.Pattern, Source: "allowlist", MatchedDomain: domain}
	}
	if gr != nil {
		if r, ok := gr.deny.match(domain); ok {
			return Decision{Blocked: true, Rule: r.Pattern, Source: "denylist:" + group, MatchedDomain: domain}
		}
	}
	if r, ok := globalDeny.match(domain); ok {
		return Decision{Blocked: true, Rule: r.Pattern, Source: "denylist", MatchedDomain: domain}
	}

	if allow := e.allowDomains.Load(); allow.Len() > 0 {
		if src, ok := allow.Contains(domain); ok {
			return Decision{Rule: domain, Source: "allowlist:" + src, MatchedDomain: domain}
		}
		for i := 0; i < len(domain); i++ {
			if domain[i] != '.' {
				continue
			}
			if src, ok := allow.Contains(domain[i+1:]); ok {
				return Decision{Rule: domain[i+1:], Source: "allowlist:" + src, MatchedDomain: domain[i+1:]}
			}
		}
	}

	set := e.domains.Load()
	if src, ok := set.Contains(domain); ok {
		return Decision{Blocked: true, Rule: domain, Source: src, MatchedDomain: domain}
	}
	if e.blockSubdomains.Load() {
		for i := 0; i < len(domain); i++ {
			if domain[i] != '.' {
				continue
			}
			parent := domain[i+1:]
			if src, ok := set.Contains(parent); ok {
				return Decision{Blocked: true, Rule: parent, Source: src, MatchedDomain: parent}
			}
		}
	}
	return Decision{}
}

// CheckCNAMEs runs Check over CNAME targets so cloaked trackers are caught
// after the upstream answer comes back.
func (e *Engine) CheckCNAMEs(targets []string, group string) Decision {
	for _, t := range targets {
		if d := e.Check(t, group); d.Blocked {
			d.Source = d.Source + " (cname)"
			return d
		}
	}
	return Decision{}
}

// Matcher is a standalone pattern set, used by features that need the same
// exact/wildcard/regex semantics as the rule engine (schedules, allowlist
// subscriptions) without the rest of the engine.
type Matcher struct {
	rules compiledRules
}

// NewMatcher compiles patterns into a matcher. Invalid regexes are skipped.
func NewMatcher(patterns []string) *Matcher {
	rules := make([]Rule, 0, len(patterns))
	for _, p := range patterns {
		rules = append(rules, Rule{Pattern: p, Action: ActionBlock})
	}
	return &Matcher{rules: compile(rules, ActionBlock, "")}
}

// Match reports whether domain matches, and which pattern did it.
func (m *Matcher) Match(domain string) (string, bool) {
	if m == nil {
		return "", false
	}
	r, ok := m.rules.match(Normalize(domain))
	return r.Pattern, ok
}

// Len is the number of compiled patterns.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.rules.exact) + len(m.rules.wildcard) + len(m.rules.regex)
}

// SetAllowDomains installs a set of subscribed allowlist domains ("I trust
// these lists to override my blocklists"), the equivalent of Pi-hole v6's
// Antigravity lists.
func (e *Engine) SetAllowDomains(d *DomainSet) { e.allowDomains.Store(d) }

// AllowDomains returns the subscribed allowlist set.
func (e *Engine) AllowDomains() *DomainSet { return e.allowDomains.Load() }
