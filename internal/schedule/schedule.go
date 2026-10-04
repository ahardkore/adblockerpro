// Package schedule implements time-based filtering: homework hours, bedtime
// for the kids' tablets, "no social media during work". Pi-hole has no
// native equivalent — you are expected to drive its API from cron.
package schedule

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ahardkore/adblockerpro/internal/blocklist"
)

// Mode decides what an active window does.
type Mode string

const (
	// ModeBlockAll cuts everything except the allow rules: bedtime.
	ModeBlockAll Mode = "block-all"
	// ModeBlockList blocks only the listed patterns: no TikTok at dinner.
	ModeBlockList Mode = "block-list"
	// ModeAllowOnly permits the listed patterns and blocks the rest:
	// homework time with school sites open.
	ModeAllowOnly Mode = "allow-only"
)

// Schedule is one recurring window.
type Schedule struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Enabled bool     `json:"enabled"`
	// Group selects which devices it applies to; empty means every device.
	Group string `json:"group,omitempty"`
	// Days are mon,tue,wed,thu,fri,sat,sun — or the shorthands "all",
	// "weekdays", "weekends". Empty means every day.
	Days []string `json:"days,omitempty"`
	// Start and End are "HH:MM" in the Pi's local time. A window whose end
	// is before its start wraps past midnight (22:00–07:00).
	Start    string   `json:"start"`
	End      string   `json:"end"`
	Mode     Mode     `json:"mode"`
	Patterns []string `json:"patterns,omitempty"`
}

type compiled struct {
	s       Schedule
	days    map[time.Weekday]bool
	start   int // minutes since midnight
	end     int
	matcher *blocklist.Matcher
}

// Engine evaluates schedules.
type Engine struct {
	mu   sync.RWMutex
	list []compiled
}

// New returns an empty engine.
func New() *Engine { return &Engine{} }

func parseHHMM(s string) (int, error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("schedule: %q is not HH:MM", s)
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("schedule: %q is not a valid time", s)
	}
	return h*60 + m, nil
}

var weekdayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
	"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday,
	"sat": time.Saturday,
}

func parseDays(days []string) map[time.Weekday]bool {
	out := map[time.Weekday]bool{}
	if len(days) == 0 {
		for d := time.Sunday; d <= time.Saturday; d++ {
			out[d] = true
		}
		return out
	}
	for _, raw := range days {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "all", "daily", "everyday":
			for d := time.Sunday; d <= time.Saturday; d++ {
				out[d] = true
			}
		case "weekdays":
			for d := time.Monday; d <= time.Friday; d++ {
				out[d] = true
			}
		case "weekends":
			out[time.Saturday] = true
			out[time.Sunday] = true
		default:
			k := strings.ToLower(strings.TrimSpace(raw))
			if len(k) >= 3 {
				if d, ok := weekdayNames[k[:3]]; ok {
					out[d] = true
				}
			}
		}
	}
	return out
}

// Validate checks a schedule before it is stored.
func Validate(s Schedule) error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("schedule needs a name")
	}
	if _, err := parseHHMM(s.Start); err != nil {
		return err
	}
	if _, err := parseHHMM(s.End); err != nil {
		return err
	}
	switch s.Mode {
	case ModeBlockAll, ModeBlockList, ModeAllowOnly:
	default:
		return fmt.Errorf("schedule mode %q must be block-all, block-list or allow-only", s.Mode)
	}
	if s.Mode != ModeBlockAll && len(s.Patterns) == 0 {
		return fmt.Errorf("mode %s needs at least one pattern", s.Mode)
	}
	return nil
}

// Set replaces every schedule, skipping ones that do not parse.
func (e *Engine) Set(schedules []Schedule) {
	list := make([]compiled, 0, len(schedules))
	for _, s := range schedules {
		start, err := parseHHMM(s.Start)
		if err != nil {
			continue
		}
		end, err := parseHHMM(s.End)
		if err != nil {
			continue
		}
		if s.Mode == "" {
			s.Mode = ModeBlockAll
		}
		list = append(list, compiled{
			s:       s,
			days:    parseDays(s.Days),
			start:   start,
			end:     end,
			matcher: blocklist.NewMatcher(s.Patterns),
		})
	}
	e.mu.Lock()
	e.list = list
	e.mu.Unlock()
}

// All returns the stored schedules.
func (e *Engine) All() []Schedule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Schedule, 0, len(e.list))
	for _, c := range e.list {
		out = append(out, c.s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (c compiled) activeAt(t time.Time) bool {
	if !c.s.Enabled {
		return false
	}
	minutes := t.Hour()*60 + t.Minute()
	if c.start == c.end {
		return false // zero-length window
	}
	if c.start < c.end {
		return c.days[t.Weekday()] && minutes >= c.start && minutes < c.end
	}
	// Wraps midnight: the tail belongs to the previous day's window.
	if minutes >= c.start {
		return c.days[t.Weekday()]
	}
	if minutes < c.end {
		yesterday := (t.Weekday() + 6) % 7
		return c.days[yesterday]
	}
	return false
}

func (c compiled) appliesTo(group string) bool {
	return c.s.Group == "" || strings.EqualFold(c.s.Group, group)
}

// Active returns the schedules currently in force for a group.
func (e *Engine) Active(group string, now time.Time) []Schedule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []Schedule
	for _, c := range e.list {
		if c.appliesTo(group) && c.activeAt(now) {
			out = append(out, c.s)
		}
	}
	return out
}

// Decision reports whether a domain should be blocked right now for a group,
// and which schedule decided it.
func (e *Engine) Decision(group, domain string, now time.Time) (blocked bool, name string) {
	domain = blocklist.Normalize(domain)
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, c := range e.list {
		if !c.appliesTo(group) || !c.activeAt(now) {
			continue
		}
		switch c.s.Mode {
		case ModeBlockAll:
			return true, c.s.Name
		case ModeBlockList:
			if _, hit := c.matcher.Match(domain); hit {
				return true, c.s.Name
			}
		case ModeAllowOnly:
			if _, hit := c.matcher.Match(domain); !hit {
				return true, c.s.Name
			}
		}
	}
	return false, ""
}

// NextChange reports when the schedule picture for a group changes next, so
// the dashboard can show "bedtime starts in 40 minutes".
func (e *Engine) NextChange(group string, now time.Time) (time.Time, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var best time.Time
	found := false
	for i := 1; i <= 24*60; i++ {
		t := now.Add(time.Duration(i) * time.Minute)
		changed := false
		for _, c := range e.list {
			if !c.appliesTo(group) {
				continue
			}
			if c.activeAt(t) != c.activeAt(now) {
				changed = true
				break
			}
		}
		if changed {
			best, found = t.Truncate(time.Minute), true
			break
		}
	}
	return best, found
}
