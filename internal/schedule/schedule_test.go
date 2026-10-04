package schedule

import (
	"testing"
	"time"
)

func at(t *testing.T, s string) time.Time {
	t.Helper()
	// 2026-10-05 is a Monday.
	parsed, err := time.ParseInLocation("2006-01-02 15:04", s, time.Local)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return parsed
}

func TestBedtimeWrapsMidnight(t *testing.T) {
	e := New()
	e.Set([]Schedule{{
		ID: "1", Name: "Bedtime", Enabled: true, Group: "kids",
		Start: "22:00", End: "07:00", Mode: ModeBlockAll,
	}})

	cases := []struct {
		when  string
		block bool
	}{
		{"2026-10-05 22:30", true},
		{"2026-10-06 02:00", true},
		{"2026-10-06 06:59", true},
		{"2026-10-06 07:00", false},
		{"2026-10-05 21:59", false},
		{"2026-10-05 12:00", false},
	}
	for _, c := range cases {
		blocked, name := e.Decision("kids", "anything.example", at(t, c.when))
		if blocked != c.block {
			t.Errorf("%s: blocked=%v, want %v (schedule %q)", c.when, blocked, c.block, name)
		}
	}
}

func TestGroupScoping(t *testing.T) {
	e := New()
	e.Set([]Schedule{{
		ID: "1", Name: "Bedtime", Enabled: true, Group: "kids",
		Start: "22:00", End: "07:00", Mode: ModeBlockAll,
	}})
	night := at(t, "2026-10-05 23:00")
	if blocked, _ := e.Decision("kids", "x.example", night); !blocked {
		t.Error("kids should be blocked at 23:00")
	}
	if blocked, _ := e.Decision("", "x.example", night); blocked {
		t.Error("ungrouped devices should be unaffected")
	}
}

func TestBlockListMode(t *testing.T) {
	e := New()
	e.Set([]Schedule{{
		ID: "2", Name: "Dinner", Enabled: true,
		Start: "18:00", End: "19:00", Mode: ModeBlockList,
		Patterns: []string{"*.tiktok.com", "instagram.com"},
	}})
	dinner := at(t, "2026-10-05 18:30")
	if blocked, _ := e.Decision("", "www.tiktok.com", dinner); !blocked {
		t.Error("tiktok should be blocked at dinner")
	}
	if blocked, _ := e.Decision("", "wikipedia.org", dinner); blocked {
		t.Error("wikipedia should stay available")
	}
	if blocked, _ := e.Decision("", "www.tiktok.com", at(t, "2026-10-05 20:00")); blocked {
		t.Error("the window has closed")
	}
}

func TestAllowOnlyMode(t *testing.T) {
	e := New()
	e.Set([]Schedule{{
		ID: "3", Name: "Homework", Enabled: true, Group: "kids",
		Days: []string{"weekdays"}, Start: "16:00", End: "18:00",
		Mode: ModeAllowOnly, Patterns: []string{"*.wikipedia.org", "classroom.google.com"},
	}})
	homework := at(t, "2026-10-05 17:00") // Monday
	if blocked, _ := e.Decision("kids", "en.wikipedia.org", homework); blocked {
		t.Error("wikipedia should be allowed during homework")
	}
	if blocked, _ := e.Decision("kids", "youtube.com", homework); !blocked {
		t.Error("everything else should be blocked during homework")
	}
	weekend := at(t, "2026-10-10 17:00") // Saturday
	if blocked, _ := e.Decision("kids", "youtube.com", weekend); blocked {
		t.Error("weekdays-only schedule must not fire on Saturday")
	}
}

func TestDisabledSchedule(t *testing.T) {
	e := New()
	e.Set([]Schedule{{ID: "4", Name: "Off", Enabled: false, Start: "00:00", End: "23:59", Mode: ModeBlockAll}})
	if blocked, _ := e.Decision("", "x.example", time.Now()); blocked {
		t.Error("a disabled schedule must not block")
	}
}

func TestActiveAndNextChange(t *testing.T) {
	e := New()
	e.Set([]Schedule{{ID: "5", Name: "Focus", Enabled: true, Start: "09:00", End: "11:00", Mode: ModeBlockAll}})
	during := at(t, "2026-10-05 09:30")
	if got := e.Active("", during); len(got) != 1 || got[0].Name != "Focus" {
		t.Errorf("Active = %+v", got)
	}
	next, ok := e.NextChange("", during)
	if !ok {
		t.Fatal("expected a next change")
	}
	if next.Hour() != 11 || next.Minute() != 0 {
		t.Errorf("next change = %s, want 11:00", next.Format("15:04"))
	}
}

func TestValidate(t *testing.T) {
	ok := Schedule{Name: "x", Start: "08:00", End: "09:00", Mode: ModeBlockAll}
	if err := Validate(ok); err != nil {
		t.Errorf("valid schedule rejected: %v", err)
	}
	bad := []Schedule{
		{Name: "", Start: "08:00", End: "09:00", Mode: ModeBlockAll},
		{Name: "x", Start: "25:00", End: "09:00", Mode: ModeBlockAll},
		{Name: "x", Start: "08:00", End: "09:61", Mode: ModeBlockAll},
		{Name: "x", Start: "08:00", End: "09:00", Mode: "nonsense"},
		{Name: "x", Start: "08:00", End: "09:00", Mode: ModeBlockList},
	}
	for i, s := range bad {
		if err := Validate(s); err == nil {
			t.Errorf("case %d should have failed validation", i)
		}
	}
}

func TestParseDaysShorthand(t *testing.T) {
	days := parseDays([]string{"weekends"})
	if !days[time.Saturday] || !days[time.Sunday] || days[time.Monday] {
		t.Errorf("weekends = %+v", days)
	}
	all := parseDays(nil)
	for d := time.Sunday; d <= time.Saturday; d++ {
		if !all[d] {
			t.Errorf("empty day list should mean every day, %v missing", d)
		}
	}
}
