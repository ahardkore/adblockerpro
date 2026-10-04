package blocklist

import "testing"

func testEngine(t *testing.T) *Engine {
	t.Helper()
	e := New(true)
	e.SetDomains(NewDomainSet(map[string]string{
		"doubleclick.net":      "TestList",
		"ads.example.com":      "TestList",
		"analytics.tiktok.com": "TestList",
	}))
	return e
}

func TestExactAndSubdomainMatching(t *testing.T) {
	e := testEngine(t)

	if d := e.Check("doubleclick.net", ""); !d.Blocked {
		t.Error("exact listed domain should be blocked")
	}
	if d := e.Check("stats.g.doubleclick.net", ""); !d.Blocked {
		t.Errorf("subdomain should be blocked, got %+v", d)
	} else if d.MatchedDomain != "doubleclick.net" {
		t.Errorf("matched %q, want doubleclick.net", d.MatchedDomain)
	}
	if d := e.Check("example.com", ""); d.Blocked {
		t.Error("parent of a listed subdomain must not be blocked")
	}
	if d := e.Check("notdoubleclick.net", ""); d.Blocked {
		t.Error("suffix string match must not count as a subdomain")
	}

	e.SetBlockSubdomains(false)
	if d := e.Check("stats.g.doubleclick.net", ""); d.Blocked {
		t.Error("subdomain blocking is off, should be allowed")
	}
}

func TestAllowRuleBeatsList(t *testing.T) {
	e := testEngine(t)
	e.SetRules([]Rule{{Pattern: "ads.example.com", Action: ActionAllow}})
	if d := e.Check("ads.example.com", ""); d.Blocked {
		t.Errorf("allow rule should win, got %+v", d)
	}
	if d := e.Check("doubleclick.net", ""); !d.Blocked {
		t.Error("unrelated domain should still be blocked")
	}
}

func TestWildcardAndRegexRules(t *testing.T) {
	e := New(true)
	e.SetRules([]Rule{
		{Pattern: "*.metrics.example.net", Action: ActionBlock},
		{Pattern: `/^ads?[0-9]*\./`, Action: ActionBlock},
	})
	for _, d := range []string{"a.metrics.example.net", "metrics.example.net", "ads3.cdn.io", "ad.cdn.io"} {
		if !e.Check(d, "").Blocked {
			t.Errorf("%s should be blocked", d)
		}
	}
	for _, d := range []string{"example.net", "downloads.cdn.io"} {
		if e.Check(d, "").Blocked {
			t.Errorf("%s should be allowed", d)
		}
	}
}

func TestGroupScopedRules(t *testing.T) {
	e := New(true)
	e.SetRules([]Rule{
		{Pattern: "youtube.com", Action: ActionBlock, Group: "kids"},
		{Pattern: "doubleclick.net", Action: ActionBlock},
	})
	if !e.Check("youtube.com", "kids").Blocked {
		t.Error("kids group should block youtube.com")
	}
	if e.Check("youtube.com", "").Blocked {
		t.Error("default group should not block youtube.com")
	}
	if !e.Check("doubleclick.net", "kids").Blocked {
		t.Error("global rules apply to every group")
	}
}

func TestAddAndRemoveRule(t *testing.T) {
	e := New(true)
	e.AddRule(Rule{Pattern: "tracker.io", Action: ActionBlock})
	e.AddRule(Rule{Pattern: "tracker.io", Action: ActionBlock, Comment: "dupe"})
	if got := len(e.Rules()); got != 1 {
		t.Fatalf("rules = %d, want 1 after replacing a duplicate", got)
	}
	if !e.Check("tracker.io", "").Blocked {
		t.Error("rule should block")
	}
	if !e.RemoveRule("tracker.io", ActionBlock, "") {
		t.Fatal("RemoveRule returned false")
	}
	if e.Check("tracker.io", "").Blocked {
		t.Error("rule should be gone")
	}
}

func TestCNAMECloaking(t *testing.T) {
	e := testEngine(t)
	d := e.CheckCNAMEs([]string{"cdn.first-party.example", "x.analytics.tiktok.com"}, "")
	if !d.Blocked {
		t.Fatal("cloaked CNAME target should be blocked")
	}
}

func TestNormalize(t *testing.T) {
	if got := Normalize("  Ads.Example.COM. "); got != "ads.example.com" {
		t.Errorf("Normalize = %q", got)
	}
}

func BenchmarkCheck(b *testing.B) {
	e := New(true)
	m := make(map[string]string, 100000)
	for i := 0; i < 100000; i++ {
		m[string(rune('a'+i%26))+"domain"+itoa(i)+".com"] = "bench"
	}
	m["doubleclick.net"] = "bench"
	e.SetDomains(NewDomainSet(m))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Check("stats.g.doubleclick.net", "")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
