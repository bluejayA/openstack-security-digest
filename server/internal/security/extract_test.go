package security

import (
	"os"
	"strings"
	"testing"

	"github.com/jayahn/openstack-security-digest/server/internal/feed"
)

func issueByDate(t *testing.T, date string) feed.Item {
	t.Helper()
	data, err := os.ReadFile("../../testdata/feed.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	items, err := feed.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, it := range items {
		if strings.Contains(it.GUID, date) {
			return it
		}
	}
	t.Fatalf("issue %s not found", date)
	return feed.Item{}
}

func findAdvisory(advs []Advisory, id string) (Advisory, bool) {
	for _, a := range advs {
		if a.ID == id {
			return a, true
		}
	}
	return Advisory{}, false
}

func TestExtract_Issue20260530_HasThreeAdvisories(t *testing.T) {
	it := issueByDate(t, "2026-05-30")
	advs := ExtractSecurity(it.Content)
	if len(advs) != 3 {
		t.Fatalf("want 3 advisories, got %d: %+v", len(advs), advs)
	}
}

func TestExtract_KeystoneAdvisory(t *testing.T) {
	it := issueByDate(t, "2026-05-30")
	advs := ExtractSecurity(it.Content)

	a, ok := findAdvisory(advs, "OSSA-2026-015")
	if !ok {
		t.Fatalf("OSSA-2026-015 not found")
	}
	if a.Component != "Keystone" {
		t.Errorf("component = %q, want Keystone", a.Component)
	}
	if len(a.CVEs) != 5 {
		t.Errorf("CVEs = %v, want 5", a.CVEs)
	}
	if !contains(a.CVEs, "CVE-2026-42999") {
		t.Errorf("missing CVE-2026-42999 in %v", a.CVEs)
	}
	if len(a.Affected) == 0 {
		t.Errorf("expected affected version ranges")
	}
	if !strings.Contains(a.Link, "EFA4UUCOCZBXQFGPOXDCZ7UIW7Q3W23C") {
		t.Errorf("link = %q, want advisory archive link", a.Link)
	}
	if !strings.Contains(a.Summary, "escalate to cloud admin") {
		t.Errorf("summary missing key phrase: %q", a.Summary)
	}
}

func TestExtract_NeutronCVEPending(t *testing.T) {
	it := issueByDate(t, "2026-05-30")
	advs := ExtractSecurity(it.Content)
	a, ok := findAdvisory(advs, "OSSA-2026-016")
	if !ok {
		t.Fatalf("OSSA-2026-016 not found")
	}
	if a.Component != "Neutron" {
		t.Errorf("component = %q, want Neutron", a.Component)
	}
	if len(a.CVEs) != 0 {
		t.Errorf("CVEs = %v, want none (CVE pending)", a.CVEs)
	}
}

func TestExtract_NoSecuritySection(t *testing.T) {
	advs := ExtractSecurity(`<h2 id="the-big-picture">The Big Picture</h2><p>No security this week.</p>`)
	if len(advs) != 0 {
		t.Errorf("want 0 advisories, got %d", len(advs))
	}
}

func TestExtract_EmptyContent(t *testing.T) {
	if advs := ExtractSecurity(""); len(advs) != 0 {
		t.Errorf("want 0, got %d", len(advs))
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
