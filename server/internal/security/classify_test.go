package security

import (
	"os"
	"strings"
	"testing"

	"github.com/jayahn/openstack-security-digest/server/internal/feed"
)

// --- Rule-based classification on real fixture advisories ---

func TestClassify_KeystoneCloudAdmin_Critical(t *testing.T) {
	a := advByID(t, "2026-05-30", "OSSA-2026-015")
	if got := Classify(a); got != ImpactCritical {
		t.Errorf("Keystone = %s, want Critical", got)
	}
}

func TestClassify_NeutronTaggingBypass_Medium(t *testing.T) {
	// policy bypass but scoped to project readers / same-project -> downgraded
	a := advByID(t, "2026-05-30", "OSSA-2026-016")
	if got := Classify(a); got != ImpactMedium {
		t.Errorf("Neutron tagging = %s, want Medium", got)
	}
}

func TestClassify_SwiftDoS_High(t *testing.T) {
	// DoS that leaves a worker permanently unresponsive -> upgraded from Medium
	a := advByID(t, "2026-05-30", "OSSA-2026-014")
	if got := Classify(a); got != ImpactHigh {
		t.Errorf("Swift DoS = %s, want High", got)
	}
}

// --- Rule behavior on synthetic advisories ---

func TestClassify_RCE_Critical(t *testing.T) {
	a := Advisory{Summary: "Unauthenticated remote code execution in the Nova metadata API."}
	if got := Classify(a); got != ImpactCritical {
		t.Errorf("RCE = %s, want Critical", got)
	}
}

func TestClassify_PlainPolicyBypass_High(t *testing.T) {
	a := Advisory{Summary: "An attacker can perform an authorization bypass against the volume API."}
	if got := Classify(a); got != ImpactHigh {
		t.Errorf("plain bypass = %s, want High", got)
	}
}

func TestClassify_MultiCVEBump(t *testing.T) {
	// DoS (Medium) carrying 3 CVEs should bump one tier to High
	a := Advisory{
		Summary: "Several denial of service issues in the API.",
		CVEs:    []string{"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"},
	}
	if got := Classify(a); got != ImpactHigh {
		t.Errorf("multi-CVE DoS = %s, want High", got)
	}
}

func TestClassify_OperatorNote_Low(t *testing.T) {
	a := Advisory{
		Kind:    "OSSN",
		ID:      "OSSN-0095",
		Summary: "Operator action item: legacy security-group rules may be ineffective after upgrade.",
	}
	if got := Classify(a); got != ImpactLow {
		t.Errorf("operator note = %s, want Low", got)
	}
}

func TestClassifyAll_SetsImpactAndSorts(t *testing.T) {
	it := issueByDate(t, "2026-05-30")
	advs := ClassifyAll(ExtractSecurity(it.Content))
	if len(advs) != 3 {
		t.Fatalf("want 3, got %d", len(advs))
	}
	for _, a := range advs {
		if a.Impact == "" || a.Impact == ImpactUnknown {
			t.Errorf("%s has no impact", a.ID)
		}
	}
	// sorted most-severe first
	for i := 1; i < len(advs); i++ {
		if advs[i].Impact.Rank() > advs[i-1].Impact.Rank() {
			t.Errorf("not sorted by severity at %d", i)
		}
	}
}

func TestGroupByImpact(t *testing.T) {
	it := issueByDate(t, "2026-05-30")
	groups := GroupByImpact(ClassifyAll(ExtractSecurity(it.Content)))
	if len(groups[ImpactCritical]) != 1 {
		t.Errorf("Critical count = %d, want 1", len(groups[ImpactCritical]))
	}
	if len(groups[ImpactHigh]) != 1 {
		t.Errorf("High count = %d, want 1", len(groups[ImpactHigh]))
	}
	if len(groups[ImpactMedium]) != 1 {
		t.Errorf("Medium count = %d, want 1", len(groups[ImpactMedium]))
	}
}

func advByID(t *testing.T, date, id string) Advisory {
	t.Helper()
	it := issueByDate(t, date)
	for _, a := range ExtractSecurity(it.Content) {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("advisory %s not found in %s", id, date)
	return Advisory{}
}

// ensure fixture loader from extract_test is reused; guard against unused import
var _ = strings.TrimSpace
var _ = os.ReadFile
var _ = feed.Item{}
