package security

import (
	"regexp"
	"sort"
	"strings"
)

// Rule-based impact classification.
//
// Strategy: derive a base tier from keyword signals (taking the most severe
// match), then apply scope modifiers — broad blast radius upgrades, narrowly
// scoped issues downgrade — and finally bump bundles carrying many CVEs.
// Deterministic, dependency-free, and fast.

func compileAll(pats []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(pats))
	for i, p := range pats {
		out[i] = regexp.MustCompile("(?i)" + p)
	}
	return out
}

var (
	criticalPatterns = compileAll([]string{
		`escalate to cloud admin`,
		`cloud admin`,
		`admin escalation`,
		`remote code execution`,
		`arbitrary code execution`,
		`\brce\b`,
		`authentication bypass`,
		`bypass authentication`,
	})
	highPatterns = compileAll([]string{
		`policy bypass`,
		`authorization bypass`,
		`bypass authorization`,
		`privilege escalation`,
		`\bescalat`, // escalate / escalation
		`credential`,
		`impersonation`,
		`\bspoof`,
		`\bssrf\b`,
		`sql injection`,
		`path traversal`,
		`directory traversal`,
	})
	mediumPatterns = compileAll([]string{
		`denial of service`,
		`\bdos\b`,
		`infinite loop`,
		`unresponsive`,
		`information disclosure`,
		`information leak`,
		`info leak`,
		`\btampering`,
		`\bbypass\b`,
	})
	broadScopePatterns = compileAll([]string{
		`all \d{4}`, // all 2026.x deployments
		`all [\w .\-]{0,25}deployments`,
		`any policy-protected`,
		`any [\w .\-]{0,30}endpoint`,
		`permanently`,
	})
	limitedScopePatterns = compileAll([]string{
		`project reader`,
		`same-project`,
		`same project`,
		`within a shared project`,
		`requires local`,
		`local access`,
		`specific configuration`,
	})
)

func matchAny(text string, pats []*regexp.Regexp) bool {
	for _, re := range pats {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// Classify assigns an Impact to an advisory using its summary text, CVE count,
// and scope signals.
func Classify(a Advisory) Impact {
	text := strings.ToLower(a.Summary)

	base := ImpactLow
	switch {
	case matchAny(text, criticalPatterns):
		base = ImpactCritical
	case matchAny(text, highPatterns):
		base = ImpactHigh
	case matchAny(text, mediumPatterns):
		base = ImpactMedium
	}

	broad := matchAny(text, broadScopePatterns)
	limited := matchAny(text, limitedScopePatterns)

	// Narrowly scoped High issues (e.g. same-project project-reader bypass)
	// drop to Medium — unless they also have broad blast radius.
	if base == ImpactHigh && limited && !broad {
		base = ImpactMedium
	}

	// Broad blast radius upgrades Medium/High one tier (Critical is the cap).
	if broad && (base == ImpactMedium || base == ImpactHigh) {
		base = upgrade(base)
	}

	// A bundle of three or more CVEs bumps one tier (below Critical).
	if len(a.CVEs) >= 3 && base != ImpactCritical {
		base = upgrade(base)
	}

	return base
}

func upgrade(i Impact) Impact {
	switch i {
	case ImpactLow:
		return ImpactMedium
	case ImpactMedium:
		return ImpactHigh
	case ImpactHigh:
		return ImpactCritical
	default:
		return i
	}
}

// ClassifyAll sets Impact on each advisory and returns them sorted most-severe
// first (stable within a tier, preserving extraction order).
func ClassifyAll(advs []Advisory) []Advisory {
	out := make([]Advisory, len(advs))
	copy(out, advs)
	for i := range out {
		out[i].Impact = Classify(out[i])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Impact.Rank() > out[j].Impact.Rank()
	})
	return out
}

// GroupByImpact buckets advisories by their assigned Impact.
func GroupByImpact(advs []Advisory) map[Impact][]Advisory {
	groups := map[Impact][]Advisory{}
	for _, a := range advs {
		imp := a.Impact
		if imp == "" {
			imp = Classify(a)
		}
		groups[imp] = append(groups[imp], a)
	}
	return groups
}
