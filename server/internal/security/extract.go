// Package security extracts the "Security" section from a weekly digest's HTML
// body and classifies each advisory by operational impact.
package security

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// Advisory is a single security entry parsed from the digest Security section.
type Advisory struct {
	ID        string   `json:"id"`        // OSSA-2026-015, OSSN-0095, or "" when none
	Kind      string   `json:"kind"`      // OSSA | OSSN | OTHER
	Component string   `json:"component"` // Keystone, Neutron, Swift, ...
	CVEs      []string `json:"cves"`
	Affected  []string `json:"affected"` // version-range strings
	Summary   string   `json:"summary"`  // plain-text entry body
	Link      string   `json:"link"`     // advisory / source URL
	Impact    Impact   `json:"impact"`   // set by Classify; zero value until then
}

var (
	reOSSA    = regexp.MustCompile(`OSSA-\d{4}-\d{3}`)
	reOSSN    = regexp.MustCompile(`OSSN-\d{4}`)
	reCVE     = regexp.MustCompile(`CVE-\d{4}-\d+`)
	reParen   = regexp.MustCompile(`\(([^)]*)\)`)
	reVersion = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)
	reSpaces  = regexp.MustCompile(`\s+`)
)

// ExtractSecurity parses the HTML body of a digest item and returns the
// advisories found under the <h2 id="security"> section. Returns an empty
// slice (never nil-error) when there is no security section.
func ExtractSecurity(contentHTML string) []Advisory {
	if strings.TrimSpace(contentHTML) == "" {
		return nil
	}
	doc, err := html.Parse(strings.NewReader("<html><body>" + contentHTML + "</body></html>"))
	if err != nil {
		return nil
	}

	h2 := findSecurityHeader(doc)
	if h2 == nil {
		return nil
	}

	// Collect the entry nodes (<li> and qualifying <p>) that follow the
	// security <h2>, stopping at the next <h2>.
	var entries []*html.Node
	for sib := h2.NextSibling; sib != nil; sib = sib.NextSibling {
		if sib.Type == html.ElementNode && sib.Data == "h2" {
			break
		}
		collectEntries(sib, &entries)
	}

	var advs []Advisory
	seen := map[string]bool{}
	for _, node := range entries {
		a, ok := parseEntry(node)
		if !ok {
			continue
		}
		key := a.ID
		if key == "" {
			key = a.Summary
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		advs = append(advs, a)
	}
	return advs
}

func findSecurityHeader(n *html.Node) *html.Node {
	if n.Type == html.ElementNode && n.Data == "h2" {
		for _, attr := range n.Attr {
			if attr.Key == "id" && attr.Val == "security" {
				return n
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := findSecurityHeader(c); found != nil {
			return found
		}
	}
	return nil
}

// collectEntries gathers advisory-bearing nodes from a section sibling. <li>
// elements are always entries; a <p> qualifies only when it carries an
// OSSA/OSSN/CVE token (skips the intro paragraph).
func collectEntries(n *html.Node, out *[]*html.Node) {
	if n.Type == html.ElementNode && n.Data == "li" {
		*out = append(*out, n)
		return // do not descend into nested lists as separate entries
	}
	if n.Type == html.ElementNode && n.Data == "p" {
		txt := textOf(n)
		if reOSSA.MatchString(txt) || reOSSN.MatchString(txt) || reCVE.MatchString(txt) {
			*out = append(*out, n)
		}
		return
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		collectEntries(c, out)
	}
}

func parseEntry(n *html.Node) (Advisory, bool) {
	summary := textOf(n)
	if strings.TrimSpace(summary) == "" {
		return Advisory{}, false
	}

	a := Advisory{Summary: summary}

	switch {
	case reOSSA.MatchString(summary):
		a.ID = reOSSA.FindString(summary)
		a.Kind = "OSSA"
	case reOSSN.MatchString(summary):
		a.ID = reOSSN.FindString(summary)
		a.Kind = "OSSN"
	default:
		a.Kind = "OTHER"
	}

	a.CVEs = dedupStrings(reCVE.FindAllString(summary, -1))
	a.Component = detectComponent(summary)
	a.Affected = extractAffected(n)
	a.Link = firstLink(n)

	// A qualifying entry must carry at least an ID or a CVE; otherwise it is
	// likely stray prose.
	if a.ID == "" && len(a.CVEs) == 0 {
		return Advisory{}, false
	}
	return a, true
}

// detectComponent reads the component name from the leading parenthetical,
// e.g. "OSSA-2026-015 (Keystone, five CVEs)" -> "Keystone". Falls back to a
// known-component scan of the summary.
func detectComponent(summary string) string {
	if m := reParen.FindStringSubmatch(summary); m != nil {
		inner := strings.TrimSpace(m[1])
		// first token before a space or comma
		inner = strings.FieldsFunc(inner, func(r rune) bool {
			return r == ',' || r == ' '
		})[0]
		if looksLikeComponent(inner) {
			return inner
		}
	}
	for _, c := range knownComponents {
		if strings.Contains(summary, c) {
			return c
		}
	}
	return ""
}

var knownComponents = []string{
	"Keystone", "Neutron", "Nova", "Swift", "Cinder", "Glance", "Horizon",
	"Heat", "Octavia", "Ironic", "Manila", "Designate", "Barbican", "Placement",
	"Magnum", "OVN",
}

func looksLikeComponent(s string) bool {
	if s == "" {
		return false
	}
	// component names start uppercase and contain no digits
	if s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	return !strings.ContainsAny(s, "0123456789")
}

// extractAffected collects version-range strings from <code> elements in the
// entry that look like version constraints.
func extractAffected(n *html.Node) []string {
	var out []string
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "code" {
			t := strings.TrimSpace(textOf(node))
			if reVersion.MatchString(t) && strings.ContainsAny(t, "<>") {
				out = append(out, t)
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return dedupStrings(out)
}

func firstLink(n *html.Node) string {
	var href string
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if href != "" {
			return
		}
		if node.Type == html.ElementNode && node.Data == "a" {
			for _, attr := range node.Attr {
				if attr.Key == "href" {
					href = attr.Val
					return
				}
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return href
}

// textOf returns normalized, whitespace-collapsed text content of a node.
func textOf(n *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			sb.WriteString(node.Data)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.TrimSpace(reSpaces.ReplaceAllString(sb.String(), " "))
}

func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
