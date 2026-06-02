package feed

import (
	"os"
	"testing"
	"time"
)

func loadFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/feed.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func TestParse_ItemCount(t *testing.T) {
	items, err := Parse(loadFixture(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(items) != 20 {
		t.Fatalf("want 20 items, got %d", len(items))
	}
}

func TestParse_FirstItemFields(t *testing.T) {
	items, err := Parse(loadFixture(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	first := items[0]

	if first.Title != "Stackers Network Digest — May 30, 2026" {
		t.Errorf("title = %q", first.Title)
	}
	if first.Link != "https://stackers.network/issues/2026-05-30.html" {
		t.Errorf("link = %q", first.Link)
	}
	if first.GUID != "https://stackers.network/issues/2026-05-30.html" {
		t.Errorf("guid = %q", first.GUID)
	}
	want := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
	if !first.PubDate.Equal(want) {
		t.Errorf("pubDate = %v, want %v", first.PubDate, want)
	}
	if first.Content == "" {
		t.Error("content:encoded is empty")
	}
	// content:encoded should carry the HTML body, including the security section
	if want := `<h2 id="security">Security</h2>`; !contains(first.Content, want) {
		t.Errorf("content missing security section header")
	}
}

func TestParse_ItemsSortedNewestFirst(t *testing.T) {
	items, err := Parse(loadFixture(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for i := 1; i < len(items); i++ {
		if items[i].PubDate.After(items[i-1].PubDate) {
			t.Fatalf("items not newest-first at index %d: %v before %v",
				i, items[i-1].PubDate, items[i].PubDate)
		}
	}
}

func TestParse_Invalid(t *testing.T) {
	if _, err := Parse([]byte("not xml")); err == nil {
		t.Error("expected error for invalid XML")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
