// Package feed fetches and parses the Stackers Network weekly OpenStack digest
// RSS feed (https://stackers.network/feed.xml).
package feed

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Item is a single weekly digest entry from the feed.
type Item struct {
	Title   string
	Link    string
	GUID    string
	PubDate time.Time
	// Content is the full HTML body from <content:encoded>, which contains the
	// section headers (The Big Picture, Security, ...) the extractor relies on.
	Content string
}

// rssDoc mirrors the subset of the RSS 2.0 document we consume. The
// content:encoded element lives in the standard content module namespace.
type rssDoc struct {
	XMLName xml.Name  `xml:"rss"`
	Items   []rssItem `xml:"channel>item"`
}

type rssItem struct {
	Title   string `xml:"title"`
	Link    string `xml:"link"`
	GUID    string `xml:"guid"`
	PubDate string `xml:"pubDate"`
	Content string `xml:"http://purl.org/rss/1.0/modules/content/ encoded"`
}

// pubDateLayouts covers the RFC1123Z form the feed uses plus common fallbacks.
var pubDateLayouts = []string{
	time.RFC1123Z, // "Mon, 02 Jan 2006 15:04:05 -0700"
	time.RFC1123,
	"Mon, 2 Jan 2006 15:04:05 -0700",
}

// Parse decodes the RSS feed bytes into items sorted newest-first by PubDate.
func Parse(data []byte) ([]Item, error) {
	var doc rssDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("feed: decode rss: %w", err)
	}
	if doc.XMLName.Local != "rss" {
		return nil, fmt.Errorf("feed: not an rss document (root=%q)", doc.XMLName.Local)
	}

	items := make([]Item, 0, len(doc.Items))
	for _, ri := range doc.Items {
		items = append(items, Item{
			Title:   strings.TrimSpace(ri.Title),
			Link:    strings.TrimSpace(ri.Link),
			GUID:    strings.TrimSpace(ri.GUID),
			PubDate: parsePubDate(ri.PubDate),
			Content: ri.Content,
		})
	}

	sort.SliceStable(items, func(i, j int) bool {
		return items[i].PubDate.After(items[j].PubDate)
	})
	return items, nil
}

func parsePubDate(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range pubDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
