package feed

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// DefaultFeedURL is the public Stackers Network feed.
const DefaultFeedURL = "https://stackers.network/feed.xml"

// Fetcher retrieves and parses the feed, caching the parsed items for a TTL to
// avoid hammering the upstream (which itself refreshes roughly every 15 min).
type Fetcher struct {
	url    string
	ttl    time.Duration
	client *http.Client

	mu       sync.Mutex
	cached   []Item
	cachedAt time.Time
}

// NewFetcher creates a Fetcher for the given feed URL and cache TTL.
func NewFetcher(url string, ttl time.Duration) *Fetcher {
	return &Fetcher{
		url:    url,
		ttl:    ttl,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// Items returns the parsed feed items, served from cache when fresh.
func (f *Fetcher) Items(ctx context.Context) ([]Item, error) {
	f.mu.Lock()
	if f.cached != nil && f.ttl > 0 && time.Since(f.cachedAt) < f.ttl {
		items := f.cached
		f.mu.Unlock()
		return items, nil
	}
	f.mu.Unlock()

	raw, err := f.download(ctx)
	if err != nil {
		// fall back to stale cache rather than failing hard
		f.mu.Lock()
		stale := f.cached
		f.mu.Unlock()
		if stale != nil {
			return stale, nil
		}
		return nil, err
	}

	items, err := Parse(raw)
	if err != nil {
		return nil, err
	}

	f.mu.Lock()
	f.cached = items
	f.cachedAt = time.Now()
	f.mu.Unlock()
	return items, nil
}

func (f *Fetcher) download(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("feed: new request: %w", err)
	}
	req.Header.Set("Accept", "application/rss+xml, application/xml, text/xml")
	req.Header.Set("User-Agent", "openstack-security-digest/1.0")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("feed: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed: upstream status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MiB cap
	if err != nil {
		return nil, fmt.Errorf("feed: read body: %w", err)
	}
	return body, nil
}
