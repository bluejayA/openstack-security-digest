package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetcher_ParsesItems(t *testing.T) {
	fixture := loadFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		w.Write(fixture)
	}))
	defer srv.Close()

	f := NewFetcher(srv.URL, time.Minute)
	items, err := f.Items(context.Background())
	if err != nil {
		t.Fatalf("Items: %v", err)
	}
	if len(items) != 20 {
		t.Fatalf("want 20 items, got %d", len(items))
	}
}

func TestFetcher_CachesWithinTTL(t *testing.T) {
	fixture := loadFixture(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write(fixture)
	}))
	defer srv.Close()

	f := NewFetcher(srv.URL, time.Minute)
	if _, err := f.Items(context.Background()); err != nil {
		t.Fatalf("first Items: %v", err)
	}
	if _, err := f.Items(context.Background()); err != nil {
		t.Fatalf("second Items: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("server hits = %d, want 1 (second call should be cached)", got)
	}
}

func TestFetcher_RefetchesAfterTTL(t *testing.T) {
	fixture := loadFixture(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write(fixture)
	}))
	defer srv.Close()

	f := NewFetcher(srv.URL, 0) // zero TTL: never serve from cache
	if _, err := f.Items(context.Background()); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := f.Items(context.Background()); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("server hits = %d, want 2", got)
	}
}

// TestFetcher_ConcurrentItems hammers the cache from many goroutines so that
// `go test -race` exercises the mutex-guarded read/write paths. With ttl=0 every
// call falls through to the cache-write branch (f.cached/f.cachedAt), which is
// exactly where an unguarded Fetcher would race.
func TestFetcher_ConcurrentItems(t *testing.T) {
	fixture := loadFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture)
	}))
	defer srv.Close()

	f := NewFetcher(srv.URL, 0) // zero TTL: force the download + cache-write path every call

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				items, err := f.Items(context.Background())
				if err != nil {
					t.Errorf("Items: %v", err)
					return
				}
				if len(items) != 20 {
					t.Errorf("want 20 items, got %d", len(items))
					return
				}
			}
		}()
	}
	wg.Wait()
}
