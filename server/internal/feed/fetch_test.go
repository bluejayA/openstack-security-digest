package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
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
