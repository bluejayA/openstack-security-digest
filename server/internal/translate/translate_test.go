package translate

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// --- fakes ---

type fakeTranslator struct {
	mu    sync.Mutex
	calls int
	fail  bool
}

func (f *fakeTranslator) Translate(_ context.Context, text, lang string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail {
		return "", errors.New("boom")
	}
	return "[" + lang + "] " + text, nil
}

type mapCache struct {
	mu sync.Mutex
	m  map[string]string
}

func newMapCache() *mapCache { return &mapCache{m: map[string]string{}} }

func (c *mapCache) GetTranslation(hash, lang string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[hash+"|"+lang]
	return v, ok
}
func (c *mapCache) SaveTranslation(hash, lang, text string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[hash+"|"+lang] = text
	return nil
}

// --- tests ---

func TestService_TranslatesAndCaches(t *testing.T) {
	ft := &fakeTranslator{}
	svc := NewService(ft, newMapCache())

	got := svc.To(context.Background(), "hello", "ko")
	if got != "[ko] hello" {
		t.Fatalf("got %q", got)
	}
	// second call served from cache → translator not invoked again
	if got2 := svc.To(context.Background(), "hello", "ko"); got2 != "[ko] hello" {
		t.Fatalf("got2 %q", got2)
	}
	if ft.calls != 1 {
		t.Errorf("translator called %d times, want 1 (cached)", ft.calls)
	}
}

func TestService_DisabledReturnsOriginal(t *testing.T) {
	svc := NewService(nil, newMapCache())
	if svc.Enabled() {
		t.Error("nil translator should be disabled")
	}
	if got := svc.To(context.Background(), "hello", "ko"); got != "hello" {
		t.Errorf("disabled should return original, got %q", got)
	}
}

func TestService_FallbackOnError(t *testing.T) {
	ft := &fakeTranslator{fail: true}
	cache := newMapCache()
	svc := NewService(ft, cache)

	got := svc.To(context.Background(), "hello", "ko")
	if got != "hello" {
		t.Errorf("error should fall back to original, got %q", got)
	}
	// failed translation must not be cached
	if _, ok := cache.GetTranslation(hashText("hello"), "ko"); ok {
		t.Error("failed translation should not be cached")
	}
}

func TestService_EmptyText(t *testing.T) {
	svc := NewService(&fakeTranslator{}, newMapCache())
	if got := svc.To(context.Background(), "   ", "ko"); got != "   " {
		t.Errorf("blank text returned %q", got)
	}
}
