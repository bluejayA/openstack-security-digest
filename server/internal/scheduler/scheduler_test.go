package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jayahn/openstack-security-digest/server/internal/feed"
	"github.com/jayahn/openstack-security-digest/server/internal/slack"
	"github.com/jayahn/openstack-security-digest/server/internal/store"
	"github.com/jayahn/openstack-security-digest/server/internal/translate"
)

func readFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/feed.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

// --- fakes ---

type fakeSource struct{ items []feed.Item }

func (f *fakeSource) Items(context.Context) ([]feed.Item, error) { return f.items, nil }

type fakeSender struct {
	mu    sync.Mutex
	calls []slack.Message
	fail  bool
}

func (f *fakeSender) Send(_ context.Context, _ string, m slack.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errFakeSend
	}
	f.calls = append(f.calls, m)
	return nil
}

var errFakeSend = &sendErr{}

type sendErr struct{}

func (*sendErr) Error() string { return "fake send failure" }

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func enabledSettings(st *store.Store, threshold string) {
	cfg := store.DefaultSettings()
	cfg.Enabled = true
	cfg.WebhookURL = "https://hooks.slack.com/services/T/B/X"
	cfg.Threshold = threshold
	st.SaveSettings(cfg)
}

// loadRealItems uses the actual fixture so classification is exercised end-to-end.
func loadRealItems(t *testing.T) []feed.Item {
	t.Helper()
	data := readFixture(t)
	items, err := feed.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return items
}

func TestRunOnce_ColdStartIsBaseline_NoSends(t *testing.T) {
	st := newStore(t)
	enabledSettings(st, "High")
	src := &fakeSource{items: loadRealItems(t)}
	sender := &fakeSender{}
	svc := New(src, st, sender, translate.NewService(nil, st))

	res, err := svc.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.Baseline {
		t.Error("first run should be a baseline sync")
	}
	if len(sender.calls) != 0 {
		t.Errorf("baseline should send nothing, sent %d", len(sender.calls))
	}
	// all digests now marked seen
	n, _ := st.SeenDigestCount()
	if n != len(src.items) {
		t.Errorf("seen=%d, want %d", n, len(src.items))
	}
}

func TestRunOnce_NotifiesNewDigest(t *testing.T) {
	st := newStore(t)
	enabledSettings(st, "High")
	real := loadRealItems(t)
	// baseline with everything EXCEPT the newest (2026-05-30, which has Critical+High)
	src := &fakeSource{items: real[1:]}
	sender := &fakeSender{}
	svc := New(src, st, sender, translate.NewService(nil, st))
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("baseline: %v", err)
	}

	// now the newest digest appears
	src.items = real
	res, err := svc.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Baseline {
		t.Error("second run should not be baseline")
	}
	if len(sender.calls) != 1 {
		t.Fatalf("want 1 slack message for the new digest, got %d", len(sender.calls))
	}
	// the message must carry at least one attachment (a notable advisory)
	if len(sender.calls[0].Attachments) == 0 {
		t.Error("expected advisory attachments in the message")
	}
	// deliveries recorded
	dels, _ := st.ListDeliveries(10)
	if len(dels) == 0 {
		t.Error("expected recorded deliveries")
	}
}

func TestRunOnce_DedupOnRepeat(t *testing.T) {
	st := newStore(t)
	enabledSettings(st, "High")
	real := loadRealItems(t)
	src := &fakeSource{items: real[1:]}
	sender := &fakeSender{}
	svc := New(src, st, sender, translate.NewService(nil, st))
	svc.RunOnce(context.Background()) // baseline

	src.items = real
	svc.RunOnce(context.Background()) // notifies newest
	first := len(sender.calls)

	svc.RunOnce(context.Background()) // nothing new
	if len(sender.calls) != first {
		t.Errorf("repeat run sent more messages: %d -> %d", first, len(sender.calls))
	}
}

func TestRunOnce_DisabledSendsNothing(t *testing.T) {
	st := newStore(t)
	// settings left disabled (default)
	src := &fakeSource{items: loadRealItems(t)}
	sender := &fakeSender{}
	svc := New(src, st, sender, translate.NewService(nil, st))

	res, err := svc.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(sender.calls) != 0 {
		t.Errorf("disabled should send nothing, sent %d", len(sender.calls))
	}
	if res.Skipped == "" {
		t.Error("expected a skip reason when disabled")
	}
}

func TestRunOnce_FailedSendNotMarkedSeen(t *testing.T) {
	st := newStore(t)
	enabledSettings(st, "High")
	real := loadRealItems(t)
	src := &fakeSource{items: real[1:]}
	sender := &fakeSender{}
	svc := New(src, st, sender, translate.NewService(nil, st))
	svc.RunOnce(context.Background()) // baseline (sender ok)

	sender.fail = true
	src.items = real
	if _, err := svc.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error when send fails")
	}
	// newest digest must remain unseen so it retries
	if st.HasDigest(real[0].GUID) {
		t.Error("failed-send digest should not be marked seen")
	}
}

func TestRunOnce_RetriesAfterTransientFailure(t *testing.T) {
	st := newStore(t)
	enabledSettings(st, "High")
	real := loadRealItems(t)
	src := &fakeSource{items: real[1:]}
	sender := &fakeSender{}
	svc := New(src, st, sender, translate.NewService(nil, st))
	svc.RunOnce(context.Background()) // baseline

	// transient failure on the new digest
	sender.fail = true
	src.items = real
	if _, err := svc.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error on transient send failure")
	}
	if len(sender.calls) != 0 {
		t.Fatalf("no message should have been delivered yet, got %d", len(sender.calls))
	}

	// failure recovers: the notification must NOT be silently dropped
	sender.fail = false
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("retry RunOnce: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("notification should be retried and sent, got %d messages", len(sender.calls))
	}
	if !st.HasDigest(real[0].GUID) {
		t.Error("digest should be marked seen after successful retry")
	}
}

type koTranslator struct{}

func (koTranslator) Translate(_ context.Context, text, lang string) (string, error) {
	return "[" + lang + "] " + text, nil
}

func TestRunOnce_PushesTranslatedSlack(t *testing.T) {
	st := newStore(t)
	enabledSettings(st, "High")
	real := loadRealItems(t)
	src := &fakeSource{items: real[1:]}
	sender := &fakeSender{}
	svc := New(src, st, sender, translate.NewService(koTranslator{}, st))
	svc.RunOnce(context.Background()) // baseline

	src.items = real
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("want 1 message, got %d", len(sender.calls))
	}
	// the Slack message body must contain the translated (Korean-prefixed) text
	found := false
	for _, att := range sender.calls[0].Attachments {
		for _, b := range att.Blocks {
			if b.Text != nil && strings.Contains(b.Text.Text, "[ko] ") {
				found = true
			}
		}
	}
	if !found {
		t.Error("Slack message was not translated to the display language")
	}
}

func TestThresholdFilter_MediumExcludedAtHigh(t *testing.T) {
	st := newStore(t)
	enabledSettings(st, "High")
	// craft an item whose security section yields only a Medium advisory
	mediumOnly := feed.Item{
		Title:   "Test Digest",
		GUID:    "test-medium",
		Link:    "https://x",
		PubDate: time.Now().UTC(),
		Content: `<h2 id="security">Security</h2><ul><li><strong>OSSA-2099-001 (Cinder, info)</strong> minor information disclosure of volume names (CVE-2099-1).</li></ul>`,
	}
	src := &fakeSource{items: []feed.Item{mediumOnly}}
	sender := &fakeSender{}
	svc := New(src, st, sender, translate.NewService(nil, st))
	svc.RunOnce(context.Background()) // baseline marks it seen, no send

	// force re-evaluation: a brand new store, pre-seed baseline differently
	st2 := newStore(t)
	enabledSettings(st2, "High")
	// baseline with a dummy so cold-start isn't triggered
	st2.MarkDigestSeen("dummy", time.Now().UTC())
	svc2 := New(src, st2, sender, translate.NewService(nil, st2))
	if _, err := svc2.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(sender.calls) != 0 {
		t.Errorf("Medium advisory should be filtered at High threshold, sent %d", len(sender.calls))
	}
}
