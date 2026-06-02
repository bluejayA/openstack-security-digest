package store

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSettings_DefaultsWhenEmpty(t *testing.T) {
	s := newTestStore(t)
	got, err := s.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if got.Threshold != "High" {
		t.Errorf("default threshold = %q, want High", got.Threshold)
	}
	if got.PollMinutes != 60 {
		t.Errorf("default pollMinutes = %d, want 60", got.PollMinutes)
	}
	if got.ScopeWeeks != 1 {
		t.Errorf("default scopeWeeks = %d, want 1", got.ScopeWeeks)
	}
}

func TestSettings_SaveAndLoad(t *testing.T) {
	s := newTestStore(t)
	in := Settings{
		WebhookURL:  "https://hooks.slack.com/services/XXX",
		Threshold:   "Critical",
		PollMinutes: 30,
		ScopeWeeks:  2,
		Enabled:     true,
	}
	if err := s.SaveSettings(in); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	got, err := s.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if got != in {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, in)
	}
}

func TestDigests_SeenTracking(t *testing.T) {
	s := newTestStore(t)
	guid := "https://stackers.network/issues/2026-05-30.html"

	if s.HasDigest(guid) {
		t.Fatal("digest should be unseen initially")
	}
	if err := s.MarkDigestSeen(guid, time.Now().UTC()); err != nil {
		t.Fatalf("MarkDigestSeen: %v", err)
	}
	if !s.HasDigest(guid) {
		t.Fatal("digest should be seen after marking")
	}
	// idempotent
	if err := s.MarkDigestSeen(guid, time.Now().UTC()); err != nil {
		t.Fatalf("MarkDigestSeen (repeat): %v", err)
	}
}

func TestHasDelivered_OnlyCountsSent(t *testing.T) {
	s := newTestStore(t)
	key := "guid1:OSSA-2026-099"

	// A failed attempt must NOT count as delivered (so it can be retried).
	if err := s.RecordDelivery(Delivery{Key: key, Status: "failed", Error: "boom"}); err != nil {
		t.Fatalf("RecordDelivery(failed): %v", err)
	}
	if s.HasDelivered(key) {
		t.Fatal("a failed delivery must not count as delivered")
	}

	// A later successful attempt updates the row and now counts.
	if err := s.RecordDelivery(Delivery{Key: key, Status: "sent", Component: "Nova", Impact: "High"}); err != nil {
		t.Fatalf("RecordDelivery(sent): %v", err)
	}
	if !s.HasDelivered(key) {
		t.Fatal("a sent delivery must count as delivered")
	}

	list, _ := s.ListDeliveries(10)
	if len(list) != 1 {
		t.Fatalf("want 1 row (updated in place), got %d", len(list))
	}
	if list[0].Status != "sent" || list[0].Component != "Nova" {
		t.Errorf("row should reflect the successful retry: %+v", list[0])
	}
}

func TestDeliveries_DedupAndList(t *testing.T) {
	s := newTestStore(t)
	d := Delivery{
		Key:        "guid1:OSSA-2026-015",
		DigestGUID: "guid1",
		AdvisoryID: "OSSA-2026-015",
		Component:  "Keystone",
		Impact:     "Critical",
		Status:     "sent",
		SentAt:     time.Now().UTC(),
	}

	if s.HasDelivered(d.Key) {
		t.Fatal("should not be delivered initially")
	}
	if err := s.RecordDelivery(d); err != nil {
		t.Fatalf("RecordDelivery: %v", err)
	}
	if !s.HasDelivered(d.Key) {
		t.Fatal("should be delivered after recording")
	}
	// duplicate record must not error and must not create a second row
	if err := s.RecordDelivery(d); err != nil {
		t.Fatalf("RecordDelivery (dup): %v", err)
	}
	list, err := s.ListDeliveries(10)
	if err != nil {
		t.Fatalf("ListDeliveries: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1 delivery, got %d", len(list))
	}
	if list[0].Component != "Keystone" || list[0].Impact != "Critical" {
		t.Errorf("unexpected delivery: %+v", list[0])
	}
}
