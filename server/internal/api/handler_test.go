package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jayahn/openstack-security-digest/server/internal/feed"
	"github.com/jayahn/openstack-security-digest/server/internal/slack"
	"github.com/jayahn/openstack-security-digest/server/internal/store"
	"github.com/jayahn/openstack-security-digest/server/internal/translate"
)

// prefixTranslator returns "[lang] " + text — enough to assert translation ran.
type prefixTranslator struct{}

func (prefixTranslator) Translate(_ context.Context, text, lang string) (string, error) {
	return "[" + lang + "] " + text, nil
}

type fakeSource struct{ items []feed.Item }

func (f *fakeSource) Items(context.Context) ([]feed.Item, error) { return f.items, nil }

type fakeSender struct {
	calls int
	fail  bool
}

func (f *fakeSender) Send(context.Context, string, slack.Message) error {
	if f.fail {
		return errSend
	}
	f.calls++
	return nil
}

type sErr struct{}

func (sErr) Error() string { return "send fail" }

var errSend = sErr{}

func testHandler(t *testing.T) (*Handler, *store.Store, *fakeSender) {
	t.Helper()
	data, err := os.ReadFile("../../testdata/feed.xml")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	items, err := feed.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	sender := &fakeSender{}
	// Translation disabled by default so existing assertions see English text.
	h := New(&fakeSource{items: items}, st, sender, translate.NewService(nil, st))
	return h, st, sender
}

func doGET(t *testing.T, h *Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, req)
	return rec
}

func TestHealthz(t *testing.T) {
	h, _, _ := testHandler(t)
	rec := doGET(t, h, "/healthz")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSecurity_DefaultWeek_GroupsByImpact(t *testing.T) {
	h, _, _ := testHandler(t)
	rec := doGET(t, h, "/api/security?weeks=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp SecurityResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// newest digest (2026-05-30) has Critical + High + Medium advisories
	if resp.Totals["Critical"] != 1 {
		t.Errorf("Critical total = %d, want 1", resp.Totals["Critical"])
	}
	if len(resp.Groups["Critical"]) != 1 {
		t.Errorf("Critical group = %d, want 1", len(resp.Groups["Critical"]))
	}
	// enriched with digest metadata
	if resp.Groups["Critical"][0].DigestTitle == "" {
		t.Error("advisory missing digest title")
	}
	if resp.Groups["Critical"][0].ID != "OSSA-2026-015" {
		t.Errorf("unexpected critical advisory: %s", resp.Groups["Critical"][0].ID)
	}
}

func TestSecurity_TranslatesSummaryWhenEnabled(t *testing.T) {
	data, _ := os.ReadFile("../../testdata/feed.xml")
	items, _ := feed.Parse(data)
	st, _ := store.Open(filepath.Join(t.TempDir(), "tr.db"))
	t.Cleanup(func() { st.Close() })
	h := New(&fakeSource{items: items}, st, &fakeSender{},
		translate.NewService(prefixTranslator{}, st))

	resp := mustSecurity(t, h, "/api/security?weeks=1")
	a := resp.Groups["Critical"][0]
	if !strings.HasPrefix(a.Summary, "[ko] ") {
		t.Errorf("summary not translated: %q", a.Summary)
	}
	if strings.HasPrefix(a.SummaryEn, "[ko] ") || a.SummaryEn == "" {
		t.Errorf("summaryEn should keep the original English: %q", a.SummaryEn)
	}
}

func TestSecurity_MoreWeeksYieldMoreAdvisories(t *testing.T) {
	h, _, _ := testHandler(t)
	one := mustSecurity(t, h, "/api/security?weeks=1")
	twelve := mustSecurity(t, h, "/api/security?weeks=20")
	if twelve.Count <= one.Count {
		t.Errorf("weeks=20 count %d should exceed weeks=1 count %d", twelve.Count, one.Count)
	}
}

func TestSecurity_DateRange_ToIsInclusive(t *testing.T) {
	h, _, _ := testHandler(t)
	// A single-day range on a date that has a digest must include that digest.
	resp := mustSecurity(t, h, "/api/security?from=2026-05-30&to=2026-05-30")
	if resp.Count == 0 {
		t.Fatal("single-day range to=2026-05-30 should include the 2026-05-30 digest")
	}
	if resp.Totals["Critical"] != 1 {
		t.Errorf("expected the Keystone Critical advisory in range, totals=%v", resp.Totals)
	}
	// And the digest itself should be listed.
	found := false
	for _, d := range resp.Digests {
		if d.Date == "2026-05-30" {
			found = true
		}
	}
	if !found {
		t.Error("2026-05-30 digest missing from inclusive to-range result")
	}
}

func TestSettings_GetThenPut(t *testing.T) {
	h, _, _ := testHandler(t)

	rec := doGET(t, h, "/api/settings")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET settings status = %d", rec.Code)
	}

	body := `{"webhookUrl":"https://hooks.slack.com/services/A/B/C","threshold":"Critical","pollMinutes":30,"scopeWeeks":2,"enabled":true}`
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT settings status = %d body=%s", rec.Code, rec.Body.String())
	}

	var got store.Settings
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Threshold != "Critical" || got.PollMinutes != 30 || !got.Enabled {
		t.Errorf("settings not persisted: %+v", got)
	}
}

func TestSettings_PutValidation(t *testing.T) {
	h, _, _ := testHandler(t)
	body := `{"threshold":"Bogus","pollMinutes":-5}`
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestTestSend_NoWebhook_400(t *testing.T) {
	h, _, _ := testHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/settings/test", nil)
	rec := httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (no webhook configured)", rec.Code)
	}
}

func TestTestSend_WithWebhook_Sends(t *testing.T) {
	h, st, sender := testHandler(t)
	cfg := store.DefaultSettings()
	cfg.WebhookURL = "https://hooks.slack.com/services/A/B/C"
	st.SaveSettings(cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/settings/test", nil)
	rec := httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if sender.calls != 1 {
		t.Errorf("sender called %d times, want 1", sender.calls)
	}
}

func TestNotify_NoWebhook_400(t *testing.T) {
	h, _, _ := testHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/notify", nil)
	rec := httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestNotify_SendsLatestWeekTranslated(t *testing.T) {
	data, _ := os.ReadFile("../../testdata/feed.xml")
	items, _ := feed.Parse(data)
	st, _ := store.Open(filepath.Join(t.TempDir(), "n.db"))
	t.Cleanup(func() { st.Close() })
	cfg := store.DefaultSettings()
	cfg.WebhookURL = "https://hooks.slack.com/services/A/B/C"
	st.SaveSettings(cfg)
	sender := &fakeSender{}
	h := New(&fakeSource{items: items}, st, sender, translate.NewService(prefixTranslator{}, st))

	req := httptest.NewRequest(http.MethodPost, "/api/notify", nil)
	rec := httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["sent"].(float64) != 3 { // latest digest (2026-05-30) has 3 advisories
		t.Errorf("sent = %v, want 3", resp["sent"])
	}
	if sender.calls != 1 {
		t.Errorf("sender calls = %d, want 1", sender.calls)
	}
	dels, _ := st.ListDeliveries(10)
	if len(dels) != 3 {
		t.Errorf("recorded deliveries = %d, want 3", len(dels))
	}
}

func TestDeliveries_List(t *testing.T) {
	h, st, _ := testHandler(t)
	st.RecordDelivery(store.Delivery{Key: "k1", Component: "Keystone", Impact: "Critical", Status: "sent"})
	rec := doGET(t, h, "/api/deliveries")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var list []store.Delivery
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0].Component != "Keystone" {
		t.Errorf("unexpected deliveries: %+v", list)
	}
}

func mustSecurity(t *testing.T, h *Handler, path string) SecurityResponse {
	t.Helper()
	rec := doGET(t, h, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s status = %d", path, rec.Code)
	}
	var resp SecurityResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}
