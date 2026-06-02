// Package api exposes the HTTP REST surface consumed by the dashboard: filtered
// security advisories grouped by impact, settings CRUD, Slack test-send, and
// delivery history.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jayahn/openstack-security-digest/server/internal/feed"
	"github.com/jayahn/openstack-security-digest/server/internal/security"
	"github.com/jayahn/openstack-security-digest/server/internal/slack"
	"github.com/jayahn/openstack-security-digest/server/internal/store"
	"github.com/jayahn/openstack-security-digest/server/internal/translate"
)

// displayLang is the language advisory summaries are rendered in.
const displayLang = "ko"

// translateConcurrency bounds simultaneous translation calls per request.
const translateConcurrency = 6

// Source supplies feed items (newest first).
type Source interface {
	Items(context.Context) ([]feed.Item, error)
}

// Sender posts a Slack message to a webhook URL.
type Sender interface {
	Send(ctx context.Context, webhookURL string, msg slack.Message) error
}

// Handler holds the dependencies for the REST API.
type Handler struct {
	src        Source
	store      *store.Store
	sender     Sender
	translator *translate.Service
}

// New constructs an API Handler.
func New(src Source, st *store.Store, sender Sender, translator *translate.Service) *Handler {
	return &Handler{src: src, store: st, sender: sender, translator: translator}
}

// Routes returns the HTTP handler with all routes registered (CORS-enabled for
// the separately-served dashboard).
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /api/security", h.getSecurity)
	mux.HandleFunc("GET /api/settings", h.getSettings)
	mux.HandleFunc("PUT /api/settings", h.putSettings)
	mux.HandleFunc("POST /api/settings/test", h.testSend)
	mux.HandleFunc("POST /api/notify", h.notifyLatest)
	mux.HandleFunc("GET /api/deliveries", h.getDeliveries)
	return withCORS(mux)
}

// --- response types ---

// APIAdvisory is an advisory enriched with its source digest metadata. The
// embedded Summary is rendered in the display language; SummaryEn keeps the
// original English text.
type APIAdvisory struct {
	security.Advisory
	SummaryEn   string `json:"summaryEn"`
	DigestTitle string `json:"digestTitle"`
	DigestLink  string `json:"digestLink"`
	DigestDate  string `json:"digestDate"`
}

// DigestSummary is a per-week entry for the dashboard timeline.
type DigestSummary struct {
	Title   string `json:"title"`
	Link    string `json:"link"`
	Date    string `json:"date"`
	Count   int    `json:"count"`
	TopRank int    `json:"topRank"` // highest impact rank in this digest
}

// SecurityResponse is the payload for GET /api/security.
type SecurityResponse struct {
	GeneratedAt string                            `json:"generatedAt"`
	Scope       map[string]any                    `json:"scope"`
	Count       int                               `json:"count"`
	Totals      map[string]int                    `json:"totals"`
	Groups      map[security.Impact][]APIAdvisory `json:"groups"`
	Digests     []DigestSummary                   `json:"digests"`
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) getSecurity(w http.ResponseWriter, r *http.Request) {
	items, err := h.src.Items(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "fetch feed: "+err.Error())
		return
	}

	cfg, _ := h.store.GetSettings()
	scope := map[string]any{}

	// Date-range filter takes precedence over the weeks window.
	from, fromOK := parseDate(r.URL.Query().Get("from"))
	to, toOK := parseDate(r.URL.Query().Get("to"))

	var window []feed.Item
	switch {
	case fromOK || toOK:
		toLabel := to.Format("2006-01-02")
		if !toOK {
			to = time.Now().UTC()
			toLabel = to.Format("2006-01-02")
		}
		// `to` is a calendar day: include everything published before the END of
		// that day, not just midnight at its start.
		toEnd := to.AddDate(0, 0, 1)
		for _, it := range items {
			if (it.PubDate.After(from) || it.PubDate.Equal(from)) && it.PubDate.Before(toEnd) {
				window = append(window, it)
			}
		}
		scope["from"], scope["to"] = from.Format("2006-01-02"), toLabel
	default:
		weeks := cfg.ScopeWeeks
		if v := r.URL.Query().Get("weeks"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				weeks = n
			}
		}
		if weeks <= 0 {
			weeks = 1
		}
		if weeks > len(items) {
			weeks = len(items)
		}
		window = items[:weeks] // items are newest-first
		scope["weeks"] = weeks
	}

	resp := SecurityResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Scope:       scope,
		Totals:      map[string]int{},
		Groups:      map[security.Impact][]APIAdvisory{},
		Digests:     []DigestSummary{},
	}

	// First pass: flatten advisories (preserving order) and build the timeline.
	var flat []*APIAdvisory
	for _, it := range window {
		advs := security.ClassifyAll(security.ExtractSecurity(it.Content))
		ds := DigestSummary{
			Title: it.Title,
			Link:  it.Link,
			Date:  it.PubDate.Format("2006-01-02"),
			Count: len(advs),
		}
		for _, a := range advs {
			flat = append(flat, &APIAdvisory{
				Advisory:    a,
				SummaryEn:   a.Summary,
				DigestTitle: it.Title,
				DigestLink:  it.Link,
				DigestDate:  it.PubDate.Format("2006-01-02"),
			})
			resp.Totals[string(a.Impact)]++
			resp.Count++
			if a.Impact.Rank() > ds.TopRank {
				ds.TopRank = a.Impact.Rank()
			}
		}
		resp.Digests = append(resp.Digests, ds)
	}

	// Translate summaries to the display language (cached, bounded concurrency).
	h.translateSummaries(r.Context(), flat)

	// Second pass: group by impact (insertion order preserved).
	for _, a := range flat {
		resp.Groups[a.Impact] = append(resp.Groups[a.Impact], *a)
	}

	writeJSON(w, http.StatusOK, resp)
}

// translateSummaries fills each advisory's Summary with the display-language
// translation (concurrently, bounded). No-op when translation is disabled.
func (h *Handler) translateSummaries(ctx context.Context, advs []*APIAdvisory) {
	if h.translator == nil || !h.translator.Enabled() || len(advs) == 0 {
		return
	}
	sem := make(chan struct{}, translateConcurrency)
	var wg sync.WaitGroup
	for _, a := range advs {
		wg.Add(1)
		sem <- struct{}{}
		go func(a *APIAdvisory) {
			defer wg.Done()
			defer func() { <-sem }()
			a.Summary = h.translator.To(ctx, a.SummaryEn, displayLang)
		}(a)
	}
	wg.Wait()
}

func (h *Handler) getSettings(w http.ResponseWriter, _ *http.Request) {
	cfg, err := h.store.GetSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (h *Handler) putSettings(w http.ResponseWriter, r *http.Request) {
	var cfg store.Settings
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if msg := validateSettings(cfg); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if err := h.store.SaveSettings(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	saved, _ := h.store.GetSettings()
	writeJSON(w, http.StatusOK, saved)
}

func validateSettings(cfg store.Settings) string {
	switch security.Impact(cfg.Threshold) {
	case security.ImpactCritical, security.ImpactHigh, security.ImpactMedium, security.ImpactLow:
	default:
		return "threshold must be one of Critical, High, Medium, Low"
	}
	if cfg.PollMinutes <= 0 {
		return "pollMinutes must be positive"
	}
	if cfg.ScopeWeeks <= 0 {
		return "scopeWeeks must be positive"
	}
	return ""
}

func (h *Handler) testSend(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cfg.WebhookURL == "" {
		writeError(w, http.StatusBadRequest, "no webhook URL configured")
		return
	}
	sample := security.Advisory{
		ID: "TEST-0000", Kind: "TEST", Component: "Test",
		Summary: "This is a test notification from OpenStack Security Digest. If you can read this, your webhook is configured correctly.",
		Impact:  security.ImpactHigh,
	}
	msg := slack.BuildMessage("Test Notification", "https://stackers.network", []security.Advisory{sample})
	if err := h.sender.Send(r.Context(), cfg.WebhookURL, msg); err != nil {
		writeError(w, http.StatusBadGateway, "slack send failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// notifyLatest pushes the most recent digest's advisories to the configured
// Slack webhook on demand (a manual "send this week now" trigger), translated
// to the display language. Unlike the scheduler it ignores the threshold and
// the delivered-dedup, so it can be used to test or re-send.
func (h *Handler) notifyLatest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg, err := h.store.GetSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cfg.WebhookURL == "" {
		writeError(w, http.StatusBadRequest, "no webhook URL configured")
		return
	}
	items, err := h.src.Items(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, "fetch feed: "+err.Error())
		return
	}
	if len(items) == 0 {
		writeError(w, http.StatusNotFound, "no digests available")
		return
	}
	latest := items[0]
	advs := security.ClassifyAll(security.ExtractSecurity(latest.Content))
	if len(advs) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"sent": 0, "digest": latest.Title, "message": "no security advisories this week"})
		return
	}

	// translate copies (cache-backed); keep originals for the delivery keys
	localized := make([]security.Advisory, len(advs))
	copy(localized, advs)
	if h.translator != nil && h.translator.Enabled() {
		for i := range localized {
			localized[i].Summary = h.translator.To(ctx, localized[i].Summary, displayLang)
		}
	}

	msg := slack.BuildMessage(latest.Title, latest.Link, localized)
	if err := h.sender.Send(ctx, cfg.WebhookURL, msg); err != nil {
		writeError(w, http.StatusBadGateway, "slack send failed: "+err.Error())
		return
	}

	for _, a := range advs {
		id := a.ID
		if id == "" {
			id = a.Summary
		}
		_ = h.store.RecordDelivery(store.Delivery{
			Key:        latest.GUID + ":" + id,
			DigestGUID: latest.GUID,
			AdvisoryID: a.ID,
			Component:  a.Component,
			Impact:     string(a.Impact),
			Status:     "sent",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": len(advs), "digest": latest.Title})
}

func (h *Handler) getDeliveries(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	list, err := h.store.ListDeliveries(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []store.Delivery{}
	}
	writeJSON(w, http.StatusOK, list)
}

// --- helpers ---

func parseDate(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
