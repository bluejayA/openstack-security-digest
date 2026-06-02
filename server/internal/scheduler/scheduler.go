// Package scheduler polls the feed on an interval, detects newly published
// digests, and pushes notable (threshold+) security advisories to Slack.
package scheduler

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jayahn/openstack-security-digest/server/internal/feed"
	"github.com/jayahn/openstack-security-digest/server/internal/security"
	"github.com/jayahn/openstack-security-digest/server/internal/slack"
	"github.com/jayahn/openstack-security-digest/server/internal/store"
	"github.com/jayahn/openstack-security-digest/server/internal/translate"
)

// displayLang is the language advisories are pre-translated and pushed in.
const displayLang = "ko"

// Source supplies the current feed items (newest first).
type Source interface {
	Items(context.Context) ([]feed.Item, error)
}

// Sender posts a Slack message to a webhook URL.
type Sender interface {
	Send(ctx context.Context, webhookURL string, msg slack.Message) error
}

// Service ties together the feed source, persistence, Slack delivery, and
// translation.
type Service struct {
	src        Source
	store      *store.Store
	sender     Sender
	translator *translate.Service
}

// New constructs a scheduler Service.
func New(src Source, st *store.Store, sender Sender, translator *translate.Service) *Service {
	return &Service{src: src, store: st, sender: sender, translator: translator}
}

// Result summarizes a single poll cycle.
type Result struct {
	Baseline       bool   `json:"baseline"`       // first run: marked existing digests seen, no notifications
	Skipped        string `json:"skipped"`        // non-empty when the cycle was skipped (and why)
	NewDigests     int    `json:"newDigests"`     // digests newly processed
	Notifications  int    `json:"notifications"`  // Slack messages sent
	AdvisoriesSent int    `json:"advisoriesSent"` // advisories included across messages
}

// RunOnce executes a single poll/notify cycle.
func (s *Service) RunOnce(ctx context.Context) (Result, error) {
	cfg, err := s.store.GetSettings()
	if err != nil {
		return Result{}, err
	}
	if !cfg.Enabled || cfg.WebhookURL == "" {
		return Result{Skipped: "notifications disabled or webhook not configured"}, nil
	}

	items, err := s.src.Items(ctx)
	if err != nil {
		return Result{}, err
	}

	seenCount, err := s.store.SeenDigestCount()
	if err != nil {
		return Result{}, err
	}

	// Cold start: adopt the current feed as a baseline without notifying, so we
	// never dump weeks of history into Slack on first enable.
	if seenCount == 0 {
		for _, it := range items {
			if err := s.store.MarkDigestSeen(it.GUID, it.PubDate); err != nil {
				return Result{}, err
			}
		}
		return Result{Baseline: true, NewDigests: len(items)}, nil
	}

	threshold := security.ParseImpact(cfg.Threshold)
	res := Result{}

	for _, it := range items {
		if s.store.HasDigest(it.GUID) {
			continue
		}
		res.NewDigests++

		advs := security.ClassifyAll(security.ExtractSecurity(it.Content))

		// Pre-translate every advisory of the new digest so the dashboard renders
		// instantly in the display language (warms the translation cache).
		s.pretranslate(ctx, advs)

		notable := s.notableUndelivered(it, advs, threshold)

		if len(notable) == 0 {
			// nothing to notify; safe to mark seen
			if err := s.store.MarkDigestSeen(it.GUID, it.PubDate); err != nil {
				return res, err
			}
			continue
		}

		// Push to Slack in the display language (delivery keys stay tied to the
		// original advisory IDs, so dedup is unaffected).
		msg := slack.BuildMessage(it.Title, it.Link, s.localized(ctx, notable))
		if err := s.sender.Send(ctx, cfg.WebhookURL, msg); err != nil {
			// record failed deliveries and leave the digest unseen for retry
			for _, a := range notable {
				_ = s.store.RecordDelivery(failedDelivery(it, a))
			}
			return res, fmt.Errorf("scheduler: send for %s: %w", it.GUID, err)
		}

		for _, a := range notable {
			if err := s.store.RecordDelivery(sentDelivery(it, a)); err != nil {
				return res, err
			}
		}
		if err := s.store.MarkDigestSeen(it.GUID, it.PubDate); err != nil {
			return res, err
		}
		res.Notifications++
		res.AdvisoriesSent += len(notable)
	}

	return res, nil
}

// pretranslate warms the translation cache for every advisory summary.
func (s *Service) pretranslate(ctx context.Context, advs []security.Advisory) {
	if s.translator == nil || !s.translator.Enabled() {
		return
	}
	for i := range advs {
		_ = s.translator.To(ctx, advs[i].Summary, displayLang)
	}
}

// localized returns copies of the advisories with summaries translated to the
// display language (cache-backed). Returns the originals when disabled.
func (s *Service) localized(ctx context.Context, advs []security.Advisory) []security.Advisory {
	if s.translator == nil || !s.translator.Enabled() {
		return advs
	}
	out := make([]security.Advisory, len(advs))
	copy(out, advs)
	for i := range out {
		out[i].Summary = s.translator.To(ctx, out[i].Summary, displayLang)
	}
	return out
}

// notableUndelivered returns advisories at/above the threshold that have not
// already been delivered.
func (s *Service) notableUndelivered(it feed.Item, advs []security.Advisory, threshold security.Impact) []security.Advisory {
	var out []security.Advisory
	for _, a := range advs {
		if a.Impact.Rank() < threshold.Rank() {
			continue
		}
		if s.store.HasDelivered(deliveryKey(it, a)) {
			continue
		}
		out = append(out, a)
	}
	return out
}

func deliveryKey(it feed.Item, a security.Advisory) string {
	id := a.ID
	if id == "" {
		id = a.Summary
	}
	return it.GUID + ":" + id
}

func sentDelivery(it feed.Item, a security.Advisory) store.Delivery {
	d := baseDelivery(it, a)
	d.Status = "sent"
	return d
}

func failedDelivery(it feed.Item, a security.Advisory) store.Delivery {
	d := baseDelivery(it, a)
	d.Status = "failed"
	d.Error = "slack send failed"
	return d
}

func baseDelivery(it feed.Item, a security.Advisory) store.Delivery {
	return store.Delivery{
		Key:        deliveryKey(it, a),
		DigestGUID: it.GUID,
		AdvisoryID: a.ID,
		Component:  a.Component,
		Impact:     string(a.Impact),
		SentAt:     time.Now().UTC(),
	}
}

// Start runs RunOnce immediately and then on the configured poll interval until
// the context is cancelled. The interval is re-read from settings each cycle.
func (s *Service) Start(ctx context.Context) {
	for {
		if res, err := s.RunOnce(ctx); err != nil {
			log.Printf("scheduler: cycle error: %v", err)
		} else if res.Notifications > 0 {
			log.Printf("scheduler: sent %d notification(s), %d advisory(ies)", res.Notifications, res.AdvisoriesSent)
		}

		cfg, err := s.store.GetSettings()
		interval := 60 * time.Minute
		if err == nil && cfg.PollMinutes > 0 {
			interval = time.Duration(cfg.PollMinutes) * time.Minute
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
