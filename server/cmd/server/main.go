// Command server runs the OpenStack Security Digest HTTP API and the background
// scheduler that pushes notable advisories to Slack.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jayahn/openstack-security-digest/server/internal/api"
	"github.com/jayahn/openstack-security-digest/server/internal/feed"
	"github.com/jayahn/openstack-security-digest/server/internal/scheduler"
	"github.com/jayahn/openstack-security-digest/server/internal/slack"
	"github.com/jayahn/openstack-security-digest/server/internal/store"
	"github.com/jayahn/openstack-security-digest/server/internal/translate"
)

// defaultTranslateModel is the Claude model used for translation when not
// overridden via TRANSLATE_MODEL.
const defaultTranslateModel = "claude-haiku-4-5-20251001"

func main() {
	addr := env("ADDR", ":8080")
	dbPath := env("DB_PATH", "./data/digest.db")
	feedURL := env("FEED_URL", feed.DefaultFeedURL)
	cacheTTL := envDuration("FEED_CACHE_TTL", 10*time.Minute)

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		log.Fatalf("create data dir: %v", err)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	fetcher := feed.NewFetcher(feedURL, cacheTTL)
	notifier := slack.New()

	// Translation is optional: with no API key, summaries stay in English.
	var translator *translate.Service
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		model := env("TRANSLATE_MODEL", defaultTranslateModel)
		translator = translate.NewService(translate.NewClaudeTranslator(key, model), st)
		log.Printf("translation enabled (model=%s)", model)
	} else {
		translator = translate.NewService(nil, st)
		log.Println("translation disabled (ANTHROPIC_API_KEY not set) — summaries stay in English")
	}

	handler := api.New(fetcher, st, notifier, translator)
	sched := scheduler.New(fetcher, st, notifier, translator)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go sched.Start(ctx)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("listening on %s (feed=%s, db=%s)", addr, feedURL, dbPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
