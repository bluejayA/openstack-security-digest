// Package store persists application settings, seen-digest tracking, and Slack
// delivery history in a single-file SQLite database (pure-Go driver, no CGO).
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Settings is the user-configurable application configuration.
type Settings struct {
	WebhookURL  string `json:"webhookUrl"`
	Threshold   string `json:"threshold"`   // minimum severity to notify: "Critical" or "High"
	PollMinutes int    `json:"pollMinutes"` // scheduler poll interval
	ScopeWeeks  int    `json:"scopeWeeks"`  // default lookback window for the dashboard
	Enabled     bool   `json:"enabled"`     // whether auto-push is active
}

// DefaultSettings returns the baseline configuration used before the user saves
// anything: notify on High and above, poll hourly, one-week scope, disabled.
func DefaultSettings() Settings {
	return Settings{
		Threshold:   "High",
		PollMinutes: 60,
		ScopeWeeks:  1,
		Enabled:     false,
	}
}

// Delivery is one recorded Slack notification attempt.
type Delivery struct {
	Key        string    `json:"key"`
	DigestGUID string    `json:"digestGuid"`
	AdvisoryID string    `json:"advisoryId"`
	Component  string    `json:"component"`
	Impact     string    `json:"impact"`
	SentAt     time.Time `json:"sentAt"`
	Status     string    `json:"status"` // "sent" | "failed"
	Error      string    `json:"error,omitempty"`
}

// Store wraps the SQLite database connection.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS seen_digests (
	guid       TEXT PRIMARY KEY,
	pub_date   TEXT,
	first_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS slack_deliveries (
	delivery_key TEXT PRIMARY KEY,
	digest_guid  TEXT,
	advisory_id  TEXT,
	component    TEXT,
	impact       TEXT,
	sent_at      TEXT NOT NULL,
	status       TEXT NOT NULL,
	error        TEXT
);
CREATE TABLE IF NOT EXISTS translations (
	hash TEXT NOT NULL,
	lang TEXT NOT NULL,
	text TEXT NOT NULL,
	PRIMARY KEY (hash, lang)
);
`

// Open opens (creating if needed) the SQLite database at path and applies the
// schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite: serialize writers, avoid "database is locked"
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

const settingsKey = "app"

// GetSettings returns the stored settings, or DefaultSettings if none saved.
func (s *Store) GetSettings() (Settings, error) {
	var raw string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, settingsKey).Scan(&raw)
	if err == sql.ErrNoRows {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("store: get settings: %w", err)
	}
	out := DefaultSettings()
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return Settings{}, fmt.Errorf("store: decode settings: %w", err)
	}
	return out, nil
}

// SaveSettings persists the settings, replacing any existing config.
func (s *Store) SaveSettings(cfg Settings) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("store: encode settings: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		settingsKey, string(raw))
	if err != nil {
		return fmt.Errorf("store: save settings: %w", err)
	}
	return nil
}

// HasDigest reports whether the digest guid has been processed before.
func (s *Store) HasDigest(guid string) bool {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM seen_digests WHERE guid = ?`, guid).Scan(&one)
	return err == nil
}

// SeenDigestCount returns how many digests have been processed.
func (s *Store) SeenDigestCount() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM seen_digests`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count digests: %w", err)
	}
	return n, nil
}

// MarkDigestSeen records a digest guid as processed (idempotent).
func (s *Store) MarkDigestSeen(guid string, pubDate time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO seen_digests (guid, pub_date, first_seen) VALUES (?, ?, ?)
		 ON CONFLICT(guid) DO NOTHING`,
		guid, pubDate.UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("store: mark digest: %w", err)
	}
	return nil
}

// HasDelivered reports whether a Slack notification with this key was
// successfully sent. Failed attempts do not count, so they can be retried.
func (s *Store) HasDelivered(key string) bool {
	var one int
	err := s.db.QueryRow(
		`SELECT 1 FROM slack_deliveries WHERE delivery_key = ? AND status = 'sent'`,
		key).Scan(&one)
	return err == nil
}

// RecordDelivery stores a delivery keyed by Key. A repeated key updates the
// existing row, so a failed attempt that later succeeds transitions to "sent".
func (s *Store) RecordDelivery(d Delivery) error {
	if d.SentAt.IsZero() {
		d.SentAt = time.Now().UTC()
	}
	_, err := s.db.Exec(
		`INSERT INTO slack_deliveries
		   (delivery_key, digest_guid, advisory_id, component, impact, sent_at, status, error)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(delivery_key) DO UPDATE SET
		   digest_guid = excluded.digest_guid,
		   advisory_id = excluded.advisory_id,
		   component   = excluded.component,
		   impact      = excluded.impact,
		   sent_at     = excluded.sent_at,
		   status      = excluded.status,
		   error       = excluded.error`,
		d.Key, d.DigestGUID, d.AdvisoryID, d.Component, d.Impact,
		d.SentAt.UTC().Format(time.RFC3339), d.Status, d.Error)
	if err != nil {
		return fmt.Errorf("store: record delivery: %w", err)
	}
	return nil
}

// GetTranslation returns a cached translation for (hash, lang) if present.
func (s *Store) GetTranslation(hash, lang string) (string, bool) {
	var text string
	err := s.db.QueryRow(
		`SELECT text FROM translations WHERE hash = ? AND lang = ?`, hash, lang).Scan(&text)
	if err != nil {
		return "", false
	}
	return text, true
}

// SaveTranslation upserts a cached translation keyed by (hash, lang).
func (s *Store) SaveTranslation(hash, lang, text string) error {
	_, err := s.db.Exec(
		`INSERT INTO translations (hash, lang, text) VALUES (?, ?, ?)
		 ON CONFLICT(hash, lang) DO UPDATE SET text = excluded.text`,
		hash, lang, text)
	if err != nil {
		return fmt.Errorf("store: save translation: %w", err)
	}
	return nil
}

// ListDeliveries returns the most recent deliveries, newest first.
func (s *Store) ListDeliveries(limit int) ([]Delivery, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT delivery_key, digest_guid, advisory_id, component, impact, sent_at, status, error
		 FROM slack_deliveries ORDER BY sent_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list deliveries: %w", err)
	}
	defer rows.Close()

	var out []Delivery
	for rows.Next() {
		var d Delivery
		var sentAt string
		var errStr sql.NullString
		if err := rows.Scan(&d.Key, &d.DigestGUID, &d.AdvisoryID, &d.Component,
			&d.Impact, &sentAt, &d.Status, &errStr); err != nil {
			return nil, fmt.Errorf("store: scan delivery: %w", err)
		}
		d.SentAt, _ = time.Parse(time.RFC3339, sentAt)
		d.Error = errStr.String
		out = append(out, d)
	}
	return out, rows.Err()
}
