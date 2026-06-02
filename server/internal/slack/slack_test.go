package slack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jayahn/openstack-security-digest/server/internal/security"
)

func keystone() security.Advisory {
	return security.Advisory{
		ID:        "OSSA-2026-015",
		Kind:      "OSSA",
		Component: "Keystone",
		CVEs:      []string{"CVE-2026-42999", "CVE-2026-42998"},
		Affected:  []string{">=14.0.0 <27.0.2"},
		Summary:   "Authenticated attacker can escalate to cloud admin.",
		Link:      "https://lists.openstack.org/advisory",
		Impact:    security.ImpactCritical,
	}
}

func TestBuildMessage_Structure(t *testing.T) {
	msg := BuildMessage("Stackers Digest — May 30, 2026",
		"https://stackers.network/issues/2026-05-30.html",
		[]security.Advisory{keystone()})

	if len(msg.Blocks) == 0 {
		t.Fatal("expected header/context blocks")
	}
	if len(msg.Attachments) != 1 {
		t.Fatalf("want 1 attachment, got %d", len(msg.Attachments))
	}
	att := msg.Attachments[0]
	if att.Color != colorFor(security.ImpactCritical) {
		t.Errorf("color = %q, want critical color", att.Color)
	}

	// the rendered JSON should mention the key fields
	raw, _ := json.Marshal(msg)
	body := string(raw)
	for _, want := range []string{"OSSA-2026-015", "Keystone", "Critical", "CVE-2026-42999", "27.0.2"} {
		if !strings.Contains(body, want) {
			t.Errorf("message missing %q", want)
		}
	}
}

func TestSend_PostsJSON(t *testing.T) {
	var gotBody string
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	n := New()
	msg := BuildMessage("t", "https://x", []security.Advisory{keystone()})
	if err := n.Send(context.Background(), srv.URL, msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(gotContentType, "application/json") {
		t.Errorf("content-type = %q", gotContentType)
	}
	if !strings.Contains(gotBody, "OSSA-2026-015") {
		t.Errorf("posted body missing advisory: %s", gotBody)
	}
}

func TestSend_ErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid_payload", http.StatusBadRequest)
	}))
	defer srv.Close()

	n := New()
	err := n.Send(context.Background(), srv.URL, Message{})
	if err == nil {
		t.Fatal("expected error on 400 response")
	}
}

func TestSend_EmptyURL(t *testing.T) {
	if err := New().Send(context.Background(), "", Message{}); err == nil {
		t.Error("expected error for empty webhook URL")
	}
}
