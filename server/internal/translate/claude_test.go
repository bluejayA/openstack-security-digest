package translate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClaudeTranslator_RequestAndParse(t *testing.T) {
	var gotPath, gotKey, gotVersion, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"content":[{"type":"text","text":"안녕하세요"}]}`)
	}))
	defer srv.Close()

	tr := NewClaudeTranslator("sk-test", "claude-haiku-4-5-20251001")
	tr.baseURL = srv.URL

	out, err := tr.Translate(context.Background(), "hello", "ko")
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if out != "안녕하세요" {
		t.Errorf("out = %q", out)
	}
	if gotPath != "/v1/messages" {
		t.Errorf("path = %q", gotPath)
	}
	if gotKey != "sk-test" {
		t.Errorf("x-api-key = %q", gotKey)
	}
	if gotVersion == "" {
		t.Error("missing anthropic-version header")
	}
	for _, want := range []string{"claude-haiku-4-5-20251001", "Korean", "hello"} {
		if !strings.Contains(gotBody, want) {
			t.Errorf("request body missing %q: %s", want, gotBody)
		}
	}
}

func TestClaudeTranslator_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"bad"}}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	tr := NewClaudeTranslator("k", "m")
	tr.baseURL = srv.URL
	if _, err := tr.Translate(context.Background(), "x", "ko"); err == nil {
		t.Error("expected error on 400")
	}
}

func TestClaudeTranslator_ParsesMultipleTextBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{"content": []map[string]string{
			{"type": "text", "text": "첫째 "},
			{"type": "text", "text": "둘째"},
		}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	tr := NewClaudeTranslator("k", "m")
	tr.baseURL = srv.URL
	out, err := tr.Translate(context.Background(), "x", "ko")
	if err != nil {
		t.Fatal(err)
	}
	if out != "첫째 둘째" {
		t.Errorf("concat = %q", out)
	}
}
