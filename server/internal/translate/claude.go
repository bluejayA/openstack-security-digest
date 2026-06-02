package translate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const anthropicVersion = "2023-06-01"

// langNames maps language codes to the names used in the prompt.
var langNames = map[string]string{
	"ko": "Korean",
	"ja": "Japanese",
	"en": "English",
}

func langName(lang string) string {
	if n, ok := langNames[lang]; ok {
		return n
	}
	return lang
}

// ClaudeTranslator translates via the Anthropic Messages API.
type ClaudeTranslator struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
}

// NewClaudeTranslator builds a translator for the given API key and model.
func NewClaudeTranslator(apiKey, model string) *ClaudeTranslator {
	return &ClaudeTranslator{
		apiKey:  apiKey,
		model:   model,
		baseURL: "https://api.anthropic.com",
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

type messagesRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    string          `json:"system"`
	Messages  []messagesEntry `json:"messages"`
}

type messagesEntry struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messagesResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

func systemPrompt(lang string) string {
	return fmt.Sprintf(
		"You are a professional translator specializing in cloud computing and "+
			"security. Translate the user's OpenStack security advisory text into "+
			"natural, fluent %s. Keep technical identifiers unchanged and in their "+
			"original form: CVE IDs (e.g. CVE-2026-42999), OSSA/OSSN advisory IDs, "+
			"project and component names (Keystone, Neutron, Swift, Nova, Cinder, "+
			"etc.), version ranges, and code. Do not add explanations, notes, or "+
			"quotation marks. Output only the translation.",
		langName(lang))
}

// Translate sends one message to the Anthropic API and returns the result text.
func (c *ClaudeTranslator) Translate(ctx context.Context, text, lang string) (string, error) {
	reqBody := messagesRequest{
		Model:     c.model,
		MaxTokens: 1024,
		System:    systemPrompt(lang),
		Messages:  []messagesEntry{{Role: "user", Content: text}},
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("translate: encode: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(buf))
	if err != nil {
		return "", fmt.Errorf("translate: request: %w", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("translate: call: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("translate: anthropic status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out messagesResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("translate: decode: %w", err)
	}
	var sb strings.Builder
	for _, block := range out.Content {
		if block.Type == "text" || block.Type == "" {
			sb.WriteString(block.Text)
		}
	}
	return strings.TrimSpace(sb.String()), nil
}
