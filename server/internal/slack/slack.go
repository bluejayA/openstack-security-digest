// Package slack renders security advisories as Slack Block Kit messages and
// posts them to an Incoming Webhook.
package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jayahn/openstack-security-digest/server/internal/security"
)

// Message is the JSON payload accepted by a Slack Incoming Webhook.
type Message struct {
	Blocks      []Block      `json:"blocks,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

// Attachment renders a colored side-bar around a set of blocks.
type Attachment struct {
	Color  string  `json:"color,omitempty"`
	Blocks []Block `json:"blocks"`
}

// Block is a Block Kit block (header / section / context).
type Block struct {
	Type     string `json:"type"`
	Text     *Text  `json:"text,omitempty"`
	Elements []Text `json:"elements,omitempty"`
}

// Text is a Block Kit text object.
type Text struct {
	Type string `json:"type"` // "plain_text" | "mrkdwn"
	Text string `json:"text"`
}

func colorFor(i security.Impact) string {
	switch i {
	case security.ImpactCritical:
		return "#B71C1C"
	case security.ImpactHigh:
		return "#E64A19"
	case security.ImpactMedium:
		return "#F9A825"
	case security.ImpactLow:
		return "#2E7D32"
	default:
		return "#607D8B"
	}
}

func emojiFor(i security.Impact) string {
	switch i {
	case security.ImpactCritical:
		return ":rotating_light:"
	case security.ImpactHigh:
		return ":large_orange_diamond:"
	case security.ImpactMedium:
		return ":large_yellow_circle:"
	default:
		return ":white_circle:"
	}
}

// BuildMessage renders a digest's advisories into a Slack message: a header and
// context block, then one colored attachment per advisory.
func BuildMessage(digestTitle, digestLink string, advs []security.Advisory) Message {
	msg := Message{
		Blocks: []Block{
			{
				Type: "header",
				Text: &Text{Type: "plain_text", Text: "🛡 OpenStack Security — " + digestTitle},
			},
			{
				Type:     "context",
				Elements: []Text{{Type: "mrkdwn", Text: fmt.Sprintf("<%s|Read the full digest>", digestLink)}},
			},
		},
	}

	for _, a := range advs {
		msg.Attachments = append(msg.Attachments, Attachment{
			Color:  colorFor(a.Impact),
			Blocks: []Block{{Type: "section", Text: &Text{Type: "mrkdwn", Text: renderAdvisory(a)}}},
		})
	}
	return msg
}

func renderAdvisory(a security.Advisory) string {
	var sb strings.Builder

	title := a.ID
	if title == "" {
		title = a.Component
	}
	fmt.Fprintf(&sb, "%s *[%s] %s", emojiFor(a.Impact), a.Impact, title)
	if a.Component != "" && a.Component != title {
		fmt.Fprintf(&sb, " — %s", a.Component)
	}
	sb.WriteString("*\n")

	sb.WriteString(truncate(a.Summary, 600))

	if len(a.CVEs) > 0 {
		fmt.Fprintf(&sb, "\n*CVEs:* %s", strings.Join(a.CVEs, ", "))
	}
	if len(a.Affected) > 0 {
		fmt.Fprintf(&sb, "\n*Affected:* %s", strings.Join(a.Affected, ", "))
	}
	if a.Link != "" {
		fmt.Fprintf(&sb, "\n<%s|Advisory ↗>", a.Link)
	}
	return sb.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.TrimSpace(s[:max]) + "…"
}

// Notifier posts messages to Slack Incoming Webhooks.
type Notifier struct {
	client *http.Client
}

// New returns a Notifier with a sensible request timeout.
func New() *Notifier {
	return &Notifier{client: &http.Client{Timeout: 10 * time.Second}}
}

// Send posts the message JSON to the given Incoming Webhook URL.
func (n *Notifier) Send(ctx context.Context, webhookURL string, msg Message) error {
	if strings.TrimSpace(webhookURL) == "" {
		return fmt.Errorf("slack: empty webhook URL")
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("slack: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("slack: webhook returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}
