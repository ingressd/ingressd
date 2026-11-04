// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// Notification is what a channel delivers.
type Notification struct {
	Event
	Edge string // edge name, for multi-edge setups
	// Reminder marks a re-send of a still-firing alert.
	Reminder bool
}

// Subject is a one-line summary.
func (n Notification) Subject() string {
	s := n.Title
	switch {
	case n.Resolved:
		s = "✅ " + s
	case n.Severity == Critical:
		s = "🚨 " + s
	default:
		s = "⚠️ " + s
	}
	if n.Reminder {
		s += " (still firing)"
	}
	if n.Edge != "" {
		s = "[" + n.Edge + "] " + s
	}
	return s
}

// Text is a plain-text body.
func (n Notification) Text() string {
	var b strings.Builder
	if n.Message != "" {
		b.WriteString(n.Message)
		b.WriteString("\n")
	}
	keys := make([]string, 0, len(n.Fields))
	for k := range n.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\n", k, n.Fields[k])
	}
	fmt.Fprintf(&b, "event: %s · %s", n.Kind, n.Time.UTC().Format(time.RFC3339))
	return b.String()
}

// Channel delivers notifications to one destination.
type Channel interface {
	Send(ctx context.Context, n Notification) error
}

// Sender sends plain-text email. Phase 3 provides SES and SMTP senders;
// until one is injected (EngineOptions.Email) email channels fail with
// ErrEmailNotConfigured.
type Sender interface {
	SendEmail(ctx context.Context, to []string, subject, body string) error
}

var ErrEmailNotConfigured = errors.New("email sending is not configured")

type noSender struct{}

func (noSender) SendEmail(context.Context, []string, string, string) error {
	return ErrEmailNotConfigured
}

// Resolver resolves secret:// references in channel URLs.
type Resolver interface {
	Resolve(v string) (string, error)
}

// NewChannel builds a channel from config.
func NewChannel(c config.AlertChannel, res Resolver, email Sender, client *http.Client) (Channel, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	url := c.Endpoint()
	if res != nil && url != "" {
		var err error
		if url, err = res.Resolve(url); err != nil {
			return nil, err
		}
	}
	switch c.Type {
	case config.ChannelNtfy:
		return ntfy{url: url, client: client}, nil
	case config.ChannelDiscord:
		return discord{url: url, client: client}, nil
	case config.ChannelWebhook:
		return webhook{url: url, client: client}, nil
	case config.ChannelEmail:
		if email == nil {
			email = noSender{}
		}
		return emailChannel{to: c.To, sender: email}, nil
	}
	return nil, fmt.Errorf("unknown channel type %q", c.Type)
}

func post(ctx context.Context, client *http.Client, url, contentType string, body []byte, hdr map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "ingressd-alerts")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		// Do not echo the URL: it is often a secret (webhook token).
		var ue interface{ Unwrap() error }
		if errors.As(err, &ue) {
			return fmt.Errorf("request failed: %w", ue.Unwrap())
		}
		return errors.New("request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// ntfy posts the text to a topic URL (https://ntfy.sh/<topic>).
type ntfy struct {
	url    string
	client *http.Client
}

func (c ntfy) Send(ctx context.Context, n Notification) error {
	prio, tags := "default", "warning"
	switch {
	case n.Resolved:
		prio, tags = "low", "white_check_mark"
	case n.Severity == Critical:
		prio, tags = "urgent", "rotating_light"
	}
	// Header values must be ASCII; ntfy decodes RFC 2047 for the title.
	title := n.Title
	if n.Edge != "" {
		title = "[" + n.Edge + "] " + title
	}
	return post(ctx, c.client, c.url, "text/plain; charset=utf-8", []byte(n.Text()), map[string]string{
		"Title": asciiHeader(title), "Priority": prio, "Tags": tags,
	})
}

func asciiHeader(s string) string {
	for _, r := range s {
		if r > 126 || r < 32 {
			return "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
		}
	}
	return s
}

// discord posts an embed to a Discord webhook.
type discord struct {
	url    string
	client *http.Client
}

func (c discord) Send(ctx context.Context, n Notification) error {
	color := 0xF59E0B
	switch {
	case n.Resolved:
		color = 0x22C55E
	case n.Severity == Critical:
		color = 0xDC2626
	}
	body, _ := json.Marshal(map[string]any{
		"username": "ingressd",
		"embeds": []map[string]any{{
			"title":       truncate(n.Subject(), 256),
			"description": truncate(n.Text(), 4000),
			"color":       color,
			"timestamp":   n.Time.UTC().Format(time.RFC3339),
		}},
	})
	return post(ctx, c.client, c.url, "application/json", body, nil)
}

// WebhookPayload is the JSON body of generic webhook notifications.
type WebhookPayload struct {
	Edge     string            `json:"edge,omitempty"`
	Event    Kind              `json:"event"`
	Key      string            `json:"key"`
	Status   string            `json:"status"` // firing | resolved
	Severity Severity          `json:"severity"`
	Title    string            `json:"title"`
	Message  string            `json:"message,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
	Time     time.Time         `json:"time"`
	Reminder bool              `json:"reminder,omitempty"`
}

type webhook struct {
	url    string
	client *http.Client
}

func (c webhook) Send(ctx context.Context, n Notification) error {
	status := "firing"
	if n.Resolved {
		status = "resolved"
	}
	body, _ := json.Marshal(WebhookPayload{
		Edge: n.Edge, Event: n.Kind, Key: n.Key, Status: status, Severity: n.Severity,
		Title: n.Title, Message: n.Message, Fields: n.Fields, Time: n.Time.UTC(), Reminder: n.Reminder,
	})
	return post(ctx, c.client, c.url, "application/json", body, nil)
}

type emailChannel struct {
	to     []string
	sender Sender
}

func (c emailChannel) Send(ctx context.Context, n Notification) error {
	return c.sender.SendEmail(ctx, c.to, n.Subject(), n.Text())
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) > n-1 {
		r = r[:n-1]
	}
	return string(r) + "…"
}
