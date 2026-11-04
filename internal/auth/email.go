// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sestypes "github.com/aws/aws-sdk-go-v2/service/sesv2/types"

	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/mailtheme"
)

// Message is one email with text and HTML alternatives.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Sender delivers email.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// NewSender builds the sender configured under email:.
func NewSender(cfg *config.Config, res Resolver) (Sender, error) {
	e := cfg.Email
	switch e.Provider {
	case config.EmailLog:
		return &LogSender{Path: e.Log.Path}, nil
	case config.EmailSMTP:
		s := &SMTPSender{From: e.From, Host: e.SMTP.Host, Port: e.SMTP.Port, TLS: e.SMTP.TLS}
		var err error
		if s.Username, err = res.Resolve(e.SMTP.Username); err != nil {
			return nil, fmt.Errorf("email.smtp.username: %w", err)
		}
		if s.Password, err = res.Resolve(e.SMTP.Password); err != nil {
			return nil, fmt.Errorf("email.smtp.password: %w", err)
		}
		return s, nil
	case config.EmailSES:
		return newSESSender(e, res)
	case "":
		return nil, fmt.Errorf("email.provider is not configured")
	}
	return nil, fmt.Errorf("unknown email provider %q", e.Provider)
}

// LogSender appends messages to a file instead of sending them. Tests read
// codes from it; it is also handy while setting up DNS for real email.
type LogSender struct {
	Path string
	mu   sync.Mutex
}

func (l *LogSender) Send(_ context.Context, m Message) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(l.Path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "Date: %s\nTo: %s\nSubject: %s\n\n%s\n-----\n", time.Now().UTC().Format(time.RFC3339), m.To, m.Subject, m.Text)
	return err
}

// SMTPSender sends through an SMTP relay.
type SMTPSender struct {
	From               string
	Host               string
	Port               int
	Username, Password string
	TLS                string // starttls | tls | none
}

func (s *SMTPSender) Send(ctx context.Context, m Message) error {
	from, err := mail.ParseAddress(s.From)
	if err != nil {
		return err
	}
	body, err := buildMIME(s.From, m)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	d := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	if s.TLS == "tls" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: s.Host})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if s.TLS == "starttls" {
		if err := c.StartTLS(&tls.Config{ServerName: s.Host}); err != nil {
			return err
		}
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(m.To); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// buildMIME renders a multipart/alternative message.
func buildMIME(from string, m Message) ([]byte, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	domain := "ingressd"
	if a, err := mail.ParseAddress(from); err == nil {
		if i := strings.LastIndexByte(a.Address, '@'); i >= 0 {
			domain = a.Address[i+1:]
		}
	}
	hdr := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=%q\r\n\r\n",
		from, m.To, mime(m.Subject), time.Now().Format(time.RFC1123Z), hex.EncodeToString(id), domain, mw.Boundary())
	var out bytes.Buffer
	out.WriteString(hdr)
	for _, part := range []struct{ ctype, body string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
		pw, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.ctype + "; charset=utf-8"},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		qp := quotedprintable.NewWriter(pw)
		if _, err := qp.Write([]byte(part.body)); err != nil {
			return nil, err
		}
		qp.Close()
	}
	mw.Close()
	out.Write(buf.Bytes())
	return out.Bytes(), nil
}

func mime(s string) string {
	for _, r := range s {
		if r > 127 {
			return "=?utf-8?q?" + strings.ReplaceAll(s, " ", "_") + "?="
		}
	}
	return s
}

// SESSender sends with Amazon SES API v2.
type SESSender struct {
	From   string
	client *sesv2.Client
}

func newSESSender(e config.Email, res Resolver) (*SESSender, error) {
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(e.Region)}
	if e.AccessKeyID != "" {
		id, err := res.Resolve(e.AccessKeyID)
		if err != nil {
			return nil, fmt.Errorf("email.access_key_id: %w", err)
		}
		secret, err := res.Resolve(e.SecretAccessKey)
		if err != nil {
			return nil, fmt.Errorf("email.secret_access_key: %w", err)
		}
		opts = append(opts, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(id, secret, "")))
	}
	ac, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}
	return &SESSender{From: e.From, client: sesv2.NewFromConfig(ac)}, nil
}

func (s *SESSender) Send(ctx context.Context, m Message) error {
	utf8 := aws.String("UTF-8")
	_, err := s.client.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(s.From),
		Destination:      &sestypes.Destination{ToAddresses: []string{m.To}},
		Content: &sestypes.EmailContent{Simple: &sestypes.Message{
			Subject: &sestypes.Content{Data: aws.String(m.Subject), Charset: utf8},
			Body: &sestypes.Body{
				Text: &sestypes.Content{Data: aws.String(m.Text), Charset: utf8},
				Html: &sestypes.Content{Data: aws.String(m.HTML), Charset: utf8},
			},
		}},
	})
	return err
}

// retrySend delivers with exponential backoff (1s, 2s, 4s...).
func retrySend(ctx context.Context, s Sender, m Message, attempts int) error {
	var err error
	for i := 0; i < attempts; i++ {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = s.Send(sctx, m)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second << i):
		}
	}
	return err
}

// --- templates ---

type codeEmail struct {
	Brand    config.Branding
	App      string
	Code     string
	IP       string
	Location string
	TTL      string
}

func renderCodeEmail(to string, d codeEmail) (Message, error) {
	from := d.IP
	if d.Location != "" {
		from += " (" + d.Location + ")"
	}
	e := mailtheme.Email{
		Subject:   "Your sign-in code for " + d.App,
		Preheader: "Your sign-in code is " + d.Code + ". It expires in " + d.TTL + ".",
		Eyebrow:   "Sign in",
		Title:     "Sign in to " + d.App,
		Intro:     []string{"Enter this code to finish signing in to " + d.App + "."},
		CodeLabel: "Your sign-in code is",
		Code:      d.Code,
		Details:   []mailtheme.Detail{{Label: "Expires in", Value: d.TTL}, {Label: "Requested from", Value: from}},
		Outro:     []string{"If you did not try to sign in, you can ignore this email."},
	}
	text, html, err := e.Render(mailtheme.Theme{Name: d.Brand.Name, LogoURL: d.Brand.LogoURL, Accent: d.Brand.Color})
	if err != nil {
		return Message{}, err
	}
	return Message{To: to, Subject: e.Subject, Text: text, HTML: html}, nil
}
