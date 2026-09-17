package notification

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

type ChannelConfig struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	Enabled        bool      `json:"enabled"`
	Host           string    `json:"host,omitempty"`
	Port           int       `json:"port,omitempty"`
	Username       string    `json:"username,omitempty"`
	Security       string    `json:"security,omitempty"`
	SenderName     string    `json:"sender_name,omitempty"`
	From           string    `json:"from,omitempty"`
	ReplyTo        string    `json:"reply_to,omitempty"`
	HELO           string    `json:"helo,omitempty"`
	Recipients     []string  `json:"recipients,omitempty"`
	ChatID         string    `json:"chat_id,omitempty"`
	ParseMode      string    `json:"parse_mode,omitempty"`
	TimeoutSeconds int       `json:"timeout_seconds"`
	PerMinute      int       `json:"per_minute"`
	PasswordSet    bool      `json:"password_set"`
	TokenSet       bool      `json:"token_set"`
	LastTest       time.Time `json:"last_test"`
	LastDelivery   time.Time `json:"last_delivery"`
	Health         string    `json:"health"`
}
type ChannelInput struct {
	ChannelConfig
	Password string `json:"password,omitempty"`
	BotToken string `json:"bot_token,omitempty"`
}
type TestStage struct {
	Name         string `json:"name"`
	OK           bool   `json:"ok"`
	Milliseconds int64  `json:"milliseconds"`
	Detail       string `json:"detail,omitempty"`
}
type DeliveryError struct {
	Reason     string
	Temporary  bool
	RetryAfter time.Duration
}

func (e *DeliveryError) Error() string { return e.Reason }

// Channel transports receive a shared rendered message. They never evaluate
// conditions or mutate alert lifecycle state.
type Channel interface {
	Validate(ChannelConfig, string) error
	Send(context.Context, ChannelConfig, string, RenderedMessage, string) ([]TestStage, error)
	Test(context.Context, ChannelConfig, string) ([]TestStage, error)
}

func validateCommon(c ChannelConfig) error {
	if c.Name == "" || len(c.Name) > 120 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 30 || c.PerMinute < 1 || c.PerMinute > 120 {
		return errors.New("channel requires name, timeout 1..30 seconds and rate 1..120/minute")
	}
	return nil
}

type EmailChannel struct{}

func (EmailChannel) Validate(c ChannelConfig, secret string) error {
	if e := validateCommon(c); e != nil {
		return e
	}
	if c.Host == "" || len(c.Host) > 253 || strings.ContainsAny(c.Host, "/\r\n\x00 ") || c.Port < 1 || c.Port > 65535 {
		return errors.New("invalid SMTP host or port")
	}
	if !contains([]string{"starttls", "smtps", "relay"}, c.Security) {
		return errors.New("SMTP security must be starttls, smtps or relay")
	}
	if c.Security == "relay" && c.Username != "" {
		return errors.New("unencrypted relay cannot use password authentication")
	}
	if c.Username != "" && secret == "" {
		return errors.New("SMTP password is required")
	}
	if len(secret) > 4096 || len(c.Username) > 256 || strings.ContainsAny(c.SenderName+c.HELO+c.Username, "\r\n\x00") || len(c.SenderName) > 120 || len(c.HELO) > 253 {
		return errors.New("invalid SMTP field")
	}
	if e := safeAddress(c.From); e != nil {
		return e
	}
	if c.ReplyTo != "" {
		if e := safeAddress(c.ReplyTo); e != nil {
			return e
		}
	}
	if len(c.Recipients) < 1 || len(c.Recipients) > 50 {
		return errors.New("1..50 email recipients are required")
	}
	for _, v := range c.Recipients {
		if e := safeAddress(v); e != nil {
			return e
		}
	}
	return nil
}
func smtpFailure(stage string, err error) error {
	var pe *textproto.Error
	if errors.As(err, &pe) {
		return &DeliveryError{Reason: fmt.Sprintf("%s failed (SMTP %d)", stage, pe.Code), Temporary: pe.Code >= 400 && pe.Code < 500}
	}
	return &DeliveryError{Reason: stage + " failed; check connectivity, TLS certificate and server configuration", Temporary: stage == "DNS resolution" || stage == "TCP connection" || stage == "SMTP submission"}
}
func smtpSession(ctx context.Context, c ChannelConfig, secret string, payload []byte) (stages []TestStage, err error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	start := time.Now()
	_, err = net.DefaultResolver.LookupHost(ctx, c.Host)
	stages = append(stages, TestStage{"DNS resolution", err == nil, time.Since(start).Milliseconds(), ""})
	if err != nil {
		return stages, smtpFailure("DNS resolution", err)
	}
	start = time.Now()
	conn, err := (&net.Dialer{Timeout: time.Duration(c.TimeoutSeconds) * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
	stages = append(stages, TestStage{"TCP connection", err == nil, time.Since(start).Milliseconds(), ""})
	if err != nil {
		return stages, smtpFailure("TCP connection", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return stages, smtpFailure("TCP connection", err)
	}
	tlsConfig := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
	wire := conn
	if c.Security == "smtps" {
		start = time.Now()
		tc := tls.Client(conn, tlsConfig)
		err = tc.HandshakeContext(ctx)
		stages = append(stages, TestStage{"TLS negotiation", err == nil, time.Since(start).Milliseconds(), "certificate verification enabled"})
		if err != nil {
			return stages, smtpFailure("TLS negotiation", err)
		}
		wire = tc
	}
	client, err := smtp.NewClient(wire, c.Host)
	if err != nil {
		return stages, smtpFailure("SMTP greeting", err)
	}
	defer client.Close()
	if c.HELO != "" {
		if err = client.Hello(c.HELO); err != nil {
			return stages, smtpFailure("EHLO", err)
		}
	}
	if c.Security == "starttls" {
		start = time.Now()
		err = client.StartTLS(tlsConfig)
		stages = append(stages, TestStage{"STARTTLS negotiation", err == nil, time.Since(start).Milliseconds(), "certificate verification required"})
		if err != nil {
			return stages, smtpFailure("TLS negotiation", err)
		}
	}
	if c.Username != "" {
		start = time.Now()
		err = client.Auth(smtp.PlainAuth("", c.Username, secret, c.Host))
		stages = append(stages, TestStage{"Authentication", err == nil, time.Since(start).Milliseconds(), ""})
		if err != nil {
			return stages, smtpFailure("Authentication", err)
		}
	}
	start = time.Now()
	err = client.Mail(c.From)
	stages = append(stages, TestStage{"Sender validation", err == nil, time.Since(start).Milliseconds(), ""})
	if err != nil {
		return stages, smtpFailure("Sender validation", err)
	}
	for _, to := range c.Recipients {
		if err = client.Rcpt(to); err != nil {
			return stages, smtpFailure("Recipient validation", err)
		}
	}
	stages = append(stages, TestStage{Name: "Recipient validation", OK: true})
	if payload == nil {
		if err = client.Reset(); err != nil {
			return stages, smtpFailure("SMTP reset", err)
		}
		return stages, nil
	}
	start = time.Now()
	w, err := client.Data()
	if err != nil {
		return stages, smtpFailure("SMTP submission", err)
	}
	if _, err = w.Write(payload); err != nil {
		return stages, smtpFailure("SMTP submission", err)
	}
	err = w.Close()
	stages = append(stages, TestStage{"SMTP submission", err == nil, time.Since(start).Milliseconds(), ""})
	if err != nil {
		return stages, smtpFailure("SMTP submission", err)
	}
	// DATA acknowledgement is authoritative. A QUIT failure must not cause an
	// acknowledged email to be retried.
	_ = client.Quit()
	return stages, nil
}
func (e EmailChannel) Send(ctx context.Context, c ChannelConfig, s string, m RenderedMessage, id string) ([]TestStage, error) {
	if err := e.Validate(c, s); err != nil {
		return nil, err
	}
	b, err := buildMIME(c, m, id, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return smtpSession(ctx, c, s, b)
}
func (e EmailChannel) Test(ctx context.Context, c ChannelConfig, s string) ([]TestStage, error) {
	if err := e.Validate(c, s); err != nil {
		return nil, err
	}
	return smtpSession(ctx, c, s, nil)
}

type TelegramChannel struct {
	client   *http.Client
	endpoint string
}

func newTelegramChannel() *TelegramChannel {
	return &TelegramChannel{client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, endpoint: "https://api.telegram.org"}
}
func (t *TelegramChannel) Validate(c ChannelConfig, s string) error {
	if e := validateCommon(c); e != nil {
		return e
	}
	if len(s) < 10 || len(s) > 256 || !strings.Contains(s, ":") || strings.ContainsAny(s, "/\r\n ?#") || c.ChatID == "" || len(c.ChatID) > 128 {
		return errors.New("valid bot token and target chat are required")
	}
	if c.ParseMode != "HTML" {
		return errors.New("Telegram parse mode must be HTML")
	}
	return nil
}
func (t *TelegramChannel) call(ctx context.Context, c ChannelConfig, secret, method string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return errors.New("invalid Telegram payload")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint+"/bot"+secret+"/"+method, bytes.NewReader(b))
	if err != nil {
		return errors.New("invalid Telegram configuration")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return &DeliveryError{Reason: "Telegram connection failed or timed out", Temporary: true}
	}
	defer resp.Body.Close()
	var result struct {
		OK         bool `json:"ok"`
		ErrorCode  int  `json:"error_code"`
		Parameters struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result)
	code := resp.StatusCode
	if result.ErrorCode != 0 {
		code = result.ErrorCode
	}
	if err == nil && resp.StatusCode == 200 && result.OK {
		return nil
	}
	delay := result.Parameters.RetryAfter
	if h, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && h > delay {
		delay = h
	}
	delay = min(max(delay, 0), 86400)
	reason := "Telegram rejected request"
	switch code {
	case 401:
		reason = "Telegram bot authentication failed"
	case 403:
		reason = "Telegram bot is blocked or lacks permission"
	case 400:
		reason = "Telegram target chat or message is invalid"
	case 429:
		reason = "Telegram rate limit"
	}
	return &DeliveryError{Reason: reason, Temporary: code == 429 || code >= 500, RetryAfter: time.Duration(delay) * time.Second}
}
func (t *TelegramChannel) Send(ctx context.Context, c ChannelConfig, s string, m RenderedMessage, id string) ([]TestStage, error) {
	if e := t.Validate(c, s); e != nil {
		return nil, e
	}
	buttons := [][]ActionLink{}
	for _, l := range m.Links {
		buttons = append(buttons, []ActionLink{l})
	}
	start := time.Now()
	e := t.call(ctx, c, s, "sendMessage", map[string]any{"chat_id": c.ChatID, "parse_mode": "HTML", "text": m.Telegram, "link_preview_options": map[string]bool{"is_disabled": true}, "reply_markup": map[string]any{"inline_keyboard": buttons}})
	return []TestStage{{"Message delivery", e == nil, time.Since(start).Milliseconds(), ""}}, e
}
func (t *TelegramChannel) Test(ctx context.Context, c ChannelConfig, s string) ([]TestStage, error) {
	if e := t.Validate(c, s); e != nil {
		return nil, e
	}
	stages := []TestStage{}
	for _, method := range []string{"getMe", "getChat"} {
		start := time.Now()
		payload := map[string]string{}
		if method == "getChat" {
			payload["chat_id"] = c.ChatID
		}
		err := t.call(ctx, c, s, method, payload)
		stages = append(stages, TestStage{method, err == nil, time.Since(start).Milliseconds(), ""})
		if err != nil {
			return stages, err
		}
	}
	return stages, nil
}
