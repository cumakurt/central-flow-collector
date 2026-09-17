package notification

import (
	"bytes"
	"central-flow-collector/internal/model"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

type Config struct {
	WebhookURL, WebhookSecret, TelegramBotToken, TelegramChatID string
	SMTPAddr, SMTPFrom, SMTPTo, SMTPUsername, SMTPPassword      string
	SyslogAddr                                                  string
}

type Sender interface {
	Name() string
	Send(context.Context, model.Alert) error
}

type Manager struct {
	platform atomic.Pointer[Platform]
	cfg      Config
	q        chan model.Alert
	stop     chan struct{}
	done     chan struct{}
	senders  []Sender
	sent     atomic.Uint64
	failed   atomic.Uint64
	dropped  atomic.Uint64
}

type Stats struct {
	Senders       int    `json:"senders"`
	Sent          uint64 `json:"sent"`
	Failed        uint64 `json:"failed"`
	Dropped       uint64 `json:"dropped"`
	QueueDepth    int    `json:"queue_depth"`
	QueueCapacity int    `json:"queue_capacity"`
}

func New(cfg Config) *Manager {
	m := &Manager{cfg: cfg, q: make(chan model.Alert, 256), stop: make(chan struct{}), done: make(chan struct{})}
	if cfg.WebhookURL != "" {
		m.senders = append(m.senders, &webhookSender{url: cfg.WebhookURL, secret: cfg.WebhookSecret, client: &http.Client{Timeout: 5 * time.Second}})
	}
	if cfg.TelegramBotToken != "" && cfg.TelegramChatID != "" {
		m.senders = append(m.senders, &telegramSender{token: cfg.TelegramBotToken, chatID: cfg.TelegramChatID, client: &http.Client{Timeout: 5 * time.Second}})
	}
	if cfg.SMTPAddr != "" {
		m.senders = append(m.senders, &smtpSender{addr: cfg.SMTPAddr, from: cfg.SMTPFrom, to: strings.Split(cfg.SMTPTo, ","), user: cfg.SMTPUsername, password: cfg.SMTPPassword})
	}
	if cfg.SyslogAddr != "" {
		m.senders = append(m.senders, &syslogSender{addr: cfg.SyslogAddr})
	}
	go m.loop()
	return m
}
func (m *Manager) Notify(a model.Alert) {
	if p := m.platform.Load(); p != nil {
		p.observeLegacy(a)
	}
	if len(m.senders) == 0 {
		return
	}
	select {
	case m.q <- a:
	default:
		m.dropped.Add(1)
	}
}
func (m *Manager) loop() {
	defer close(m.done)
	for {
		select {
		case a := <-m.q:
			for _, s := range m.senders {
				if m.platform.Load() != nil && (s.Name() == "smtp" || s.Name() == "telegram") {
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				err := s.Send(ctx, a)
				cancel()
				if err != nil {
					m.failed.Add(1)
					log.Printf("notification provider=%s delivery failed", s.Name())
				} else {
					m.sent.Add(1)
				}
			}
		case <-m.stop:
			return
		}
	}
}
func (m *Manager) Close() {
	select {
	case <-m.done:
		return
	default:
		close(m.stop)
		<-m.done
	}
}
func (m *Manager) Stats() Stats {
	return Stats{Senders: len(m.senders), Sent: m.sent.Load(), Failed: m.failed.Load(), Dropped: m.dropped.Load(), QueueDepth: len(m.q), QueueCapacity: cap(m.q)}
}

func message(a model.Alert) string {
	return fmt.Sprintf("[%s] %s\n%s\nEvidence: %s\nEntity: %s\nObserved: %.3f Threshold: %.3f", strings.ToUpper(a.Severity), a.Title, a.Reason, a.Evidence, a.Entity, a.Observed, a.Threshold)
}

type webhookSender struct {
	url, secret string
	client      *http.Client
}

func (s *webhookSender) Name() string { return "webhook" }
func (s *webhookSender) Send(ctx context.Context, a model.Alert) error {
	b, _ := json.Marshal(a)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	if s.secret != "" {
		mac := hmac.New(sha256.New, []byte(s.secret))
		_, _ = mac.Write(b)
		req.Header.Set("X-FlowCollector-Signature", "sha256="+fmt.Sprintf("%x", mac.Sum(nil)))
	}
	r, e := s.client.Do(req)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode/100 != 2 {
		x, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
		return fmt.Errorf("HTTP %s: %s", r.Status, strings.TrimSpace(string(x)))
	}
	return nil
}

type telegramSender struct {
	token, chatID string
	client        *http.Client
}

func (s *telegramSender) Name() string { return "telegram" }
func (s *telegramSender) Send(ctx context.Context, a model.Alert) error {
	u := "https://api.telegram.org/bot" + url.PathEscape(s.token) + "/sendMessage"
	b, _ := json.Marshal(map[string]string{"chat_id": s.chatID, "text": message(a)})
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	r, e := s.client.Do(req)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %s", r.Status)
	}
	return nil
}

type smtpSender struct {
	addr, from     string
	to             []string
	user, password string
}

func (s *smtpSender) Name() string { return "smtp" }
func (s *smtpSender) Send(ctx context.Context, a model.Alert) error {
	host, _, e := net.SplitHostPort(s.addr)
	if e != nil {
		return e
	}
	d := net.Dialer{Timeout: 4 * time.Second}
	conn, e := d.DialContext(ctx, "tcp", s.addr)
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	c, e := smtp.NewClient(conn, host)
	if e != nil {
		return e
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if e = c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); e != nil {
			return e
		}
	}
	if s.user != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return fmt.Errorf("SMTP server does not advertise AUTH")
		}
		if e = c.Auth(smtp.PlainAuth("", s.user, s.password, host)); e != nil {
			return e
		}
	}
	if e = c.Mail(s.from); e != nil {
		return e
	}
	for _, to := range s.to {
		to = strings.TrimSpace(to)
		if to != "" {
			if e = c.Rcpt(to); e != nil {
				return e
			}
		}
	}
	w, e := c.Data()
	if e != nil {
		return e
	}
	msg := []byte("To: " + strings.Join(s.to, ",") + "\r\nSubject: FlowCollector alert: " + a.Title + "\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + message(a) + "\r\n")
	if _, e = w.Write(msg); e != nil {
		_ = w.Close()
		return e
	}
	if e = w.Close(); e != nil {
		return e
	}
	return c.Quit()
}

type syslogSender struct{ addr string }

func (s *syslogSender) Name() string { return "syslog" }
func (s *syslogSender) Send(ctx context.Context, a model.Alert) error {
	network, address := "udp", s.addr
	if strings.Contains(s.addr, "://") {
		u, e := url.Parse(s.addr)
		if e != nil {
			return e
		}
		network = u.Scheme
		address = u.Host
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	c, e := d.DialContext(ctx, network, address)
	if e != nil {
		return e
	}
	defer c.Close()
	_, e = fmt.Fprintf(c, "<132>1 %s flowcollector - - - - %s\n", time.Now().UTC().Format(time.RFC3339), strings.ReplaceAll(message(a), "\n", " | "))
	return e
}

// SendReport delivers a generated report outside the ingestion path. It is
// intentionally synchronous: callers run it from the reporting scheduler, not
// packet workers. SMTP uses a MIME attachment and webhook uses multipart/form-data.
func (m *Manager) SendReport(ctx context.Context, name, path string, data []byte) error {
	return m.SendReportWithEmail(ctx, name, path, data, nil, nil)
}

// SendReportWithEmail preserves webhook delivery while allowing each scheduled
// report to explicitly enable/disable SMTP and optionally override recipients.
// A nil emailEnabled keeps the legacy behavior: use configured SMTP when present.
func (m *Manager) SendReportWithEmail(ctx context.Context, name, path string, data []byte, emailEnabled *bool, recipients []string) error {
	return SendReportConfig(ctx, m.cfg, name, path, data, emailEnabled, recipients)
}

// SendReportConfig delivers a report using the supplied configuration. Keeping
// this operation independent from Manager allows scheduled reports to use the
// latest administrator SMTP/webhook settings without restarting the collector.
func SendReportConfig(ctx context.Context, cfg Config, name, path string, data []byte, emailEnabled *bool, recipients []string) error {
	var errs []string
	if cfg.WebhookURL != "" {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		_ = mw.WriteField("type", "scheduled_report")
		_ = mw.WriteField("name", name)
		part, err := mw.CreateFormFile("report", filepath.Base(path))
		if err == nil {
			_, err = part.Write(data)
		}
		_ = mw.Close()
		if err == nil {
			req, e := http.NewRequestWithContext(ctx, http.MethodPost, cfg.WebhookURL, bytes.NewReader(body.Bytes()))
			if e == nil {
				req.Header.Set("Content-Type", mw.FormDataContentType())
				resp, e2 := (&http.Client{Timeout: 10 * time.Second}).Do(req)
				if e2 != nil {
					err = e2
				} else {
					defer resp.Body.Close()
					if resp.StatusCode/100 != 2 {
						err = fmt.Errorf("webhook HTTP %s", resp.Status)
					}
				}
			} else {
				err = e
			}
		}
		if err != nil {
			errs = append(errs, "webhook: "+err.Error())
		}
	}
	wantsEmail := emailEnabled == nil || *emailEnabled
	if wantsEmail {
		if cfg.SMTPAddr == "" {
			if emailEnabled != nil && *emailEnabled {
				errs = append(errs, "smtp: SMTP is not configured")
			}
		} else {
			if len(recipients) > 0 {
				cfg.SMTPTo = strings.Join(recipients, ",")
			}
			if strings.TrimSpace(cfg.SMTPTo) == "" {
				errs = append(errs, "smtp: no report recipients configured")
			} else if err := sendSMTPAttachment(ctx, cfg, name, path, data); err != nil {
				errs = append(errs, "smtp: "+err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("report delivery failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

func sendSMTPAttachment(ctx context.Context, cfg Config, name, path string, data []byte) error {
	host, port, err := net.SplitHostPort(cfg.SMTPAddr)
	if err != nil {
		return fmt.Errorf("invalid SMTP address %q: %w", cfg.SMTPAddr, err)
	}
	from, err := mail.ParseAddress(strings.TrimSpace(cfg.SMTPFrom))
	if err != nil || from.Address == "" {
		return fmt.Errorf("invalid SMTP sender address")
	}
	tos := strings.Split(cfg.SMTPTo, ",")
	cleanTo := make([]string, 0, len(tos))
	for _, raw := range tos {
		a, e := mail.ParseAddress(strings.TrimSpace(raw))
		if e != nil || a.Address == "" {
			return fmt.Errorf("invalid SMTP recipient %q", strings.TrimSpace(raw))
		}
		cleanTo = append(cleanTo, a.Address)
	}
	if len(cleanTo) == 0 {
		return fmt.Errorf("no SMTP recipients configured")
	}
	name = strings.NewReplacer("\r", " ", "\n", " ").Replace(name)
	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	d := net.Dialer{Timeout: 5 * time.Second}
	var conn net.Conn
	if port == "465" {
		conn, err = tls.DialWithDialer(&d, "tcp", cfg.SMTPAddr, tlsConfig)
	} else {
		conn, err = d.DialContext(ctx, "tcp", cfg.SMTPAddr)
	}
	if err != nil {
		return fmt.Errorf("SMTP connection failed: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP greeting failed: %w", err)
	}
	defer c.Close()
	if port != "465" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err = c.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("SMTP STARTTLS failed: %w", err)
			}
		}
	}
	if cfg.SMTPUsername != "" {
		if err = c.Auth(smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, host)); err != nil {
			return err
		}
	}
	if err = c.Mail(from.Address); err != nil {
		return fmt.Errorf("SMTP sender rejected: %w", err)
	}
	for _, to := range cleanTo {
		if err = c.Rcpt(to); err != nil {
			return fmt.Errorf("SMTP recipient %s rejected: %w", to, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	boundary := "fc-report-" + fmt.Sprint(time.Now().UnixNano())
	mime := "application/octet-stream"
	if strings.HasSuffix(strings.ToLower(path), ".pdf") {
		mime = "application/pdf"
	} else if strings.HasSuffix(strings.ToLower(path), ".csv") {
		mime = "text/csv"
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "To: %s\r\nSubject: FlowCollector report: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n", strings.Join(cleanTo, ","), name, boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nScheduled report attached.\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: %s\r\nContent-Disposition: attachment; filename=%q\r\nContent-Transfer-Encoding: base64\r\n\r\n", boundary, mime, filepath.Base(path))
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	if _, err = w.Write(b.Bytes()); err != nil {
		_ = w.Close()
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return c.Quit()

}

// TestConfig performs a synchronous provider health/test delivery using the
// supplied configuration. It is intended for explicit administrator actions,
// never the collector hot path.
func TestConfig(ctx context.Context, cfg Config, provider string) error {
	a := model.Alert{ID: "notification-test", Type: "test", Severity: "info", Title: "FlowCollector notification test", Reason: "Administrator requested a notification provider test", Evidence: "control-plane test message", Entity: "flowcollector", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(), Count: 1, Status: "test"}
	provider = strings.ToLower(strings.TrimSpace(provider))
	var s Sender
	switch provider {
	case "webhook":
		if cfg.WebhookURL == "" {
			return fmt.Errorf("webhook is not configured")
		}
		s = &webhookSender{url: cfg.WebhookURL, client: &http.Client{Timeout: 6 * time.Second}}
	case "telegram":
		if cfg.TelegramBotToken == "" || cfg.TelegramChatID == "" {
			return fmt.Errorf("telegram is not configured")
		}
		s = &telegramSender{token: cfg.TelegramBotToken, chatID: cfg.TelegramChatID, client: &http.Client{Timeout: 6 * time.Second}}
	case "smtp":
		if cfg.SMTPAddr == "" {
			return fmt.Errorf("SMTP is not configured")
		}
		s = &smtpSender{addr: cfg.SMTPAddr, from: cfg.SMTPFrom, to: strings.Split(cfg.SMTPTo, ","), user: cfg.SMTPUsername, password: cfg.SMTPPassword}
	case "syslog":
		if cfg.SyslogAddr == "" {
			return fmt.Errorf("syslog is not configured")
		}
		s = &syslogSender{addr: cfg.SyslogAddr}
	default:
		return fmt.Errorf("unsupported notification provider %q", provider)
	}
	return s.Send(ctx, a)
}
