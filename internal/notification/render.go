package notification

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"html/template"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

type MessageContext struct {
	ExclusiveEnd   bool              `json:"exclusive_end,omitempty"`
	NotificationID string            `json:"notification_id"`
	AlertID        string            `json:"alert_id"`
	RuleID         string            `json:"rule_id"`
	RuleName       string            `json:"rule_name"`
	Summary        string            `json:"summary"`
	Entity         string            `json:"entity"`
	State          string            `json:"state"`
	Priority       string            `json:"priority"`
	Observed       float64           `json:"observed"`
	Threshold      float64           `json:"threshold"`
	Metric         string            `json:"metric"`
	WindowSeconds  int               `json:"window_seconds"`
	At             time.Time         `json:"at"`
	From           time.Time         `json:"from"`
	FiredAt        time.Time         `json:"fired_at"`
	Dimensions     map[string]string `json:"dimensions,omitempty"`
}
type ActionLink struct {
	Text string `json:"text"`
	URL  string `json:"url"`
}
type RenderedMessage struct {
	Subject  string       `json:"subject"`
	HTML     string       `json:"html"`
	Plain    string       `json:"plain"`
	Telegram string       `json:"telegram"`
	Links    []ActionLink `json:"links"`
}

func newID(prefix string) string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic("random source unavailable")
	}
	return prefix + hex.EncodeToString(b)
}

// Only the administrator-configured public origin supplies links. Request Host
// and forwarded headers are deliberately ignored.
func ValidatePortalURL(base string) error {
	if base == "" {
		return nil
	}
	u, e := url.Parse(base)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("portal URL must be an absolute HTTP(S) URL without credentials, query or fragment")
	}
	return nil
}
func portalLinks(base string, c MessageContext) []ActionLink {
	if base == "" || ValidatePortalURL(base) != nil {
		return nil
	}
	u, _ := url.Parse(base)
	q := url.Values{"page": {"notifications"}, "tab": {"alerts"}, "alert": {c.AlertID}}
	u.RawQuery = q.Encode()
	links := []ActionLink{{"Open Alert", u.String()}}
	to := c.At
	if c.ExclusiveEnd {
		to = to.Add(-time.Millisecond)
	}
	q = url.Values{"page": {"flows"}, "range": {"custom"}, "from": {c.From.UTC().Format(time.RFC3339Nano)}, "to": {to.UTC().Format(time.RFC3339Nano)}}
	for k, v := range c.Dimensions {
		switch k {
		case "src_ip", "dst_ip", "src_port", "dst_port", "exporter", "ingress_if", "egress_if", "src_country", "dst_country", "src_as", "dst_as":
			q.Set(k, v)
		case "src_network":
			q.Set("src_cidr", v)
		case "dst_network":
			q.Set("dst_cidr", v)
		case "application":
			q.Set("app", v)
		case "protocol":
			q.Set("ip_protocol", v)
		}
	}
	u.RawQuery = q.Encode()
	return append(links, ActionLink{"Flow Explorer", u.String()})
}

// Table layout, inline styles and system fonts intentionally form a small,
// email-safe subset of the portal's slate / teal design tokens.
var emailTemplate = template.Must(template.New("email").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;background:#eef2f5;color:#172633;font-family:Arial,Helvetica,sans-serif"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px"><table role="presentation" width="640" cellpadding="0" cellspacing="0" style="width:100%;max-width:640px;border:1px solid #ccd6df;background:#ffffff"><tr><td style="background:#14232e;border-top:4px solid #30a99b;padding:22px;color:#f0f5f8;font-size:13px;letter-spacing:2px;font-weight:bold">⌁ CENTRAL FLOW COLLECTOR</td></tr><tr><td style="padding:22px"><p style="font-size:12px;font-weight:bold;color:#26796f">{{.Context.State}} · {{.Context.Priority}}</p><h1 style="font-size:23px;line-height:1.3;margin:12px 0">{{.Context.RuleName}}</h1><p style="font-size:14px;line-height:1.7;color:#506274">{{.Context.Summary}}</p><table role="presentation" width="100%" cellpadding="9" cellspacing="0" style="font-size:13px;border-top:1px solid #dce3e9"><tr><td style="color:#506274">Affected entity</td><td>{{.Context.Entity}}</td></tr><tr><td style="color:#506274">Observed / threshold</td><td><strong>{{.Context.Observed}}</strong> / {{.Context.Threshold}} {{.Context.Metric}}</td></tr><tr><td style="color:#506274">Window</td><td>{{.Context.WindowSeconds}} seconds</td></tr><tr><td style="color:#506274">Evaluated at (UTC)</td><td>{{.Timestamp}}</td></tr>{{if .RecoveryDuration}}<tr><td>Firing duration</td><td>{{.RecoveryDuration}}</td></tr>{{end}}</table>{{range .Links}}<p style="margin:20px 0 0"><a href="{{.URL}}" style="display:inline-block;background:#176f66;color:#ffffff;text-decoration:none;padding:11px 18px;font-size:13px;font-weight:bold">{{.Text}}</a></p>{{end}}</td></tr><tr><td style="padding:18px 22px;background:#f3f6f8;border-top:1px solid #dce3e9;color:#586979;font-size:11px;line-height:1.7">Notification {{.Context.NotificationID}}<br>Generated {{.Timestamp}} UTC · Observed telemetry; sampling is not normalized.</td></tr></table></td></tr></table></body></html>`))

func RenderMessage(c MessageContext, base string) (RenderedMessage, error) {
	if e := ValidatePortalURL(base); e != nil {
		return RenderedMessage{}, e
	}
	if strings.ContainsAny(c.RuleName, "\r\n") || len(c.RuleName) > 160 || len(c.Summary) > 4096 || len(c.Entity) > 1024 {
		return RenderedMessage{}, errors.New("message fields exceed safe limits")
	}
	links := portalLinks(base, c)
	if links == nil {
		links = []ActionLink{}
	}
	stamp := c.At.UTC().Format("2006-01-02 15:04:05")
	duration := ""
	if c.State == "RECOVERED" && !c.FiredAt.IsZero() {
		duration = c.At.Sub(c.FiredAt).Round(time.Second).String()
	}
	var b bytes.Buffer
	if e := emailTemplate.Execute(&b, struct {
		Context                     MessageContext
		Links                       []ActionLink
		Timestamp, RecoveryDuration string
	}{c, links, stamp, duration}); e != nil {
		return RenderedMessage{}, e
	}
	subject := fmt.Sprintf("Central Flow Collector — %s — %s", c.State, c.RuleName)
	plain := fmt.Sprintf("Central Flow Collector\n%s · %s\n%s\n\n%s\nEntity: %s\nObserved: %g %s\nThreshold: %g\nWindow: %ds\nTime: %s UTC\nNotification: %s", c.State, c.Priority, c.RuleName, c.Summary, c.Entity, c.Observed, c.Metric, c.Threshold, c.WindowSeconds, stamp, c.NotificationID)
	for _, l := range links {
		plain += "\n" + l.Text + ": " + l.URL
	}
	if duration != "" {
		plain += "\nFiring duration: " + duration
	}
	// Keep Telegram well under 4096 decoded characters, including user text.
	summary := []rune(c.Summary)
	if len(summary) > 700 {
		summary = append(summary[:700], []rune("…")...)
	}
	tg := fmt.Sprintf("<b>Central Flow Collector</b>\n\n<b>%s · %s</b>\n<b>%s</b>\n\n%s\n\nEntity: <code>%s</code>\nObserved: %g %s\nThreshold: %g\nWindow: %ds\nTime: %s UTC\nID: %s", html.EscapeString(c.State), html.EscapeString(c.Priority), html.EscapeString(c.RuleName), html.EscapeString(string(summary)), html.EscapeString(c.Entity), c.Observed, html.EscapeString(c.Metric), c.Threshold, c.WindowSeconds, stamp, html.EscapeString(c.NotificationID))
	if duration != "" {
		tg += "\nFiring duration: " + duration
	}
	return RenderedMessage{subject, b.String(), plain, tg, links}, nil
}
func safeAddress(v string) error {
	if strings.ContainsAny(v, "\r\n") || len(v) > 320 {
		return errors.New("invalid email address")
	}
	a, e := mail.ParseAddress(v)
	if e != nil || a.Address != v {
		return errors.New("use a plain email address without display name")
	}
	return nil
}
func buildMIME(c ChannelConfig, m RenderedMessage, id string, now time.Time) ([]byte, error) {
	if id == "" || len(id) > 120 || strings.ContainsAny(id, "\r\n<>@ \x00") {
		return nil, errors.New("invalid notification ID")
	}
	if strings.ContainsAny(m.Subject+c.SenderName+c.ReplyTo, "\r\n") {
		return nil, errors.New("header newline is forbidden")
	}
	if e := safeAddress(c.From); e != nil {
		return nil, e
	}
	for _, to := range c.Recipients {
		if e := safeAddress(to); e != nil {
			return nil, e
		}
	}
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	from := (&mail.Address{Name: c.SenderName, Address: c.From}).String()
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@central-flow-collector.local>\r\nX-CFC-Notification-ID: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=%q\r\n", from, strings.Join(c.Recipients, ", "), mime.QEncoding.Encode("utf-8", m.Subject), now.Format(time.RFC1123Z), id, id, w.Boundary())
	if c.ReplyTo != "" {
		if e := safeAddress(c.ReplyTo); e != nil {
			return nil, e
		}
		fmt.Fprintf(&b, "Reply-To: %s\r\n", c.ReplyTo)
	}
	b.WriteString("\r\n")
	for _, part := range []struct{ kind, body string }{{"text/plain", m.Plain}, {"text/html", m.HTML}} {
		p, e := w.CreatePart(textproto.MIMEHeader{"Content-Type": {part.kind + "; charset=utf-8"}, "Content-Transfer-Encoding": {"quoted-printable"}})
		if e != nil {
			return nil, e
		}
		q := quotedprintable.NewWriter(p)
		if _, e = q.Write([]byte(part.body)); e != nil {
			return nil, e
		}
		if e = q.Close(); e != nil {
			return nil, e
		}
	}
	if e := w.Close(); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
