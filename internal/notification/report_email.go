package notification

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SendReportEmail sends a generated report through the first enabled email
// channel configured in the notification platform. The boolean result reports
// whether an enabled platform email channel existed. This lets callers fall
// back to legacy SMTP configuration without sending duplicates.
func (p *Platform) SendReportEmail(ctx context.Context, name, path string, data []byte, recipients []string) (bool, error) {
	if p == nil {
		return false, nil
	}
	p.mu.Lock()
	choices := make([]storedChannel, 0, len(p.state.Channels))
	for _, ch := range p.state.Channels {
		if ch.Config.Type == "email" && ch.Config.Enabled {
			choices = append(choices, ch)
		}
	}
	p.mu.Unlock()
	if len(choices) == 0 {
		return false, nil
	}
	sort.Slice(choices, func(i, j int) bool {
		if choices[i].Config.Name == choices[j].Config.Name {
			return choices[i].Config.ID < choices[j].Config.ID
		}
		return choices[i].Config.Name < choices[j].Config.Name
	})
	ch := choices[0]
	secret, err := p.unseal(ch.Config.ID, ch.Secret)
	if err != nil {
		return true, err
	}
	if len(recipients) > 0 {
		ch.Config.Recipients = append([]string(nil), recipients...)
	}
	if err = (EmailChannel{}).Validate(ch.Config, secret); err != nil {
		return true, err
	}
	id := newID("CFC-REPORT-")
	payload, err := buildReportMIME(ch.Config, name, path, data, id, time.Now().UTC())
	if err != nil {
		return true, err
	}
	_, err = smtpSession(ctx, ch.Config, secret, payload)
	at := time.Now().UTC()
	_ = p.transaction(func(s *platformState) error {
		current, ok := s.Channels[ch.Config.ID]
		if !ok {
			return nil
		}
		current.Config.LastDelivery = at
		if err != nil {
			current.Config.Health = "Degraded"
		} else {
			current.Config.Health = "Healthy"
		}
		s.Channels[ch.Config.ID] = current
		return nil
	})
	return true, err
}

func buildReportMIME(c ChannelConfig, name, path string, data []byte, id string, now time.Time) ([]byte, error) {
	if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(id, "\r\n<>@ \x00") {
		return nil, errors.New("invalid report mail header")
	}
	if err := safeAddress(c.From); err != nil {
		return nil, err
	}
	for _, to := range c.Recipients {
		if err := safeAddress(to); err != nil {
			return nil, err
		}
	}
	if len(c.Recipients) == 0 {
		return nil, errors.New("no email recipients configured")
	}
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	from := (&mail.Address{Name: c.SenderName, Address: c.From}).String()
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@central-flow-collector.local>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n", from, strings.Join(c.Recipients, ", "), mime.QEncoding.Encode("utf-8", "Central Flow Collector report — "+name), now.Format(time.RFC1123Z), id, w.Boundary())
	plain, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"}, "Content-Transfer-Encoding": {"8bit"}})
	if err != nil {
		return nil, err
	}
	if _, err = fmt.Fprintf(plain, "Central Flow Collector scheduled report attached.\r\nReport: %s\r\nGenerated: %s\r\n", name, now.Format(time.RFC3339)); err != nil {
		return nil, err
	}
	contentType := "application/octet-stream"
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pdf":
		contentType = "application/pdf"
	case ".csv":
		contentType = "text/csv"
	case ".json":
		contentType = "application/json"
	case ".xlsx":
		contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	}
	part, err := w.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {contentType},
		"Content-Disposition":       {fmt.Sprintf("attachment; filename=%q", filepath.Base(path))},
		"Content-Transfer-Encoding": {"base64"},
	})
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	for len(encoded) > 76 {
		if _, err = part.Write([]byte(encoded[:76] + "\r\n")); err != nil {
			return nil, err
		}
		encoded = encoded[76:]
	}
	if _, err = part.Write([]byte(encoded + "\r\n")); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
