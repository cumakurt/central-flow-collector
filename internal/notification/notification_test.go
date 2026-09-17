package notification

import (
	"bufio"
	"central-flow-collector/internal/model"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebhookNotification(t *testing.T) {
	var n atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1); w.WriteHeader(204) }))
	defer s.Close()
	m := New(Config{WebhookURL: s.URL})
	m.Notify(model.Alert{Title: "test", Severity: "high"})
	deadline := time.Now().Add(time.Second)
	for n.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	m.Close()
	if n.Load() != 1 {
		t.Fatalf("notifications=%d stats=%+v", n.Load(), m.Stats())
	}
}

func TestReportWebhookDelivery(t *testing.T) {
	var contentType string
	var gotName, gotFile string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("multipart: %v", err)
			w.WriteHeader(400)
			return
		}
		gotName = r.FormValue("name")
		f, h, err := r.FormFile("report")
		if err != nil {
			t.Errorf("report part: %v", err)
			w.WriteHeader(400)
			return
		}
		defer f.Close()
		gotFile = h.Filename
		b := make([]byte, 8)
		n, _ := f.Read(b)
		if string(b[:n]) != "a,b\n1,2\n" {
			t.Errorf("payload=%q", string(b[:n]))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()
	m := New(Config{WebhookURL: s.URL})
	defer m.Close()
	if err := m.SendReport(context.Background(), "Daily SOC", "/tmp/daily.csv", []byte("a,b\n1,2\n")); err != nil {
		t.Fatal(err)
	}
	if gotName != "Daily SOC" || gotFile != "daily.csv" || !strings.HasPrefix(contentType, "multipart/form-data;") {
		t.Fatalf("name=%q file=%q content-type=%q", gotName, gotFile, contentType)
	}
}

func TestScheduledReportEmailOverrideAndDisable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	rcpts := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		send := func(v string) { fmt.Fprint(rw, v+"\r\n"); _ = rw.Flush() }
		send("220 localhost SMTP")
		var got []string
		for {
			line, e := rw.ReadString('\n')
			if e != nil {
				return
			}
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				send("250 localhost")
			case strings.HasPrefix(line, "MAIL FROM:"):
				send("250 OK")
			case strings.HasPrefix(line, "RCPT TO:"):
				got = append(got, line)
				send("250 OK")
			case line == "DATA":
				send("354 continue")
				for {
					v, e := rw.ReadString('\n')
					if e != nil {
						return
					}
					if v == ".\r\n" {
						break
					}
				}
				send("250 accepted")
			case line == "QUIT":
				send("221 bye")
				rcpts <- got
				return
			default:
				send("250 OK")
			}
		}
	}()
	m := New(Config{SMTPAddr: ln.Addr().String(), SMTPFrom: "collector@example.com", SMTPTo: "default@example.com"})
	defer m.Close()
	yes := true
	if err := m.SendReportWithEmail(context.Background(), "Daily", "/tmp/daily.pdf", []byte("pdf"), &yes, []string{"soc@example.com", "noc@example.com"}); err != nil {
		t.Fatal(err)
	}
	got := <-rcpts
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "soc@example.com") || !strings.Contains(joined, "noc@example.com") || strings.Contains(joined, "default@example.com") {
		t.Fatalf("rcpt commands=%v", got)
	}

	no := false
	// SMTP is intentionally unreachable here; disabled email must not attempt it.
	m2 := New(Config{SMTPAddr: "127.0.0.1:1", SMTPFrom: "collector@example.com", SMTPTo: "default@example.com"})
	defer m2.Close()
	if err := m2.SendReportWithEmail(context.Background(), "Disabled", "/tmp/x.csv", []byte("x"), &no, nil); err != nil {
		t.Fatalf("disabled email attempted delivery: %v", err)
	}
}

func TestScheduledReportEmailEnabledRequiresSMTP(t *testing.T) {
	m := New(Config{})
	defer m.Close()
	yes := true
	err := m.SendReportWithEmail(context.Background(), "Daily", "/tmp/daily.pdf", []byte("pdf"), &yes, []string{"soc@example.com"})
	if err == nil || !strings.Contains(err.Error(), "SMTP is not configured") {
		t.Fatalf("err=%v", err)
	}
}
