package notification

import (
	"bufio"
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"central-flow-collector/internal/model"
)

func testRule() RuleDefinition {
	return RuleDefinition{ID: "r1", Name: "Network usage", Kind: "aggregate", Condition: Condition{Op: "eq", Field: "protocol", Values: []string{"6"}}, Metric: "bytes", Operator: "gt", Threshold: 80, WindowSeconds: 300, IntervalSeconds: 60, CooldownSeconds: 1800, Recovery: true, PolicyID: "p1", Priority: "high", Revision: 1}
}
func testState() platformState {
	s := emptyState()
	s.Channels["email"] = storedChannel{Config: ChannelConfig{ID: "email", Name: "Email", Type: "email", Enabled: true}}
	s.Channels["telegram"] = storedChannel{Config: ChannelConfig{ID: "telegram", Name: "Telegram", Type: "telegram", Enabled: true}}
	s.Policies["p1"] = NotificationPolicy{ID: "p1", Name: "NOC", Routes: []Route{{ChannelID: "email"}, {ChannelID: "telegram"}}}
	return s
}

func TestBooleanTreeCIDRAndPorts(t *testing.T) {
	c := Condition{Op: "and", Children: []Condition{{Op: "in", Field: "src_network", Values: []string{"10.20.0.0/16", "2001:db8::/32"}}, {Op: "range", Field: "dst_port", Values: []string{"22", "443"}}, {Op: "not", Children: []Condition{{Op: "eq", Field: "protocol", Values: []string{"17"}}}}}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, tt := range []struct {
		ip    string
		port  uint16
		proto uint8
		match bool
	}{{"10.20.1.2", 443, 6, true}, {"2001:db8::2", 22, 6, true}, {"10.21.1.2", 443, 6, false}, {"10.20.1.2", 444, 6, false}, {"10.20.1.2", 443, 17, false}} {
		if got := c.Match(model.Flow{SrcIP: tt.ip, DstPort: tt.port, IPProtocol: tt.proto}); got != tt.match {
			t.Fatalf("%+v: %v", tt, got)
		}
	}
	or := Condition{Op: "or", Children: []Condition{{Op: "eq", Field: "dst_port", Values: []string{"53"}}, {Op: "eq", Field: "dst_port", Values: []string{"443"}}}}
	if !or.Match(model.Flow{DstPort: 53}) || or.Match(model.Flow{DstPort: 80}) {
		t.Fatal("OR mismatch")
	}
	for _, c := range []Condition{{Op: "not", Children: []Condition{}}, {Op: "eq", Field: "src_network", Values: []string{"invalid"}}, {Op: "eq", Field: "dst_port", Values: []string{"65536"}}, {Op: "eq", Field: "bytes", Values: []string{"NaN"}}} {
		if c.Validate() == nil {
			t.Fatal("accepted invalid condition", c)
		}
	}
}
func TestLifecycleCooldownRecoveryHysteresisAndSilence(t *testing.T) {
	s := testState()
	r := testRule()
	r.ForSeconds = 120
	low := 70.0
	r.RecoveryThreshold = &low
	at := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	step := func(seconds int, value float64) EvaluationCounts {
		t.Helper()
		c, e := applyEvaluation(&s, r, []Observation{{Entity: "router", Value: value}}, at.Add(time.Duration(seconds)*time.Second))
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	step(0, 90)
	if s.Alerts[alertKey(r.ID, "router")].State != "PENDING" {
		t.Fatal("expected pending")
	}
	step(60, 90)
	step(120, 90)
	if len(s.Deliveries) != 2 {
		t.Fatalf("deliveries %d", len(s.Deliveries))
	}
	step(180, 75)
	if s.Alerts[alertKey(r.ID, "router")].State != "FIRING" || len(s.Deliveries) != 2 {
		t.Fatal("hysteresis or dedup failed")
	}
	step(240, 65)
	if len(s.Deliveries) != 4 || s.Deliveries[2].Context.State != "RECOVERED" {
		t.Fatal("recovery missing")
	}
	step(300, 90)
	step(360, 90)
	step(420, 90)
	if len(s.Deliveries) != 4 {
		t.Fatal("cooldown reset on recovery")
	}
	s.Silences["maintenance"] = Silence{RuleID: r.ID, From: at, Until: at.Add(time.Hour)}
	c := step(2400, 90)
	if c.Suppressed != 1 || len(s.Deliveries) != 4 {
		t.Fatal("silence failed")
	}
}
func TestComparisonZeroAndMinimum(t *testing.T) {
	r := testRule()
	r.Kind = "comparison"
	r.Threshold = 100
	r.MinimumCurrent = 1000
	for _, tt := range []struct {
		v, p float64
		want bool
	}{{10000, 0, false}, {100, 1, false}, {1500, 1000, false}, {3000, 1000, true}} {
		if breached(r, Observation{Value: tt.v, Previous: tt.p}, AlertInstance{}) != tt.want {
			t.Fatal(tt)
		}
	}
}
func TestScheduleOvernightAndDST(t *testing.T) {
	s := Schedule{Timezone: "America/New_York", Weekdays: []int{1}, StartMinute: 23 * 60, EndMinute: 2 * 60}
	for _, tt := range []struct {
		at   string
		want bool
	}{{"2026-03-10T04:30:00Z", true}, {"2026-03-10T06:01:00Z", false}, {"2026-03-09T04:30:00Z", false}} {
		at, _ := time.Parse(time.RFC3339, tt.at)
		if s.Active(at) != tt.want {
			t.Fatal(tt)
		}
	}
}

func emailConfig() ChannelConfig {
	return ChannelConfig{ID: "c1", Name: "Test relay", Type: "email", Enabled: true, Host: "127.0.0.1", Port: 25, Security: "relay", From: "collector@example.test", Recipients: []string{"noc@example.test"}, TimeoutSeconds: 2, PerMinute: 30}
}
func TestPersistentSecretRedactionAndRestart(t *testing.T) {
	dir := t.TempDir()
	p, e := OpenPlatform(dir, nil)
	if e != nil {
		t.Fatal(e)
	}
	c := emailConfig()
	c.Security = "starttls"
	c.Username = "test"
	secret := newID("test-only-")
	out, e := p.SaveChannel(ChannelInput{ChannelConfig: c, Password: secret})
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(out)
	disk, _ := os.ReadFile(p.path)
	if strings.Contains(string(b), secret) || strings.Contains(string(disk), secret) || !out.PasswordSet {
		t.Fatal("secret exposed")
	}
	c.Name = "Renamed"
	if _, e = p.SaveChannel(ChannelInput{ChannelConfig: c}); e != nil {
		t.Fatal(e)
	}
	p2, e := OpenPlatform(dir, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer p2.Close()
	stored := p2.state.Channels[c.ID]
	got, e := p2.unseal(c.ID, stored.Secret)
	if e != nil || got != secret {
		t.Fatal("secret lost after update/restart")
	}
	if _, e = p2.unseal("other", stored.Secret); e == nil {
		t.Fatal("ciphertext not bound to channel ID")
	}
}

func TestFakeSMTPMultipart(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	data := make(chan string, 1)
	commands := make(chan []string, 1)
	go func() {
		conn, e := l.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		send := func(v string) { fmt.Fprint(rw, v+"\r\n"); rw.Flush() }
		send("220 localhost SMTP")
		all := []string{}
		for {
			line, e := rw.ReadString('\n')
			if e != nil {
				return
			}
			line = strings.TrimSpace(line)
			all = append(all, line)
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				send("250 localhost")
			case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
				send("250 OK")
			case line == "DATA":
				send("354 continue")
				var b strings.Builder
				for {
					v, e := rw.ReadString('\n')
					if e != nil {
						return
					}
					if v == ".\r\n" {
						break
					}
					b.WriteString(v)
				}
				data <- b.String()
				send("250 accepted")
			case line == "QUIT":
				send("221 bye")
				commands <- all
				return
			default:
				send("250 OK")
			}
		}
	}()
	c := emailConfig()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	c.Port, _ = strconv.Atoi(port)
	m, e := RenderMessage(MessageContext{RuleName: "Flow > threshold", State: "FIRING", Priority: "high", At: time.Now().UTC()}, "https://collector.example.test")
	if e != nil {
		t.Fatal(e)
	}
	_, e = (EmailChannel{}).Send(context.Background(), c, "", m, "CFC-NOT-test")
	if e != nil {
		t.Fatal(e)
	}
	raw := <-data
	message, e := mail.ReadMessage(strings.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	media, params, e := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if e != nil || media != "multipart/alternative" {
		t.Fatal("not multipart")
	}
	parts := multipart.NewReader(message.Body, params["boundary"])
	for _, kind := range []string{"text/plain", "text/html"} {
		part, e := parts.NextPart()
		if e != nil || !strings.HasPrefix(part.Header.Get("Content-Type"), kind) {
			t.Fatal("missing MIME alternative", e)
		}
		b, _ := io.ReadAll(part)
		if !strings.Contains(string(b), "Central Flow Collector") && !strings.Contains(string(b), "CENTRAL FLOW COLLECTOR") {
			t.Fatal("brand missing")
		}
	}
	if message.Header.Get("X-CFC-Notification-ID") != "CFC-NOT-test" || message.Header.Get("Message-ID") == "" {
		t.Fatal("message identity missing")
	}
	cmd := strings.Join(<-commands, "\n")
	if !strings.Contains(cmd, "MAIL FROM:<collector@example.test>") || !strings.Contains(cmd, "RCPT TO:<noc@example.test>") {
		t.Fatal(cmd)
	}
}
func TestHeaderAndRendererSafety(t *testing.T) {
	c := emailConfig()
	c.From = "noc@example.test\r\nBcc: attacker@example.test"
	if (EmailChannel{}).Validate(c, "") == nil {
		t.Fatal("header injection accepted")
	}
	if _, e := RenderMessage(MessageContext{RuleName: "hello\nBcc:x"}, ""); e == nil {
		t.Fatal("subject injection")
	}
	m, e := RenderMessage(MessageContext{RuleName: "<script>alert(1)</script>", Summary: "<img src=x onerror=alert(1)>", Entity: "<b>unsafe</b>", State: "FIRING", At: time.Unix(0, 0)}, "https://portal.example.test")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(m.HTML, "<script>") || strings.Contains(m.HTML, "<img src=x") || strings.Contains(m.Telegram, "<script>") {
		t.Fatal("escaping failure")
	}
	if ValidatePortalURL("javascript:alert(1)") == nil || ValidatePortalURL("https://user:pass@example.test") == nil {
		t.Fatal("unsafe portal URL")
	}
}

func TestFakeTelegramResponses(t *testing.T) {
	for _, status := range []int{200, 401, 403, 429, 500} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload map[string]any
				if e := json.NewDecoder(r.Body).Decode(&payload); e != nil {
					t.Error(e)
				}
				if payload["parse_mode"] != "HTML" || payload["chat_id"] != "123" {
					t.Error(payload)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				if status == 200 {
					fmt.Fprint(w, `{"ok":true,"result":{"message_id":1}}`)
				} else {
					fmt.Fprintf(w, `{"ok":false,"error_code":%d,"description":"secret must not escape","parameters":{"retry_after":17}}`, status)
				}
			}))
			defer s.Close()
			ch := newTelegramChannel()
			ch.endpoint = s.URL
			c := ChannelConfig{Name: "Test", Type: "telegram", ChatID: "123", ParseMode: "HTML", TimeoutSeconds: 2, PerMinute: 20}
			token := "123:" + newID("local-")
			_, e := ch.Send(context.Background(), c, token, RenderedMessage{Telegram: "<b>Test</b>", Links: []ActionLink{{"Portal", "https://portal.example.test"}}}, "id")
			if status == 200 {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				de, ok := e.(*DeliveryError)
				if !ok || de.Temporary != (status == 429 || status == 500) || strings.Contains(e.Error(), token) || strings.Contains(e.Error(), "secret") {
					t.Fatal(e)
				}
				if status == 429 && de.RetryAfter != 17*time.Second {
					t.Fatal("retry-after ignored")
				}
			}
		})
	}
}

func TestSimulationUsesLifecycleAndDoesNotDeliver(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	calls := 0
	p, e := OpenPlatform(t.TempDir(), func(_ context.Context, r RuleDefinition, timestamp time.Time) ([]Observation, error) {
		calls++
		v := 90.0
		if timestamp.Sub(at) > 5*time.Minute {
			v = 20
		}
		return []Observation{{Entity: "router", Value: v}}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	p.state = testState()
	r := testRule()
	out, e := p.Simulate(context.Background(), r, at, at.Add(10*time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	if out.Counts.AfterDedup != 1 || out.Counts.Recoveries != 1 || out.Notifications["email"] != 2 || out.Notifications["telegram"] != 2 || out.Latest == nil || calls != 10 {
		t.Fatalf("%+v calls=%d", out, calls)
	}
	if len(p.state.Alerts) != 0 || len(p.state.Deliveries) != 0 {
		t.Fatal("simulation modified live state")
	}
}
func TestHighCardinalityRejectsPartialEvaluation(t *testing.T) {
	s := testState()
	r := testRule()
	obs := make([]Observation, MaxGroups+1)
	if _, e := applyEvaluation(&s, r, obs, time.Now()); e == nil {
		t.Fatal("group limit missing")
	}
	if len(s.Deliveries) != 0 {
		t.Fatal("partial alerts produced")
	}
}

func TestEmailGolden(t *testing.T) {
	m, e := RenderMessage(MessageContext{NotificationID: "CFC-NOT-golden", AlertID: "alert", RuleID: "rule", RuleName: "Exporter Telemetry Missing", Summary: "No flow received for 600 seconds", Entity: "router.example.test", State: "FIRING", Priority: "high", Metric: "flows", WindowSeconds: 600, At: time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC), From: time.Date(2026, 9, 16, 11, 50, 0, 0, time.UTC)}, "https://collector.example.test")
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join("testdata", "email.golden.html")
	if os.Getenv("CFC_UPDATE_GOLDEN") == "1" {
		if e = os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, []byte(m.HTML), 0644); e != nil {
			t.Fatal(e)
		}
	}
	gold, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if string(gold) != m.HTML {
		t.Fatal("email renderer changed; inspect and update golden intentionally")
	}
}

func BenchmarkRuleSchedule(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			p := &Platform{state: emptyState()}
			for i := 0; i < n; i++ {
				r := testRule()
				r.ID = strconv.Itoa(i)
				r.Enabled = true
				p.state.Rules[r.ID] = r
			}
			p.rebuildScheduleLocked()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				x := heap.Pop(&p.schedule).(dueRule)
				x.At = x.At.Add(time.Minute)
				heap.Push(&p.schedule, x)
			}
		})
	}
}
func BenchmarkConditionMatch(b *testing.B) {
	c := Condition{Op: "and", Children: []Condition{{Op: "eq", Field: "protocol", Values: []string{"6"}}, {Op: "in", Field: "dst_port", Values: []string{"443", "8443"}}}}
	f := model.Flow{IPProtocol: 6, DstPort: 443}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Match(f)
	}
}
