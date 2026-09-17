package notification

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPlatformSendReportEmailUsesEnabledEmailChannelAndAttachment(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type captured struct {
		rcpts []string
		data  string
	}
	got := make(chan captured, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		send := func(v string) { fmt.Fprint(rw, v+"\r\n"); _ = rw.Flush() }
		send("220 localhost SMTP")
		var c captured
		for {
			line, e := rw.ReadString('\n')
			if e != nil {
				return
			}
			trim := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(trim, "EHLO"), strings.HasPrefix(trim, "HELO"):
				send("250 localhost")
			case strings.HasPrefix(trim, "MAIL FROM:"):
				send("250 OK")
			case strings.HasPrefix(trim, "RCPT TO:"):
				c.rcpts = append(c.rcpts, trim)
				send("250 OK")
			case trim == "DATA":
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
				c.data = b.String()
				send("250 accepted")
			case trim == "QUIT":
				send("221 bye")
				got <- c
				return
			default:
				send("250 OK")
			}
		}
	}()

	p, err := OpenPlatform(t.TempDir(), func(context.Context, RuleDefinition, time.Time) ([]Observation, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	host, portText, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscanf(portText, "%d", &port)
	_, err = p.SaveChannel(ChannelInput{ChannelConfig: ChannelConfig{
		ID: "reports-email", Name: "Reports SMTP", Type: "email", Enabled: true,
		Host: host, Port: port, Security: "relay", From: "collector@example.test",
		Recipients: []string{"default@example.test"}, TimeoutSeconds: 3, PerMinute: 30,
	}})
	if err != nil {
		t.Fatal(err)
	}
	handled, err := p.SendReportEmail(context.Background(), "Network Usage", "/tmp/network.pdf", []byte("PDF-DATA"), []string{"soc@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !handled {
		t.Fatal("enabled platform email channel was not used")
	}
	select {
	case c := <-got:
		joined := strings.Join(c.rcpts, " ")
		if !strings.Contains(joined, "soc@example.test") || strings.Contains(joined, "default@example.test") {
			t.Fatalf("recipients=%v", c.rcpts)
		}
		if !strings.Contains(c.data, "network.pdf") || !strings.Contains(c.data, "Content-Transfer-Encoding: base64") {
			t.Fatalf("missing attachment MIME: %s", c.data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP message not received")
	}
}
