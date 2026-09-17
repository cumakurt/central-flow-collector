package reporting

import (
	"archive/zip"
	"bytes"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/storage"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGenerateAllSupportedFormats(t *testing.T) {
	d := t.TempDir()
	st, e := storage.NewLocal(d+"/store", 7, 16)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	now := time.Now().UTC()
	_ = st.Write(model.Flow{ReceiveTime: now, StartTime: now, EndTime: now, SrcIP: "10.0.0.1", DstIP: "8.8.8.8", Bytes: 100, Packets: 2})
	m, _ := New(d, st)
	for _, f := range []string{"pdf", "csv", "json", "xlsx"} {
		j := Job{Name: "Daily", Format: f, Cadence: "daily", Hour: now.Hour()}
		p, b, e := m.Generate(context.Background(), j, now.Add(time.Second))
		if e != nil {
			t.Fatal(e)
		}
		if len(b) < 20 || p == "" {
			t.Fatalf("bad %s", f)
		}
		switch f {
		case "pdf":
			if string(b[:4]) != "%PDF" {
				t.Fatal("not pdf")
			}
		case "json":
			var summary Summary
			if err := json.Unmarshal(b, &summary); err != nil || summary.Analysis.Totals.Flows == 0 {
				t.Fatalf("invalid json report: err=%v summary=%#v", err, summary)
			}
		case "xlsx":
			zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
			if err != nil {
				t.Fatalf("invalid xlsx zip: %v", err)
			}
			want := map[string]bool{"[Content_Types].xml": false, "xl/workbook.xml": false, "xl/worksheets/sheet1.xml": false}
			for _, zf := range zr.File {
				if _, ok := want[zf.Name]; ok {
					want[zf.Name] = true
				}
			}
			for name, ok := range want {
				if !ok {
					t.Fatalf("xlsx missing %s", name)
				}
			}
		}
	}
}

func TestRunDueDeliveryAndPersistence(t *testing.T) {
	d := t.TempDir()
	st, e := storage.NewLocal(d+"/store", 7, 16)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	now := time.Now().UTC().Truncate(time.Hour)
	m, e := New(d, st)
	if e != nil {
		t.Fatal(e)
	}
	j, e := m.Upsert(Job{Name: "Scheduled", Format: "csv", Cadence: "daily", Hour: now.Hour(), Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	called := 0
	m.SetDelivery(func(ctx context.Context, got Job, path string, data []byte) error {
		called++
		if got.ID != j.ID || len(data) == 0 || path == "" {
			t.Fatalf("bad delivery %#v %q", got, path)
		}
		return nil
	})
	m.RunDue(context.Background(), now)
	if called != 1 {
		t.Fatalf("deliveries=%d", called)
	}
	m2, e := New(d, st)
	if e != nil {
		t.Fatal(e)
	}
	jobs := m2.Jobs()
	if len(jobs) != 1 || jobs[0].LastRun.IsZero() || jobs[0].LastPath == "" || jobs[0].LastError != "" {
		t.Fatalf("jobs=%#v", jobs)
	}
}

func TestScheduledReportCRUDAndRunNowPersistence(t *testing.T) {
	d := t.TempDir()
	st, err := storage.NewLocal(d+"/store", 7, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC().Truncate(time.Second)
	if err := st.Write(model.Flow{ReceiveTime: now.Add(-time.Minute), StartTime: now.Add(-time.Minute), EndTime: now.Add(-time.Minute), SrcIP: "10.0.0.10", DstIP: "203.0.113.10", Bytes: 4096, Packets: 8}); err != nil {
		t.Fatal(err)
	}
	m, err := New(d, st)
	if err != nil {
		t.Fatal(err)
	}
	created, err := m.Upsert(Job{Name: "Ops Daily", Format: "csv", Cadence: "daily", Hour: now.Hour(), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || len(m.Jobs()) != 1 {
		t.Fatalf("created=%#v jobs=%#v", created, m.Jobs())
	}
	created.Format = "json"
	created.Cadence = "weekly"
	created.Enabled = false
	updated, err := m.Upsert(created)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != created.ID || updated.Format != "json" || updated.Cadence != "weekly" || updated.Enabled {
		t.Fatalf("updated=%#v", updated)
	}

	updated.Enabled = true
	updated.Cadence = "daily"
	updated, err = m.Upsert(updated)
	if err != nil {
		t.Fatal(err)
	}
	deliveries := 0
	m.SetDelivery(func(ctx context.Context, got Job, path string, data []byte) error {
		deliveries++
		if got.ID != updated.ID || path == "" || len(data) == 0 {
			t.Fatalf("delivery job=%#v path=%q bytes=%d", got, path, len(data))
		}
		return nil
	})
	path, data, err := m.RunNow(context.Background(), updated.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 || path == "" || len(data) == 0 {
		t.Fatalf("deliveries=%d path=%q bytes=%d", deliveries, path, len(data))
	}
	jobs := m.Jobs()
	if len(jobs) != 1 || jobs[0].LastRun.IsZero() || jobs[0].LastPath == "" || jobs[0].LastError != "" {
		t.Fatalf("run state=%#v", jobs)
	}
	m2, err := New(d, st)
	if err != nil {
		t.Fatal(err)
	}
	persisted := m2.Jobs()
	if len(persisted) != 1 || persisted[0].ID != updated.ID || persisted[0].LastRun.IsZero() {
		t.Fatalf("persisted=%#v", persisted)
	}
	if err := m2.Delete(updated.ID); err != nil {
		t.Fatal(err)
	}
	if got := m2.Jobs(); len(got) != 0 {
		t.Fatalf("jobs after delete=%#v", got)
	}
	m3, err := New(d, st)
	if err != nil {
		t.Fatal(err)
	}
	if got := m3.Jobs(); len(got) != 0 {
		t.Fatalf("deleted job persisted=%#v", got)
	}
}

func TestScheduledReportValidation(t *testing.T) {
	d := t.TempDir()
	st, err := storage.NewLocal(d+"/store", 7, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m, err := New(d, st)
	if err != nil {
		t.Fatal(err)
	}
	cases := []Job{
		{Name: "", Format: "pdf", Cadence: "daily", Hour: 1},
		{Name: "x", Format: "exe", Cadence: "daily", Hour: 1},
		{Name: "x", Format: "pdf", Cadence: "hourly", Hour: 1},
		{Name: "x", Format: "pdf", Cadence: "daily", Hour: 24},
	}
	for _, j := range cases {
		if _, err := m.Upsert(j); err == nil {
			t.Fatalf("expected validation error for %#v", j)
		}
	}
}

func TestScheduledReportEmailRecipientsValidation(t *testing.T) {
	d := t.TempDir()
	st, err := storage.NewLocal(d+"/store", 7, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m, err := New(d, st)
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	j, err := m.Upsert(Job{Name: "Mail Daily", Format: "pdf", Cadence: "daily", Hour: 7, Enabled: true, EmailEnabled: &yes, EmailRecipients: []string{" SOC@example.com ", "soc@example.com", "noc@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(j.EmailRecipients) != 2 || j.EmailRecipients[0] != "SOC@example.com" || j.EmailRecipients[1] != "noc@example.com" {
		t.Fatalf("recipients=%#v", j.EmailRecipients)
	}
	if _, err := m.Upsert(Job{Name: "Bad Mail", Format: "pdf", Cadence: "daily", Hour: 7, EmailEnabled: &yes, EmailRecipients: []string{"bad\nheader@example.com"}}); err == nil {
		t.Fatal("expected invalid recipient error")
	}
}

func TestDueRules(t *testing.T) {
	monday := time.Date(2026, 9, 21, 7, 0, 0, 0, time.Local)
	if !due(Job{Enabled: true, Cadence: "weekly", Hour: 7}, monday) {
		t.Fatal("weekly report should be due Monday at configured hour")
	}
	if due(Job{Enabled: true, Cadence: "weekly", Hour: 7}, monday.Add(24*time.Hour)) {
		t.Fatal("weekly report must not run Tuesday")
	}
	first := time.Date(2026, 10, 1, 5, 0, 0, 0, time.Local)
	if !due(Job{Enabled: true, Cadence: "monthly", Hour: 5}, first) {
		t.Fatal("monthly report should be due on first day at configured hour")
	}
	if due(Job{Enabled: false, Cadence: "daily", Hour: 5}, first) {
		t.Fatal("disabled report must not run")
	}
	if due(Job{Enabled: true, Cadence: "daily", Hour: 6}, first) {
		t.Fatal("report must not run outside configured hour")
	}
	j := Job{Enabled: true, Cadence: "daily", Hour: 5, LastRun: first.Add(-30 * time.Minute)}
	if due(j, first) {
		t.Fatal("report must not run twice within one hour")
	}
}

func TestPDFReportUsesApplicationTheme(t *testing.T) {
	s := Summary{
		Product:     "Central Flow Collector",
		ReportName:  "Network Usage Report",
		GeneratedAt: time.Date(2026, 9, 17, 15, 0, 0, 0, time.UTC),
		From:        time.Date(2026, 9, 16, 15, 0, 0, 0, time.UTC),
		To:          time.Date(2026, 9, 17, 15, 0, 0, 0, time.UTC),
		Analysis:    storage.AnalysisResult{Dimensions: map[string][]storage.DimensionMetric{}},
	}
	b := pdfBytes(s)
	text := string(b)
	for _, want := range []string{
		"CENTRAL FLOW COLLECTOR",
		"NETWORK TELEMETRY / REPORTING",
		"TRAFFIC SUMMARY",
		"/BaseFont /Helvetica-Bold",
		"0.0902 0.4314 0.3647 rg", // UI light-theme accent #176e5d.
		"0.9294 0.9451 0.9490 rg", // UI light-theme background #edf1f2.
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("themed PDF missing %q", want)
		}
	}
}

func TestScheduledPDFDeliveryUsesExactGeneratedDocument(t *testing.T) {
	d := t.TempDir()
	st, err := storage.NewLocal(d+"/store", 7, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC().Truncate(time.Second)
	if err := st.Write(model.Flow{ReceiveTime: now.Add(-time.Minute), StartTime: now.Add(-time.Minute), EndTime: now.Add(-time.Minute), SrcIP: "10.0.0.1", DstIP: "203.0.113.10", Bytes: 2048, Packets: 4}); err != nil {
		t.Fatal(err)
	}
	m, err := New(d, st)
	if err != nil {
		t.Fatal(err)
	}
	job, err := m.Upsert(Job{Name: "Styled PDF", Format: "pdf", Cadence: "daily", Hour: now.Hour(), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	var delivered []byte
	m.SetDelivery(func(ctx context.Context, got Job, path string, data []byte) error {
		delivered = append([]byte(nil), data...)
		return nil
	})
	path, generated, err := m.RunNow(context.Background(), job.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated, delivered) {
		t.Fatal("email delivery did not receive the exact generated PDF")
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated, onDisk) {
		t.Fatal("downloaded/stored PDF differs from scheduled email attachment")
	}
}
