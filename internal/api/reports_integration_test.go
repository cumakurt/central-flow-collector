package api

import (
	"central-flow-collector/internal/reporting"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestScheduledReportsCRUDRunAndPermissions(t *testing.T) {
	f := newV17Fixture(t)
	rm, err := reporting.New(f.dir, f.st)
	if err != nil {
		t.Fatal(err)
	}
	deliveries := 0
	rm.SetDelivery(func(_ context.Context, _ reporting.Job, _ string, _ []byte) error { deliveries++; return nil })
	f.srv.SetReports(rm)
	h := f.srv.Handler()

	create := `{"name":"Daily Network","format":"csv","cadence":"daily","hour":3,"enabled":true,"email_enabled":true,"email_recipients":["soc@example.com","noc@example.com"]}`
	w := doBearer(h, http.MethodPost, "/api/v1/reports", f.aliceToken, create)
	if w.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	var job reporting.Job
	if err := json.Unmarshal(w.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	if job.ID == "" || job.Name != "Daily Network" || job.EmailEnabled == nil || !*job.EmailEnabled || len(job.EmailRecipients) != 2 {
		t.Fatalf("job=%#v", job)
	}

	w = doBearer(h, http.MethodGet, "/api/v1/reports", f.aliceToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
	}
	var jobs []reporting.Job
	if err := json.Unmarshal(w.Body.Bytes(), &jobs); err != nil || len(jobs) != 1 {
		t.Fatalf("jobs=%#v err=%v", jobs, err)
	}

	job.Enabled = false
	job.Format = "json"
	body, _ := json.Marshal(job)
	w = doBearer(h, http.MethodPost, "/api/v1/reports", f.aliceToken, string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", w.Code, w.Body.String())
	}

	w = doBearer(h, http.MethodPost, "/api/v1/reports/"+job.ID+"/run", f.aliceToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("run status=%d body=%s", w.Code, w.Body.String())
	}
	if deliveries != 1 {
		t.Fatalf("deliveries=%d", deliveries)
	}
	jobs = rm.Jobs()
	if len(jobs) != 1 || jobs[0].LastRun.IsZero() || jobs[0].LastError != "" {
		t.Fatalf("run state=%#v", jobs)
	}

	w = doBearer(h, http.MethodDelete, "/api/v1/reports/"+job.ID, f.aliceToken, "")
	if w.Code != http.StatusOK || len(rm.Jobs()) != 0 {
		t.Fatalf("delete status=%d body=%s jobs=%#v", w.Code, w.Body.String(), rm.Jobs())
	}

	// Read-only users may list reports but must not create, run, or delete them.
	if err := f.am.AddUser("reader", "GoodPassw0rd!", "read_only"); err != nil {
		t.Fatal(err)
	}
	_, readerToken, err := f.am.CreateAPIToken("reader", "reader-test", 1)
	if err != nil {
		t.Fatal(err)
	}
	w = doBearer(h, http.MethodPost, "/api/v1/reports", readerToken, create)
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only create status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestScheduledReportRunReturnsDeliveryErrorDetail(t *testing.T) {
	f := newV17Fixture(t)
	rm, err := reporting.New(f.dir, f.st)
	if err != nil {
		t.Fatal(err)
	}
	rm.SetDelivery(func(_ context.Context, _ reporting.Job, _ string, _ []byte) error {
		return errors.New("report delivery failed: smtp: Authentication failed")
	})
	f.srv.SetReports(rm)
	h := f.srv.Handler()
	yes := true
	job, err := rm.Upsert(reporting.Job{Name: "Mail Failure", Format: "pdf", Cadence: "daily", Hour: 3, Enabled: true, EmailEnabled: &yes, EmailRecipients: []string{"soc@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	w := doBearer(h, http.MethodPost, "/api/v1/reports/"+job.ID+"/run", f.aliceToken, "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "smtp: Authentication failed") {
		t.Fatalf("delivery detail masked: %s", w.Body.String())
	}
}
