package reporting

import (
	"archive/zip"
	"bytes"
	"central-flow-collector/internal/storage"
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Job struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Format          string    `json:"format"`
	Cadence         string    `json:"cadence"`
	Hour            int       `json:"hour"`
	Enabled         bool      `json:"enabled"`
	EmailEnabled    *bool     `json:"email_enabled,omitempty"`
	EmailRecipients []string  `json:"email_recipients,omitempty"`
	LastRun         time.Time `json:"last_run,omitempty"`
	LastPath        string    `json:"last_path,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
}
type state struct {
	Version int   `json:"version"`
	Jobs    []Job `json:"jobs"`
}

type Summary struct {
	Product     string                 `json:"product"`
	ReportName  string                 `json:"report_name"`
	GeneratedAt time.Time              `json:"generated_at"`
	From        time.Time              `json:"from"`
	To          time.Time              `json:"to"`
	Filters     map[string]string      `json:"filters,omitempty"`
	Analysis    storage.AnalysisResult `json:"analysis"`
	Capacity    storage.CapacityInfo   `json:"storage_capacity"`
}

type DeliveryFunc func(context.Context, Job, string, []byte) error
type Manager struct {
	mu         sync.Mutex
	path, dir  string
	store      storage.Backend
	s          state
	deliver    DeliveryFunc
	stop, done chan struct{}
}

func New(dataDir string, st storage.Backend) (*Manager, error) {
	m := &Manager{path: filepath.Join(dataDir, "report-jobs.json"), dir: filepath.Join(dataDir, "reports"), store: st, s: state{Version: 2}, stop: make(chan struct{}), done: make(chan struct{})}
	if b, e := os.ReadFile(m.path); e == nil {
		var raw struct {
			Version int   `json:"version"`
			Jobs    []Job `json:"jobs"`
		}
		if e = json.Unmarshal(b, &raw); e != nil {
			return nil, e
		}
		m.s.Version = 2
		m.s.Jobs = raw.Jobs
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	return m, nil
}
func id() string                               { b := make([]byte, 8); _, _ = rand.Read(b); return "report-" + hex.EncodeToString(b) }
func (m *Manager) SetDelivery(fn DeliveryFunc) { m.mu.Lock(); m.deliver = fn; m.mu.Unlock() }
func (m *Manager) saveLocked() error {
	if e := os.MkdirAll(filepath.Dir(m.path), 0750); e != nil {
		return e
	}
	b, _ := json.MarshalIndent(m.s, "", "  ")
	tmp := m.path + ".tmp"
	if e := os.WriteFile(tmp, append(b, '\n'), 0640); e != nil {
		return e
	}
	return os.Rename(tmp, m.path)
}
func (m *Manager) Jobs() []Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]Job(nil), m.s.Jobs...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func validFormat(v string) bool {
	switch strings.ToLower(v) {
	case "pdf", "csv", "json", "xlsx":
		return true
	}
	return false
}
func (m *Manager) Upsert(j Job) (Job, error) {
	j.Name = strings.TrimSpace(j.Name)
	j.Format = strings.ToLower(strings.TrimSpace(j.Format))
	if j.Name == "" {
		return j, errors.New("report name required")
	}
	if !validFormat(j.Format) {
		return j, errors.New("format must be pdf, xlsx, csv or json")
	}
	if j.Cadence != "daily" && j.Cadence != "weekly" && j.Cadence != "monthly" {
		return j, errors.New("cadence must be daily/weekly/monthly")
	}
	if j.Hour < 0 || j.Hour > 23 {
		return j, errors.New("hour must be 0..23")
	}
	if len(j.EmailRecipients) > 20 {
		return j, errors.New("email recipients must contain at most 20 addresses")
	}
	cleanRecipients := make([]string, 0, len(j.EmailRecipients))
	seenRecipients := make(map[string]struct{}, len(j.EmailRecipients))
	for _, raw := range j.EmailRecipients {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		a, err := mail.ParseAddress(raw)
		if err != nil || a.Address == "" || strings.ContainsAny(a.Address, "\r\n") {
			return j, fmt.Errorf("invalid email recipient %q", raw)
		}
		addr := strings.ToLower(a.Address)
		if _, ok := seenRecipients[addr]; ok {
			continue
		}
		seenRecipients[addr] = struct{}{}
		cleanRecipients = append(cleanRecipients, a.Address)
	}
	j.EmailRecipients = cleanRecipients
	m.mu.Lock()
	defer m.mu.Unlock()
	if j.ID != "" {
		for i := range m.s.Jobs {
			if m.s.Jobs[i].ID == j.ID {
				old := m.s.Jobs[i]
				j.LastRun = old.LastRun
				j.LastPath = old.LastPath
				j.LastError = old.LastError
				m.s.Jobs[i] = j
				return j, m.saveLocked()
			}
		}
	}
	j.ID = id()
	m.s.Jobs = append(m.s.Jobs, j)
	return j, m.saveLocked()
}
func (m *Manager) Delete(idv string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, j := range m.s.Jobs {
		if j.ID == idv {
			m.s.Jobs = append(m.s.Jobs[:i], m.s.Jobs[i+1:]...)
			return m.saveLocked()
		}
	}
	return errors.New("report not found")
}
func window(j Job, now time.Time) (time.Time, time.Time) {
	to := now.UTC()
	switch j.Cadence {
	case "weekly":
		return to.Add(-7 * 24 * time.Hour), to
	case "monthly":
		return to.AddDate(0, -1, 0), to
	default:
		return to.Add(-24 * time.Hour), to
	}
}
func safe(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else if r == ' ' {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "report"
	}
	return b.String()
}

func (m *Manager) Build(ctx context.Context, name, format string, q storage.Query, filters map[string]string) (Summary, []byte, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if !validFormat(format) {
		return Summary{}, nil, errors.New("format must be pdf, xlsx, csv or json")
	}
	if strings.TrimSpace(name) == "" {
		name = "Network Flow Analysis"
	}
	a, e := m.store.Analyze(ctx, q, 20)
	if e != nil {
		return Summary{}, nil, e
	}
	capInfo, _ := m.store.Capacity(ctx)
	s := Summary{Product: "Central Flow Collector", ReportName: name, GeneratedAt: time.Now().UTC(), From: a.From, To: a.To, Filters: filters, Analysis: a, Capacity: capInfo}
	var data []byte
	switch format {
	case "csv":
		data = csvBytes(s)
	case "json":
		data, _ = json.MarshalIndent(s, "", "  ")
		data = append(data, '\n')
	case "xlsx":
		data = xlsxBytes(s)
	default:
		data = pdfBytes(s)
	}
	return s, data, nil
}

func (m *Manager) GenerateRange(ctx context.Context, name, format string, q storage.Query, filters map[string]string) (string, []byte, error) {
	s, data, e := m.Build(ctx, name, format, q, filters)
	if e != nil {
		return "", nil, e
	}
	if e = os.MkdirAll(m.dir, 0750); e != nil {
		return "", nil, e
	}
	ext := strings.ToLower(format)
	p := filepath.Join(m.dir, fmt.Sprintf("%s-%s.%s", safe(name), s.GeneratedAt.Format("20060102T150405Z"), ext))
	if e = os.WriteFile(p, data, 0640); e != nil {
		return "", nil, e
	}
	return p, data, nil
}
func (m *Manager) Generate(ctx context.Context, j Job, now time.Time) (string, []byte, error) {
	from, to := window(j, now)
	q := storage.Query{From: from, To: to}
	return m.GenerateRange(ctx, j.Name, j.Format, q, map[string]string{"schedule": j.Cadence})
}

func dim(s Summary, k string) []storage.DimensionMetric { return s.Analysis.Dimensions[k] }
func csvBytes(s Summary) []byte {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"Central Flow Collector", s.ReportName})
	_ = w.Write([]string{"from", s.From.Format(time.RFC3339)})
	_ = w.Write([]string{"to", s.To.Format(time.RFC3339)})
	_ = w.Write([]string{"generated_at", s.GeneratedAt.Format(time.RFC3339)})
	_ = w.Write([]string{})
	_ = w.Write([]string{"section", "key", "bytes", "packets", "flows"})
	t := s.Analysis.Totals
	_ = w.Write([]string{"overview", "total", strconv.FormatUint(t.Bytes, 10), strconv.FormatUint(t.Packets, 10), strconv.FormatUint(t.Flows, 10)})
	for _, d := range analysisSheetOrder() {
		for _, x := range dim(s, d.key) {
			_ = w.Write([]string{d.title, x.Key, strconv.FormatUint(x.Bytes, 10), strconv.FormatUint(x.Packets, 10), strconv.FormatUint(x.Flows, 10)})
		}
	}
	for _, x := range s.Analysis.Timeline {
		_ = w.Write([]string{"timeline", x.Timestamp.Format(time.RFC3339), strconv.FormatUint(x.Bytes, 10), strconv.FormatUint(x.Packets, 10), strconv.FormatUint(x.Flows, 10)})
	}
	w.Flush()
	return b.Bytes()
}

type sheetDef struct{ title, key string }

func analysisSheetOrder() []sheetDef {
	return []sheetDef{{"Top Sources", "src_ip"}, {"Top Destinations", "dst_ip"}, {"Applications", "application"}, {"Protocols", "protocol"}, {"Source Ports", "src_port"}, {"Destination Ports", "dst_port"}, {"ASNs", "asn"}, {"Countries", "country"}, {"Exporters", "exporter"}, {"Interfaces", "interface"}, {"Directions", "direction"}}
}

func colName(n int) string {
	var b []byte
	for n > 0 {
		n--
		b = append([]byte{byte('A' + n%26)}, b...)
		n /= 26
	}
	return string(b)
}
func xcell(ref, v string, num bool) string {
	if num {
		return `<c r="` + ref + `"><v>` + html.EscapeString(v) + `</v></c>`
	}
	return `<c r="` + ref + `" t="inlineStr"><is><t>` + html.EscapeString(v) + `</t></is></c>`
}
func sheetXML(rows [][]string, numeric map[int]bool) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetData>`)
	for r, row := range rows {
		fmt.Fprintf(&b, `<row r="%d">`, r+1)
		for c, v := range row {
			b.WriteString(xcell(fmt.Sprintf("%s%d", colName(c+1), r+1), v, numeric[c]))
		}
		b.WriteString(`</row>`)
	}
	b.WriteString(`</sheetData></worksheet>`)
	return b.String()
}
func xlsxBytes(s Summary) []byte {
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	sheets := []struct {
		name string
		rows [][]string
		num  map[int]bool
	}{}
	t := s.Analysis.Totals
	overview := [][]string{{"Metric", "Value"}, {"Report", s.ReportName}, {"From", s.From.Format(time.RFC3339)}, {"To", s.To.Format(time.RFC3339)}, {"Generated", s.GeneratedAt.Format(time.RFC3339)}, {"Total Flows", strconv.FormatUint(t.Flows, 10)}, {"Total Packets", strconv.FormatUint(t.Packets, 10)}, {"Total Bytes", strconv.FormatUint(t.Bytes, 10)}, {"Unique Sources", strconv.FormatUint(t.UniqueSources, 10)}, {"Unique Destinations", strconv.FormatUint(t.UniqueDestinations, 10)}, {"Unique Conversations", strconv.FormatUint(t.UniqueConversations, 10)}, {"Unique ASNs", strconv.FormatUint(t.UniqueASNs, 10)}, {"Unique Countries", strconv.FormatUint(t.UniqueCountries, 10)}, {"Active Exporters", strconv.FormatUint(t.UniqueExporters, 10)}, {"Active Interfaces", strconv.FormatUint(t.UniqueInterfaces, 10)}}
	sheets = append(sheets, struct {
		name string
		rows [][]string
		num  map[int]bool
	}{"Overview", overview, map[int]bool{1: true}})
	for _, d := range analysisSheetOrder() {
		rows := [][]string{{"Key", "Bytes", "Packets", "Flows"}}
		for _, x := range dim(s, d.key) {
			rows = append(rows, []string{x.Key, strconv.FormatUint(x.Bytes, 10), strconv.FormatUint(x.Packets, 10), strconv.FormatUint(x.Flows, 10)})
		}
		sheets = append(sheets, struct {
			name string
			rows [][]string
			num  map[int]bool
		}{d.title, rows, map[int]bool{1: true, 2: true, 3: true}})
	}
	tr := [][]string{{"Timestamp", "Bytes", "Packets", "Flows"}}
	for _, x := range s.Analysis.Timeline {
		tr = append(tr, []string{x.Timestamp.Format(time.RFC3339), strconv.FormatUint(x.Bytes, 10), strconv.FormatUint(x.Packets, 10), strconv.FormatUint(x.Flows, 10)})
	}
	sheets = append(sheets, struct {
		name string
		rows [][]string
		num  map[int]bool
	}{"Timeline", tr, map[int]bool{1: true, 2: true, 3: true}})
	files := map[string]string{"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>`}
	var ct, wb, rels strings.Builder
	wb.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>`)
	rels.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`)
	for i, sh := range sheets {
		n := i + 1
		fmt.Fprintf(&wb, `<sheet name="%s" sheetId="%d" r:id="rId%d"/>`, html.EscapeString(sh.name), n, n)
		fmt.Fprintf(&rels, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>`, n, n)
		fmt.Fprintf(&ct, `<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`, n)
		files[fmt.Sprintf("xl/worksheets/sheet%d.xml", n)] = sheetXML(sh.rows, sh.num)
	}
	wb.WriteString(`</sheets></workbook>`)
	rels.WriteString(`</Relationships>`)
	files["xl/workbook.xml"] = wb.String()
	files["xl/_rels/workbook.xml.rels"] = rels.String()
	files["_rels/.rels"] = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`
	files["[Content_Types].xml"] += ct.String() + `</Types>`
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		w, _ := zw.Create(k)
		_, _ = w.Write([]byte(files[k]))
	}
	_ = zw.Close()
	return out.Bytes()
}

// PDF report theme mirrors the light application surface in static/style.css.
// Keep these values synchronized with the UI design tokens when the product theme changes.
type pdfColor struct{ r, g, b float64 }

var pdfTheme = struct {
	bg, nav, panel, panel2, text, muted, line, accent, accent2, good pdfColor
}{
	bg:      pdfRGB(0xed, 0xf1, 0xf2),
	nav:     pdfRGB(0xe4, 0xea, 0xec),
	panel:   pdfRGB(0xfb, 0xfc, 0xfc),
	panel2:  pdfRGB(0xf0, 0xf4, 0xf5),
	text:    pdfRGB(0x1c, 0x30, 0x3b),
	muted:   pdfRGB(0x52, 0x68, 0x73),
	line:    pdfRGB(0xc5, 0xd2, 0xd7),
	accent:  pdfRGB(0x17, 0x6e, 0x5d),
	accent2: pdfRGB(0x32, 0x6a, 0x9e),
	good:    pdfRGB(0x24, 0x6b, 0x50),
}

func pdfRGB(r, g, b int) pdfColor {
	return pdfColor{float64(r) / 255, float64(g) / 255, float64(b) / 255}
}
func pdfFill(c pdfColor) string   { return fmt.Sprintf("%.4f %.4f %.4f rg\n", c.r, c.g, c.b) }
func pdfStroke(c pdfColor) string { return fmt.Sprintf("%.4f %.4f %.4f RG\n", c.r, c.g, c.b) }
func pdfRect(x, y, w, h float64, fill, stroke pdfColor) string {
	return pdfFill(fill) + pdfStroke(stroke) + fmt.Sprintf("%.1f %.1f %.1f %.1f re B\n", x, y, w, h)
}
func pdfRule(x1, y1, x2, y2 float64, c pdfColor) string {
	return pdfStroke(c) + fmt.Sprintf("0.7 w %.1f %.1f m %.1f %.1f l S\n", x1, y1, x2, y2)
}
func escPDF(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	return s
}
func pdfTextStyled(x, y, size float64, text, font string, color pdfColor) string {
	return pdfFill(color) + fmt.Sprintf("BT /%s %.1f Tf %.1f %.1f Td (%s) Tj ET\n", font, size, x, y, escPDF(text))
}
func pdfText(x, y, size float64, text string) string {
	return pdfTextStyled(x, y, size, text, "F1", pdfTheme.text)
}
func pdfBold(x, y, size float64, text string) string {
	return pdfTextStyled(x, y, size, text, "F2", pdfTheme.text)
}
func pdfMuted(x, y, size float64, text string) string {
	return pdfTextStyled(x, y, size, text, "F1", pdfTheme.muted)
}
func pdfBar(x, y, w, h float64) string {
	return pdfFill(pdfTheme.accent2) + fmt.Sprintf("%.1f %.1f %.1f %.1f re f\n", x, y, w, h)
}
func pdfPageChrome(b *strings.Builder, s Summary, page, total int, section string) {
	// Application background and top navigation band.
	b.WriteString(pdfFill(pdfTheme.bg))
	b.WriteString("0 0 612 842 re f\n")
	b.WriteString(pdfFill(pdfTheme.nav))
	b.WriteString("0 782 612 60 re f\n")
	b.WriteString(pdfRule(0, 782, 612, 782, pdfTheme.line))
	// Brand mark mirrors the square accent mark in the web sidebar.
	b.WriteString(pdfFill(pdfTheme.accent))
	b.WriteString("32 797 31 31 re f\n")
	b.WriteString(pdfTextStyled(43, 804, 17, "+", "F2", pdfRGB(255, 255, 255)))
	b.WriteString(pdfBold(76, 815, 11, "CENTRAL FLOW COLLECTOR"))
	b.WriteString(pdfMuted(76, 800, 7.5, "NETWORK TELEMETRY / REPORTING"))
	b.WriteString(pdfTextStyled(532, 809, 8, section, "F2", pdfTheme.accent))
	// Footer uses the same restrained divider/muted treatment as the application.
	b.WriteString(pdfRule(32, 37, 580, 37, pdfTheme.line))
	b.WriteString(pdfMuted(32, 22, 7, "Generated "+s.GeneratedAt.Format("02 Jan 2006 15:04 UTC")))
	b.WriteString(pdfMuted(516, 22, 7, fmt.Sprintf("Page %d / %d", page, total)))
}
func pdfMetricCard(b *strings.Builder, x, y, w, h float64, label, value string) {
	b.WriteString(pdfRect(x, y, w, h, pdfTheme.panel, pdfTheme.line))
	b.WriteString(pdfMuted(x+11, y+h-17, 7, strings.ToUpper(label)))
	b.WriteString(pdfBold(x+11, y+14, 13, value))
}
func pdfSectionHeader(b *strings.Builder, y float64, title, ordinal string) {
	b.WriteString(pdfTextStyled(32, y, 7.5, strings.ToUpper(title), "F2", pdfTheme.accent))
	b.WriteString(pdfMuted(540, y, 7, ordinal))
	b.WriteString(pdfRule(32, y-8, 580, y-8, pdfTheme.line))
}
func pdfPageSummary(s Summary) string {
	var b strings.Builder
	pdfPageChrome(&b, s, 1, 2, "SUMMARY")
	b.WriteString(pdfBold(32, 752, 20, s.ReportName))
	b.WriteString(pdfMuted(32, 733, 8, "Network usage report"))
	b.WriteString(pdfMuted(32, 715, 8, "Period: "+s.From.Format("02 Jan 2006 15:04 UTC")+" - "+s.To.Format("02 Jan 2006 15:04 UTC")))
	pdfSectionHeader(&b, 686, "Traffic summary", "01 / OVERVIEW")

	t := s.Analysis.Totals
	cards := []struct{ label, value string }{
		{"Total traffic", humanBytes(t.Bytes)}, {"Flows", humanInt(t.Flows)}, {"Packets", humanInt(t.Packets)},
		{"Unique sources", humanInt(t.UniqueSources)}, {"Unique destinations", humanInt(t.UniqueDestinations)}, {"Conversations", humanInt(t.UniqueConversations)},
	}
	for i, c := range cards {
		col, row := i%3, i/3
		x := 32.0 + float64(col)*184
		y := 600.0 - float64(row)*72
		pdfMetricCard(&b, x, y, 172, 58, c.label, c.value)
	}
	b.WriteString(pdfMuted(32, 508, 8, fmt.Sprintf("ASNs %s   /   Countries %s", humanInt(t.UniqueASNs), humanInt(t.UniqueCountries))))

	pdfSectionHeader(&b, 478, "Top sources by traffic", "02 / CONTRIBUTORS")
	xs := dim(s, "src_ip")
	max := uint64(1)
	if len(xs) > 0 && xs[0].Bytes > 0 {
		max = xs[0].Bytes
	}
	y := 446.0
	for i, x := range xs {
		if i >= 10 {
			break
		}
		if i%2 == 0 {
			b.WriteString(pdfFill(pdfTheme.panel2))
			b.WriteString(fmt.Sprintf("32 %.1f 548 20 re f\n", y-6))
		}
		b.WriteString(pdfText(42, y, 8, x.Key))
		bar := float64(x.Bytes) / float64(max) * 225
		b.WriteString(pdfBar(205, y-2, bar, 6))
		b.WriteString(pdfTextStyled(470, y, 8, humanBytes(x.Bytes), "F2", pdfTheme.text))
		y -= 24
	}
	return b.String()
}
func pdfPageDetails(s Summary) string {
	var b strings.Builder
	pdfPageChrome(&b, s, 2, 2, "DETAILS")
	b.WriteString(pdfBold(32, 752, 19, "Traffic distribution"))
	b.WriteString(pdfMuted(32, 733, 8, "Leading network contributors for the selected reporting window"))
	sections := []sheetDef{{"Top Destinations", "dst_ip"}, {"Applications", "application"}, {"Countries", "country"}, {"Autonomous Systems", "asn"}, {"Exporters", "exporter"}}
	y := 700.0
	for si, sec := range sections {
		if y < 115 {
			break
		}
		b.WriteString(pdfRect(32, y-96, 548, 102, pdfTheme.panel, pdfTheme.line))
		b.WriteString(pdfTextStyled(44, y-15, 8, strings.ToUpper(sec.title), "F2", pdfTheme.accent))
		b.WriteString(pdfRule(44, y-25, 568, y-25, pdfTheme.line))
		xs := dim(s, sec.key)
		rowY := y - 43
		if len(xs) == 0 {
			b.WriteString(pdfMuted(44, rowY, 8, "No data in the selected period"))
		} else {
			for i, x := range xs {
				if i >= 4 {
					break
				}
				b.WriteString(pdfText(44, rowY, 7.5, x.Key))
				b.WriteString(pdfTextStyled(410, rowY, 7.5, humanBytes(x.Bytes), "F2", pdfTheme.text))
				b.WriteString(pdfMuted(490, rowY, 7, "flows "+humanInt(x.Flows)))
				rowY -= 14
			}
		}
		_ = si
		y -= 116
	}
	return b.String()
}
func pdfBytes(s Summary) []byte {
	pages := []string{pdfPageSummary(s), pdfPageDetails(s)}
	var objs []string
	objs = append(objs, "<< /Type /Catalog /Pages 2 0 R >>")
	kids := []string{}
	for i := range pages {
		kids = append(kids, fmt.Sprintf("%d 0 R", 3+i*2))
	}
	objs = append(objs, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages)))
	regularFontObj := 3 + len(pages)*2
	boldFontObj := regularFontObj + 1
	for i, p := range pages {
		pageObj := 3 + i*2
		contentObj := pageObj + 1
		objs = append(objs, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> /Contents %d 0 R >>", regularFontObj, boldFontObj, contentObj))
		objs = append(objs, fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(p), p))
	}
	objs = append(objs, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	objs = append(objs, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offs := make([]int, len(objs)+1)
	for i, o := range objs {
		offs[i+1] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for i := 1; i < len(offs); i++ {
		fmt.Fprintf(&b, "%010d 00000 n \n", offs[i])
	}
	fmt.Fprintf(&b, "trailer << /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes()
}
func humanInt(n uint64) string { return strconv.FormatUint(n, 10) }
func humanBytes(n uint64) string {
	x := float64(n)
	u := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	i := 0
	for x >= 1024 && i < len(u)-1 {
		x /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", x, u[i])
	}
	return fmt.Sprintf("%.1f %s", x, u[i])
}

func due(j Job, now time.Time) bool {
	if !j.Enabled || now.Hour() != j.Hour {
		return false
	}
	if !j.LastRun.IsZero() && now.Sub(j.LastRun) < time.Hour {
		return false
	}
	switch j.Cadence {
	case "weekly":
		return now.Weekday() == time.Monday
	case "monthly":
		return now.Day() == 1
	default:
		return true
	}
}
func (m *Manager) recordRun(id string, now time.Time, path string, runErr error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.s.Jobs {
		if m.s.Jobs[i].ID != id {
			continue
		}
		m.s.Jobs[i].LastRun = now.UTC()
		m.s.Jobs[i].LastPath = path
		if runErr != nil {
			m.s.Jobs[i].LastError = runErr.Error()
		} else {
			m.s.Jobs[i].LastError = ""
		}
		return m.saveLocked()
	}
	return errors.New("report not found")
}

func (m *Manager) run(ctx context.Context, j Job, now time.Time, deliverReport bool) (string, []byte, error) {
	p, b, genErr := m.Generate(ctx, j, now)
	var deliveryErr error
	if genErr == nil && deliverReport {
		m.mu.Lock()
		deliver := m.deliver
		m.mu.Unlock()
		if deliver != nil {
			deliveryErr = deliver(ctx, j, p, b)
		}
	}
	runErr := genErr
	if runErr == nil {
		runErr = deliveryErr
	}
	if stateErr := m.recordRun(j.ID, now, p, runErr); stateErr != nil && runErr == nil {
		runErr = stateErr
	}
	return p, b, runErr
}

// RunNow generates and delivers one configured scheduled report immediately,
// and persists its execution status just like the background scheduler.
func (m *Manager) RunNow(ctx context.Context, idv string, now time.Time) (string, []byte, error) {
	for _, j := range m.Jobs() {
		if j.ID == idv {
			return m.run(ctx, j, now, true)
		}
	}
	return "", nil, errors.New("report not found")
}

func (m *Manager) RunDue(ctx context.Context, now time.Time) {
	for _, j := range m.Jobs() {
		if !due(j, now) {
			continue
		}
		_, _, _ = m.run(ctx, j, now, true)
	}
}
func (m *Manager) Start() {
	go func() {
		defer close(m.done)
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case now := <-t.C:
				m.RunDue(context.Background(), now)
			case <-m.stop:
				return
			}
		}
	}()
}
func (m *Manager) Close() {
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	<-m.done
}
