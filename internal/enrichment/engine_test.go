package enrichment

import (
	"os"
	"path/filepath"
	"testing"

	"central-flow-collector/internal/model"
)

func TestOfflineEnrichmentAndLongestPrefixSite(t *testing.T) {
	d := t.TempDir()
	csv := filepath.Join(d, "geo.csv")
	if err := os.WriteFile(csv, []byte("cidr,country,asn,as_name\n203.0.113.0/24,TR,64510,Example ASN\n2001:db8::/32,US,64511,IPv6 ASN\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := New(d, true, csv)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.UpsertSite(Site{ID: "corp", Name: "Corp", CIDR: "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if err := e.UpsertSite(Site{ID: "hq", Name: "HQ", CIDR: "10.1.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	f := model.Flow{SrcIP: "203.0.113.9", DstIP: "10.1.2.3"}
	e.Enrich(&f)
	if f.SrcCountry != "TR" || f.SrcAS != 64510 || f.SrcASName != "Example ASN" {
		t.Fatalf("unexpected src enrichment: %+v", f)
	}
	if f.DstSite != "HQ" {
		t.Fatalf("expected longest-prefix HQ site, got %q", f.DstSite)
	}
}

func TestExporterASNIsPreserved(t *testing.T) {
	d := t.TempDir()
	csv := filepath.Join(d, "geo.csv")
	_ = os.WriteFile(csv, []byte("198.51.100.0/24,DE,64501,DB ASN\n"), 0600)
	e, err := New(d, true, csv)
	if err != nil {
		t.Fatal(err)
	}
	f := model.Flow{SrcIP: "198.51.100.7", SrcAS: 65000}
	e.Enrich(&f)
	if f.SrcAS != 65000 {
		t.Fatalf("exporter ASN overwritten: %d", f.SrcAS)
	}
	if f.Custom["src_as_source"] != "exporter" {
		t.Fatalf("missing provenance: %+v", f.Custom)
	}
}

func TestSitesWorkWhenGeoPrefixEnrichmentDisabled(t *testing.T) {
	e, err := New(t.TempDir(), false, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.UpsertSite(Site{ID: "lab", Name: "Lab", CIDR: "fd00:1234::/48"}); err != nil {
		t.Fatal(err)
	}
	f := model.Flow{SrcIP: "fd00:1234::10"}
	e.Enrich(&f)
	if f.SrcSite != "Lab" {
		t.Fatalf("site enrichment should be independent of geo DB: %+v", f)
	}
}
