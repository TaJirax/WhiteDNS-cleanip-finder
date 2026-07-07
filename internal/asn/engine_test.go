package asn

import (
	"strings"
	"testing"
)

func TestSearchSummariesPrioritizesTypedName(t *testing.T) {
	eng := NewASNEngine(t.TempDir())
	data := strings.NewReader(`cidr,c1,c2,c3,c4,asn,name,c7,type
10.0.0.0/32,,,,,AS65000,Target Network Alpha,,isp
10.0.0.1/32,,,,,AS65000,Target Network Alpha,,isp
10.0.1.0/32,,,,,AS65001,Target Network,,isp
`)
	if err := eng.loadCSVReader(data, true); err != nil {
		t.Fatal(err)
	}
	eng.loadedV4 = true

	rows, err := eng.SearchSummaries("Target Network", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d", len(rows))
	}
	if rows[0].ASN != "AS65001" {
		t.Fatalf("expected exact name match first, got %+v", rows[0])
	}
}

func TestSearchSummariesBlankKeepsSubnetSort(t *testing.T) {
	eng := NewASNEngine(t.TempDir())
	data := strings.NewReader(`cidr,c1,c2,c3,c4,asn,name,c7,type
10.0.0.0/32,,,,,AS65000,Small,,isp
10.0.1.0/32,,,,,AS65001,Large,,isp
10.0.1.1/32,,,,,AS65001,Large,,isp
`)
	if err := eng.loadCSVReader(data, true); err != nil {
		t.Fatal(err)
	}
	eng.loadedV4 = true

	rows, err := eng.SearchSummaries("*", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d", len(rows))
	}
	if rows[0].ASN != "AS65001" {
		t.Fatalf("expected largest ASN first for blank list, got %+v", rows[0])
	}
}
