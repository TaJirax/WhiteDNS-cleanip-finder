package dnsscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMobileReportsStayAtTwoFilesAndCategorizeResults(t *testing.T) {
	dir := t.TempDir()
	paths, err := NewMobileReportPaths(dir)
	if err != nil {
		t.Fatal(err)
	}

	results := []ResolverResult{
		{IP: "192.0.2.10", Status: StatusValid, Score: 6, Responded: true, TunnelReady: true, BestLatency: 12 * time.Millisecond},
		{IP: "192.0.2.20", Status: StatusPoison, Score: 3, Responded: true, Poisoned: true, PoisonIP: "203.0.113.9"},
		{IP: "192.0.2.30", Status: StatusHijack, Score: 4, Responded: true, Transparent: true, HijackIP: "198.51.100.7"},
		{IP: "192.0.2.40", Status: StatusInvalid},
		{IP: "192.0.2.50", Status: StatusValid, Score: 2, Responded: true, TunnelReady: false},
	}
	if err := WriteMobileReports(paths, results[:1]); err != nil {
		t.Fatal(err)
	}
	// A later chunk flush must rewrite the original paths, not allocate more.
	if err := WriteMobileReports(paths, results); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("mobile DNS report created %d files (%v), want exactly 2", len(entries), names)
	}
	for _, path := range []string{paths.Detailed, paths.PassedRaw} {
		if filepath.Dir(path) != dir {
			t.Fatalf("report path %q is outside %q", path, dir)
		}
	}

	detailedBytes, err := os.ReadFile(paths.Detailed)
	if err != nil {
		t.Fatal(err)
	}
	detailed := string(detailedBytes)
	for _, want := range []string{"[PASSED] 1", "192.0.2.10", "[POISON] 1", "192.0.2.20", "poison_ip=203.0.113.9", "[HIJACK] 1", "192.0.2.30", "hijack_ip=198.51.100.7"} {
		if !strings.Contains(detailed, want) {
			t.Errorf("detailed report missing %q\n%s", want, detailed)
		}
	}
	for _, unwanted := range []string{"192.0.2.40", "192.0.2.50"} {
		if strings.Contains(detailed, unwanted) {
			t.Errorf("non-passing resolver %s should be counted but not listed\n%s", unwanted, detailed)
		}
	}

	rawBytes, err := os.ReadFile(paths.PassedRaw)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(rawBytes), "192.0.2.10\n"; got != want {
		t.Fatalf("raw passed list = %q, want %q", got, want)
	}
}
