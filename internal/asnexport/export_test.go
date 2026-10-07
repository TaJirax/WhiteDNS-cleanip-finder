package asnexport

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportMergesOverlapsAndSamplesIPv6(t *testing.T) {
	dir := t.TempDir()
	path, n, err := ExportTargetsToTXT(dir, []string{"10.0.0.0/30", "10.0.0.2/31", "10.0.0.4", "9.255.255.255", "2001:db8::/32"}, "out.txt")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "out.txt"))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")[4:] // after the header
	if got := strings.Join(lines[:6], ","); got != "9.255.255.255,10.0.0.0,10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4" {
		t.Fatalf("IPv4 must be merged, unique and ascending: %s", got)
	}
	_, wide, _ := net.ParseCIDR("2001:db8::/32")
	v6 := lines[6:]
	if len(v6) == 0 || len(v6) > 4096 || n != len(lines) || path == "" {
		t.Fatalf("IPv6 /32 must be sampled, not enumerated: %d samples, n=%d", len(v6), n)
	}
	for _, s := range v6 {
		if !wide.Contains(net.ParseIP(s)) {
			t.Fatalf("sample %q outside the prefix", s)
		}
	}
}

func TestAppendIPv4MatchesNetIP(t *testing.T) {
	for _, v := range []uint32{0, 9, 256, 0x0A000001, 0xFFFFFFFF} {
		if got, want := string(AppendIPv4(nil, v)), net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String(); got != want {
			t.Fatalf("%d: %q want %q", v, got, want)
		}
	}
}
