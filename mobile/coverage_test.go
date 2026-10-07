package mobile

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"whitedns-go/internal/asn"
	"whitedns-go/internal/asnexport"
)

// coverage is an oracle for "which IPv4 addresses do these ranges cover",
// built by a sweep over start/end events. It shares no code with the
// expanders, so agreeing with it proves they neither lose nor invent IPs.
type coverage struct{ starts, ends []uint64 }

func coverageOf(ranges [][2]uint64) coverage {
	type event struct {
		at    uint64
		delta int
	}
	events := make([]event, 0, 2*len(ranges))
	for _, r := range ranges {
		events = append(events, event{r[0], +1}, event{r[1] + 1, -1})
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].at != events[j].at {
			return events[i].at < events[j].at
		}
		return events[i].delta > events[j].delta
	})
	var c coverage
	depth := 0
	for _, e := range events {
		if depth == 0 && e.delta > 0 {
			c.starts = append(c.starts, e.at)
		}
		depth += e.delta
		if depth == 0 {
			c.ends = append(c.ends, e.at-1)
		}
	}
	return c
}

func (c coverage) size() (n uint64) {
	for i := range c.starts {
		n += c.ends[i] - c.starts[i] + 1
	}
	return n
}

// checker: strictly ascending (all distinct) + inside the coverage + count ==
// size  ⇒  the output is exactly the covered set.
type checker struct {
	c    coverage
	i    int
	last uint64
	n    uint64
	err  string
}

func (k *checker) add(v uint64) {
	if k.err != "" {
		return
	}
	if k.n > 0 && v <= k.last {
		k.err = "not strictly ascending"
		return
	}
	for k.i < len(k.c.ends) && k.c.ends[k.i] < v {
		k.i++
	}
	if k.i == len(k.c.starts) || v < k.c.starts[k.i] {
		k.err = "address outside every input range: " + net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
		return
	}
	k.last, k.n = v, k.n+1
}

func parseIPv4(s string) (uint64, bool) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, false
	}
	return uint64(ip[0])<<24 | uint64(ip[1])<<16 | uint64(ip[2])<<8 | uint64(ip[3]), true
}

// allIPv4 returns every bundled ASN's IPv4 ranges and their address spans;
// capPerCIDR > 0 trims each span the way the scan stager does.
func allIPv4(t *testing.T, capPerCIDR uint64) ([]string, [][2]uint64) {
	eng := asn.NewASNEngine(t.TempDir())
	if err := eng.LoadIPv4(); err != nil {
		t.Fatal(err)
	}
	groups, err := eng.SearchSummariesFamily("", 0, "ipv4")
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(groups))
	for i, g := range groups {
		ids[i] = g.ASN
	}
	cidrs, err := eng.CIDRsForASNs(ids, "ipv4")
	if err != nil {
		t.Fatal(err)
	}
	spans := make([][2]uint64, 0, len(cidrs))
	for _, c := range cidrs {
		if !strings.Contains(c, "/") {
			c += "/32"
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatal(err)
		}
		ones, _ := n.Mask.Size()
		first, _ := parseIPv4(n.IP.String())
		last := first + 1<<uint(32-ones) - 1
		if capPerCIDR > 0 && last-first+1 > capPerCIDR {
			last = first + capPerCIDR - 1
		}
		spans = append(spans, [2]uint64{first, last})
	}
	return cidrs, spans
}

// Export ASN IPs: every IPv4 address of every bundled ASN, exactly once.
func TestASNExportLosesNoIPv4Address(t *testing.T) {
	if testing.Short() {
		t.Skip("exhaustive: expands the whole ASN dataset")
	}
	cidrs, spans := allIPv4(t, 0)
	want := coverageOf(spans)
	dir := t.TempDir()
	_, n, err := asnexport.ExportTargetsToTXT(dir, cidrs, "all.txt")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "all.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	k := &checker{c: want}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := parseIPv4(sc.Text()); ok {
			k.add(v)
		}
	}
	if k.err != "" || k.n != want.size() || uint64(n) != want.size() {
		t.Fatalf("exported %d (%d checked, %s); the ranges cover %d", n, k.n, k.err, want.size())
	}
	t.Logf("%d ranges, %d unique IPv4 addresses, all exported once", len(cidrs), k.n)
}

// Scan staging: every address the per-CIDR cap allows, exactly once, so no
// IP is skipped and none is scanned twice (the old seen-set stopped at 400k).
func TestScanWalkerLosesNoIPv4Address(t *testing.T) {
	if testing.Short() {
		t.Skip("exhaustive: stages the whole ASN dataset")
	}
	cidrs, spans := allIPv4(t, perCIDRMaxIPs)
	want := coverageOf(spans)
	k := &checker{c: want}
	n, err := walkTargets(context.Background(), cidrs, stageDedupCap, func(line string) error {
		if v, ok := parseIPv4(line); ok {
			k.add(v)
		}
		return nil
	})
	if err != nil || k.err != "" || k.n != want.size() || uint64(n) != want.size() {
		t.Fatalf("staged %d (%d checked, %s, %v); the capped ranges cover %d", n, k.n, k.err, err, want.size())
	}
	t.Logf("%d ranges, %d unique IPv4 addresses staged once each", len(cidrs), k.n)
}
