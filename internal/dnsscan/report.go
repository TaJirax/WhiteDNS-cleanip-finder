package dnsscan

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ReportPaths lists the files written by WriteReports.
type ReportPaths struct {
	Dir         string
	Full        string // human-readable per-resolver + header dump
	TunnelReady string // tunnel-ready shortlist
	CSV         string
	JSON        string
}

// WriteReports dumps every result to dir in txt, csv, and json (range-scout
// parity: txt/csv/json export). Files are timestamped. dir is created if needed.
func WriteReports(dir string, results []ResolverResult) (ReportPaths, error) {
	var paths ReportPaths
	if strings.TrimSpace(dir) == "" {
		dir = "dns scan"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return paths, err
	}
	ts := time.Now().Format("20060102_150405")
	paths.Dir = dir

	sorted := append([]ResolverResult(nil), results...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Score != sorted[j].Score {
			return sorted[i].Score > sorted[j].Score // best first
		}
		return sorted[i].IP < sorted[j].IP
	})

	paths.Full = filepath.Join(dir, fmt.Sprintf("dns_scan_%s.txt", ts))
	if err := writeFullReport(paths.Full, sorted); err != nil {
		return paths, err
	}
	paths.TunnelReady = filepath.Join(dir, fmt.Sprintf("tunnel_ready_%s.txt", ts))
	if err := writeTunnelReport(paths.TunnelReady, sorted); err != nil {
		return paths, err
	}
	paths.CSV = filepath.Join(dir, fmt.Sprintf("resolvers_%s.csv", ts))
	if err := writeCSV(paths.CSV, sorted); err != nil {
		return paths, err
	}
	paths.JSON = filepath.Join(dir, fmt.Sprintf("resolvers_%s.json", ts))
	if err := writeJSON(paths.JSON, sorted); err != nil {
		return paths, err
	}
	return paths, nil
}

func writeFullReport(path string, results []ResolverResult) error {
	var b strings.Builder
	fmt.Fprintf(&b, "DNS Resolver / Tunnel Scan\nGenerated: %s\nTotal: %d\n", time.Now().Format("2006-01-02 15:04:05"), len(results))
	b.WriteString("Score 0-6 = UDP + TCP + RA + EDNS0 + TXT-passthrough + answer-integrity\n")
	b.WriteString(strings.Repeat("=", 90) + "\n")
	for _, r := range results {
		fmt.Fprintf(&b, "\n%-21s score=%d/6 tunnel=%s poison=%v transparent=%v %dms\n",
			r.IP, r.Score, ynb(r.TunnelReady), r.Poisoned, r.Transparent, r.BestLatency.Milliseconds())
		fmt.Fprintf(&b, "    RA=%v EDNS=%v TXT=%v UDP=%v TCP=%v reason=%s\n",
			r.RA, r.EDNS, r.TxtPass, r.UDPOK, r.TCPOK, r.TunnelReason)
		for _, hd := range r.HeaderDump() {
			b.WriteString("    " + hd + "\n")
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writeTunnelReport(path string, results []ResolverResult) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Tunnel-Ready DNS Resolvers\nGenerated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	b.WriteString("Criteria: open recursion (RA) + EDNS0 large-payload + TXT passthrough\n")
	b.WriteString(strings.Repeat("=", 70) + "\n")
	count := 0
	for _, r := range results {
		if !r.TunnelReady {
			continue
		}
		count++
		fmt.Fprintf(&b, "%-21s score=%d/6 poison=%v transparent=%v %dms\n",
			r.IP, r.Score, r.Poisoned, r.Transparent, r.BestLatency.Milliseconds())
	}
	fmt.Fprintf(&b, "\nTotal tunnel-ready: %d\n", count)
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writeCSV(path string, results []ResolverResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"ip", "score", "responded", "udp", "tcp", "ra", "edns", "txt_pass", "poisoned", "transparent", "tunnel_ready", "latency_ms", "nearby", "reason"})
	for _, r := range results {
		_ = w.Write([]string{
			r.IP,
			strconv.Itoa(r.Score),
			strconv.FormatBool(r.Responded),
			strconv.FormatBool(r.UDPOK),
			strconv.FormatBool(r.TCPOK),
			strconv.FormatBool(r.RA),
			strconv.FormatBool(r.EDNS),
			strconv.FormatBool(r.TxtPass),
			strconv.FormatBool(r.Poisoned),
			strconv.FormatBool(r.Transparent),
			strconv.FormatBool(r.TunnelReady),
			strconv.FormatInt(r.BestLatency.Milliseconds(), 10),
			strconv.FormatBool(r.Nearby),
			r.TunnelReason,
		})
	}
	return w.Error()
}

// jsonResolver is the export view (flattened, no raw probe internals).
type jsonResolver struct {
	IP          string   `json:"ip"`
	Score       int      `json:"score"`
	Responded   bool     `json:"responded"`
	UDP         bool     `json:"udp"`
	TCP         bool     `json:"tcp"`
	RA          bool     `json:"recursion_available"`
	EDNS        bool     `json:"edns0"`
	TxtPass     bool     `json:"txt_passthrough"`
	Poisoned    bool     `json:"poisoned"`
	Transparent bool     `json:"transparent_proxy"`
	TunnelReady bool     `json:"tunnel_ready"`
	LatencyMs   int64    `json:"latency_ms"`
	Nearby      bool     `json:"nearby"`
	Reason      string   `json:"reason"`
	Headers     []string `json:"headers"`
}

func writeJSON(path string, results []ResolverResult) error {
	out := make([]jsonResolver, 0, len(results))
	for _, r := range results {
		out = append(out, jsonResolver{
			IP: r.IP, Score: r.Score, Responded: r.Responded, UDP: r.UDPOK, TCP: r.TCPOK,
			RA: r.RA, EDNS: r.EDNS, TxtPass: r.TxtPass, Poisoned: r.Poisoned,
			Transparent: r.Transparent, TunnelReady: r.TunnelReady,
			LatencyMs: r.BestLatency.Milliseconds(), Nearby: r.Nearby, Reason: r.TunnelReason,
			Headers: r.HeaderDump(),
		})
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func ynb(v bool) string {
	if v {
		return "Y"
	}
	return "N"
}
