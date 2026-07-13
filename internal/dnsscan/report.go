package dnsscan

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
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
	HTML        string // colour-coded per-status table (opens in browser/Excel)
	JSON        string
}

// statusCounts tallies how many resolvers landed in each state.
func statusCounts(results []ResolverResult) map[string]int {
	c := map[string]int{}
	for _, r := range results {
		c[r.Status]++
	}
	return c
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
	paths.HTML = filepath.Join(dir, fmt.Sprintf("resolvers_%s.html", ts))
	if err := writeHTML(paths.HTML, sorted); err != nil {
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
	c := statusCounts(results)
	fmt.Fprintf(&b, "States: valid(green)=%d  poison(purple)=%d  hijack(yellow)=%d  invalid(red)=%d\n",
		c[StatusValid], c[StatusPoison], c[StatusHijack], c[StatusInvalid])
	b.WriteString("Score 0-6 = UDP + TCP + RA + EDNS0 + TXT-passthrough + answer-integrity\n")
	b.WriteString("Header fields per probe: qr/aa/tc/rd/ra flags, rcode, and qd/an/ns/ar section counts.\n")
	b.WriteString(strings.Repeat("=", 90) + "\n")
	for _, r := range results {
		fmt.Fprintf(&b, "\n%-21s [%s] score=%d/6 tunnel=%s poison=%v hijack=%v %dms\n",
			r.IP, strings.ToUpper(r.Status), r.Score, ynb(r.TunnelReady), r.Poisoned, r.Transparent, r.BestLatency.Milliseconds())
		fmt.Fprintf(&b, "    RA=%v EDNS0=%v TXT-pass=%v UDP=%v TCP=%v NS-records=%d AR-records=%d reason=%s\n",
			r.RA, r.EDNS, r.TxtPass, r.UDPOK, r.TCPOK, r.NSCount, r.ARCount, r.TunnelReason)
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
	// status + color make the per-state verdict explicit so spreadsheets can
	// conditional-format it (poison=purple, hijack=yellow, valid=green,
	// invalid=red); resolvers_*.html renders those colours directly.
	_ = w.Write([]string{"ip", "status", "color", "score", "responded", "udp", "tcp", "ra", "edns", "txt_pass", "ns_records", "ar_records", "poisoned", "hijacked", "tunnel_ready", "latency_ms", "nearby", "reason"})
	for _, r := range results {
		_ = w.Write([]string{
			r.IP,
			r.Status,
			StatusColor(r.Status),
			strconv.Itoa(r.Score),
			strconv.FormatBool(r.Responded),
			strconv.FormatBool(r.UDPOK),
			strconv.FormatBool(r.TCPOK),
			strconv.FormatBool(r.RA),
			strconv.FormatBool(r.EDNS),
			strconv.FormatBool(r.TxtPass),
			strconv.Itoa(r.NSCount),
			strconv.Itoa(r.ARCount),
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

// htmlStatusFill maps a status to a spreadsheet/browser-friendly row fill.
var htmlStatusFill = map[string]string{
	StatusPoison:  "#b39ddb", // purple
	StatusHijack:  "#fff59d", // yellow
	StatusValid:   "#a5d6a7", // green
	StatusInvalid: "#ef9a9a", // red
}

// writeHTML renders a colour-coded table where every row is filled by resolver
// status (poison=purple, hijack=yellow, valid=green, invalid=red). It opens in
// any browser and imports into Excel/LibreOffice with the fills preserved, so
// the colours requested for the CSV are actually visible. Columns surface the
// EDNS0, TXT-passthrough, and NS/AR header data probed per resolver.
func writeHTML(path string, results []ResolverResult) error {
	c := statusCounts(results)
	var b strings.Builder
	b.WriteString("<!doctype html><meta charset=\"utf-8\"><title>DNS Resolver Scan</title>\n")
	b.WriteString("<style>body{font:13px system-ui,Segoe UI,Arial,sans-serif;margin:16px}" +
		"table{border-collapse:collapse;width:100%}th,td{border:1px solid #999;padding:3px 7px;text-align:left;white-space:nowrap}" +
		"th{background:#333;color:#fff;position:sticky;top:0}code{font:12px Consolas,monospace}" +
		".legend span{display:inline-block;padding:2px 8px;margin-right:8px;border:1px solid #999}</style>\n")
	fmt.Fprintf(&b, "<h2>DNS Resolver / Tunnel Scan</h2><p>Generated: %s &middot; Total: %d</p>\n",
		html.EscapeString(time.Now().Format("2006-01-02 15:04:05")), len(results))
	fmt.Fprintf(&b, "<p class=legend>"+
		"<span style=\"background:%s\">valid: %d</span>"+
		"<span style=\"background:%s\">poison: %d</span>"+
		"<span style=\"background:%s\">hijack: %d</span>"+
		"<span style=\"background:%s\">invalid: %d</span></p>\n",
		htmlStatusFill[StatusValid], c[StatusValid], htmlStatusFill[StatusPoison], c[StatusPoison],
		htmlStatusFill[StatusHijack], c[StatusHijack], htmlStatusFill[StatusInvalid], c[StatusInvalid])
	b.WriteString("<table><tr><th>IP</th><th>Status</th><th>Score</th><th>RA</th><th>EDNS0</th>" +
		"<th>TXT-pass</th><th>UDP</th><th>TCP</th><th>NS</th><th>AR</th><th>Poison</th><th>Hijack</th>" +
		"<th>Tunnel</th><th>ms</th><th>Reason</th><th>Headers (qr/aa/tc/rd/ra rcode qd/an/ns/ar)</th></tr>\n")
	esc := html.EscapeString
	for _, r := range results {
		fill := htmlStatusFill[r.Status]
		if fill == "" {
			fill = htmlStatusFill[StatusInvalid]
		}
		fmt.Fprintf(&b, "<tr style=\"background:%s\"><td><code>%s</code></td><td><b>%s</b></td>"+
			"<td>%d/6</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td>"+
			"<td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td><code>%s</code></td></tr>\n",
			fill, esc(r.IP), esc(strings.ToUpper(r.Status)), r.Score,
			ynb(r.RA), ynb(r.EDNS), ynb(r.TxtPass), ynb(r.UDPOK), ynb(r.TCPOK), r.NSCount, r.ARCount,
			ynb(r.Poisoned), ynb(r.Transparent), ynb(r.TunnelReady), r.BestLatency.Milliseconds(),
			esc(r.TunnelReason), esc(strings.Join(r.HeaderDump(), " ⏐ ")))
	}
	b.WriteString("</table>\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// jsonResolver is the export view (flattened, no raw probe internals).
type jsonResolver struct {
	IP          string   `json:"ip"`
	Status      string   `json:"status"`
	Color       string   `json:"color"`
	Score       int      `json:"score"`
	Responded   bool     `json:"responded"`
	UDP         bool     `json:"udp"`
	TCP         bool     `json:"tcp"`
	RA          bool     `json:"recursion_available"`
	EDNS        bool     `json:"edns0"`
	TxtPass     bool     `json:"txt_passthrough"`
	NSCount     int      `json:"ns_records"`
	ARCount     int      `json:"ar_records"`
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
			IP: r.IP, Status: r.Status, Color: StatusColor(r.Status), Score: r.Score,
			Responded: r.Responded, UDP: r.UDPOK, TCP: r.TCPOK,
			RA: r.RA, EDNS: r.EDNS, TxtPass: r.TxtPass, NSCount: r.NSCount, ARCount: r.ARCount,
			Poisoned: r.Poisoned,
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
