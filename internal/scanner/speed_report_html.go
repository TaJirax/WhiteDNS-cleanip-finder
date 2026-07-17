package scanner

import (
	"fmt"
	"html"
	"path/filepath"
	"strings"
	"time"

	"whitedns-go/internal/storage"
)

// WriteSpeedRankHTML renders a ranked, sortable HTML table of speed-rank
// results (real download/upload/loss/latency numbers, best-first) and writes
// it to a timestamped file under dataDir. results is assumed pre-sorted
// (SpeedRankIPs always returns best-first by Score).
func WriteSpeedRankHTML(dataDir string, results []SpeedRankResult) (string, error) {
	if dataDir == "" {
		dataDir = "."
	}
	outDir := filepath.Join(dataDir, "whitedns logs")
	stamp := time.Now().Format("20060102-150405")
	path := filepath.Join(outDir, fmt.Sprintf("speedrank-%s.html", stamp))

	esc := html.EscapeString
	var b strings.Builder
	b.WriteString("<!doctype html><meta charset=\"utf-8\"><title>WhiteDNS Speed Rank</title>\n")
	b.WriteString("<style>body{font:13px system-ui,Segoe UI,Arial,sans-serif;margin:16px;background:#111;color:#eee}" +
		"table{border-collapse:collapse;width:100%}th,td{border:1px solid #444;padding:4px 8px;text-align:left;white-space:nowrap}" +
		"th{background:#222;cursor:pointer;position:sticky;top:0}tr:nth-child(even){background:#1a1a1a}" +
		"code{font:12px Consolas,monospace}.down{color:#f66}.pin{color:#6f6;font-weight:bold}</style>\n")
	fmt.Fprintf(&b, "<h2>WhiteDNS Speed Rank</h2><p>Generated: %s &middot; Ranked: %d</p>\n",
		esc(time.Now().Format("2006-01-02 15:04:05")), len(results))
	b.WriteString("<table id=t><tr>" +
		"<th>#</th><th>IP</th><th>Port</th><th>Download Mbps</th><th>Upload Mbps</th>" +
		"<th>Latency ms</th><th>Jitter ms</th><th>Loss %</th><th>Score</th>" +
		"<th>Download via</th><th>Upload via</th><th>Note</th></tr>\n")
	for i, r := range results {
		if !r.Reachable {
			reason := r.Error
			if reason == "" {
				reason = "unreachable"
			}
			fmt.Fprintf(&b, "<tr class=down><td>%d</td><td><code>%s</code></td><td>%d</td>"+
				"<td>-</td><td>-</td><td>-</td><td>-</td><td>100.0</td><td>0.00</td><td>-</td><td>-</td><td>%s</td></tr>\n",
				i+1, esc(r.IP), r.Port, esc(reason))
			continue
		}
		downCell, upCell := esc(r.Source), esc(r.UploadSource)
		if r.Source == "cloudflare" {
			downCell = "<span class=pin>" + downCell + " (pinned)</span>"
		}
		if r.UploadSource == "cloudflare" {
			upCell = "<span class=pin>" + upCell + " (pinned)</span>"
		}
		fmt.Fprintf(&b, "<tr><td>%d</td><td><code>%s</code></td><td>%d</td>"+
			"<td>%.2f</td><td>%.2f</td><td>%.0f</td><td>%.0f</td><td>%.1f</td><td>%.2f</td><td>%s</td><td>%s</td><td></td></tr>\n",
			i+1, esc(r.IP), r.Port, r.DownloadMbps, r.UploadMbps, r.LatencyMs, r.JitterMs, r.LossPct, r.Score, downCell, upCell)
	}
	b.WriteString("</table>\n")
	b.WriteString("<script>document.querySelectorAll('#t th').forEach((th,i)=>{th.onclick=()=>{" +
		"const tb=document.getElementById('t'),rows=[...tb.querySelectorAll('tr')].slice(1);" +
		"const num=c=>parseFloat(c.replace(/[^0-9.\\-]/g,''))||0;" +
		"rows.sort((a,b)=>num(b.children[i].textContent)-num(a.children[i].textContent));" +
		"rows.forEach(r=>tb.appendChild(r));};});</script>\n")

	if err := storage.AtomicWriteText(path, b.String()); err != nil {
		return "", err
	}
	return path, nil
}
