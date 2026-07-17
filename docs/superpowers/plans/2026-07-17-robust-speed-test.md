# Robust Speed Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give real, sorted download/upload/ping results for main "find clean IPs" scans (not just the separate Speed Rank feature), with a readable ranked HTML report, a corrected/expanded fallback endpoint chain, no artificial 256-IP ceiling, and an Android toggle that auto-chains a speed test onto scan results.

**Architecture:** Delete the crude, discard-the-result throughput prober in `network_health.go`. Reuse the existing, already-correct `SpeedRankIPs` engine (`internal/scanner/speedrank.go`) as a post-scan pass: desktop TUI runs it inline on the accepted-IP list `ScanIPsWithProgress` already returns; Android reuses it by auto-chaining to the existing `ScanKind.SPEED` scan kind via a new opt-in toggle. One measurement engine, reused everywhere, no new fields threaded through `ProbeResult`.

**Tech Stack:** Go (stdlib only — `net/http`, `crypto/tls`, `strings.Builder` for HTML), Kotlin/Jetpack Compose (Android).

## Global Constraints

- No new external dependency, in Go or Kotlin — matches the existing hand-built HTML/CSV export pattern (`internal/dnsscan/report.go`).
- Download fallback chain, in order: Cloudflare (pinned) → Cachefly (unpinned, real bytes) → Hetzner (unpinned, real bytes) → Google `generate_204` (unpinned, reachability-only, last resort, 0 Mbps claimed).
- Upload fallback chain, in order: Cloudflare `/__up` (pinned) → `postman-echo.com/post` (unpinned) → `httpbin.org/post` (unpinned).
- `maxSpeedRankIPs` (`mobile/api.go:1075`) raised from 256 to 2000.
- Android `speedTestEnabled` toggle lives on `FormState`, default `false`, rendered only in the `ScanKind.IP` section of `ScanConfigForm.kt`.
- Desktop TUI speed-ranks and reports only for `opType == "scan_ips"` — not `sni_scanner`/`desync_scanner`, which have different target semantics.

---

### Task 1: Fix the download fallback chain

**Files:**
- Modify: `internal/scanner/speedrank.go:68-86` (`DefaultSpeedEndpoints`)
- Test: `internal/scanner/speedrank_test.go` (new file)

**Interfaces:**
- Consumes: existing `SpeedEndpoint` struct (`speedrank.go:50-64`) — no changes to its shape.
- Produces: `DefaultSpeedEndpoints(downloadBytes int) []SpeedEndpoint` returns 4 endpoints in this order: cloudflare (pinned), cachefly (unpinned), hetzner (unpinned), google-204 (unpinned, `Reachability: true`). Later tasks/tests rely on this exact order and these exact `Name` values: `"cloudflare"`, `"cachefly"`, `"hetzner"`, `"google-204"`.

- [ ] **Step 1: Write the failing test**

```go
package scanner

import "testing"

func TestDefaultSpeedEndpointsOrderAndNames(t *testing.T) {
	eps := DefaultSpeedEndpoints(10 * 1024 * 1024)
	if len(eps) != 4 {
		t.Fatalf("expected 4 download endpoints, got %d", len(eps))
	}
	wantNames := []string{"cloudflare", "cachefly", "hetzner", "google-204"}
	for i, want := range wantNames {
		if eps[i].Name != want {
			t.Fatalf("endpoint %d: want name %q, got %q", i, want, eps[i].Name)
		}
	}
	if !eps[0].PinToCandidate {
		t.Fatalf("cloudflare endpoint must be PinToCandidate")
	}
	if eps[1].PinToCandidate || eps[2].PinToCandidate || eps[3].PinToCandidate {
		t.Fatalf("only cloudflare should be PinToCandidate")
	}
	if !eps[3].Reachability {
		t.Fatalf("google-204 must be Reachability-only")
	}
	if eps[1].URL != "https://cachefly.cachefly.net/10mb.test" {
		t.Fatalf("unexpected cachefly URL: %s", eps[1].URL)
	}
	if eps[2].URL != "https://speed.hetzner.de/100MB.bin" {
		t.Fatalf("unexpected hetzner URL: %s", eps[2].URL)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run TestDefaultSpeedEndpointsOrderAndNames -v`
Expected: FAIL (current list has only 3 endpoints, wrong names/URLs, google-204 is 2nd not 4th).

- [ ] **Step 3: Update `DefaultSpeedEndpoints`**

Replace `internal/scanner/speedrank.go:68-86` with:

```go
// DefaultSpeedEndpoints returns the ordered fallback list. downloadBytes is
// substituted into the Cloudflare endpoint. Only the Cloudflare entry is
// PinToCandidate (dials the IP being ranked directly) since it is the anycast
// network these clean-IP scans target; the others are real transfers against
// well-known public test files but measure the box's general path, not the
// candidate IP specifically. google-204 is a last-resort reachability check
// only (0 bytes) — Google has no stable public bandwidth-test file.
func DefaultSpeedEndpoints(downloadBytes int) []SpeedEndpoint {
	return []SpeedEndpoint{
		{
			Name:           "cloudflare",
			URL:            fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", downloadBytes),
			Host:           "speed.cloudflare.com",
			PinToCandidate: true,
		},
		{
			Name: "cachefly",
			URL:  "https://cachefly.cachefly.net/10mb.test",
		},
		{
			Name: "hetzner",
			URL:  "https://speed.hetzner.de/100MB.bin",
		},
		{
			Name:         "google-204",
			URL:          "https://www.google.com/generate_204",
			Reachability: true,
		},
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scanner/ -run TestDefaultSpeedEndpointsOrderAndNames -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/speedrank.go internal/scanner/speedrank_test.go
git commit -m "fix: correct speed-test download fallback chain (cachefly url, add hetzner, google as last-resort reachability)"
```

---

### Task 2: Add an upload fallback chain (currently hardcoded to Cloudflare only)

**Files:**
- Modify: `internal/scanner/speedrank.go`
- Test: `internal/scanner/speedrank_test.go`

**Interfaces:**
- Consumes: `SpeedEndpoint` (Task 1, unchanged shape), `endpointHTTPClient` (`speedrank.go:324`, unchanged), `countingReader` (`speedrank.go:426`, unchanged).
- Produces:
  - `DefaultUploadEndpoints() []SpeedEndpoint` — 3 endpoints, in order: `"cloudflare"` (pinned), `"postman-echo"` (unpinned), `"httpbin"` (unpinned).
  - `SpeedRankOptions.UploadEndpoints []SpeedEndpoint` — new field, defaulted by `applyDefaults()` to `DefaultUploadEndpoints()` when empty.
  - `measureUpload(ctx context.Context, candidateAddr string, opts SpeedRankOptions) (mbps float64, source string, err error)` — signature changes from `(float64, error)` to `(float64, string, error)`; iterates `opts.UploadEndpoints` in order, returns on first success, source is the winning endpoint's `Name`.
  - `SpeedRankResult.UploadSource string` — new field, set by `benchmarkOneIP` from `measureUpload`'s returned source.

- [ ] **Step 1: Write the failing test**

```go
func TestMeasureUploadFallsBackOnFirstEndpointFailure(t *testing.T) {
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer okServer.Close()
	okHost := okServer.Listener.Addr().String()

	opts := SpeedRankOptions{
		UploadBytes: 1024,
		Timeout:     2 * time.Second,
		UploadEndpoints: []SpeedEndpoint{
			{Name: "broken", URL: "https://127.0.0.1:1/__up"}, // nothing listens here -> dial error
			{Name: "ok", URL: "http://" + okHost + "/post"},
		},
	}
	opts.applyDefaults()

	mbps, source, err := measureUpload(context.Background(), okHost, opts)
	if err != nil {
		t.Fatalf("expected fallback to succeed, got err: %v", err)
	}
	if source != "ok" {
		t.Fatalf("expected fallback source 'ok', got %q", source)
	}
	if mbps <= 0 {
		t.Fatalf("expected positive mbps, got %f", mbps)
	}
}

func TestDefaultUploadEndpointsOrderAndNames(t *testing.T) {
	eps := DefaultUploadEndpoints()
	wantNames := []string{"cloudflare", "postman-echo", "httpbin"}
	if len(eps) != len(wantNames) {
		t.Fatalf("expected %d upload endpoints, got %d", len(wantNames), len(eps))
	}
	for i, want := range wantNames {
		if eps[i].Name != want {
			t.Fatalf("endpoint %d: want name %q, got %q", i, want, eps[i].Name)
		}
	}
	if !eps[0].PinToCandidate {
		t.Fatalf("cloudflare upload endpoint must be PinToCandidate")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run "TestMeasureUploadFallsBackOnFirstEndpointFailure|TestDefaultUploadEndpointsOrderAndNames" -v`
Expected: FAIL to compile (`measureUpload` has wrong signature, `DefaultUploadEndpoints` doesn't exist, `UploadEndpoints`/`UploadSource` fields don't exist).

- [ ] **Step 3: Implement**

Add `UploadSource` to `SpeedRankResult` (`speedrank.go:116-129`):

```go
type SpeedRankResult struct {
	IP           string
	Port         int
	Reachable    bool
	DownloadMbps float64
	UploadMbps   float64
	LossPct      float64
	LatencyMs    float64
	JitterMs     float64
	Score        float64
	// Source is the name of the endpoint that produced the download throughput number.
	Source string
	// UploadSource is the name of the endpoint that produced the upload throughput number.
	UploadSource string
	Error        string
}
```

Add `UploadEndpoints` to `SpeedRankOptions` (`speedrank.go:23-46`), right after `DownloadEndpoints`:

```go
	// UploadEndpoints are tried in order for the upload throughput measurement;
	// the first one that responds is used. Defaults to Cloudflare plus two
	// public echo endpoints as unpinned fallbacks.
	UploadEndpoints []SpeedEndpoint
```

Add `DefaultUploadEndpoints` next to `DefaultSpeedEndpoints`:

```go
// DefaultUploadEndpoints returns the ordered upload fallback list. Only
// Cloudflare is PinToCandidate — postman-echo and httpbin are well-known
// public API-testing echo endpoints that don't persist the uploaded body,
// but measure the box's general upload path, not the candidate IP.
func DefaultUploadEndpoints() []SpeedEndpoint {
	return []SpeedEndpoint{
		{
			Name:           "cloudflare",
			URL:            "https://speed.cloudflare.com/__up",
			Host:           "speed.cloudflare.com",
			PinToCandidate: true,
		},
		{
			Name: "postman-echo",
			URL:  "https://postman-echo.com/post",
		},
		{
			Name: "httpbin",
			URL:  "https://httpbin.org/post",
		},
	}
}
```

In `applyDefaults()` (`speedrank.go:88-113`), after the existing `DownloadEndpoints` default block, add:

```go
	if len(o.UploadEndpoints) == 0 {
		o.UploadEndpoints = DefaultUploadEndpoints()
	}
```

Replace `measureUpload` (`speedrank.go:396-422`) with an endpoint-iterating version:

```go
// measureUpload posts opts.UploadBytes of zero bytes to each endpoint in
// opts.UploadEndpoints, in order, returning the first success's throughput
// and the winning endpoint's name.
func measureUpload(ctx context.Context, candidateAddr string, opts SpeedRankOptions) (float64, string, error) {
	var lastErr error
	for _, ep := range opts.UploadEndpoints {
		host := ep.Host
		if host == "" {
			host = hostFromURL(ep.URL)
		}
		client := endpointHTTPClient(candidateAddr, host, ep.PinToCandidate, opts)
		reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		body := &countingReader{remaining: opts.UploadBytes}
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, ep.URL, body)
		if err != nil {
			cancel()
			client.CloseIdleConnections()
			lastErr = err
			continue
		}
		if host != "" {
			req.Host = host
		}
		req.ContentLength = int64(opts.UploadBytes)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Content-Type", "application/octet-stream")

		start := time.Now()
		resp, err := client.Do(req)
		cancel()
		if err != nil {
			client.CloseIdleConnections()
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		client.CloseIdleConnections()
		if resp.StatusCode >= 400 {
			lastErr = fmt.Errorf("%s: status %d", ep.Name, resp.StatusCode)
			continue
		}
		elapsed := time.Since(start).Seconds()
		sent := opts.UploadBytes - body.remaining
		return mbps(int64(sent), elapsed), ep.Name, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no upload endpoints configured")
	}
	return 0, "", lastErr
}
```

Update the call site in `benchmarkOneIP` (`speedrank.go:285-291`):

```go
	// --- Upload throughput with ordered endpoint fallback ---
	waitWhilePaused(ctx, opts)
	if ctx.Err() == nil {
		if mbps, source, err := measureUpload(ctx, addr, opts); err == nil {
			res.UploadMbps = mbps
			res.UploadSource = source
		}
	}
```

Add `"net/http/httptest"` to the test file's imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scanner/ -run "TestMeasureUploadFallsBackOnFirstEndpointFailure|TestDefaultUploadEndpointsOrderAndNames" -v`
Expected: PASS

- [ ] **Step 5: Run the full scanner package test suite to check for regressions**

Run: `go build ./... && go test ./internal/scanner/... -v`
Expected: PASS (all tests, including Task 1's and the pre-existing `network_health_test.go` tests)

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/speedrank.go internal/scanner/speedrank_test.go
git commit -m "feat: add upload fallback endpoint chain to speed rank (was Cloudflare-only, no fallback)"
```

---

### Task 3: Add the ranked HTML report writer

**Files:**
- Create: `internal/scanner/speed_report_html.go`
- Test: `internal/scanner/speed_report_html_test.go`

**Interfaces:**
- Consumes: `SpeedRankResult` (Task 2's shape, with `UploadSource`), `storage.AtomicWriteText` (`internal/storage`, used identically to `WriteSpeedRankCSV` at `speedrank.go:509-527`).
- Produces: `WriteSpeedRankHTML(dataDir string, results []SpeedRankResult) (string, error)` — writes a timestamped HTML file under `<dataDir>/whitedns logs/speedrank-<stamp>.html` (same directory/naming convention as `WriteSpeedRankCSV`) and returns its path. Assumes `results` is already sorted (the caller — `SpeedRankIPs` — always returns pre-sorted results).

- [ ] **Step 1: Write the failing test**

```go
package scanner

import (
	"os"
	"strings"
	"testing"
)

func TestWriteSpeedRankHTMLContainsRankedRows(t *testing.T) {
	dir := t.TempDir()
	results := []SpeedRankResult{
		{IP: "1.1.1.1", Port: 443, Reachable: true, DownloadMbps: 123.45, UploadMbps: 12.3, LatencyMs: 20, JitterMs: 2, LossPct: 0, Score: 130.1, Source: "cloudflare", UploadSource: "cloudflare"},
		{IP: "2.2.2.2", Port: 443, Reachable: true, DownloadMbps: 50.0, UploadMbps: 5.0, LatencyMs: 80, JitterMs: 5, LossPct: 16.7, Score: 40.2, Source: "cachefly", UploadSource: "httpbin"},
		{IP: "3.3.3.3", Port: 443, Reachable: false, Error: "no successful handshake"},
	}

	path, err := WriteSpeedRankHTML(dir, results)
	if err != nil {
		t.Fatalf("WriteSpeedRankHTML failed: %v", err)
	}
	if !strings.Contains(path, "whitedns logs") || !strings.HasSuffix(path, ".html") {
		t.Fatalf("unexpected path: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read report: %v", err)
	}
	html := string(data)
	for _, want := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "123.45", "cloudflare", "cachefly", "no successful handshake"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected html to contain %q, got:\n%s", want, html)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run TestWriteSpeedRankHTMLContainsRankedRows -v`
Expected: FAIL to compile (`WriteSpeedRankHTML` doesn't exist).

- [ ] **Step 3: Implement**

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scanner/ -run TestWriteSpeedRankHTMLContainsRankedRows -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/speed_report_html.go internal/scanner/speed_report_html_test.go
git commit -m "feat: add ranked, sortable HTML report for speed rank results"
```

---

### Task 4: Delete the dead, discard-the-result throughput prober

**Files:**
- Modify: `internal/scanner/network_health.go`
- Modify: `internal/scanner/ips.go`
- Modify: `internal/scanner/ips_optimized.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing new — this is pure deletion. Confirms (via Step 1) that nothing outside this dead code path references the removed symbols before deleting.

- [ ] **Step 1: Confirm no other callers**

Run: `grep -rn "runTransferBenchmarkAsync\|benchmarkEndpointTransfer\|benchmarkDirectEndpointTransfer\|proxyTransferBenchmarkSummary\|defaultEndpointTransferDomains\|transferTagForDomain" --include=*.go .`
Expected: only hits inside `internal/scanner/network_health.go` itself, plus the two call sites `internal/scanner/ips.go:830` and `internal/scanner/ips_optimized.go:162`.

- [ ] **Step 2: Remove the call sites**

In `internal/scanner/ips.go`, delete line 761 (`benchSem := make(chan struct{}, 3)`) and its doc comment (lines 759-760), and delete the `if !probeOpts.LowBandwidth { s.runTransferBenchmarkAsync(...) }` block at lines 829-831, leaving the surrounding accept-log/resultLine code intact.

In `internal/scanner/ips_optimized.go`, delete the equivalent `benchSem := make(chan struct{}, 3)` (line 100) and the `s.runTransferBenchmarkAsync(...)` call (line 162) the same way.

- [ ] **Step 3: Remove the dead functions from network_health.go**

Delete from `internal/scanner/network_health.go`: `proxyTransferBenchmarkSummary` (694-703), `runTransferBenchmarkAsync` (705-732), `benchmarkEndpointTransfer` (734-771), `benchmarkDirectEndpointTransfer` (773-830), and `transferTagForDomain` plus `defaultEndpointTransferDomains` if Step 1's grep confirmed no other callers. Remove now-unused imports (`bytes`, `strconv` — check with `go build` in Step 4) if they become unused as a result.

- [ ] **Step 4: Build and run the existing test suite**

Run: `go build ./... && go test ./internal/scanner/... -v`
Expected: PASS. `network_health_test.go`'s tests (`TestTransportHealthSummaryUsesOverride`, `TestScanIPsWithProgressLocalHTTP`, etc.) do not reference the deleted functions and must still pass unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/network_health.go internal/scanner/ips.go internal/scanner/ips_optimized.go
git commit -m "refactor: delete dead post-accept transfer benchmark (computed speed, discarded into a log line, never stored)"
```

---

### Task 5: Wire the desktop TUI's main IP scan to speed-rank and report its results

**Files:**
- Modify: `internal/ui/tui.go`

**Interfaces:**
- Consumes: `scanner.SpeedRankIPs(ctx, ips []string, opts scanner.SpeedRankOptions, progressCb func(processed, total, reachable int, currentIP string)) []scanner.SpeedRankResult` (existing, `speedrank.go:151`), `scanner.FormatSpeedRankLine(rank int, r scanner.SpeedRankResult) string` (existing, `speedrank.go:491`), `scanner.WriteSpeedRankCSV(dataDir string, results []scanner.SpeedRankResult) (string, error)` (existing, `speedrank.go:509`), `scanner.WriteSpeedRankHTML(dataDir string, results []scanner.SpeedRankResult) (string, error)` (Task 3).
- Produces: for `opType == "scan_ips"`, the `results []string` inside `poolOperationCompleteMsg` (built around `tui.go:3369-3378`) becomes speed-ranked, sorted, formatted lines instead of raw unsorted `"ip:port\tdomains"` lines; two report files are written and logged.

- [ ] **Step 1: Locate and read the exact current code to replace**

Run: `grep -n "results, err := scannerInst.ScanIPsWithProgress" internal/ui/tui.go`
Confirm it is still at (or near) line 3369, inside the `func() tea.Msg` closure that starts around line 3161 (the non-SNI branch of `cmdPoolOperation`, reached only when `opType` is `"scan_ips"`, `"sni_scanner"`, or `"desync_scanner"` and the earlier `isSNI` branch was not taken).

- [ ] **Step 2: Replace the block**

Replace `internal/ui/tui.go:3369-3378`:

```go
				results, err := scannerInst.ScanIPsWithProgress(targets, opts, progressCb)
				if err != nil {
					close(ch)
					return poolOperationCompleteMsg{operationType: opType, err: err, duration: time.Since(t0)}
				}
				if len(results) == 0 {
					results = []string{"No responding IPs found"}
				}
				close(ch)
				return poolOperationCompleteMsg{operationType: opType, results: results, duration: time.Since(t0)}
```

with:

```go
				results, err := scannerInst.ScanIPsWithProgress(targets, opts, progressCb)
				if err != nil {
					close(ch)
					return poolOperationCompleteMsg{operationType: opType, err: err, duration: time.Since(t0)}
				}
				if len(results) == 0 {
					results = []string{"No responding IPs found"}
				} else if opType == "scan_ips" {
					// Real, sorted speed data for the main scan's results — reuses the
					// same benchmark engine as the dedicated Speed Rank feature instead
					// of leaving results unsorted with no download/upload numbers.
					select {
					case ch <- logMsg{text: fmt.Sprintf("[SPEED-RANK] benchmarking %d accepted IPs...", len(results))}:
					default:
					}
					speedResults := scanner.SpeedRankIPs(runCtx, results, scanner.SpeedRankOptions{}, func(processed, total, reachable int, currentIP string) {
						select {
						case ch <- scanProgressMsg{current: processed, total: total, hits: reachable, startTime: start, currentIP: currentIP, totalIPs: total}:
						default:
						}
					})
					formatted := make([]string, len(speedResults))
					for i, r := range speedResults {
						formatted[i] = scanner.FormatSpeedRankLine(i+1, r)
					}
					results = formatted
					if csvPath, err := scanner.WriteSpeedRankCSV(m.app.DataDir, speedResults); err == nil {
						select {
						case ch <- logMsg{text: "[SPEED-RANK] csv report: " + csvPath}:
						default:
						}
					}
					if htmlPath, err := scanner.WriteSpeedRankHTML(m.app.DataDir, speedResults); err == nil {
						select {
						case ch <- logMsg{text: "[SPEED-RANK] html report: " + htmlPath}:
						default:
						}
					}
				}
				close(ch)
				return poolOperationCompleteMsg{operationType: opType, results: results, duration: time.Since(t0)}
```

`runCtx` and `start` must be in scope at this point — confirm via Step 1's read; if the closure at this point doesn't already have a context variable named `runCtx`, use `m.scanCtx` directly (falling back to `context.Background()` if nil), matching the pattern already used at `tui.go:3265-3268`. Similarly, if `start` is not in scope, use `t0`.

- [ ] **Step 3: Build**

Run: `go build ./...`
Expected: no errors. Fix any scope mismatches found in Step 2 (exact variable names for the context/start-time depend on what Step 1's read shows).

- [ ] **Step 4: Manual verification**

Run the TUI (`go run ./cmd/whitedns`), run a small "Find Clean IPs" scan against a known-reachable test CIDR, and confirm: (a) results in the final list show `DOWN ... Mbps  UP ... Mbps  LOSS ...% RTT ...ms` (via `FormatSpeedRankLine`) instead of bare `ip:port`, (b) they appear best-score-first, (c) two `[SPEED-RANK] ... report:` log lines appear with paths under `<DataDir>/whitedns logs/`, and (d) opening the `.html` path in a browser shows a ranked, click-to-sort table.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/tui.go
git commit -m "feat: speed-rank and report the main IP scan's accepted results (real download/upload/ping, sorted best-first)"
```

---

### Task 6: Raise the Android speed-rank IP cap from 256 to 2000

**Files:**
- Modify: `mobile/api.go:1075`

**Interfaces:**
- Consumes: nothing new.
- Produces: `maxSpeedRankIPs` constant value change only.

- [ ] **Step 1: Write the failing test**

```go
package mobile

import "testing"

func TestMaxSpeedRankIPsRaised(t *testing.T) {
	if maxSpeedRankIPs != 2000 {
		t.Fatalf("expected maxSpeedRankIPs = 2000, got %d", maxSpeedRankIPs)
	}
}
```

Add to a new file `mobile/api_test.go` if one doesn't already exist, or append if it does — check first with `ls mobile/*_test.go`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mobile/ -run TestMaxSpeedRankIPsRaised -v`
Expected: FAIL (`maxSpeedRankIPs` is 256).

- [ ] **Step 3: Change the constant**

In `mobile/api.go:1075`, change:

```go
const maxSpeedRankIPs = 256
```

to:

```go
const maxSpeedRankIPs = 2000
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mobile/ -run TestMaxSpeedRankIPsRaised -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add mobile/api.go mobile/api_test.go
git commit -m "feat: raise Android speed-rank IP cap from 256 to 2000"
```

---

### Task 7: Add the Android "Speed Test" toggle to the scan config form

**Files:**
- Modify: `android/app/src/main/java/com/whitescan/app/ui/ScanConfigForm.kt`

**Interfaces:**
- Consumes: existing `FormState` data class (`ScanConfigForm.kt:21-39`), existing `Switch`/`Row`/`Column` Compose pattern used by `e2eEnabled` (`ScanConfigForm.kt:248-259`).
- Produces: `FormState.speedTestEnabled: Boolean` (default `false`) — Task 8 reads this field by name.

- [ ] **Step 1: Add the field to `FormState`**

In `android/app/src/main/java/com/whitescan/app/ui/ScanConfigForm.kt`, in the `FormState` data class (around line 35, next to `e2eEnabled`), add:

```kotlin
    val speedTestEnabled: Boolean = false,
```

- [ ] **Step 2: Render the toggle**

In the `ScanKind.IP` section of the form (find the block that renders IP-scan-specific options — the same section where port/concurrency fields for `ScanKind.IP` live), add a `Switch` row mirroring the `e2eEnabled` one at `ScanConfigForm.kt:248-259`:

```kotlin
Row(verticalAlignment = Alignment.CenterVertically) {
    Switch(
        checked = form.speedTestEnabled,
        onCheckedChange = { onFormChange(form.copy(speedTestEnabled = it)) },
    )
    Column {
        Text("Speed Test")
        Text(
            "After this scan finds IPs, automatically rank them by download/upload speed and ping.",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}
```

Match whatever `Row`/`Column`/`Text` styling parameters the neighboring `e2eEnabled` block actually uses (padding, `Modifier`, `MaterialTheme.typography` variant) — copy them exactly rather than inventing new styling, so the new toggle looks identical to existing ones.

- [ ] **Step 3: Build the Android app**

Run: `cd android && ./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Manual verification**

Launch the app, select an IP scan, confirm the "Speed Test" toggle appears in the IP-scan config section, defaults off, and can be switched on.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/java/com/whitescan/app/ui/ScanConfigForm.kt
git commit -m "feat(android): add Speed Test toggle to IP scan config"
```

---

### Task 8: Auto-chain the Speed Rank scan onto a completed IP scan when the toggle is on

**Files:**
- Modify: `android/app/src/main/java/com/whitescan/app/MainActivity.kt`

**Interfaces:**
- Consumes: `form.speedTestEnabled` (Task 7), `scanState.savedPath` (existing, `ScanUiState`), `ScanKind.SPEED` and `Mobile.startSpeedRankScan` (existing — already wired at `ScanViewModel.kt:74`), the existing `LaunchedEffect(scanState.done)` block (`MainActivity.kt:145-173`) and its DNS→E2E precedent.
- Produces: when an IP scan finishes with the toggle on, a `ScanKind.SPEED` scan auto-launches using the saved IP file as targets — no new public interface, this is UI orchestration only.

- [ ] **Step 1: Read the current `LaunchedEffect(scanState.done)` block**

Run: `grep -n "LaunchedEffect(scanState.done)" -A 30 android/app/src/main/java/com/whitescan/app/MainActivity.kt`
Confirm the exact current structure of the `finishedKind == ScanKind.DNS && form.e2eEnabled` branch (`MainActivity.kt:145-167` per prior investigation) so the new branch is added with matching style/indentation and doesn't disturb the existing DNS→E2E chain.

- [ ] **Step 2: Add the IP→SPEED chain branch**

Add a sibling `if` branch alongside the existing `finishedKind == ScanKind.DNS && form.e2eEnabled` one, before the fallback `screen = Screen.Results` line:

```kotlin
if (finishedKind == ScanKind.IP && form.speedTestEnabled) {
    val ipsPath = scanState.savedPath
    if (!ipsPath.isNullOrEmpty()) {
        val speedCfg = form.copy(targets = "@$ipsPath").toEngineConfig(...)
        stopForegroundScanService()
        screen = Screen.Scanning(ScanKind.SPEED)
        startForegroundScanService(ScanKind.SPEED)
        vm.start(ScanKind.SPEED, dir, speedCfg)
        return@LaunchedEffect
    }
}
```

Fill in `toEngineConfig(...)`'s actual arguments by copying them exactly from the neighboring `e2eCfg = form.copy(targets = "@$trPath").toEngineConfig(...)` call found in Step 1 — do not guess the parameter list, use what that call site already passes.

- [ ] **Step 3: Build**

Run: `cd android && ./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Manual verification**

With the Speed Test toggle on, run an IP scan against a small target range that will find at least one IP. Confirm: (a) after the IP scan completes, the screen transitions straight into a `ScanKind.SPEED` scan (not the results screen) without user action, (b) that scan's targets are the IPs the first scan just found, (c) once it finishes, the results screen shows speed-ranked results sorted best-first with real Mbps numbers. Also confirm with the toggle off that behavior is unchanged (IP scan finishes straight to Results screen, as today).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/java/com/whitescan/app/MainActivity.kt
git commit -m "feat(android): auto-chain Speed Rank scan onto IP scan results when Speed Test toggle is on"
```
