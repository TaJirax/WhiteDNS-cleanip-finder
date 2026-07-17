# Robust Speed Test — Design Spec

Date: 2026-07-17

## Problem

Two separate, disconnected speed-measurement code paths exist:

1. **Speed Rank** (`internal/scanner/speedrank.go`) — a dedicated benchmark feature. Works correctly (measures download/upload/latency/loss, sorts by score, exports CSV) but: has a weak fallback chain (one useless reachability-only probe, no upload fallback at all), and is hard-capped to 256 IPs on Android only.
2. **Main "find clean IPs" scan** — has its own separate, cruder throughput prober (`internal/scanner/network_health.go`) that computes download/upload speed per accepted IP but only ever writes it to a transient log line. `ProbeResult` has no field to store it. The main results list has no sort at all (not by speed, not by ping).

The user wants: real download/upload numbers reported for scan results, results ranked by speed/ping, no artificial 256-IP ceiling, more (and more legitimate) fallback speed-test endpoints, and a readable HTML report of ranked results. Plus, on Android specifically, a "Speed Test" toggle that auto-chains a Speed Rank pass onto IPs found by a completed main scan.

## Scope

Both desktop (Go TUI) and Android (Kotlin/Compose), sharing the Go core.

## Design

### 1. Delete the dead prober; reuse `SpeedRankIPs` as a post-scan pass

`internal/scanner/ips.go`'s `ScanIPsWithProgress` (and the optimized pipeline) already return the full accepted-IP list as a flat `[]string` once scanning finishes — it is not a live-only stream the caller must sort mid-flight. That makes threading new fields through `ProbeResult`/the hot probe path unnecessary.

- Delete `runTransferBenchmarkAsync`, `benchmarkEndpointTransfer`, `benchmarkDirectEndpointTransfer` in `internal/scanner/network_health.go` and their call sites (`internal/scanner/ips.go:830`, `ips_optimized.go:162`, plus the now-unused `benchSem` pool). Confirmed via grep: these functions have no other callers.
- No changes to `ProbeResult` (`internal/scanner/types.go`) — out of scope now.
- **Desktop TUI** (`internal/ui/tui.go`, the ip-scan branch around line 3369): after `scannerInst.ScanIPsWithProgress(...)` returns its accepted `[]string`, immediately run `scanner.SpeedRankIPs(ctx, results, scanner.SpeedRankOptions{}, progressCb)` on that list, then use the sorted, formatted output (`FormatSpeedRankLine`) as the final results list instead of the raw unsorted accepted lines. One measurement pass, real numbers, already sorted — no separate TUI-side `sort.Slice` needed since `SpeedRankIPs` already sorts by `Score` desc.
- **Android**: no core `mobile/api.go` `StartIPScan` change needed for this part — mobile already streams accepted IPs to disk in memory-bounded chunks (`runChunk`, `mobile/api.go:531-554`), so holding a full slice to speed-rank inline would fight that design. Instead, Android gets speed-ranking via the toggle+auto-chain described in section 6 below, which launches the *existing*, already-correct `StartSpeedRankScan` (`SpeedRankIPs` under the hood) as a second scan over the saved IP file. Its results already render sorted with real Mbps numbers today (confirmed: Speed Rank output is pre-sorted server-side and Android just renders it in order) — no `ResultsScreen.kt` changes needed either.

### 2. (removed — superseded by section 1; no `ProbeResult` changes)

### 3. (removed — superseded by section 1; sorting comes for free from `SpeedRankIPs`, no separate UI-side sort code needed on either platform)

### 4. Fallback endpoint chains — real, known, public, max 3 each

**Download** (`DefaultSpeedEndpoints`, `speedrank.go:68-86`):
1. Cloudflare `speed.cloudflare.com/__down?bytes=N` — `PinToCandidate: true` (unchanged; dials the candidate IP directly, real measurement of that specific IP).
2. Cachefly `cachefly.cachefly.net/10mb.test` — industry-standard public bandwidth test file (replaces current `/50mb.test`; unpinned — measures the box's general path, not the candidate IP specifically, but real bytes transferred).
3. Hetzner `speed.hetzner.de/100MB.bin` — official public speed-test file, well known, unpinned.
4. Google `www.google.com/generate_204` — kept as a **last-resort reachability-only** entry (`Reachability: true`, 0 bytes, no Mbps claimed). Google has no stable public bandwidth-test file, so this isn't counted as a throughput fallback like the other three; it only distinguishes "network is up but every real download endpoint failed" from total failure.

**Upload** (new: `measureUpload` becomes a fallback list, matching the download pattern, instead of a single hardcoded Cloudflare call):
1. Cloudflare `speed.cloudflare.com/__up` — pinned (unchanged, real).
2. `postman-echo.com/post` — well-known public API-testing echo endpoint; doesn't persist the uploaded body.
3. `httpbin.org/post` — same category, long-established, doesn't persist the body.

Only Cloudflare is `PinToCandidate` — the other two measure the local network path, not that specific IP, and are labeled "unpinned" in results/report so pinned Cloudflare data is weighted higher in scoring when available.

### 5. HTML report

New `WriteSpeedRankHTML(dataDir string, results []SpeedRankResult) (string, error)` in `internal/scanner`, alongside the existing `internal/dnsscan/report.go` `writeHTML` pattern: plain `strings.Builder`, inline `<style>` block, `html.EscapeString` for all values, no template engine or new dependency. Ranked table columns: rank #, IP:port, download Mbps, upload Mbps, latency ms, jitter ms, loss %, score, pinned/unpinned indicator (derived from `Source`/`UploadSource` == `"cloudflare"`). Small inline vanilla JS for click-to-sort columns. Since the main scan now produces `[]SpeedRankResult` too (section 1), this one writer serves both the main scan's results and the dedicated Speed Rank feature's results. Written next to existing CSV/text output in `dataDir` on both desktop and Android.

### 6. Remove the IP ceiling; Android auto-chain toggle

- `mobile/api.go:1075`: raise `maxSpeedRankIPs` from 256 to 2000.
- Desktop: already uncapped (no code change needed).
- Android: add `speedTestEnabled: Boolean = false` to `FormState` (`android/app/src/main/java/com/whitescan/app/ui/ScanConfigForm.kt`), rendered as a `Switch` in the `ScanKind.IP` section, mirroring the existing `e2eEnabled` toggle exactly (state/rendering pattern at `ScanConfigForm.kt:21-39` and `:248-259`).
- In `MainActivity.kt`'s `LaunchedEffect(scanState.done)` (`MainActivity.kt:145-173`), add a sibling branch next to the existing DNS→E2E auto-chain: when `finishedKind == ScanKind.IP && form.speedTestEnabled`, auto-launch `ScanKind.SPEED` using `scanState.savedPath` as `@file` targets — same mechanism the DNS→E2E chain already uses.

## Out of scope

- No new external dependency for HTML generation (matches existing hand-built string approach).
- No user-configurable endpoint list — hardcoded list like today, just corrected/expanded.
- No retry/backoff framework redesign beyond what `benchmarkOneIP` already does.

## Testing

- Unit test: `measureUpload`/`measureEndpoint` fallback-chain iteration (first endpoint fails → falls through to next; all fail → error).
- Unit test: sort-by-score ordering on a mixed result set (desktop and, where feasible, Android).
- Manual: run a main scan with `speedTestEnabled` on Android, confirm Speed Rank auto-launches on completion and HTML report renders with correct ranking.
