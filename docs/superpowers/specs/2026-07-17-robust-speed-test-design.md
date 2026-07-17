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

### 1. Unify the two probe engines

Delete `runTransferBenchmarkAsync`, `benchmarkEndpointTransfer`, `benchmarkDirectEndpointTransfer` in `internal/scanner/network_health.go` and their call sites in `internal/scanner/ips.go:830` and `internal/scanner/ips_optimized.go:162`. Replace with a call into the same `benchmarkOneIP` engine `speedrank.go` already uses, run per accepted IP during the main scan. One accurate measurement engine, not two.

### 2. Store results on `ProbeResult`

Add to `internal/scanner/types.go` `ProbeResult`: `DownloadMbps`, `UploadMbps`, `LatencyMs`, `JitterMs`, `LossPct`, `Score float64`. Populate from the unified benchmark call. These persist to the result file/CSV instead of being discarded into a log line.

### 3. Sort results everywhere

- Desktop TUI (`internal/ui/tui.go`): sort the main scan results list by `Score` desc before rendering (same key Speed Rank uses).
- Android `ResultsScreen.kt`: sort the actual IP results list by score (today only the per-row domain-tag chips are sorted, not the list).

### 4. Fallback endpoint chains — real, known, public, max 3 each

**Download** (`DefaultSpeedEndpoints`, `speedrank.go:68-86`):
1. Cloudflare `speed.cloudflare.com/__down?bytes=N` — `PinToCandidate: true` (unchanged; dials the candidate IP directly, real measurement of that specific IP).
2. Cachefly `cachefly.cachefly.net/10mb.test` — industry-standard public bandwidth test file (replaces current `/50mb.test`; unpinned — measures the box's general path, not the candidate IP specifically, but real bytes transferred).
3. Hetzner `speed.hetzner.de/100MB.bin` — official public speed-test file, well known, unpinned.

Remove `google.com/generate_204` (0 bytes returned — measures reachability only, not throughput; this was reported as a no-op).

**Upload** (new: `measureUpload` becomes a fallback list, matching the download pattern, instead of a single hardcoded Cloudflare call):
1. Cloudflare `speed.cloudflare.com/__up` — pinned (unchanged, real).
2. `postman-echo.com/post` — well-known public API-testing echo endpoint; doesn't persist the uploaded body.
3. `httpbin.org/post` — same category, long-established, doesn't persist the body.

Only Cloudflare is `PinToCandidate` — the other two measure the local network path, not that specific IP, and are labeled "unpinned" in results/report so pinned Cloudflare data is weighted higher in scoring when available.

### 5. HTML report

New function alongside the existing `internal/dnsscan/report.go` `writeHTML` pattern: plain `strings.Builder`, inline `<style>` block, `html.EscapeString` for all values, no template engine or new dependency. Ranked table columns: rank #, IP:port, download Mbps, upload Mbps, latency ms, jitter ms, loss %, score, pinned/unpinned indicator. Small inline vanilla JS for click-to-sort columns. One shared function serves both the main scan's results and Speed Rank's results, since they now share the same result shape (`ProbeResult`/Speed Rank result fields align). Written next to existing CSV/text output in `dataDir` on both desktop and Android.

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
