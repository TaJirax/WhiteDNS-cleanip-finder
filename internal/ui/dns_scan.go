package ui

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"whitedns-go/internal/dnsscan"
	"whitedns-go/internal/tlsprobe"
)

// launchDNSScan is invoked from the shared target-selection flow (ASN / paste /
// type / file import → review) once resolver targets are chosen. It reuses the
// standard scanMsgCh + screenScanning + screenScanResults machinery, so the DNS
// feature behaves exactly like the other scans.
func (m tuiModel) launchDNSScan(targets []string) (tuiModel, tea.Cmd) {
	m.startOperation() // pushes screenScanning + fresh scanCtx/counters
	m.scanMsgCh = make(chan tea.Msg, 65536)
	m.startScanLogFile("dnsscan", targets, nil, 64, 3*time.Second)
	m.addLog(fmt.Sprintf("Starting DNS resolver/tunnel scan: targets=%d", len(targets)))
	return m, m.cmdDNSScan(targets)
}

// cmdDNSScan runs the resolver scan on a background goroutine: it streams
// per-resolver progress + full header dumps to the activity log, optionally
// expands the /24 around tunnel-ready hits ("Test Nearby IPs"), dumps txt/csv/
// json reports into the "dns scan" output folder, and returns the tunnel-ready
// shortlist (best score first) as the final result set.
func (m tuiModel) cmdDNSScan(targets []string) tea.Cmd {
	ch := m.scanMsgCh
	if ch == nil {
		ch = make(chan tea.Msg, 65536)
	}
	runCtx := m.scanCtx
	dataDir := m.app.DataDir

	return tea.Batch(
		func() tea.Msg {
			t0 := time.Now()
			if runCtx == nil {
				runCtx = context.Background()
			}

			ips := tlsprobe.ExpandTargets(targets)
			if len(ips) == 0 {
				ips = targets
			}
			total := len(ips)
			start := time.Now()

			trySend := func(msg tea.Msg) {
				select {
				case ch <- msg:
				case <-time.After(50 * time.Millisecond):
				}
			}

			trySend(logMsg{text: fmt.Sprintf("[DNS] scanning %d resolver(s): headers + score + tunnel suitability", total)})
			trySend(scanProgressMsg{current: 0, total: total, startTime: start, totalIPs: total})

			opts := dnsscan.Options{
				TargetDomain: "google.com",
				Timeout:      3 * time.Second,
				Concurrency:  64,
				Protocol:     "all",
				TestNearby:   true,
			}

			var mu sync.Mutex
			hits := 0
			progress := func(done, tot int, r dnsscan.ResolverResult) {
				status := "no-response"
				if r.Responded {
					status = fmt.Sprintf("resp %dms", r.BestLatency.Milliseconds())
				}
				trySend(logMsg{text: fmt.Sprintf("%-21s %-13s score=%d/6 RA=%v EDNS=%v POISON=%v TXT=%v TRANSP=%v TUNNEL=%v (%s)",
					r.IP, status, r.Score, r.RA, r.EDNS, r.Poisoned, r.TxtPass, r.Transparent, r.TunnelReady, r.TunnelReason)})
				for _, hd := range r.HeaderDump() {
					trySend(logMsg{text: "    " + hd})
				}
				mu.Lock()
				if r.TunnelReady {
					hits++
				}
				h := hits
				mu.Unlock()
				trySend(scanProgressMsg{current: done, total: tot, hits: h, startTime: start, currentIP: r.IP, totalIPs: tot})
			}

			all := dnsscan.ScanResolvers(runCtx, ips, opts, progress)

			// Test Nearby IPs: expand the /24 around each tunnel-ready resolver
			// and rescan the addresses we haven't already tried.
			if opts.TestNearby && runCtx.Err() == nil {
				scanned := make(map[string]struct{}, len(ips))
				for _, ip := range ips {
					scanned[ip] = struct{}{}
				}
				var nearby []string
				for _, r := range all {
					if !r.TunnelReady {
						continue
					}
					for _, nip := range dnsscan.NearbyIPs(r.IP) {
						if _, ok := scanned[nip]; ok {
							continue
						}
						scanned[nip] = struct{}{}
						nearby = append(nearby, nip)
					}
				}
				if len(nearby) > 0 {
					trySend(logMsg{text: fmt.Sprintf("[DNS] Test Nearby IPs: expanding %d address(es) around tunnel-ready hits", len(nearby))})
					base := len(ips)
					nprogress := func(done, tot int, r dnsscan.ResolverResult) {
						progress(base+done, base+tot, r)
					}
					nres := dnsscan.ScanResolvers(runCtx, nearby, opts, nprogress)
					for i := range nres {
						nres[i].Nearby = true
					}
					all = append(all, nres...)
				}
			}

			// Dump every result to the "dns scan" folder (txt + csv + json).
			outDir := filepath.Join(dataDir, "dns scan")
			if paths, err := dnsscan.WriteReports(outDir, all); err != nil {
				trySend(logMsg{text: "[DNS] report write failed: " + err.Error()})
			} else {
				trySend(logMsg{text: "[DNS] reports written to " + paths.Dir})
				trySend(logMsg{text: "    " + filepath.Base(paths.Full) + " / " + filepath.Base(paths.CSV) + " / " + filepath.Base(paths.JSON)})
			}

			// Build the on-screen shortlist (tunnel-ready, best score first).
			var tunnelReady []string
			for _, r := range all {
				if !r.TunnelReady {
					continue
				}
				tag := ""
				if r.Nearby {
					tag = " [nearby]"
				}
				tunnelReady = append(tunnelReady, fmt.Sprintf("%-21s score=%d/6 poison=%v transparent=%v%s",
					r.IP, r.Score, r.Poisoned, r.Transparent, tag))
			}
			trySend(logMsg{text: fmt.Sprintf("[DNS] done: %d tunnel-ready of %d scanned", len(tunnelReady), len(all))})
			close(ch)

			if err := runCtx.Err(); err != nil {
				return poolOperationCompleteMsg{operationType: "dns_scan", results: tunnelReady, err: err, duration: time.Since(t0)}
			}
			if len(tunnelReady) == 0 {
				tunnelReady = []string{"No tunnel-ready resolvers found (see 'dns scan' folder + activity log)"}
			}
			return poolOperationCompleteMsg{operationType: "dns_scan", results: tunnelReady, duration: time.Since(t0)}
		},
		waitForScanMessage(ch),
	)
}
