package ui

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"whitedns-go/internal/dnstt"
	"whitedns-go/internal/e2e"
)

// DNSTT end-to-end tunnel test screens, offered after a DNS scan completes. The
// flow mirrors range-scout: scan → score → (offer) end-to-end validation. The
// operator confirms, enters the DNSTT domain + public key + transport, then the
// tunnel-ready shortlist is validated by bringing up a real tunnel through each
// resolver and keeping only the ones that carry traffic end-to-end.
const (
	screenE2EPrompt    = "e2e_prompt"
	screenE2EDomain    = "e2e_domain"
	screenE2EPubKey    = "e2e_pubkey"
	screenE2ETransport = "e2e_transport"
)

// e2ePromptItems are the yes/no choices shown right after a DNS scan.
var e2ePromptItems = []string{
	"Yes — run the end-to-end tunnel test on the tunnel-ready resolvers",
	"No — just show the DNS scan results",
}

// e2eTransportPreset couples a transport label with its engine value and whether
// it is implemented. UDP/53 and TCP/53 are wired up (TCP reaches servers where
// UDP/53 is poisoned); dnstt's DoT/DoH aren't vendored yet, so those are shown
// but gated so the option set is clear without misleading the operator.
type e2eTransportPreset struct {
	label   string
	value   string
	enabled bool
}

var e2eTransportPresets = []e2eTransportPreset{
	{"UDP  (DNS over UDP/53)", "udp", true},
	{"TCP  (DNS over TCP/53 — use where UDP/53 is poisoned)", "tcp", true},
	{"DoT  (DNS over TLS — coming soon)", "dot", false},
	{"DoH  (DNS over HTTPS — coming soon)", "doh", false},
}

// extractLeadingIPs pulls the clean leading IP from each formatted result line
// (the DNS scan renders "1.2.3.4  score=…"), skipping placeholder/non-IP lines,
// so the tunnel-ready shortlist can be fed to the E2E test as clean targets.
func extractLeadingIPs(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		if net.ParseIP(fields[0]) != nil {
			out = append(out, fields[0])
		}
	}
	return out
}

// handleE2EPromptScreen offers the yes/no E2E choice after a DNS scan.
func (m tuiModel) handleE2EPromptScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(e2ePromptItems)-1 {
			m.cursor++
		}
	case "esc":
		// Declining the E2E test drops to the normal DNS results view.
		m.screen = screenScanResults
		m.cursor = 0
	case "enter":
		if m.cursor == 0 {
			m.e2eTransport = "udp"
			m.ti.SetValue("")
			cmd := m.ti.Focus()
			m.pushScreen(screenE2EDomain)
			return m, cmd
		}
		m.screen = screenScanResults
		m.cursor = 0
	}
	return m, nil
}

// viewE2EPrompt renders the post-DNS-scan yes/no choice.
func (m tuiModel) viewE2EPrompt(w, h int) string {
	title := fmt.Sprintf("END-TO-END TUNNEL TEST  (%d tunnel-ready resolver(s))", len(m.e2eShortlist))
	return m.viewList(w, h, title, e2ePromptItems,
		"↑↓ navigate  ·  Enter select  ·  Esc skip to results")
}

// handleE2EDomainScreen captures the DNSTT domain.
func (m tuiModel) handleE2EDomainScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	if m.pasteClipboardIntoInput(msg, false) {
		return m, nil
	}
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
		domain := strings.TrimSpace(m.ti.Value())
		if domain == "" {
			m.setToast(sError.Render("A DNSTT domain is required"), 3*time.Second)
			return m, nil
		}
		m.e2eDomain = domain
		m.ti.SetValue("")
		cmd := m.ti.Focus()
		m.pushScreen(screenE2EPubKey)
		return m, cmd
	}
	m.ti, _ = m.ti.Update(msg)
	return m, nil
}

// handleE2EPubKeyScreen captures the DNSTT public key (blank allowed =
// reachability-only), then advances to the transport picker.
func (m tuiModel) handleE2EPubKeyScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	if m.pasteClipboardIntoInput(msg, false) {
		return m, nil
	}
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
		m.e2ePubKey = strings.TrimSpace(m.ti.Value())
		m.ti.Blur()
		m.pushScreen(screenE2ETransport)
		m.cursor = 0
		return m, nil
	}
	m.ti, _ = m.ti.Update(msg)
	return m, nil
}

// handleE2ETransportScreen picks the transport and launches the test. Non-UDP
// options are gated with a toast until they are implemented.
func (m tuiModel) handleE2ETransportScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch k.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(e2eTransportPresets)-1 {
			m.cursor++
		}
	case "esc":
		m.goBack()
	case "enter":
		p := e2eTransportPresets[m.cursor]
		if !p.enabled {
			m.setToast(sWarn.Render(p.label+" is not available yet — UDP only for now"), 3*time.Second)
			return m, nil
		}
		m.e2eTransport = p.value
		return m.launchE2ETest()
	}
	return m, nil
}

// viewE2ETransport renders the transport picker; gated options are dimmed.
func (m tuiModel) viewE2ETransport(w, h int) string {
	items := make([]string, len(e2eTransportPresets))
	for i, p := range e2eTransportPresets {
		if p.enabled {
			items[i] = p.label
		} else {
			items[i] = sDim.Render(p.label)
		}
	}
	return m.viewList(w, h, "E2E TRANSPORT", items,
		"↑↓ navigate  ·  Enter start test  ·  Esc back")
}

// launchE2ETest starts the end-to-end validation over the tunnel-ready shortlist,
// reusing the shared scanMsgCh + screenScanning + screenScanResults machinery.
func (m tuiModel) launchE2ETest() (tuiModel, tea.Cmd) {
	m.operationType = "e2e"
	m.startOperation()
	m.scanMsgCh = make(chan tea.Msg, 65536)
	m.startScanLogFile("e2e", m.e2eShortlist, nil, 4, 20*time.Second)
	m.addLog(fmt.Sprintf("Starting DNSTT end-to-end test: resolvers=%d domain=%s transport=%s key=%v",
		len(m.e2eShortlist), m.e2eDomain, m.e2eTransport, m.e2ePubKey != ""))
	return m, m.cmdE2ETest()
}

// cmdE2ETest runs the DNSTT end-to-end validation on a background goroutine,
// streaming per-resolver progress to the activity log and returning the passed
// (end-to-end validated) resolver IPs as the result set.
func (m tuiModel) cmdE2ETest() tea.Cmd {
	ch := m.scanMsgCh
	if ch == nil {
		ch = make(chan tea.Msg, 65536)
	}
	runCtx := m.scanCtx
	resolvers := append([]string(nil), m.e2eShortlist...)
	domain := m.e2eDomain
	pubkey := m.e2ePubKey
	transport := e2e.TransportUDP
	if m.e2eTransport == "tcp" {
		transport = e2e.TransportTCP
	}

	return tea.Batch(
		func() tea.Msg {
			t0 := time.Now()
			if runCtx == nil {
				runCtx = context.Background()
			}
			start := time.Now()
			total := len(resolvers)

			trySend := func(msg tea.Msg) {
				select {
				case ch <- msg:
				case <-time.After(50 * time.Millisecond):
				}
			}

			trySend(logMsg{text: fmt.Sprintf("[E2E] validating %d resolver(s) via DNSTT tunnel to %s", total, domain)})
			trySend(scanProgressMsg{current: 0, total: total, startTime: start, totalIPs: total})

			opts := e2e.Options{
				Domain:      domain,
				PubKey:      pubkey,
				Transport:   transport,
				Timeout:     20 * time.Second,
				Concurrency: 4,
			}

			hits := 0
			progress := func(done, tot int, r e2e.Result) {
				status := "fail"
				if r.OK {
					status = "PASS"
					hits++
				}
				trySend(logMsg{text: fmt.Sprintf("%-21s %-4s %s", r.Resolver, status, r.Reason)})
				trySend(scanProgressMsg{current: done, total: tot, hits: hits, startTime: start, currentIP: r.Resolver, totalIPs: tot})
			}

			results := e2e.Run(runCtx, resolvers, opts, dnstt.NewValidator(), progress)
			passed := e2e.PassedResolvers(results)
			trySend(logMsg{text: fmt.Sprintf("[E2E] done: %d passed end-to-end of %d tested", len(passed), total)})
			close(ch)

			if err := runCtx.Err(); err != nil {
				return poolOperationCompleteMsg{operationType: "e2e", results: passed, err: err, duration: time.Since(t0)}
			}
			if len(passed) == 0 {
				passed = []string{"No resolvers passed the end-to-end test"}
			}
			return poolOperationCompleteMsg{operationType: "e2e", results: passed, duration: time.Since(t0)}
		},
		waitForScanMessage(ch),
	)
}
