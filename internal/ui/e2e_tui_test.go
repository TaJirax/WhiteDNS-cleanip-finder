package ui

import (
	"sync"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

func keyEnter() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyEnter} }
func keyDown() tea.KeyMsg  { return tea.KeyMsg{Type: tea.KeyDown} }

func TestExtractLeadingIPs(t *testing.T) {
	lines := []string{
		"1.2.3.4              score=6/6 poison=false transparent=false",
		"5.6.7.8              score=5/6 poison=false transparent=false [nearby]",
		"No tunnel-ready resolvers found (see 'dns scan' folder + activity log)",
		"   ",
	}
	got := extractLeadingIPs(lines)
	want := []string{"1.2.3.4", "5.6.7.8"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

// TestE2ETUIFlowHappyPath drives the full post-DNS-scan E2E flow through the
// model's screen handlers: prompt(Yes) → domain → pubkey → transport(TCP) →
// launch, asserting each transition and the captured config. The launch's
// returned tea.Cmd is intentionally not run, so no real tunnel is attempted.
func TestE2ETUIFlowHappyPath(t *testing.T) {
	ti := textinput.New()
	m := tuiModel{
		app:           &App{DataDir: t.TempDir()},
		screen:        screenE2EPrompt,
		cursor:        0,
		ti:            ti,
		scanLogMu:     &sync.Mutex{},
		transferLogMu: &sync.Mutex{},
		scanOutputMu:  &sync.Mutex{},
		e2eShortlist:  []string{"1.2.3.4", "5.6.7.8"},
	}

	// Prompt: Yes (cursor 0) → domain screen; default transport primed to udp.
	m, _ = m.handleE2EPromptScreen(keyEnter())
	if m.screen != screenE2EDomain {
		t.Fatalf("after Yes: screen=%q want %q", m.screen, screenE2EDomain)
	}
	if m.e2eTransport != "udp" {
		t.Fatalf("default transport=%q want udp", m.e2eTransport)
	}

	// Domain input.
	m.ti.SetValue("t.example.com")
	m, _ = m.handleE2EDomainScreen(keyEnter())
	if m.screen != screenE2EPubKey {
		t.Fatalf("after domain: screen=%q want %q", m.screen, screenE2EPubKey)
	}
	if m.e2eDomain != "t.example.com" {
		t.Fatalf("domain=%q want t.example.com", m.e2eDomain)
	}

	// Public key input.
	m.ti.SetValue("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	m, _ = m.handleE2EPubKeyScreen(keyEnter())
	if m.screen != screenE2ETransport {
		t.Fatalf("after pubkey: screen=%q want %q", m.screen, screenE2ETransport)
	}
	if m.e2ePubKey == "" {
		t.Fatalf("pubkey not captured")
	}

	// Transport: move to TCP (index 1) and select → launches (screen=scanning).
	m, _ = m.handleE2ETransportScreen(keyDown())
	m, _ = m.handleE2ETransportScreen(keyEnter())
	if m.e2eTransport != "tcp" {
		t.Fatalf("transport=%q want tcp", m.e2eTransport)
	}
	if m.screen != screenScanning {
		t.Fatalf("after launch: screen=%q want %q", m.screen, screenScanning)
	}
	if m.operationType != "e2e" {
		t.Fatalf("operationType=%q want e2e", m.operationType)
	}
}

// TestE2ETUITransportGating asserts a disabled transport (DoT) does not launch:
// it stays on the transport screen. UDP and TCP must be enabled; DoT/DoH not.
func TestE2ETUITransportGating(t *testing.T) {
	if !e2eTransportPresets[0].enabled || e2eTransportPresets[0].value != "udp" {
		t.Fatalf("expected UDP enabled at index 0")
	}
	if !e2eTransportPresets[1].enabled || e2eTransportPresets[1].value != "tcp" {
		t.Fatalf("expected TCP enabled at index 1")
	}
	for i := 2; i < len(e2eTransportPresets); i++ {
		if e2eTransportPresets[i].enabled {
			t.Fatalf("expected %q gated (disabled)", e2eTransportPresets[i].value)
		}
	}

	m := tuiModel{
		app:          &App{DataDir: t.TempDir()},
		screen:       screenE2ETransport,
		cursor:       2, // DoT (disabled)
		ti:           textinput.New(),
		e2eShortlist: []string{"1.2.3.4"},
		e2eDomain:    "t.example.com",
	}
	m, _ = m.handleE2ETransportScreen(keyEnter())
	if m.screen != screenE2ETransport {
		t.Fatalf("disabled transport should not launch; screen=%q", m.screen)
	}
	if m.operationType == "e2e" {
		t.Fatalf("disabled transport must not start an E2E operation")
	}
}

// TestE2ETUIPromptDecline asserts choosing "No" drops to the DNS results view.
func TestE2ETUIPromptDecline(t *testing.T) {
	m := tuiModel{
		screen:       screenE2EPrompt,
		cursor:       1, // No
		ti:           textinput.New(),
		e2eShortlist: []string{"1.2.3.4"},
	}
	m, _ = m.handleE2EPromptScreen(keyEnter())
	if m.screen != screenScanResults {
		t.Fatalf("after No: screen=%q want %q", m.screen, screenScanResults)
	}
}
