package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
)

func newConfigMakerTestModel(tmpDir string) tuiModel {
	ti := textinput.New()
	m := tuiModel{
		app: &App{DataDir: tmpDir},
		ti:  ti,
	}
	m.initConfigMaker()
	return m
}

// pasteMsg simulates a bracketed-paste event delivering the given text in a
// single tea.KeyMsg, as most modern terminals do.
func pasteMsg(text string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(text), Paste: true}
}

var cmEnter = tea.KeyMsg{Type: tea.KeyEnter}

func TestConfigMakerRewriteFlowWithReviewScreens(t *testing.T) {
	if orig, err := clipboard.ReadAll(); err == nil {
		t.Cleanup(func() { clipboard.WriteAll(orig) })
	}

	tmpDir := t.TempDir()
	m := newConfigMakerTestModel(tmpDir)

	// Main menu -> "Rewrite configs" (cursor 0)
	m, _ = m.handleConfigMakerScreen(cmEnter)
	if m.tiStep != cmStepSourceMode {
		t.Fatalf("expected cmStepSourceMode, got %d", m.tiStep)
	}

	// Source mode -> "Paste CONFIG text" (cursor 0)
	m, _ = m.handleConfigMakerScreen(cmEnter)
	if m.tiStep != cmStepSourceText {
		t.Fatalf("expected cmStepSourceText, got %d", m.tiStep)
	}

	// Paste two configs as a single bracketed-paste event (newlines collapse to spaces).
	configText := "vless://uuid@old1.example.com:443?security=tls&type=ws#config1\n" +
		"vmess://uuid@old2.example.com:8443?type=ws#config2"
	m, _ = m.handleConfigMakerScreen(pasteMsg(configText))
	if err := clipboard.WriteAll(configText); err != nil {
		t.Skipf("clipboard unavailable in this environment: %v", err)
	}

	// First Enter should only arm the paste-confirm.
	m, _ = m.handleConfigMakerScreen(cmEnter)
	if m.tiStep != cmStepSourceText || !m.pasteConfirm {
		t.Fatalf("expected paste confirm armed, still on cmStepSourceText: tiStep=%d pasteConfirm=%v", m.tiStep, m.pasteConfirm)
	}

	// Push lastEnterTime back so the second Enter isn't mistaken for a
	// rapid-fire pasted-newline Enter (<50ms filter).
	m.lastEnterTime = m.lastEnterTime.Add(-time.Second)

	// Second Enter confirms and should move to the review screen.
	m, _ = m.handleConfigMakerScreen(cmEnter)
	if m.tiStep != cmStepSourceReview {
		t.Fatalf("expected cmStepSourceReview, got %d", m.tiStep)
	}
	configs := configMakerDecodeList(m.stepData["cm_source_configs"])
	if len(configs) != 2 {
		t.Fatalf("expected 2 parsed configs, got %d: %v", len(configs), configs)
	}

	// Confirm the review -> target mode.
	m, _ = m.handleConfigMakerScreen(cmEnter)
	if m.tiStep != cmStepTargetMode {
		t.Fatalf("expected cmStepTargetMode, got %d", m.tiStep)
	}

	// Target mode -> "Paste IP:port target list" (cursor 0)
	m, _ = m.handleConfigMakerScreen(cmEnter)
	if m.tiStep != cmStepTargetText {
		t.Fatalf("expected cmStepTargetText, got %d", m.tiStep)
	}

	// Paste multi-line target list as a single bracketed-paste event.
	targetText := "1.2.3.4:443\n5.6.7.8:8443"
	m, _ = m.handleConfigMakerScreen(pasteMsg(targetText))
	if err := clipboard.WriteAll(targetText); err != nil {
		t.Skipf("clipboard unavailable in this environment: %v", err)
	}

	// First Enter arms paste-confirm.
	m, _ = m.handleConfigMakerScreen(cmEnter)
	if m.tiStep != cmStepTargetText || !m.pasteConfirm {
		t.Fatalf("expected paste confirm armed, still on cmStepTargetText: tiStep=%d pasteConfirm=%v", m.tiStep, m.pasteConfirm)
	}

	// Push lastEnterTime back so the second Enter isn't mistaken for a
	// rapid-fire pasted-newline Enter (<50ms filter).
	m.lastEnterTime = m.lastEnterTime.Add(-time.Second)

	// Second Enter confirms -> review screen.
	m, _ = m.handleConfigMakerScreen(cmEnter)
	if m.tiStep != cmStepTargetReview {
		t.Fatalf("expected cmStepTargetReview, got %d", m.tiStep)
	}
	targets := configMakerDecodeList(m.stepData["cm_target_list"])
	if len(targets) != 2 {
		t.Fatalf("expected 2 parsed targets, got %d: %v", len(targets), targets)
	}

	// Confirm targets -> output path screen with default in the config maker folder.
	m, _ = m.handleConfigMakerScreen(cmEnter)
	if m.tiStep != cmStepOutputPath {
		t.Fatalf("expected cmStepOutputPath, got %d", m.tiStep)
	}
	wantDefault := filepath.Join(tmpDir, "config maker", "rewritten_configs.txt")
	if m.stepData["cm_output_default"] != wantDefault {
		t.Fatalf("unexpected output default: got %q want %q", m.stepData["cm_output_default"], wantDefault)
	}

	// Accept the default output path.
	m, _ = m.handleConfigMakerScreen(cmEnter)
	if m.screen != screenScanResults {
		t.Fatalf("expected screenScanResults after save, got %q (toast=%q)", m.screen, m.toast)
	}

	data, err := os.ReadFile(wantDefault)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "1.2.3.4:443") || !strings.Contains(out, "5.6.7.8:8443") {
		t.Fatalf("rewritten output missing expected targets: %q", out)
	}
}

func TestConfigMakerEscStepsBackInsteadOfExiting(t *testing.T) {
	tmpDir := t.TempDir()
	m := newConfigMakerTestModel(tmpDir)
	m.screen = screenConfigMaker

	esc := tea.KeyMsg{Type: tea.KeyEsc}

	// Main -> Rewrite -> SourceMode
	m, _ = m.handleConfigMakerScreen(cmEnter)
	if m.tiStep != cmStepSourceMode {
		t.Fatalf("expected cmStepSourceMode, got %d", m.tiStep)
	}

	// Esc from SourceMode should step back to Main, not exit config maker.
	m, _ = m.handleConfigMakerScreen(esc)
	if m.tiStep != cmStepMain || m.screen != screenConfigMaker {
		t.Fatalf("expected to stay in config maker at cmStepMain, got tiStep=%d screen=%q", m.tiStep, m.screen)
	}

	// Esc from Main exits config maker.
	m, _ = m.handleConfigMakerScreen(esc)
	if m.screen == screenConfigMaker {
		t.Fatalf("expected config maker to exit on Esc from main menu")
	}
}

func TestRewriteConfigMakerConfigsUsesAllTargets(t *testing.T) {
	// A single config with multiple pasted targets must produce one
	// rewritten config per target - previously only the first target was used.
	configs := []string{"vless://uuid@old.example.com:443?security=tls#name"}
	targets := []string{"1.2.3.4:443", "5.6.7.8:8443", "9.10.11.12:2053"}
	out := rewriteConfigMakerConfigs(configs, targets)
	if len(out) != len(targets) {
		t.Fatalf("expected %d outputs, got %d: %v", len(targets), len(out), out)
	}
	for i, target := range targets {
		if !strings.Contains(out[i], target) {
			t.Errorf("output %d missing target %s: %s", i, target, out[i])
		}
	}
}

func TestRewriteConfigMakerConfigsUsesAllConfigs(t *testing.T) {
	// More configs than targets: every config still gets rewritten,
	// cycling through the available targets.
	configs := []string{
		"vless://uuid@old1.example.com:443?security=tls#one",
		"vmess://uuid@old2.example.com:443?type=ws#two",
		"trojan://pw@old3.example.com:443#three",
	}
	targets := []string{"1.2.3.4:443"}
	out := rewriteConfigMakerConfigs(configs, targets)
	if len(out) != len(configs) {
		t.Fatalf("expected %d outputs, got %d: %v", len(configs), len(out), out)
	}
	for i, o := range out {
		if !strings.Contains(o, targets[0]) {
			t.Errorf("output %d missing target %s: %s", i, targets[0], o)
		}
	}
}

func TestConfigMakerDisplayLabel(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"vless://uuid@1.2.3.4:443?security=tls#My%20Server", "My Server (vless)"},
		{"trojan://pw@1.2.3.4:443", "trojan://pw@1.2.3.4:443"},
	}
	for _, c := range cases {
		if got := configMakerDisplayLabel(c.in, 100); got != c.want {
			t.Errorf("configMakerDisplayLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	long := "vmess://" + strings.Repeat("a", 100)
	got := configMakerDisplayLabel(long, 20)
	if len(got) != 20 {
		t.Errorf("expected truncated label of length 20, got %d (%q)", len(got), got)
	}
}
