package ui

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"whitedns-go/internal/bundledata"
	"whitedns-go/internal/configmaker"
	"whitedns-go/internal/storage"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const screenConfigMaker = "config_maker"

const (
	cmStepMain         = 0
	cmStepSourceMode   = 10
	cmStepSourceText   = 11
	cmStepSourcePick   = 12
	cmStepSourceReview = 13
	cmStepTargetMode   = 20
	cmStepTargetText   = 21
	cmStepTargetPick   = 22
	cmStepTargetReview = 23
	cmStepOutputPath   = 30
)

func (m *tuiModel) initConfigMaker() {
	m.tiStep = cmStepMain
	m.stepData = make(map[string]string)
	m.cursor = 0
	m.ti.Blur()
	m.ti.SetValue("")
	m.ti.Placeholder = ""
}

// cmLine renders a single line of text with the given style and appends a
// plain "\n" outside the styled render. Rendering a style on a string that
// already contains "\n" makes lipgloss pad the resulting blank line(s) with
// spaces to match the content width, and those spaces then bleed into
// whatever is concatenated next - producing badly indented/shifted text.
// Keeping styled renders single-line avoids that.
func cmLine(style lipgloss.Style, text string) string {
	return style.Render(text) + "\n"
}

// cmReviewRows shrinks the visible-rows budget by the number of extra header
// lines a review screen renders above its list, while keeping a usable
// minimum.
func cmReviewRows(visibleRows, extraLines int) int {
	rows := visibleRows - extraLines
	if rows < 3 {
		rows = 3
	}
	return rows
}

func (m tuiModel) viewConfigMaker(w, h int) string {
	inner := w - 6
	visibleRows := h - 10
	if visibleRows < 3 {
		visibleRows = 3
	}
	var body strings.Builder

	switch m.tiStep {
	case cmStepMain:
		items := []string{
			"Rewrite configs (add/replace endpoint using IP:port target list)",
			"Reverse extract IP:port from proxy configs (save to file)",
			"Reverse extract IP:port from proxy configs (preview only)",
		}
		body.WriteString(configMakerRenderList(items, m.cursor, visibleRows))
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("↑↓ navigate  ·  Enter select  ·  Esc back")

	case cmStepSourceMode:
		items := []string{
			"Paste CONFIG text",
			"Choose CONFIG TXT file from config maker folder",
			"Enter CONFIG TXT file path",
		}
		body.WriteString(cmLine(sDim, "  You are adding: CONFIG input"))
		body.WriteString("\n")
		body.WriteString(configMakerRenderList(items, m.cursor, visibleRows))
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - SOURCE MODE ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("↑↓ navigate  ·  Enter select  ·  Esc back")

	case cmStepSourceText:
		if m.stepData["cm_source_mode"] == "path" {
			body.WriteString(cmLine(sDim, "  You are adding: CONFIG input"))
			body.WriteString(cmLine(sDim, "  Enter CONFIG TXT file path"))
			body.WriteString("\n")
		} else {
			body.WriteString(cmLine(sDim, "  You are adding: CONFIG input"))
			body.WriteString(cmLine(sDim, "  Paste CONFIG text (config lines)"))
			if m.pasteConfirm {
				body.WriteString(cmLine(sWarn, "  Press Enter again to confirm the pasted config(s)"))
			} else {
				body.WriteString(cmLine(sDim, "  Paste, then press Enter twice to confirm"))
			}
			body.WriteString("\n")
		}
		body.WriteString("  " + m.ti.View())
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - SOURCE INPUT ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("Enter confirm  |  Esc back")

	case cmStepSourcePick:
		files := configMakerDecodeList(m.stepData["cm_files"])
		items := make([]string, 0, len(files)+1)
		for _, f := range files {
			items = append(items, filepath.Base(f))
		}
		items = append(items, "Enter custom CONFIG TXT file path")
		body.WriteString(cmLine(sDim, "  You are adding: CONFIG input"))
		body.WriteString("\n")
		body.WriteString(configMakerRenderList(items, m.cursor, visibleRows))
		if len(files) == 0 {
			body.WriteString("\n" + sWarn.Render("  No TXT files found in config maker folder"))
		}
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - SOURCE FILE ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("↑↓ navigate  ·  Enter select  ·  Esc back")

	case cmStepSourceReview:
		configs := configMakerDecodeList(m.stepData["cm_source_configs"])
		items := make([]string, 0, len(configs))
		for _, c := range configs {
			items = append(items, configMakerDisplayLabel(c, inner-8))
		}
		body.WriteString(cmLine(sSuccess, fmt.Sprintf("  Found %d config(s) - all of them will be used", len(configs))))
		body.WriteString(cmLine(sDim, "  Review the list below, then press Enter to continue"))
		body.WriteString("\n")
		body.WriteString(configMakerRenderReviewList(items, m.cursor, cmReviewRows(visibleRows, 1)))
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - REVIEW CONFIGS ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("↑↓ scroll  ·  Enter continue  ·  Esc re-enter source")

	case cmStepTargetMode:
		items := []string{
			"Paste IP:port target list",
			"Choose IP:port targets TXT file from config maker folder",
			"Enter IP:port targets TXT file path",
		}
		body.WriteString(cmLine(sDim, "  You are adding: IP:port targets"))
		body.WriteString("\n")
		body.WriteString(configMakerRenderList(items, m.cursor, visibleRows))
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - TARGET MODE ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("↑↓ navigate  ·  Enter select  ·  Esc back")

	case cmStepTargetText:
		if m.stepData["cm_target_mode"] == "path" {
			body.WriteString(cmLine(sDim, "  You are adding: IP:port targets"))
			body.WriteString(cmLine(sDim, "  Enter IP:port targets TXT file path"))
			body.WriteString("\n")
		} else {
			body.WriteString(cmLine(sDim, "  You are adding: IP:port targets"))
			body.WriteString(cmLine(sDim, "  Paste IP:port target list"))
			if m.pasteConfirm {
				body.WriteString(cmLine(sWarn, "  Press Enter again to confirm the pasted target(s)"))
			} else {
				body.WriteString(cmLine(sDim, "  Paste, then press Enter twice to confirm"))
			}
			body.WriteString("\n")
		}
		body.WriteString("  " + m.ti.View())
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - TARGET INPUT ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("Enter confirm  |  Esc back")

	case cmStepTargetPick:
		files := configMakerDecodeList(m.stepData["cm_files"])
		items := make([]string, 0, len(files)+1)
		for _, f := range files {
			items = append(items, filepath.Base(f))
		}
		items = append(items, "Enter custom IP:port targets TXT file path")
		body.WriteString(cmLine(sDim, "  You are adding: IP:port targets"))
		body.WriteString("\n")
		body.WriteString(configMakerRenderList(items, m.cursor, visibleRows))
		if len(files) == 0 {
			body.WriteString("\n" + sWarn.Render("  No TXT files found in config maker folder"))
		}
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - TARGET FILE ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("↑↓ navigate  ·  Enter select  ·  Esc back")

	case cmStepTargetReview:
		targets := configMakerDecodeList(m.stepData["cm_target_list"])
		configs := configMakerDecodeList(m.stepData["cm_source_configs"])
		body.WriteString(cmLine(sSuccess, fmt.Sprintf("  Found %d IP:port target(s) - all of them will be used", len(targets))))
		extraLines := 1
		outN := len(targets)
		if len(configs) > outN {
			outN = len(configs)
		}
		if len(configs) > 0 {
			body.WriteString(cmLine(sDim, fmt.Sprintf("  %d config(s) + %d target(s) -> %d rewritten config(s)", len(configs), len(targets), outN)))
			extraLines++
		}
		body.WriteString(cmLine(sDim, "  Review the list below, then press Enter to continue"))
		body.WriteString("\n")
		body.WriteString(configMakerRenderReviewList(targets, m.cursor, cmReviewRows(visibleRows, extraLines)))
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - REVIEW TARGETS ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("↑↓ scroll  ·  Enter continue  ·  Esc re-enter targets")

	case cmStepOutputPath:
		def := m.stepData["cm_output_default"]
		body.WriteString(cmLine(sDim, "  Output TXT file path"))
		body.WriteString("\n")
		body.WriteString(cmLine(sDim, "  Default: "+def))
		body.WriteString(cmLine(sDim, "  Tip: filename-only path is saved in the config maker folder"))
		body.WriteString("\n")
		body.WriteString("  " + m.ti.View())
		panel := panelStyle(cBorderActive).Width(inner).Render(
			sHeader.Render(" CONFIG MAKER - OUTPUT ") + "\n\n" + body.String(),
		)
		return panel + "\n\n" + sDim.Render("Enter confirm  |  Esc back")
	}

	panel := panelStyle(cBorderActive).Width(inner).Render(sHeader.Render(" CONFIG MAKER "))
	return panel + "\n\n" + sDim.Render("Esc back")
}

func (m tuiModel) handleConfigMakerScreen(msg tea.Msg) (tuiModel, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		if m.tiStep == cmStepSourceText || m.tiStep == cmStepTargetText || m.tiStep == cmStepOutputPath {
			if m.pasteClipboardIntoInput(msg, m.tiStep == cmStepSourceText || m.tiStep == cmStepTargetText) {
				return m, nil
			}
			m.ti, _ = m.ti.Update(msg)
		}
		return m, nil
	}

	if m.tiStep == cmStepSourceText || m.tiStep == cmStepTargetText || m.tiStep == cmStepOutputPath {
		if m.pasteClipboardIntoInput(msg, m.tiStep == cmStepSourceText || m.tiStep == cmStepTargetText) {
			return m, nil
		}
	}

	s := k.String()
	if s == "q" || s == "esc" {
		switch m.tiStep {
		case cmStepMain:
			m.goBack()
		case cmStepSourceMode:
			m.tiStep = cmStepMain
			m.cursor = 0
		case cmStepSourceText, cmStepSourcePick:
			m.tiStep = cmStepSourceMode
			m.cursor = 0
			m.ti.Blur()
			m.pasteConfirm = false
		case cmStepSourceReview:
			m.tiStep = cmStepSourceMode
			m.cursor = 0
		case cmStepTargetMode:
			m.tiStep = cmStepSourceMode
			m.cursor = 0
		case cmStepTargetText, cmStepTargetPick:
			m.tiStep = cmStepTargetMode
			m.cursor = 0
			m.ti.Blur()
			m.pasteConfirm = false
		case cmStepTargetReview:
			m.tiStep = cmStepTargetMode
			m.cursor = 0
		case cmStepOutputPath:
			if m.stepData["cm_flow"] == "rewrite" {
				m.tiStep = cmStepTargetReview
			} else {
				m.tiStep = cmStepSourceReview
			}
			m.cursor = 0
			m.ti.Blur()
		}
		return m, nil
	}

	if s == "0" && m.tiStep == cmStepMain {
		m.goBack()
		return m, nil
	}
	if s == "q" || s == "esc" {
		switch m.tiStep {
		case cmStepMain:
			m.goBack()
		case cmStepSourceMode:
			m.tiStep = cmStepMain
			m.cursor = 0
		case cmStepSourceText, cmStepSourcePick:
			m.tiStep = cmStepSourceMode
			m.cursor = 0
			m.ti.Blur()
			m.pasteConfirm = false
		case cmStepSourceReview:
			m.tiStep = cmStepSourceMode
			m.cursor = 0
		case cmStepTargetMode:
			m.tiStep = cmStepSourceMode
			m.cursor = 0
		case cmStepTargetText, cmStepTargetPick:
			m.tiStep = cmStepTargetMode
			m.cursor = 0
			m.ti.Blur()
			m.pasteConfirm = false
		case cmStepTargetReview:
			m.tiStep = cmStepTargetMode
			m.cursor = 0
		case cmStepOutputPath:
			if m.stepData["cm_flow"] == "rewrite" {
				m.tiStep = cmStepTargetReview
			} else {
				m.tiStep = cmStepSourceReview
			}
			m.cursor = 0
			m.ti.Blur()
		}
		return m, nil
	}

	if s == "0" && m.tiStep == cmStepMain {
		m.goBack()
		return m, nil
	}

	switch m.tiStep {
	case cmStepMain:
		itemsCount := 3
		switch s {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < itemsCount-1 {
				m.cursor++
			}
			return m, nil
		case "enter", " ":
			switch m.cursor {
			case 0:
				m.stepData = map[string]string{"cm_flow": "rewrite"}
			case 1:
				m.stepData = map[string]string{"cm_flow": "reverse_save"}
			default:
				m.stepData = map[string]string{"cm_flow": "reverse_preview"}
			}
			m.tiStep = cmStepSourceMode
			m.cursor = 0
		}
		return m, nil

	case cmStepSourceMode:
		itemsCount := 3
		switch s {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < itemsCount-1 {
				m.cursor++
			}
			return m, nil
		case "enter", " ":
			switch m.cursor {
			case 0:
				m.tiStep = cmStepSourceText
				m.stepData["cm_source_mode"] = "paste"
				m.setupInput("Paste CONFIG text")
			case 1:
				m.tiStep = cmStepSourcePick
				m.stepData["cm_source_mode"] = "pick"
				m.stepData["cm_files"] = configMakerEncodeList(configMakerListTXTFiles(configMakerSupportDir(m)))
				m.cursor = 0
				m.ti.Blur()
			case 2:
				m.tiStep = cmStepSourceText
				m.stepData["cm_source_mode"] = "path"
				m.setupInput("Enter CONFIG TXT file path")
			}
		}
		return m, nil

	case cmStepSourcePick:
		files := configMakerDecodeList(m.stepData["cm_files"])
		itemsCount := len(files) + 1 // +1 for custom path
		switch s {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < itemsCount-1 {
				m.cursor++
			}
			return m, nil
		case "enter", " ":
			if m.cursor >= len(files) {
				m.tiStep = cmStepSourceText
				m.stepData["cm_source_mode"] = "path"
				m.setupInput("Enter CONFIG TXT file path")
				return m, nil
			}
			data := configMakerReadFile(files[m.cursor])
			if strings.TrimSpace(data) == "" {
				m.setToast(sWarn.Render("Selected file is empty"), 3*time.Second)
				return m, nil
			}
			return m.finishConfigMakerSource(data)
		}
		return m, nil

	case cmStepSourceText:
		if s != "enter" {
			m.ti, _ = m.ti.Update(msg)
			return m, nil
		}
		if m.stepData["cm_source_mode"] == "paste" {
			now := time.Now()
			if !m.lastEnterTime.IsZero() && now.Sub(m.lastEnterTime) < 50*time.Millisecond {
				// Likely a newline from pasted content, not a deliberate Enter.
				m.lastEnterTime = now
				m.ti, _ = m.ti.Update(msg)
				return m, nil
			}
			m.lastEnterTime = now
			if !m.pasteConfirm || time.Since(m.pasteConfirmAt) > 10*time.Second {
				m.pasteConfirm = true
				m.pasteConfirmAt = time.Now()
				m.setToast(sInfo.Render("Press Enter again to confirm the pasted config(s)"), 2*time.Second)
				return m, nil
			}
			m.pasteConfirm = false
			raw := strings.TrimSpace(m.ti.Value())
			if clipText := strings.TrimSpace(m.pasteBuffer); clipText != "" {
				raw = clipText
			} else if clipText := readClipboardText(); clipText != "" {
				raw = clipText
			}
			return m.finishConfigMakerSource(raw)
		}
		return m.finishConfigMakerSource(m.ti.Value())

	case cmStepSourceReview:
		configs := configMakerDecodeList(m.stepData["cm_source_configs"])
		switch s {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < len(configs)-1 {
				m.cursor++
			}
			return m, nil
		case "enter", " ":
			return m.advanceConfigMakerAfterSource()
		}
		return m, nil

	case cmStepTargetMode:
		itemsCount := 3
		switch s {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < itemsCount-1 {
				m.cursor++
			}
			return m, nil
		case "enter", " ":
			switch m.cursor {
			case 0:
				m.tiStep = cmStepTargetText
				m.stepData["cm_target_mode"] = "paste"
				m.setupInput("Paste IP:port target list")
			case 1:
				m.tiStep = cmStepTargetPick
				m.stepData["cm_target_mode"] = "pick"
				m.stepData["cm_files"] = configMakerEncodeList(configMakerListTXTFiles(configMakerSupportDir(m)))
				m.cursor = 0
				m.ti.Blur()
			case 2:
				m.tiStep = cmStepTargetText
				m.stepData["cm_target_mode"] = "path"
				m.setupInput("Enter IP:port targets TXT file path")
			}
		}
		return m, nil

	case cmStepTargetPick:
		files := configMakerDecodeList(m.stepData["cm_files"])
		itemsCount := len(files) + 1 // +1 for custom path
		switch s {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < itemsCount-1 {
				m.cursor++
			}
			return m, nil
		case "enter", " ":
			if m.cursor >= len(files) {
				m.tiStep = cmStepTargetText
				m.stepData["cm_target_mode"] = "path"
				m.setupInput("Enter IP:port targets TXT file path")
				return m, nil
			}
			data := configMakerReadFile(files[m.cursor])
			if strings.TrimSpace(data) == "" {
				m.setToast(sWarn.Render("Selected file is empty"), 3*time.Second)
				return m, nil
			}
			return m.finishConfigMakerTarget(data)
		}
		return m, nil

	case cmStepTargetText:
		if s != "enter" {
			m.ti, _ = m.ti.Update(msg)
			return m, nil
		}
		if m.stepData["cm_target_mode"] == "paste" {
			now := time.Now()
			if !m.lastEnterTime.IsZero() && now.Sub(m.lastEnterTime) < 50*time.Millisecond {
				// Likely a newline from pasted content, not a deliberate Enter.
				m.lastEnterTime = now
				m.ti, _ = m.ti.Update(msg)
				return m, nil
			}
			m.lastEnterTime = now
			if !m.pasteConfirm || time.Since(m.pasteConfirmAt) > 10*time.Second {
				m.pasteConfirm = true
				m.pasteConfirmAt = time.Now()
				m.setToast(sInfo.Render("Press Enter again to confirm the pasted target(s)"), 2*time.Second)
				return m, nil
			}
			m.pasteConfirm = false
			raw := strings.TrimSpace(m.ti.Value())
			if clipText := strings.TrimSpace(m.pasteBuffer); clipText != "" {
				raw = clipText
			} else if clipText := readClipboardText(); clipText != "" {
				raw = clipText
			}
			return m.finishConfigMakerTarget(raw)
		}
		return m.finishConfigMakerTarget(m.ti.Value())

	case cmStepTargetReview:
		targets := configMakerDecodeList(m.stepData["cm_target_list"])
		switch s {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < len(targets)-1 {
				m.cursor++
			}
			return m, nil
		case "enter", " ":
			m.tiStep = cmStepOutputPath
			m.stepData["cm_output_default"] = filepath.Join(configMakerSupportDir(m), "rewritten_configs.txt")
			m.setupInput("Enter output path or leave empty for default")
			return m, nil
		}
		return m, nil

	case cmStepOutputPath:
		if s != "enter" {
			m.ti, _ = m.ti.Update(msg)
			return m, nil
		}
		out := strings.TrimSpace(m.ti.Value())
		if out == "" {
			out = m.stepData["cm_output_default"]
		}
		if m.stepData["cm_flow"] == "rewrite" {
			return m.applyConfigMakerRewriteToPath(m.stepData["cm_source_text"], m.stepData["cm_target_text"], out)
		}
		return m.applyConfigMakerReverse(m.stepData["cm_source_text"], true, out)
	}

	return m, nil
}

func configMakerRenderList(items []string, cursor, visibleRows int) string {
	if len(items) == 0 {
		return sDim.Render("  (no items)")
	}
	start := 0
	if cursor >= visibleRows {
		start = cursor - visibleRows + 1
	}
	end := start + visibleRows
	if end > len(items) {
		end = len(items)
	}
	if cursor < 0 {
		cursor = 0
	}
	if cursor >= len(items) {
		cursor = len(items) - 1
	}

	var rows strings.Builder
	for i := start; i < end; i++ {
		if i == cursor {
			rows.WriteString(sSelected.Render(items[i]) + "\n")
		} else {
			rows.WriteString(sNormal.Render(items[i]) + "\n")
		}
	}
	if len(items) > visibleRows {
		rows.WriteString(sDim.Render(fmt.Sprintf("  [%d/%d]", cursor+1, len(items))) + "\n")
	}
	return rows.String()
}

// configMakerRenderReviewList renders a numbered list where every item is
// already included/selected for the operation - the cursor only marks the
// scroll position (shown with a ">" marker) and never implies that other
// items are excluded.
func configMakerRenderReviewList(items []string, cursor, visibleRows int) string {
	if len(items) == 0 {
		return sDim.Render("  (no items)") + "\n"
	}
	start := 0
	if cursor >= visibleRows {
		start = cursor - visibleRows + 1
	}
	end := start + visibleRows
	if end > len(items) {
		end = len(items)
	}
	if cursor < 0 {
		cursor = 0
	}
	if cursor >= len(items) {
		cursor = len(items) - 1
	}

	numWidth := len(fmt.Sprintf("%d", len(items)))
	var rows strings.Builder
	for i := start; i < end; i++ {
		line := fmt.Sprintf("%*d. %s", numWidth, i+1, items[i])
		if i == cursor {
			rows.WriteString(cmLine(sAccent, "> "+line))
		} else {
			rows.WriteString(cmLine(sNormal, "  "+line))
		}
	}
	if len(items) > visibleRows {
		rows.WriteString(sDim.Render(fmt.Sprintf("  [%d/%d]", cursor+1, len(items))) + "\n")
	}
	return rows.String()
}

func (m tuiModel) advanceConfigMakerAfterSource() (tuiModel, tea.Cmd) {
	flow := m.stepData["cm_flow"]
	source := m.stepData["cm_source_text"]
	if flow == "rewrite" {
		m.tiStep = cmStepTargetMode
		m.cursor = 0
		m.ti.Blur()
		return m, nil
	}
	if flow == "reverse_preview" {
		return m.applyConfigMakerReverse(source, false, "")
	}
	m.tiStep = cmStepOutputPath
	m.stepData["cm_output_default"] = filepath.Join(configMakerSupportDir(m), "extracted_ips.txt")
	m.setupInput("Enter output path or leave empty for default")
	return m, nil
}

// finishConfigMakerSource takes raw CONFIG input (pasted text, file content,
// or a file path for "path" mode), extracts the proxy config URIs from it,
// and advances to the review screen so the user can confirm what was found
// before continuing.
func (m tuiModel) finishConfigMakerSource(raw string) (tuiModel, tea.Cmd) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		m.setToast(sWarn.Render("No source provided"), 3*time.Second)
		return m, nil
	}
	if m.stepData["cm_source_mode"] == "path" {
		data := configMakerReadFile(raw)
		if strings.TrimSpace(data) == "" {
			m.setToast(sWarn.Render("Source file not found or empty"), 3*time.Second)
			return m, nil
		}
		raw = data
	}
	configs := extractConfigMakerConfigs(raw)
	if len(configs) == 0 {
		m.setToast(sWarn.Render("No configs found in input"), 3*time.Second)
		return m, nil
	}
	m.stepData["cm_source_text"] = raw
	m.stepData["cm_source_configs"] = configMakerEncodeList(configs)
	m.tiStep = cmStepSourceReview
	m.cursor = 0
	m.ti.Blur()
	return m, nil
}

// finishConfigMakerTarget takes raw IP:port target input (pasted text, file
// content, or a file path for "path" mode), extracts valid IP:port targets
// from it, and advances to the review screen so the user can confirm what
// was found before continuing.
func (m tuiModel) finishConfigMakerTarget(raw string) (tuiModel, tea.Cmd) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		m.setToast(sWarn.Render("No targets provided"), 3*time.Second)
		return m, nil
	}
	if m.stepData["cm_target_mode"] == "path" {
		data := configMakerReadFile(raw)
		if strings.TrimSpace(data) == "" {
			m.setToast(sWarn.Render("Targets file not found or empty"), 3*time.Second)
			return m, nil
		}
		raw = data
	}
	targets := extractConfigMakerTargets(raw)
	if len(targets) == 0 {
		m.setToast(sWarn.Render("No valid IP:port targets found"), 3*time.Second)
		return m, nil
	}
	m.stepData["cm_target_text"] = raw
	m.stepData["cm_target_list"] = configMakerEncodeList(targets)
	m.tiStep = cmStepTargetReview
	m.cursor = 0
	m.ti.Blur()
	return m, nil
}

// configMakerDisplayLabel produces a short, human-readable label for a proxy
// config URI so review lists stay readable even for long base64 vmess blobs.
func configMakerDisplayLabel(raw string, max int) string {
	raw = strings.TrimSpace(raw)
	label := raw
	if idx := strings.Index(raw, "://"); idx >= 0 {
		scheme := raw[:idx]
		rest := raw[idx+3:]
		if h := strings.LastIndexByte(rest, '#'); h >= 0 && h+1 < len(rest) {
			if name, err := url.QueryUnescape(rest[h+1:]); err == nil {
				label = fmt.Sprintf("%s (%s)", name, scheme)
			} else {
				label = fmt.Sprintf("%s (%s)", rest[h+1:], scheme)
			}
		} else {
			label = fmt.Sprintf("%s://%s", scheme, rest)
		}
	}
	if max > 3 && len(label) > max {
		label = label[:max-3] + "..."
	}
	return label
}

func (m tuiModel) applyConfigMakerRewriteToPath(configText, targetText, outPath string) (tuiModel, tea.Cmd) {
	configs := extractConfigMakerConfigs(configText)
	targets := extractConfigMakerTargets(targetText)
	if len(configs) == 0 {
		m.setToast(sWarn.Render("No configs found"), 3*time.Second)
		return m, nil
	}
	if len(targets) == 0 {
		m.setToast(sWarn.Render("No valid IP:port targets found"), 3*time.Second)
		return m, nil
	}

	blocks := rewriteConfigMakerConfigs(configs, targets)
	saved, err := configMakerSaveTextOutput(outPath, blocks, configMakerSupportDir(m))
	if err != nil {
		m.setToast(sError.Render("x Failed to save rewritten configs"), 4*time.Second)
		m.addLog(fmt.Sprintf("Config maker rewrite failed: %v", err))
		return m, nil
	}

	m.scanResults = previewStrings(blocks, 25)
	m.scanErr = nil
	m.operationType = "config_maker"
	m.scanKind = "config_maker"
	m.addLog(fmt.Sprintf("Saved %d rewritten config(s) to %s", len(blocks), saved))
	m.setToast(sSuccess.Render("OK Configs rewritten"), 4*time.Second)
	m.screen = screenScanResults
	m.cursor = 0
	m.initConfigMaker()
	return m, nil
}

func (m tuiModel) applyConfigMakerReverse(configText string, save bool, outPath string) (tuiModel, tea.Cmd) {
	ips := extractConfigMakerIPs(configText)
	if len(ips) == 0 {
		m.setToast(sWarn.Render("No IP:port endpoints found"), 4*time.Second)
		return m, nil
	}

	if save {
		saved, err := configMakerSaveTextOutput(outPath, ips, configMakerSupportDir(m))
		if err != nil {
			m.setToast(sError.Render("x Failed to save extracted IPs"), 4*time.Second)
			m.addLog(fmt.Sprintf("Config maker reverse failed: %v", err))
			return m, nil
		}
		m.addLog(fmt.Sprintf("Saved %d extracted IP(s) to %s", len(ips), saved))
	} else {
		m.addLog(fmt.Sprintf("Extracted %d endpoint(s)", len(ips)))
	}

	m.scanResults = previewStrings(ips, 25)
	m.scanErr = nil
	m.operationType = "config_maker"
	m.scanKind = "config_maker"
	m.setToast(sSuccess.Render("OK Extraction complete"), 4*time.Second)
	m.screen = screenScanResults
	m.cursor = 0
	m.initConfigMaker()
	return m, nil
}

func configMakerReadFile(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if data, err := os.ReadFile(path); err == nil {
		return string(data)
	}
	if data, err := os.ReadFile(filepath.Clean(path)); err == nil {
		return string(data)
	}
	return ""
}

func configMakerSupportDir(m tuiModel) string {
	if m.app != nil && m.app.DataDir != "" {
		if dir, err := bundledata.EnsureConfigMakerDataDir(m.app.DataDir); err == nil && strings.TrimSpace(dir) != "" {
			return dir
		}
		candidate := filepath.Join(m.app.DataDir, "config maker")
		if err := os.MkdirAll(candidate, 0o755); err == nil {
			return candidate
		}
	}
	if wd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(wd, "config maker")
		if err := os.MkdirAll(candidate, 0o755); err == nil {
			return candidate
		}
		return wd
	}
	return "."
}

func whitednsLogsDir(dataDir string) string {
	if strings.TrimSpace(dataDir) == "" {
		dataDir = "."
	}
	return filepath.Join(dataDir, "whitedns logs")
}

func configMakerListTXTFiles(folder string) []string {
	if strings.TrimSpace(folder) == "" {
		return nil
	}
	if err := os.MkdirAll(folder, 0o755); err != nil {
		return nil
	}

	entries, err := os.ReadDir(folder)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.EqualFold(filepath.Ext(name), ".txt") {
			out = append(out, filepath.Join(folder, name))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(filepath.Base(out[i])) < strings.ToLower(filepath.Base(out[j]))
	})
	return out
}

func configMakerEncodeList(items []string) string {
	return strings.Join(items, "\n")
}

func configMakerDecodeList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func configMakerSaveTextOutput(outputPath string, lines []string, baseDir string) (string, error) {
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		return "", fmt.Errorf("empty output path")
	}
	if !filepath.IsAbs(outputPath) {
		// Treat relative output as local to the provided base directory.
		if strings.TrimSpace(baseDir) != "" {
			outputPath = filepath.Join(baseDir, outputPath)
		} else if abs, err := filepath.Abs(outputPath); err == nil {
			outputPath = abs
		}
	}
	if !strings.EqualFold(filepath.Ext(outputPath), ".txt") {
		outputPath += ".txt"
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return "", err
	}
	if err := storage.AtomicWriteText(outputPath, strings.Join(lines, "\n")+"\n"); err != nil {
		return "", err
	}
	return outputPath, nil
}

// These delegate to the shared internal/configmaker package so the desktop TUI
// and the mobile bridge use one implementation.
func extractConfigMakerConfigs(raw string) []string { return configmaker.ExtractConfigs(raw) }
func extractConfigMakerTargets(raw string) []string { return configmaker.ExtractTargets(raw) }
func extractConfigMakerIPs(raw string) []string     { return configmaker.ExtractIPs(raw) }

func rewriteConfigMakerConfigs(configs, targets []string) []string {
	return configmaker.RewriteConfigs(configs, targets)
}

func previewStrings(items []string, max int) []string {
	if len(items) <= max {
		return append([]string(nil), items...)
	}
	return append([]string(nil), items[:max]...)
}
