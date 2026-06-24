package ui

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func isClipboardPasteShortcut(k tea.KeyMsg) bool {
	switch strings.ToLower(k.String()) {
	case "ctrl+v", "shift+insert", "cmd+v":
		return true
	default:
		return false
	}
}

func flattenClipboardText(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.Join(strings.Fields(strings.ReplaceAll(text, "\n", " ")), " ")
}

func (m *tuiModel) pasteClipboardIntoInput(msg tea.Msg, multiline bool) bool {
	k, ok := msg.(tea.KeyMsg)
	if !ok || !isClipboardPasteShortcut(k) {
		return false
	}

	clipText := readClipboardText()
	if clipText == "" {
		return false
	}

	if multiline {
		m.pasteBuffer = clipText
		m.ti.SetValue(flattenClipboardText(clipText))
	} else {
		m.ti.SetValue(m.ti.Value() + clipText)
	}

	m.pasteConfirm = false
	m.pasteConfirmAt = time.Time{}
	m.lastEnterTime = time.Time{}
	return true
}