//go:build !windows

package ui

import (
	"strings"

	"github.com/atotto/clipboard"
)

func readClipboardText() string {
	if clipText, err := clipboard.ReadAll(); err == nil {
		return strings.TrimSpace(clipText)
	}
	return ""
}