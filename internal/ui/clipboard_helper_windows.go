//go:build windows

package ui

import (
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                     = syscall.NewLazyDLL("user32.dll")
	kernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procOpenClipboard          = user32.NewProc("OpenClipboard")
	procCloseClipboard         = user32.NewProc("CloseClipboard")
	procGetClipboardData       = user32.NewProc("GetClipboardData")
	procIsClipboardFormatAvail = user32.NewProc("IsClipboardFormatAvailable")
	procGlobalLock             = kernel32.NewProc("GlobalLock")
	procGlobalUnlock           = kernel32.NewProc("GlobalUnlock")
	procGlobalSize             = kernel32.NewProc("GlobalSize")
)

const cfUnicodeText = 13

func readClipboardText() string {
	text, ok := readClipboardTextWindows()
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func readClipboardTextWindows() (string, bool) {
	if r1, _, _ := procIsClipboardFormatAvail.Call(cfUnicodeText); r1 == 0 {
		return "", false
	}

	if r1, _, _ := procOpenClipboard.Call(0); r1 == 0 {
		return "", false
	}
	defer procCloseClipboard.Call()

	handle, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if handle == 0 {
		return "", false
	}

	ptr, _, _ := procGlobalLock.Call(handle)
	if ptr == 0 {
		return "", false
	}
	defer procGlobalUnlock.Call(handle)

	size, _, _ := procGlobalSize.Call(handle)
	if size == 0 {
		return "", false
	}

	text := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr)))
	if text == "" {
		return "", false
	}
	return text, true
}
