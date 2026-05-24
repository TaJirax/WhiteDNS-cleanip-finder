package ui

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestAppendTransferLogLineFromScanLogCapturesBenchmarkLines(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "scan_logs", "transfer-http-20260524-000000.txt")

	m := &tuiModel{
		transferLogPath: logPath,
		transferLogMu:   &sync.Mutex{},
	}

	benchmarkLine := "[+] http 1.2.3.4:8080 lat=12ms ↓123.4KB/s ↑56.7KB/s [telegram]"
	m.appendTransferLogLineFromScanLog(benchmarkLine)

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read transfer log: %v", err)
	}
	if got := string(content); !strings.Contains(got, benchmarkLine) {
		t.Fatalf("transfer log missing benchmark line: %q", got)
	}

	ignoredLine := "[INFO] scan started"
	m.appendTransferLogLineFromScanLog(ignoredLine)
	content, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read transfer log after ignored line: %v", err)
	}
	if strings.Contains(string(content), ignoredLine) {
		t.Fatalf("non-transfer line should not be appended: %q", string(content))
	}
}
