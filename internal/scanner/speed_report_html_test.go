package scanner

import (
	"os"
	"strings"
	"testing"
)

func TestWriteSpeedRankHTMLContainsRankedRows(t *testing.T) {
	dir := t.TempDir()
	results := []SpeedRankResult{
		{IP: "1.1.1.1", Port: 443, Reachable: true, DownloadMbps: 123.45, UploadMbps: 12.3, LatencyMs: 20, JitterMs: 2, LossPct: 0, Score: 130.1, Source: "cloudflare", UploadSource: "cloudflare"},
		{IP: "2.2.2.2", Port: 443, Reachable: true, DownloadMbps: 50.0, UploadMbps: 5.0, LatencyMs: 80, JitterMs: 5, LossPct: 16.7, Score: 40.2, Source: "cachefly", UploadSource: "httpbin"},
		{IP: "3.3.3.3", Port: 443, Reachable: false, Error: "no successful handshake"},
	}

	path, err := WriteSpeedRankHTML(dir, results)
	if err != nil {
		t.Fatalf("WriteSpeedRankHTML failed: %v", err)
	}
	if !strings.Contains(path, "whitedns logs") || !strings.HasSuffix(path, ".html") {
		t.Fatalf("unexpected path: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read report: %v", err)
	}
	html := string(data)
	for _, want := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "123.45", "cloudflare", "cachefly", "no successful handshake"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected html to contain %q, got:\n%s", want, html)
		}
	}
}
