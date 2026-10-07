package mobile

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"whitedns-go/internal/antidpi"
	"whitedns-go/internal/scanner"
)

func TestStreamingExpansionMatchesSavedCoverage(t *testing.T) {
	input := []string{"192.0.2.0/29", "192.0.2.1", "[::1]:8443"}
	var streamed []string
	count, err := walkTargets(context.Background(), input, 100, func(line string) error { streamed = append(streamed, line); return nil })
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "targets")
	saved, err := expandTargetsToFile(input, path, 100)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if saved != count || strings.Join(streamed, "\n")+"\n" != string(data) {
		t.Fatal("stream coverage differs")
	}
}
func TestLargeExpansionCancelsAfterFirstAddress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	seen := 0
	_, err := walkTargets(ctx, []string{"0.0.0.0/0"}, 100, func(string) error { seen++; cancel(); return nil })
	if err != context.Canceled || seen != 1 || time.Since(start) > time.Second {
		t.Fatal(seen, err)
	}
}
func TestSelectedDownloadStaysPinnedAndRejectsRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://different.example/", 302)
			return
		}
		w.Write([]byte("payload"))
	}))
	defer server.Close()
	endpoint := strings.TrimPrefix(server.URL, "http://")
	result, err := scanner.MeasureEndpointDownload(context.Background(), endpoint, "ip", "http://must-not-resolve.invalid/", 1, 1, antidpi.Options{})
	if err != nil || result.Bytes != 7 {
		t.Fatal(result, err)
	}
	if _, err = scanner.MeasureEndpointDownload(context.Background(), endpoint, "ip", "http://must-not-resolve.invalid/redirect", 1, 1, antidpi.Options{}); err == nil {
		t.Fatal("redirect accepted")
	}
	for _, line := range []string{"http " + endpoint + " lat=1ms", "example.com " + endpoint + " OK", "[::1]:443 | 2/9"} {
		if _, err := ResultEndpoint(line); err != nil {
			t.Fatal(err)
		}
	}
}
