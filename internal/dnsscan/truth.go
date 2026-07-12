package dnsscan

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// trustedDoHProvider defines a DoH endpoint for fetching the truth table.
type trustedDoHProvider struct {
	Name string
	URL  string // %s is replaced with the domain
}

// trustedProviders is the ordered fallback list of DoH providers.
var trustedProviders = []trustedDoHProvider{
	{Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query?name=%s&type=A"},
	{Name: "Google", URL: "https://dns.google/dns-query?name=%s&type=A"},
	{Name: "Quad9", URL: "https://dns.quad9.net/dns-query?name=%s&type=A"},
}

// TruthTable holds the verified "correct" IPs for a target domain. If a resolver
// returns IPs not in this set, it is flagged as poisoned.
type TruthTable struct {
	Domain   string
	TruthIPs map[string]bool
	Provider string
	mu       sync.RWMutex
}

// NewTruthTable creates an empty truth table for a domain.
func NewTruthTable(domain string) *TruthTable {
	return &TruthTable{Domain: domain, TruthIPs: make(map[string]bool)}
}

// FetchTruth populates the table from trusted DoH providers, falling back to
// hardcoded well-known IPs for a few domains when every provider is blocked.
func (t *TruthTable) FetchTruth() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
	}

	for _, provider := range trustedProviders {
		req, err := http.NewRequest("GET", fmt.Sprintf(provider.URL, t.Domain), nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			continue
		}

		var dohResp dohJSONResponse
		if err := json.Unmarshal(body, &dohResp); err != nil || dohResp.Status != 0 {
			continue
		}
		for _, ans := range dohResp.Answer {
			if ans.Type == 1 {
				ip := strings.TrimSpace(ans.Data)
				if net.ParseIP(ip) != nil {
					t.TruthIPs[ip] = true
				}
			}
		}
		if len(t.TruthIPs) > 0 {
			t.Provider = provider.Name
			return nil
		}
	}

	fallbacks := map[string][]string{
		"google.com":    {"142.250.80.46", "142.250.80.78", "142.250.80.110"},
		"speedtest.net": {"151.139.72.2"},
		"facebook.com":  {"157.240.1.35", "157.240.3.35"},
	}
	if ips, ok := fallbacks[t.Domain]; ok {
		for _, ip := range ips {
			t.TruthIPs[ip] = true
		}
		t.Provider = "Hardcoded Fallback"
		return nil
	}
	return fmt.Errorf("truth table: all DoH providers failed and no fallback for %q", t.Domain)
}

// Verify returns true (clean) if at least one IP is in the trusted set, or if we
// have no truth data to compare against.
func (t *TruthTable) Verify(ips []string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if len(t.TruthIPs) == 0 {
		return true
	}
	for _, ip := range ips {
		if t.TruthIPs[ip] {
			return true
		}
	}
	return false
}
