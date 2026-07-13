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

// knownGoodV4Prefixes lists the /16 (first-two-octet) blocks a domain is known
// to legitimately answer from. Heavily GeoDNS/anycast domains (google.com most
// of all) return hundreds of rotating IPs across many netblocks, so an exact
// match against the handful of truth IPs a single DoH lookup returns would
// falsely flag most honest resolvers as poisoned. These prefixes are always
// accepted for the domain regardless of what the truth fetch returned.
var knownGoodV4Prefixes = map[string][]string{
	"google.com": {
		"142.250", "142.251", "172.217", "172.253", "216.58",
		"74.125", "108.177", "209.85", "173.194", "64.233", "216.239",
	},
	"facebook.com": {"157.240", "31.13", "179.60", "185.60", "129.134"},
}

// Verify reports whether an A-record answer set looks honest (clean). It is
// deliberately lenient about legitimate IP rotation but strict about the two
// unambiguous poisoning signatures used by DNS censors: sinkhole/bogon answers
// (private, loopback, unspecified, reserved) and answers that land in none of
// the domain's known-good netblocks.
//
// Clean when:
//   - no truth data AND no known-good prefixes to compare against, OR
//   - any answer matches a truth IP exactly, shares a /16 with a truth IP, or
//     falls inside a known-good prefix for the domain.
//
// Poisoned when a bogon/private IP is returned, or when we have a reference set
// and no answer matches it at all.
func (t *TruthTable) Verify(ips []string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// A private/reserved answer for a public domain is the classic sinkhole
	// poisoning signature — always dirty, whatever the truth table holds.
	for _, ip := range ips {
		if isBogonIP(ip) {
			return false
		}
	}

	prefixes := knownGoodV4Prefixes[t.Domain]
	if len(t.TruthIPs) == 0 && len(prefixes) == 0 {
		return true // nothing trustworthy to compare against => treat as clean
	}

	for _, ip := range ips {
		if t.TruthIPs[ip] {
			return true
		}
		for truth := range t.TruthIPs {
			if sameSlash16(ip, truth) {
				return true
			}
		}
		if p := v4Prefix16(ip); p != "" {
			for _, good := range prefixes {
				if p == good {
					return true
				}
			}
		}
	}
	return false
}

// isBogonIP reports whether an IP is private, loopback, link-local,
// unspecified, or otherwise reserved — none of which a public domain should
// legitimately resolve to, so seeing one is a poisoning/sinkhole signal.
func isBogonIP(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return true
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	// 240.0.0.0/4 (reserved for future use) and 0.0.0.0/8.
	if v4 := ip.To4(); v4 != nil && (v4[0] >= 240 || v4[0] == 0) {
		return true
	}
	return false
}

// v4Prefix16 returns the "a.b" first-two-octet /16 label of an IPv4 address, or
// "" for non-IPv4 input.
func v4Prefix16(s string) string {
	v4 := net.ParseIP(strings.TrimSpace(s)).To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d", v4[0], v4[1])
}

// sameSlash16 reports whether two IPv4 addresses share a /16 prefix.
func sameSlash16(a, b string) bool {
	pa, pb := v4Prefix16(a), v4Prefix16(b)
	return pa != "" && pa == pb
}
