// Package configmaker holds the pure config-rewriting / endpoint-extraction
// logic shared by the desktop TUI and the mobile bridge. It has no UI or engine
// dependencies so any caller can use it.
package configmaker

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// URIRe matches the proxy-config URI schemes the config maker understands.
var URIRe = regexp.MustCompile(`(?i)(?:vless|vmess|trojan|ss|hy2|hysteria2)://[^\s]+`)

// ExtractConfigs pulls proxy-config URIs out of raw text. If no URI-shaped
// tokens are found it falls back to treating each non-empty line as a config.
func ExtractConfigs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, match := range URIRe.FindAllString(line, -1) {
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}
			out = append(out, match)
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out
}

// ExtractTargets pulls valid IP:port tokens out of raw text (space/comma/newline
// separated). Returns a sorted, de-duplicated list.
func ExtractTargets(raw string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, token := range strings.FieldsFunc(raw, splitTokens) {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		host, port, err := net.SplitHostPort(token)
		if err != nil {
			// No port supplied. If the token is a bare IP, default to :443 so an
			// IP-only list still produces usable IP:port targets.
			if net.ParseIP(token) != nil {
				host, port = token, "443"
			} else {
				continue
			}
		} else if port == "" {
			// "ip:" with an empty port — also default to 443.
			if net.ParseIP(host) != nil {
				port = "443"
			} else {
				continue
			}
		}
		if host == "" || net.ParseIP(host) == nil {
			continue
		}
		endpoint := net.JoinHostPort(host, port)
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		out = append(out, endpoint)
	}
	sort.Strings(out)
	return out
}

// ExtractIPs pulls IP:port endpoints out of proxy configs and/or plain text
// (the "reverse" operation). Returns a sorted, de-duplicated list.
func ExtractIPs(raw string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if match := URIRe.FindString(line); match != "" {
			if endpoint := HostPort(match); endpoint != "" {
				if _, ok := seen[endpoint]; !ok {
					seen[endpoint] = struct{}{}
					out = append(out, endpoint)
				}
			}
		}
		for _, token := range strings.FieldsFunc(line, splitTokens) {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			host, port, err := net.SplitHostPort(token)
			if err != nil || host == "" || port == "" || net.ParseIP(host) == nil {
				continue
			}
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			out = append(out, token)
		}
	}
	sort.Strings(out)
	return out
}

// HostPort returns the "host:port" of a proxy-config URI when the host is an IP.
func HostPort(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return ""
	}
	host := parsed.Host
	if strings.Contains(host, "@") {
		parts := strings.Split(host, "@")
		host = parts[len(parts)-1]
	}
	hn, port, err := net.SplitHostPort(host)
	if err != nil || hn == "" || port == "" || net.ParseIP(hn) == nil {
		return ""
	}
	return host
}

// RewriteConfigs produces one rewritten config per target (cycling configs if
// fewer), each pointing at its IP:port target. Every config and target is used.
func RewriteConfigs(configs, targets []string) []string {
	if len(configs) == 0 || len(targets) == 0 {
		return nil
	}
	n := len(targets)
	if len(configs) > n {
		n = len(configs)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, rewriteConfig(configs[i%len(configs)], targets[i%len(targets)]))
	}
	return out
}

func rewriteConfig(configText, target string) string {
	configText = strings.TrimSpace(configText)
	if configText == "" || target == "" || !strings.Contains(configText, "://") {
		return configText
	}
	// vmess:// is base64-encoded JSON, not a URL — rewrite its add/port fields so
	// the config stays valid (a naive host swap corrupts it and the client
	// silently drops it).
	if strings.HasPrefix(strings.ToLower(configText), "vmess://") {
		return rewriteVmess(configText, target)
	}
	parsed, err := url.Parse(configText)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return configText
	}
	userInfo := ""
	if strings.Contains(parsed.Host, "@") {
		userInfo = strings.SplitN(parsed.Host, "@", 2)[0]
	}
	if userInfo != "" {
		parsed.Host = userInfo + "@" + target
	} else {
		parsed.Host = target
	}
	parsed.Fragment = target
	return parsed.String()
}

// rewriteVmess decodes a vmess:// base64-JSON config, points its address/port at
// the target, and re-encodes it. On any failure it returns the original config
// unchanged (so a malformed entry never silently disappears).
func rewriteVmess(configText, target string) string {
	payload := configText[len("vmess://"):]
	if i := strings.IndexAny(payload, "#?"); i >= 0 {
		payload = payload[:i]
	}
	raw, ok := decodeFlexibleBase64(payload)
	if !ok {
		return configText
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return configText
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || net.ParseIP(host) == nil {
		return configText
	}
	m["add"] = host
	m["port"] = port // vmess JSON stores port as a string
	m["ps"] = target // display name
	re, err := json.Marshal(m)
	if err != nil {
		return configText
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(re)
}

// decodeFlexibleBase64 tries the common base64 variants (std/url, padded/raw)
// since vmess payloads appear in all of them across clients.
func decodeFlexibleBase64(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

func splitTokens(r rune) bool {
	return r == ' ' || r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t'
}
