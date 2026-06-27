// Package configmaker holds the pure config-rewriting / endpoint-extraction
// logic shared by the desktop TUI and the mobile bridge. It has no UI or engine
// dependencies so any caller can use it.
package configmaker

import (
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
		if err != nil || host == "" || port == "" || net.ParseIP(host) == nil {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, token)
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

func splitTokens(r rune) bool {
	return r == ' ' || r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t'
}
