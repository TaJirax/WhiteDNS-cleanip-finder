package mobile

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

func resolveDomainTargets(ctx context.Context, targets []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, target := range targets {
		raw := target
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" || net.ParseIP(parsed.Hostname()) != nil {
			return nil, fmt.Errorf("Edge domains requires hostnames; choose IP targets for IPs/CIDRs")
		}
		lookup, cancel := context.WithTimeout(ctx, 10*time.Second)
		addresses, err := net.DefaultResolver.LookupIPAddr(lookup, parsed.Hostname())
		cancel()
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", parsed.Hostname(), err)
		}
		sort.Slice(addresses, func(i, j int) bool { return addresses[i].IP.String() < addresses[j].IP.String() })
		for _, address := range addresses {
			value := address.IP.String()
			if parsed.Port() != "" {
				value = net.JoinHostPort(value, parsed.Port())
			}
			if !seen[value] {
				seen[value] = true
				out = append(out, value)
			}
		}
	}
	return out, nil
}
