package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"whitedns-go/internal/antidpi"
	"whitedns-go/internal/scanner"
)

func ResultEndpoint(line string) (string, error) {
	for _, token := range strings.Fields(line) {
		token = strings.Trim(token, "|,;()")
		if host, _, err := net.SplitHostPort(token); err == nil && net.ParseIP(host) != nil {
			return token, nil
		}
		if net.ParseIP(token) != nil {
			return net.JoinHostPort(token, "443"), nil
		}
	}
	return "", fmt.Errorf("select a result with an IP endpoint")
}
func TestEndpointDownload(line, kind, downloadURL string, seconds, maxMB int, enabled bool, size, delay int) (string, error) {
	endpoint, err := ResultEndpoint(line)
	if err != nil {
		return "", err
	}
	result, err := scanner.MeasureEndpointDownload(context.Background(), endpoint, kind, downloadURL, seconds, maxMB, antidpi.Options{Enabled: enabled, Size: size, DelayMs: delay})
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(result)
	return string(data), err
}
