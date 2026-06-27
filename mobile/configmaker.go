package mobile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"whitedns-go/internal/configmaker"
)

// configMakerDir returns {dataDir}/config maker/ (created), so all config-maker
// outputs land inside the same WhiteDNS Scanner folder the app uses for results.
func configMakerDir(dataDir string) (string, error) {
	dir := filepath.Join(dataDir, "config maker")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func writeConfigMakerLines(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// ConfigMakerRewrite rewrites the given proxy configs (vless/vmess/trojan/ss/
// hysteria URIs) so each points at one of the supplied IP:port targets. The
// result is written under {dataDir}/config maker/ and the file path is returned.
func ConfigMakerRewrite(dataDir, configsText, targetsText string) (string, error) {
	configs := configmaker.ExtractConfigs(configsText)
	if len(configs) == 0 {
		return "", fmt.Errorf("no proxy configs found in input")
	}
	targets := configmaker.ExtractTargets(targetsText)
	if len(targets) == 0 {
		return "", fmt.Errorf("no valid IP:port targets found")
	}
	out := configmaker.RewriteConfigs(configs, targets)
	dir, err := configMakerDir(dataDir)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("rewritten-%s.txt", time.Now().Format("20060102-150405")))
	if err := writeConfigMakerLines(path, out); err != nil {
		return "", err
	}
	return path, nil
}

// ConfigMakerExtractIPs extracts IP:port endpoints from the given proxy configs
// / text (the reverse operation), writes them under {dataDir}/config maker/, and
// returns the output file path.
func ConfigMakerExtractIPs(dataDir, configsText string) (string, error) {
	ips := configmaker.ExtractIPs(configsText)
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP:port endpoints found")
	}
	dir, err := configMakerDir(dataDir)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("extracted-ips-%s.txt", time.Now().Format("20060102-150405")))
	if err := writeConfigMakerLines(path, ips); err != nil {
		return "", err
	}
	return path, nil
}
