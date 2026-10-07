// Package asnexport expands ASN target lists (IPs/CIDRs) into a flat IP list on
// disk. It is deliberately free of any UI dependency so both the terminal UI and
// the mobile bridge can reuse it.
package asnexport

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"whitedns-go/internal/tlsprobe"
)

// DefaultExportPath builds a timestamped output path under dataDir/asn_exports.
func DefaultExportPath(dataDir string) string {
	if dataDir == "" {
		dataDir = "."
	}
	stamp := time.Now().Format("20060102-150405")
	return filepath.Join(dataDir, "asn_exports", fmt.Sprintf("asn_ips-%s.txt", stamp))
}

// ExportTargetsToTXT expands every IP/CIDR target and writes one IP per line to
// outputPath (or a default path when empty). Returns the resolved path and the
// number of IPs written.
func ExportTargetsToTXT(dataDir string, targets []string, outputPath string) (string, int, error) {
	if len(targets) == 0 {
		return "", 0, fmt.Errorf("no ASN targets selected")
	}

	path := strings.TrimSpace(outputPath)
	if path == "" {
		path = DefaultExportPath(dataDir)
	} else if !filepath.IsAbs(path) {
		if dataDir == "" {
			dataDir = "."
		}
		path = filepath.Join(dataDir, path)
	}
	path = filepath.Clean(path)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", 0, err
	}

	f, err := os.Create(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 1<<20)
	written := 0

	if _, err := fmt.Fprintln(w, "# ASN IP export"); err != nil {
		return "", 0, err
	}
	if _, err := fmt.Fprintln(w, "# Generated:", time.Now().Format(time.RFC3339)); err != nil {
		return "", 0, err
	}
	if _, err := fmt.Fprintln(w, "# Source ASNs:", len(targets)); err != nil {
		return "", 0, err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return "", 0, err
	}

	// IPv4: merge every range into sorted spans first, so overlapping ASN
	// ranges are written once, then format from integers (no per-IP allocation).
	// IPv6: the scan's own samples, since a /32 alone holds 2^96 addresses.
	var spans []IPv4Span
	var v6 []string
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		cidr := target
		if !strings.Contains(cidr, "/") {
			ip := net.ParseIP(cidr)
			if ip == nil {
				return "", 0, fmt.Errorf("invalid target %q", target)
			}
			if ip.To4() != nil {
				cidr += "/32"
			} else {
				cidr += "/128"
			}
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return "", 0, err
		}
		if span, ok := IPv4SpanOf(ipnet); ok {
			spans = append(spans, span)
		} else {
			v6 = append(v6, cidr)
		}
	}
	buf := make([]byte, 0, 16)
	for _, span := range MergeIPv4Spans(spans) {
		for v := span.First; v <= span.Last; v++ {
			buf = append(AppendIPv4(buf[:0], uint32(v)), '\n')
			if _, err := w.Write(buf); err != nil {
				return "", 0, err
			}
			written++
		}
	}
	for _, ip := range tlsprobe.ExpandTargets(v6) {
		if _, err := fmt.Fprintln(w, ip); err != nil {
			return "", 0, err
		}
		written++
	}

	if err := w.Flush(); err != nil {
		return "", 0, err
	}

	return path, written, nil
}
