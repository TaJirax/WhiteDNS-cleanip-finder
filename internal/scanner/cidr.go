package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// IPRange represents a parseable IP range (single IP, CIDR, or IP-IP)
type IPRange struct {
	Start net.IP
	End   net.IP
	Size  int64
}

// ParseIPRanges parses mixed IP input (single IPs, CIDR ranges, IP-IP ranges)
// Returns efficient chunks for scanning without loading all IPs at once
func ParseIPRanges(input []string) []IPRange {
	var ranges []IPRange

	for _, item := range input {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		// Try CIDR notation first
		if strings.Contains(item, "/") {
			if r, err := parseCIDR(item); err == nil {
				ranges = append(ranges, r)
				continue
			}
		}

		// Try IP-IP range
		if strings.Contains(item, "-") {
			parts := strings.Split(item, "-")
			if len(parts) == 2 {
				startIP := net.ParseIP(strings.TrimSpace(parts[0]))
				endIP := net.ParseIP(strings.TrimSpace(parts[1]))
				if startIP != nil && endIP != nil {
					ranges = append(ranges, IPRange{Start: startIP, End: endIP, Size: calculateIPRange(startIP, endIP)})
					continue
				}
			}
		}

		// Try single IP
		if ip := net.ParseIP(item); ip != nil {
			ranges = append(ranges, IPRange{Start: ip, End: ip, Size: 1})
		}
	}

	return ranges
}

// parseCIDR parses CIDR notation and returns IPRange
func parseCIDR(cidr string) (IPRange, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return IPRange{}, err
	}

	start := ipnet.IP
	end := broadcastAddr(ipnet)
	size := calculateIPRange(start, end)

	return IPRange{Start: start, End: end, Size: size}, nil
}

// broadcastAddr calculates broadcast address of CIDR
func broadcastAddr(ipnet *net.IPNet) net.IP {
	broadcast := make(net.IP, len(ipnet.IP))
	copy(broadcast, ipnet.IP)

	for i := 0; i < len(ipnet.Mask); i++ {
		broadcast[len(ipnet.IP)-len(ipnet.Mask)+i] |= ^ipnet.Mask[i]
	}

	return broadcast
}

// calculateIPRange returns count of IPs between start and end
func calculateIPRange(start, end net.IP) int64 {
	if start == nil || end == nil {
		return 1
	}

	start4 := start.To4()
	end4 := end.To4()

	if start4 == nil || end4 == nil {
		// IPv6 - return estimate or cap
		return 1
	}

	startInt := ipToInt(start4)
	endInt := ipToInt(end4)

	if endInt < startInt {
		return 1
	}

	return endInt - startInt + 1
}

// ipToInt converts IPv4 to uint32
func ipToInt(ip net.IP) int64 {
	return int64(ip[0])<<24 | int64(ip[1])<<16 | int64(ip[2])<<8 | int64(ip[3])
}

// intToIP converts uint32 back to IPv4
func intToIP(val int64) net.IP {
	return net.IPv4(byte((val>>24)&0xFF), byte((val>>16)&0xFF), byte((val>>8)&0xFF), byte(val&0xFF))
}

// StreamIPsFromRanges yields IPs from ranges without loading all at once
// Calls handler for each batch
func StreamIPsFromRanges(ranges []IPRange, batchSize int, handler func([]string) error) error {
	var batch []string

	for _, r := range ranges {
		// For large ranges, iterate in chunks
		if r.Size > int64(batchSize*10) {
			if err := streamCIDRRange(r, batchSize, handler); err != nil {
				return err
			}
		} else {
			// For small ranges, accumulate into batch
			batch = expandIPRange(r, batch, batchSize, handler)
		}
	}

	// Handle remaining batch
	if len(batch) > 0 {
		if err := handler(batch); err != nil {
			return err
		}
	}

	return nil
}

// streamCIDRRange streams a large CIDR range in batches
func streamCIDRRange(r IPRange, batchSize int, handler func([]string) error) error {
	var batch []string
	start := ipToInt(r.Start)
	end := ipToInt(r.End)

	for current := start; current <= end; current++ {
		batch = append(batch, intToIP(current).String())

		if len(batch) >= batchSize {
			if err := handler(batch); err != nil {
				return err
			}
			batch = []string{}
		}
	}

	if len(batch) > 0 {
		return handler(batch)
	}

	return nil
}

// expandIPRange expands small IP ranges into batch
func expandIPRange(r IPRange, batch []string, batchSize int, handler func([]string) error) []string {
	start := ipToInt(r.Start)
	end := ipToInt(r.End)

	for current := start; current <= end; current++ {
		batch = append(batch, intToIP(current).String())

		if len(batch) >= batchSize {
			handler(batch)
			batch = []string{}
		}
	}

	return batch
}

// EstimateScanTime returns estimated scan time in seconds
func EstimateScanTime(ranges []IPRange, ratePerSec int) int {
	totalIPs := int64(0)
	for _, r := range ranges {
		totalIPs += r.Size
	}

	if ratePerSec <= 0 {
		ratePerSec = 1000
	}

	// Add overhead: 10% + fixed 10s
	estimatedSec := int((totalIPs*110/100)/int64(ratePerSec)) + 10
	return estimatedSec
}

// ParseTargetStats holds statistics about parsed targets
type ParseTargetStats struct {
	Valid   []string
	Invalid []string
	Total   int
}

// ParseTargetsFromPaste robustly parses pasted target input with various whitespace formats.
// Handles irregular spacing, multiple spaces, tabs, and multiple IPs per line.
// Also handles concatenated IPs like "1.2.3.41.2.3.4" by extracting individual IPs.
// Returns valid targets and statistics about parsing.
func ParseTargetsFromPaste(pastedText string) ParseTargetStats {
	stats := ParseTargetStats{
		Valid:   []string{},
		Invalid: []string{},
		Total:   0,
	}

	if pastedText == "" {
		return stats
	}

	// Normalize line endings (handle Windows CRLF, old Mac CR, and Unix LF)
	normalized := strings.ReplaceAll(pastedText, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")

	// Replace tabs with spaces
	normalized = strings.ReplaceAll(normalized, "\t", " ")

	// Treat commas and semicolons as record separators so targets pasted as
	// "a,b,c" or "a; b; c" (columns, CSV rows, delimited lists) split cleanly
	// instead of collapsing into one unparseable field. Newlines and spaces are
	// already handled below.
	normalized = strings.ReplaceAll(normalized, ",", "\n")
	normalized = strings.ReplaceAll(normalized, ";", "\n")

	// Split by newlines first to handle line-by-line input
	lines := strings.Split(normalized, "\n")

	seenTargets := make(map[string]bool) // dedup

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try to fix common spacing issues: "45.92.93 112" -> "45.92.93.112"
		// If a line has exactly one space with digits on both sides AND the two
		// halves together make up exactly four octets, treat it as a single IP
		// split by a stray space. Guarding on the octet count stops two genuine
		// space-separated IPs ("1.2.3.4 5.6.7.8" => 8 octets) from being merged
		// into a bogus "1.2.3.4.5.6.7.8".
		if strings.Count(line, " ") == 1 && !strings.Contains(line, "/") && !strings.Contains(line, "-") {
			parts := strings.Split(line, " ")
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])
			octets := strings.Count(left, ".") + strings.Count(right, ".") + 2
			if octets == 4 && isLikelyIPOctetSequence(left) && isLikelyIPOctetSequence(right) {
				line = left + "." + right
			}
		}

		// Split line by spaces to handle multiple targets per line
		fields := strings.Fields(line)
		for _, field := range fields {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}

			// Try direct parsing first
			if isValidTarget(field) {
				stats.Total++
				if !seenTargets[field] {
					stats.Valid = append(stats.Valid, field)
					seenTargets[field] = true
				}
				continue
			}

			// If direct parsing fails, try extracting IPs from concatenated string
			extractedIPs := extractConcatenatedIPs(field)
			if len(extractedIPs) > 0 {
				// If we extracted IPs, count original field as total
				stats.Total++
				// But add all extracted valid IPs
				for _, ip := range extractedIPs {
					if isValidTarget(ip) && !seenTargets[ip] {
						stats.Valid = append(stats.Valid, ip)
						seenTargets[ip] = true
					} else if !isValidTarget(ip) {
						// Track invalid extracted parts
						if !seenTargets[ip] {
							stats.Invalid = append(stats.Invalid, ip)
							seenTargets[ip] = true
						}
					}
				}
			} else {
				// No IPs extracted, mark as invalid
				stats.Total++
				stats.Invalid = append(stats.Invalid, field)
			}
		}
	}

	return stats
}

// extractConcatenatedIPs attempts to extract individual IPs from a concatenated string
// like "1.2.3.41.2.3.4" -> ["1.2.3.4", "1.2.3.4"]
// Also handles completely concatenated numbers like "1234123412341234" by finding valid octet boundaries
func extractConcatenatedIPs(s string) []string {
	var results []string

	// First, try dot-based extraction (for strings like "1.2.3.41.2.3.4")
	results = extractFromDottedString(s)
	if len(results) > 0 {
		return results
	}

	// Then try extracting from a concatenated number string (no dots)
	// This handles strings like "217214401962142252083521..." where IPs are merged
	results = extractFromNumberString(s)
	return results
}

// extractFromDottedString extracts IPs from dot-separated concatenations
func extractFromDottedString(s string) []string {
	var results []string
	parts := strings.Split(s, ".")
	if len(parts) < 4 {
		return results
	}

	// Try to extract IPs by sliding window of 4 parts
	for i := 0; i <= len(parts)-4; i++ {
		octets := parts[i : i+4]

		valid := true
		var ip string
		for j, octet := range octets {
			if octet == "" {
				valid = false
				break
			}
			// Check for leading zeros (except "0" itself)
			if len(octet) > 1 && octet[0] == '0' {
				valid = false
				break
			}
			num := 0
			for _, ch := range octet {
				if ch < '0' || ch > '9' {
					valid = false
					break
				}
				num = num*10 + int(ch-'0')
			}
			if num < 0 || num > 255 {
				valid = false
				break
			}
			if j > 0 {
				ip += "."
			}
			ip += octet
		}

		if valid && ip != "" {
			results = append(results, ip)
		}
	}

	return results
}

// extractFromNumberString extracts IPs from a completely concatenated number string
// e.g., "217214401962142252083521..." -> finds all valid 4-octet IP patterns
func extractFromNumberString(s string) []string {
	var results []string

	// Only attempt if no dots and reasonable length
	if strings.Contains(s, ".") || len(s) < 8 {
		return results
	}

	// Use recursive backtracking to find all valid IP patterns
	var extracted []string
	findIPPatterns(s, 0, []string{}, &extracted)

	// Deduplicate
	seen := make(map[string]bool)
	for _, ip := range extracted {
		if !seen[ip] {
			results = append(results, ip)
			seen[ip] = true
		}
	}

	return results
}

// findIPPatterns recursively finds valid IP patterns in a number string
func findIPPatterns(s string, pos int, current []string, results *[]string) {
	// Found a complete IP (4 octets)
	if len(current) == 4 {
		if pos == len(s) {
			ip := strings.Join(current, ".")
			*results = append(*results, ip)
		}
		return
	}

	// Too many characters consumed without completing IP
	if pos >= len(s) {
		return
	}

	// Try taking 1, 2, or 3 digits as next octet
	for digits := 1; digits <= 3 && pos+digits <= len(s); digits++ {
		octet := s[pos : pos+digits]

		// Skip leading zeros (except "0")
		if len(octet) > 1 && octet[0] == '0' {
			continue
		}

		// Parse and validate octet
		num := 0
		for _, ch := range octet {
			if ch < '0' || ch > '9' {
				continue
			}
			num = num*10 + int(ch-'0')
		}

		// Valid octet range
		if num >= 0 && num <= 255 {
			findIPPatterns(s, pos+digits, append(current, octet), results)
		}
	}
}

// isLikelyIPOctetSequence checks if a string looks like IP octets (e.g., "192.168.1" or "255")
func isLikelyIPOctetSequence(s string) bool {
	// Should contain only digits and dots
	for _, ch := range s {
		if (ch < '0' || ch > '9') && ch != '.' {
			return false
		}
	}
	return len(s) > 0
}

// isValidTarget checks if a target is a valid IP, CIDR, or IP range
func isValidTarget(target string) bool {
	// Try single IP
	if ip := net.ParseIP(target); ip != nil {
		return true
	}

	// Try ip:port format (e.g. 1.2.3.4:443)
	if host, portStr, err := net.SplitHostPort(target); err == nil {
		if net.ParseIP(host) != nil {
			if p, err2 := strconv.Atoi(portStr); err2 == nil && p > 0 && p <= 65535 {
				return true
			}
		}
	}

	// Try CIDR notation
	if strings.Contains(target, "/") {
		_, _, err := net.ParseCIDR(target)
		return err == nil
	}

	// Try IP-IP range
	if strings.Contains(target, "-") {
		parts := strings.Split(target, "-")
		if len(parts) == 2 {
			startIP := net.ParseIP(strings.TrimSpace(parts[0]))
			endIP := net.ParseIP(strings.TrimSpace(parts[1]))
			return startIP != nil && endIP != nil
		}
	}

	return false
}

// FormatParsedTargetsForDisplay formats valid targets for UI display (multi-line, grouped)
func FormatParsedTargetsForDisplay(targets []string, maxLines int) string {
	if len(targets) == 0 {
		return "No valid targets parsed"
	}

	if maxLines <= 0 {
		maxLines = 10
	}

	var lines []string
	for i, target := range targets {
		if i >= maxLines {
			remaining := len(targets) - maxLines
			lines = append(lines, fmt.Sprintf("  ... and %d more", remaining))
			break
		}
		lines = append(lines, fmt.Sprintf("  • %s", target))
	}

	return strings.Join(lines, "\n")
}

// FormatIPs formats IP count for display
func FormatIPs(count int64) string {
	if count >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(count)/1000000)
	} else if count >= 1000 {
		return fmt.Sprintf("%.1fK", float64(count)/1000)
	}
	return fmt.Sprintf("%d", count)
}
