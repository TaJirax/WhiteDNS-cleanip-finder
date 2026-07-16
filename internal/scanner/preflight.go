package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MasscanPreflight runs optimized masscan scan for any IP scale (millions supported)
func (s *Scanner) MasscanPreflight(ips []string, interactive bool) ([]string, error) {
	if len(ips) == 0 {
		s.logf("\n[*] No targets provided for Masscan pre-flight.\n")
		return []string{}, nil
	}

	s.logf("\n[*] Parsing IP ranges...\n")
	ranges := ParseIPRanges(ips)

	// Calculate total IP count
	totalIPs := int64(0)
	for _, r := range ranges {
		totalIPs += r.Size
	}

	s.logf("[+] Parsed %d range(s) with %s total IPs\n", len(ranges), FormatIPs(totalIPs))

	// Get parameters
	rate := s.config.MasscanRate
	retries := s.config.MasscanRetries
	wait := s.config.MasscanWaitSec

	// Auto-tune for massive scans
	if totalIPs > 10000000 {
		s.logf("[*] Massive scan detected (10M+ IPs) - enabling optimized mode\n")
		rate = maxInt(rate, 10000)
		wait = maxInt(wait, 30)
	} else if totalIPs > 1000000 {
		rate = maxInt(rate, 5000)
		wait = maxInt(wait, 20)
	} else if totalIPs > 100000 {
		rate = maxInt(rate, 2000)
		wait = maxInt(wait, 15)
	}

	if interactive {
		estimatedSec := EstimateScanTime(ranges, rate)
		s.logf("\n[i] Estimated time: %dm %ds\n", estimatedSec/60, estimatedSec%60)

		s.logf("[?] Enter Masscan rate (packets/sec) [Auto: %d]: ", rate)
		input := readLine()
		if input != "" && isNumeric(input) {
			if r, err := strconv.Atoi(input); err == nil {
				rate = r
			}
		}

		s.logf("[?] Enter packet retries [Default 2]: ")
		input = readLine()
		if input != "" && isNumeric(input) {
			if r, err := strconv.Atoi(input); err == nil {
				retries = r
			}
		}

		s.logf("[?] Enter end-of-scan wait time [Default 10]: ")
		input = readLine()
		if input != "" && isNumeric(input) {
			if r, err := strconv.Atoi(input); err == nil {
				wait = r
			}
		}
	}

	// Create resource manager for tracking
	rm := NewResourceManager()
	rm.StartProgress(totalIPs)

	// For massive scans (>5M IPs), use distributed streaming approach
	if totalIPs > 5000000 {
		return s.masscanMassiveScale(ranges, rate, retries, wait, rm)
	}

	// For large scans, use parallel approach
	if totalIPs > 100000 {
		return s.masscanLargeScale(ranges, rate, retries, wait, rm)
	}

	// For normal scans, use single pass
	return s.masscanNormalScale(ranges, rate, retries, wait, rm)
}

// NmapPreflight runs optimized interactive nmap scan
func (s *Scanner) NmapPreflight(ips []string, interactive bool) ([]string, error) {
	if len(ips) == 0 {
		s.logf("\n[*] No targets provided for Nmap pre-flight.\n")
		return []string{}, nil
	}

	uniqueIPs := deduplicateIPs(ips)
	s.logf("\n[*] Preparing Nmap for %d unique IPs...\n", len(uniqueIPs))

	timing := s.config.NmapTiming
	retries := s.config.NmapRetries
	minRate := s.config.NmapMinRate
	maxRate := s.config.NmapMaxRate

	// Auto-tune based on target count
	targetCount := len(uniqueIPs)
	if targetCount > 10000 {
		timing = "-T4"
		minRate = 2000
		maxRate = 5000
	} else if targetCount > 1000 {
		timing = "-T4"
		minRate = 1000
		maxRate = 3000
	} else if targetCount < 100 {
		timing = "-T3"
		minRate = 500
		maxRate = 1000
	}

	if interactive {
		s.logf("\n[?] Select Nmap timing template:\n")
		s.logf("    [1] T2 - Polite\n")
		s.logf("    [2] T3 - Normal\n")
		s.logf("    [3] T4 - Aggressive [Default]\n")
		s.logf("    Choice [Default 3 / T4]: ")

		choice := readLine()
		timingMap := map[string]string{
			"1": "-T2",
			"2": "-T3",
			"3": "-T4",
		}
		if t, ok := timingMap[choice]; ok {
			timing = t
		} else {
			timing = "-T4"
		}

		s.logf("\n[?] Max retries per probe [Default 2]: ")
		input := readLine()
		if input != "" && isNumeric(input) {
			if r, err := strconv.Atoi(input); err == nil {
				retries = r
			}
		}

		if timing != "-T2" {
			s.logf("\n[?] Minimum packet rate [Default %d]: ", minRate)
			input := readLine()
			if input != "" && isNumeric(input) {
				if r, err := strconv.Atoi(input); err == nil {
					minRate = r
				}
			}

			s.logf("[?] Maximum packet rate [Default %d]: ", maxRate)
			input = readLine()
			if input != "" && isNumeric(input) {
				if r, err := strconv.Atoi(input); err == nil {
					maxRate = r
				}
			}
		}
	}

	// Use system temp directory
	tempDir := os.TempDir()
	timestamp := time.Now().Unix()
	targetFile := filepath.Join(tempDir, fmt.Sprintf("nmap_targets_%d.txt", timestamp))
	outputFile := filepath.Join(tempDir, fmt.Sprintf("nmap_results_%d.gnmap", timestamp))
	defer os.Remove(targetFile)
	defer os.Remove(outputFile)

	// Write targets
	targetData := strings.Join(uniqueIPs, "\n") + "\n"
	if err := os.WriteFile(targetFile, []byte(targetData), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write target file: %v", err)
	}

	// Adaptive timeout: 10s base + 1s per 1000 IPs
	timeoutSec := 10 + (targetCount / 1000)
	resolvedNmap, err := ResolveToolPath("nmap")
	if err != nil {
		return nil, err
	}

	ports := intsToStrings(s.config.TargetPorts)
	portArg := strings.Join(ports, ",")
	args := []string{
		"-p" + portArg,
		timing,
		"-iL", targetFile,
		"--max-retries", fmt.Sprintf("%d", retries),
		"--host-timeout", fmt.Sprintf("%ds", maxInt(180, timeoutSec)),
		"--script-timeout", "5s",
		"--min-hostgroup", "256",
		"--min-parallelism", "32",
		"-oG", outputFile,
	}
	if timing != "-T2" {
		args = append(args, "--min-rate", fmt.Sprintf("%d", minRate))
		args = append(args, "--max-rate", fmt.Sprintf("%d", maxRate))
	}

	s.logf("[*] Launching Nmap: %s, retries=%d, timeout=%ds\n", timing, retries, timeoutSec)

	// Context with adaptive timeout
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeoutSec+20)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolvedNmap, args...)

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			s.logf("[*] Nmap timeout after %ds (partial results may be available)\n", timeoutSec+20)
		}
		return nil, fmt.Errorf("nmap scan failed: %w", err)
	}
	endpoints, parsed := parseNmapOutputStreaming(outputFile, s.config.TargetPorts)
	s.logf("[+] Nmap complete. Found %d online endpoints (%d parsed).\n", len(endpoints), parsed)
	return endpoints, nil
}

// masscanNormalScale handles typical IP ranges (< 100K IPs)
func (s *Scanner) masscanNormalScale(ranges []IPRange, rate, retries, wait int, rm *ResourceManager) ([]string, error) {
	tempDir := os.TempDir()
	timestamp := time.Now().Unix()
	targetFile := filepath.Join(tempDir, fmt.Sprintf("masscan_targets_%d.txt", timestamp))
	outputFile := filepath.Join(tempDir, fmt.Sprintf("masscan_results_%d.txt", timestamp))
	defer os.Remove(targetFile)
	defer os.Remove(outputFile)

	// Collect all IPs
	var allIPs []string
	for _, r := range ranges {
		start := ipToInt(r.Start)
		end := ipToInt(r.End)
		for current := start; current <= end; current++ {
			allIPs = append(allIPs, intToIP(current).String())
		}
	}

	targetData := strings.Join(allIPs, "\n") + "\n"
	if err := os.WriteFile(targetFile, []byte(targetData), 0o644); err != nil {
		return nil, err
	}

	ports := intsToStrings(s.config.TargetPorts)
	portArg := strings.Join(ports, ",")
	timeoutSec := 3 + int(len(allIPs)/20000)

	resolvedMasscan, err := ResolveToolPath("masscan")
	if err != nil {
		return nil, err
	}
	args := []string{
		"-p" + portArg,
		"-iL", targetFile,
		"--retries", fmt.Sprintf("%d", retries),
		"--wait", fmt.Sprintf("%d", wait),
		"--connection-timeout", fmt.Sprintf("%d", timeoutSec),
		"--rate", fmt.Sprintf("%d", rate),
		"-oL", outputFile,
	}

	s.logf("[*] Launching Masscan: %d IPs at %d pps\n", len(allIPs), rate)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(wait+30)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolvedMasscan, args...)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("masscan scan failed: %w", err)
	}

	endpoints, _ := parseMasscanOutputStreaming(outputFile, s.config.TargetPorts)
	s.logf("[+] Found %d endpoints\n", len(endpoints))
	return endpoints, nil
}

// masscanLargeScale handles large IP ranges (100K - 5M IPs) with parallel processing
func (s *Scanner) masscanLargeScale(ranges []IPRange, rate, retries, wait int, rm *ResourceManager) ([]string, error) {
	chunkSize := 100000
	numChunks := 4
	if len(ranges) > 1 {
		numChunks = 8
	}

	s.logf("[*] Large scale scan: %d parallel chunks\n", numChunks)

	var mu sync.Mutex
	var allEndpoints []string
	var wg sync.WaitGroup

	progressTicker := time.NewTicker(2 * time.Second)
	defer progressTicker.Stop()

	go func() {
		for range progressTicker.C {
			if rm.IsCancelled() {
				return
			}
			p := rm.GetProgress()
			s.logf("[DEBUG] Preflight progress: %d%% (%s / %s) found=%d rate=%d/s eta=%ds errors=%d retries=%d\n",
				p.PercentComplete,
				FormatIPs(p.ScannedIPs),
				FormatIPs(p.TotalIPs),
				p.FoundEndpoints,
				p.CurrentRate,
				p.EstimatedRemainingSec,
				p.ErrorCount,
				p.RetryCount,
			)
		}
	}()

	chunkIdx := 0
	for _, r := range ranges {
		start := ipToInt(r.Start)
		end := ipToInt(r.End)

		for current := start; current <= end; {
			wg.Add(1)
			chunkEnd := current + int64(chunkSize)
			if chunkEnd > end+1 {
				chunkEnd = end + 1
			}

			go func(cIdx int, cStart, cEnd int64) {
				defer wg.Done()

				endpoints, _ := s.masscanChunk(cIdx, cStart, cEnd, rate/numChunks, retries, wait)
				if len(endpoints) > 0 {
					mu.Lock()
					allEndpoints = append(allEndpoints, endpoints...)
					mu.Unlock()
					rm.RecordProgress(len(endpoints), int64(len(allEndpoints)))
				}
			}(chunkIdx, current, chunkEnd)

			current = chunkEnd
			chunkIdx++
		}
	}

	wg.Wait()
	progressTicker.Stop()

	s.logf("\n[+] Large scale complete: %d endpoints found\n", len(allEndpoints))
	return deduplicateEndpoints(allEndpoints), nil
}

// masscanMassiveScale handles massive IP ranges (5M+ IPs) with streaming and resource management
func (s *Scanner) masscanMassiveScale(ranges []IPRange, rate, retries, wait int, rm *ResourceManager) ([]string, error) {
	s.logf("[*] Massive scale scan (5M+ IPs) - streaming mode\n")
	s.logf("[*] Workers: %d | Memory limit: %d MB\n", rm.GetMaxWorkers(), rm.memoryLimitMB)

	var mu sync.Mutex
	var allEndpoints []string
	var wg sync.WaitGroup

	// Progress reporter
	progressTicker := time.NewTicker(3 * time.Second)
	defer progressTicker.Stop()

	go func() {
		for range progressTicker.C {
			if rm.IsCancelled() {
				return
			}
			p := rm.GetProgress()
			s.logf("[DEBUG] Preflight progress: %d%% (%s / %s) found=%d rate=%d/s eta=%ds errors=%d retries=%d\n",
				p.PercentComplete,
				FormatIPs(p.ScannedIPs),
				FormatIPs(p.TotalIPs),
				p.FoundEndpoints,
				p.CurrentRate,
				p.EstimatedRemainingSec,
				p.ErrorCount,
				p.RetryCount,
			)
		}
	}()

	chunkSize := 50000
	chunkIdx := 0

	// Process ranges with worker pool
	for _, r := range ranges {
		start := ipToInt(r.Start)
		end := ipToInt(r.End)

		for current := start; current <= end; {
			chunkEnd := current + int64(chunkSize)
			if chunkEnd > end+1 {
				chunkEnd = end + 1
			}

			wg.Add(1)
			go func(cIdx int, cStart, cEnd int64) {
				defer wg.Done()

				// Acquire worker slot
				if err := rm.AcquireWorker(); err != nil {
					rm.RecordError()
					return
				}
				defer rm.ReleaseWorker()

				endpoints, _ := s.masscanChunk(cIdx, cStart, cEnd, rate/8, retries, wait)
				if len(endpoints) > 0 {
					mu.Lock()
					allEndpoints = append(allEndpoints, endpoints...)
					mu.Unlock()
				}

				rm.RecordProgress(len(endpoints), int64(len(allEndpoints)))
			}(chunkIdx, current, chunkEnd)

			current = chunkEnd
			chunkIdx++

			// Limit concurrent submissions
			if chunkIdx%16 == 0 {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	wg.Wait()
	progressTicker.Stop()

	s.logf("\n[+] Massive scale complete: %d endpoints found\n", len(allEndpoints))
	p := rm.GetProgress()
	s.logf("[SCAN PROGRESS] %d%% (%s / %s) found=%d rate=%d/s elapsed=%.1fs eta=%ds errors=%d retries=%d\n",
		p.PercentComplete,
		FormatIPs(p.ScannedIPs),
		FormatIPs(p.TotalIPs),
		p.FoundEndpoints,
		p.CurrentRate,
		time.Since(p.StartTime).Seconds(),
		p.EstimatedRemainingSec,
		p.ErrorCount,
		p.RetryCount,
	)
	return deduplicateEndpoints(allEndpoints), nil
}

// masscanChunk runs masscan for a single chunk with streaming
func (s *Scanner) masscanChunk(chunkIdx int, startIP, endIP int64, rate, retries, wait int) ([]string, int) {
	tempDir := os.TempDir()
	timestamp := time.Now().Unix()
	targetFile := filepath.Join(tempDir, fmt.Sprintf("masscan_chunk_%d_%d.txt", chunkIdx, timestamp))
	outputFile := filepath.Join(tempDir, fmt.Sprintf("masscan_out_%d_%d.txt", chunkIdx, timestamp))
	defer os.Remove(targetFile)
	defer os.Remove(outputFile)

	// Generate IPs for chunk
	var ips []string
	for current := startIP; current < endIP; current++ {
		ips = append(ips, intToIP(current).String())
	}

	if len(ips) == 0 {
		return []string{}, 0
	}

	// Write targets
	if err := os.WriteFile(targetFile, []byte(strings.Join(ips, "\n")+"\n"), 0o644); err != nil {
		return []string{}, 0
	}

	ports := intsToStrings(s.config.TargetPorts)
	portArg := strings.Join(ports, ",")

	resolvedMasscan, err := ResolveToolPath("masscan")
	if err != nil {
		s.logf("[-] %v\n", err)
		return []string{}, 0
	}
	args := []string{
		"-p" + portArg,
		"-iL", targetFile,
		"--retries", fmt.Sprintf("%d", retries),
		"--wait", fmt.Sprintf("%d", wait),
		"--connection-timeout", "3",
		"--rate", fmt.Sprintf("%d", rate),
		"-oL", outputFile,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(wait+20)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolvedMasscan, args...)
	if err := cmd.Run(); err != nil {
		s.logf("[-] Masscan chunk %d failed: %v\n", chunkIdx, err)
		return []string{}, 0
	}

	endpoints, parsed := parseMasscanOutputStreaming(outputFile, s.config.TargetPorts)
	return endpoints, parsed
}

// parseMasscanOutputStreaming parses masscan output with streaming
func parseMasscanOutputStreaming(filepath string, targetPorts []int) ([]string, int) {
	file, err := os.Open(filepath)
	if err != nil {
		return []string{}, 0
	}
	defer file.Close()

	var endpoints []string
	scanner := bufio.NewScanner(file)
	parsed := 0

	// Pre-compile port matcher map for O(1) lookup
	portMap := make(map[int]bool)
	for _, p := range targetPorts {
		portMap[p] = true
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Fast path: check prefix
		if !strings.HasPrefix(line, "open") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		// Parse: "open/tcp/port/ttl/timestamp"
		portPart := strings.Split(parts[0], "/")
		if len(portPart) < 3 {
			continue
		}

		if port, err := strconv.Atoi(portPart[2]); err == nil && portMap[port] {
			ip := parts[1]

			// Validate IP format
			if isValidIP(ip) {
				endpoints = append(endpoints, fmt.Sprintf("%s:%d", ip, port))
				parsed++
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("[!] Warning: masscan output read error (results may be truncated): %v\n", err)
	}

	return deduplicateEndpoints(endpoints), parsed
}

// parseNmapOutput parses nmap gnmap (-oG) output
func parseNmapOutput(filepath string, targetPorts []int) ([]string, error) {
	endpoints, _ := parseNmapOutputStreaming(filepath, targetPorts)
	return endpoints, nil
}

// parseNmapOutputStreaming parses nmap gnmap output with streaming
func parseNmapOutputStreaming(filepath string, targetPorts []int) ([]string, int) {
	file, err := os.Open(filepath)
	if err != nil {
		return []string{}, 0
	}
	defer file.Close()

	var endpoints []string
	scanner := bufio.NewScanner(file)
	parsed := 0

	// Pre-compile port matcher
	portMap := make(map[int]bool)
	for _, p := range targetPorts {
		portMap[p] = true
	}

	// Pre-compile regex for efficiency
	portRe := regexp.MustCompile(`(\d+)/open/tcp`)

	for scanner.Scan() {
		line := scanner.Text()

		// Fast path: check for Host line
		if !strings.HasPrefix(line, "Host:") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		ip := parts[1]

		// Validate IP
		if !isValidIP(ip) {
			continue
		}

		// Extract ports: "80/open/tcp//http//"
		matches := portRe.FindAllStringSubmatch(line, -1)

		for _, match := range matches {
			if len(match) > 1 {
				if port, err := strconv.Atoi(match[1]); err == nil && portMap[port] {
					endpoints = append(endpoints, fmt.Sprintf("%s:%d", ip, port))
					parsed++
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("[!] Warning: nmap output read error (results may be truncated): %v\n", err)
	}

	return deduplicateEndpoints(endpoints), parsed
}

// Helper functions
func deduplicateIPs(ips []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" && !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}
	return result
}

func deduplicateEndpoints(eps []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, ep := range eps {
		ep = strings.TrimSpace(ep)
		if ep != "" && !seen[ep] {
			seen[ep] = true
			result = append(result, ep)
		}
	}
	return result
}

func isNumeric(s string) bool {
	_, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return err == nil
}

func intsToStrings(ints []int) []string {
	var result []string
	for _, i := range ints {
		result = append(result, fmt.Sprintf("%d", i))
	}
	return result
}

func readLine() string {
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return scanner.Text()
	}
	return ""
}

// Optimized helper functions

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func isValidIP(ip string) bool {
	// Quick validation - check for valid IPv4 format
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}
	return true
}

// Atomic counter for concurrent progress tracking
type atomicCounter struct {
	value atomic.Int64
}

func (ac *atomicCounter) increment() int64 {
	return ac.value.Add(1)
}

func (ac *atomicCounter) get() int64 {
	return ac.value.Load()
}
