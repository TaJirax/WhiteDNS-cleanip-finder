package asn

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ASNInfo holds ASN information
type ASNInfo struct {
	ASN  string
	Name string
	Type string
	CIDR string
}

// ASNGroup holds an ASN with all matching subnets for selection screens.
type ASNGroup struct {
	ASN         string
	Name        string
	Type        string
	SubnetCount int
	CIDRs       []string
}

// ASNEngine manages ASN lookups
type ASNEngine struct {
	mu      sync.RWMutex
	dataV4  map[int][]asnEntry // first octet → entries
	dataV6  []asnEntry
	loaded  bool
	asnPath string
}

type asnEntry struct {
	network    *net.IPNet
	asn        string
	name       string
	asnType    string
	cidrString string
}

// NewASNEngine creates a new ASN engine
func NewASNEngine(dataDir string) *ASNEngine {
	asnPath := resolveASNPath(dataDir)

	return &ASNEngine{
		dataV4:  make(map[int][]asnEntry),
		dataV6:  []asnEntry{},
		loaded:  false,
		asnPath: asnPath,
	}
}

func resolveASNPath(dataDir string) string {
	candidates := []string{}
	addRoots := func(root string) {
		if root == "" {
			return
		}
		candidates = append(candidates,
			filepath.Join(root, "IranASNs"),
			filepath.Join(root, "..", "IranASNs"),
			filepath.Join(root, "..", "..", "IranASNs"),
		)
	}

	addRoots(dataDir)
	addRoots(filepath.Dir(dataDir))
	if exePath, err := os.Executable(); err == nil {
		addRoots(filepath.Dir(exePath))
	}
	if wd, err := os.Getwd(); err == nil {
		addRoots(wd)
	}

	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if candidate == "." || candidate == string(filepath.Separator) {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}

		if _, err := os.Stat(filepath.Join(candidate, "filtered_ipv4.csv")); err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(candidate, "filtered_ipv6.csv")); err != nil {
			continue
		}
		return candidate
	}

	return filepath.Join(filepath.Dir(dataDir), "IranASNs")
}

// Load loads ASN data from CSV files
func (e *ASNEngine) Load() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.loaded {
		return nil
	}

	v4Path := filepath.Join(e.asnPath, "filtered_ipv4.csv")
	if err := e.loadCSV(v4Path, true); err != nil {
		fmt.Printf("[!] Warning: Could not load IPv4 ASN data: %v\n", err)
	}

	v6Path := filepath.Join(e.asnPath, "filtered_ipv6.csv")
	if err := e.loadCSV(v6Path, false); err != nil {
		fmt.Printf("[!] Warning: Could not load IPv6 ASN data: %v\n", err)
	}

	e.loaded = true
	return nil
}

// loadCSV loads a CSV file into the engine
func (e *ASNEngine) loadCSV(filePath string, isV4 bool) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	lineNo := 0

	parseLine := func(line string) ([]string, error) {
		line = strings.TrimSpace(line)
		if line == "" {
			return nil, nil
		}
		lineReader := csv.NewReader(strings.NewReader(line))
		lineReader.FieldsPerRecord = -1 // allow variable fields
		lineReader.LazyQuotes = true    // tolerate malformed quote usage in source data
		return lineReader.Read()
	}

	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			if len(line) == 0 {
				return readErr
			}
		}
		if readErr == io.EOF && len(line) == 0 {
			break
		}

		lineNo++
		if lineNo == 1 {
			if readErr == io.EOF {
				break
			}
			continue
		}

		record, err := parseLine(strings.TrimRight(line, "\r\n"))
		if err != nil || len(record) < 9 {
			if readErr == io.EOF {
				break
			}
			continue
		}

		cidrStr := strings.TrimSpace(record[0])
		asn := strings.TrimSpace(record[5])
		name := strings.TrimSpace(record[6])
		asnType := strings.TrimSpace(record[8])

		_, ipnet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			// Try parse as single IP and treat as /32 or /128
			ip := net.ParseIP(cidrStr)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}

		}

		if readErr == io.EOF {
			break
		}

		entry := asnEntry{
			network:    ipnet,
			asn:        asn,
			name:       name,
			asnType:    asnType,
			cidrString: cidrStr,
		}

		if isV4 {
			// Index by first octet
			ip := ipnet.IP.To4()
			if ip != nil {
				firstOctet := int(ip[0])
				e.dataV4[firstOctet] = append(e.dataV4[firstOctet], entry)
			}
		} else {
			e.dataV6 = append(e.dataV6, entry)
		}
	}

	return nil
}

// Lookup finds ASN info for an IP
func (e *ASNEngine) Lookup(ipStr string) (*ASNInfo, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.loaded {
		return nil, fmt.Errorf("ASN data not loaded")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", ipStr)
	}

	// IPv4
	if ipv4 := ip.To4(); ipv4 != nil {
		firstOctet := int(ipv4[0])
		for _, entry := range e.dataV4[firstOctet] {
			if entry.network.Contains(ip) {
				return &ASNInfo{
					ASN:  entry.asn,
					Name: entry.name,
					Type: entry.asnType,
					CIDR: entry.cidrString,
				}, nil
			}
		}
	} else {
		// IPv6
		for _, entry := range e.dataV6 {
			if entry.network.Contains(ip) {
				return &ASNInfo{
					ASN:  entry.asn,
					Name: entry.name,
					Type: entry.asnType,
					CIDR: entry.cidrString,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("ASN not found for %s", ipStr)
}

// SearchByPattern searches ASNs by regex pattern
func (e *ASNEngine) SearchByPattern(pattern string) ([]*ASNInfo, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.loaded {
		return nil, fmt.Errorf("ASN data not loaded")
	}

	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var results []*ASNInfo

	// Search IPv4
	for _, entries := range e.dataV4 {
		for _, entry := range entries {
			if re.MatchString(entry.asn) || re.MatchString(entry.name) {
				key := entry.asn + ":" + entry.name
				if !seen[key] {
					seen[key] = true
					results = append(results, &ASNInfo{
						ASN:  entry.asn,
						Name: entry.name,
						Type: entry.asnType,
						CIDR: entry.cidrString,
					})
				}
			}
		}
	}

	// Search IPv6
	for _, entry := range e.dataV6 {
		if re.MatchString(entry.asn) || re.MatchString(entry.name) {
			key := entry.asn + ":" + entry.name
			if !seen[key] {
				seen[key] = true
				results = append(results, &ASNInfo{
					ASN:  entry.asn,
					Name: entry.name,
					Type: entry.asnType,
					CIDR: entry.cidrString,
				})
			}
		}
	}

	return results, nil
}

// SearchGroups returns grouped ASN matches for the interactive selector.
func (e *ASNEngine) SearchGroups(query string) ([]ASNGroup, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.loaded {
		return nil, fmt.Errorf("ASN data not loaded")
	}

	query = strings.TrimSpace(query)
	matcher, err := compileASNQuery(query)
	if err != nil {
		return nil, err
	}

	type groupState struct {
		group ASNGroup
		seen  map[string]struct{}
	}

	groups := make(map[string]*groupState)
	addEntry := func(entry asnEntry) {
		key := entry.asn
		state, ok := groups[key]
		if !ok {
			state = &groupState{
				group: ASNGroup{ASN: entry.asn, Name: entry.name, Type: entry.asnType},
				seen:  make(map[string]struct{}),
			}
			groups[key] = state
		}
		if state.group.Name == "" && entry.name != "" {
			state.group.Name = entry.name
		}
		if state.group.Type == "" && entry.asnType != "" {
			state.group.Type = entry.asnType
		}
		cidr := entry.cidrString
		if _, ok := state.seen[cidr]; ok {
			return
		}
		state.seen[cidr] = struct{}{}
		state.group.CIDRs = append(state.group.CIDRs, cidr)
		state.group.SubnetCount = len(state.group.CIDRs)
	}

	for _, entries := range e.dataV4 {
		for _, entry := range entries {
			if matcher(entry.asn, entry.name) {
				addEntry(entry)
			}
		}
	}
	for _, entry := range e.dataV6 {
		if matcher(entry.asn, entry.name) {
			addEntry(entry)
		}
	}

	results := make([]ASNGroup, 0, len(groups))
	for _, state := range groups {
		results = append(results, state.group)
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].SubnetCount == results[j].SubnetCount {
			return results[i].ASN < results[j].ASN
		}
		return results[i].SubnetCount > results[j].SubnetCount
	})

	for i := range results {
		sort.Strings(results[i].CIDRs)
	}

	return results, nil
}

func compileASNQuery(query string) (func(asnName, name string) bool, error) {
	if query == "" || query == "*" {
		return func(string, string) bool { return true }, nil
	}

	lowerQuery := strings.ToLower(query)
	if strings.HasPrefix(lowerQuery, "/regex:") {
		query = strings.TrimSpace(query[len("/regex:"):])
	} else if strings.HasPrefix(lowerQuery, "regex:") {
		query = strings.TrimSpace(query[len("regex:"):])
	}

	if strings.HasPrefix(query, "/") && strings.Count(query, "/") >= 2 {
		query = strings.TrimPrefix(query, "/")
	}

	if strings.HasPrefix(strings.ToLower(query), "regex:") {
		query = strings.TrimSpace(query[len("regex:"):])
	}

	if strings.HasPrefix(query, "^") || strings.HasSuffix(query, "$") {
		re, err := regexp.Compile("(?i)" + query)
		if err != nil {
			return nil, err
		}
		return func(asnValue, name string) bool {
			return re.MatchString(asnValue) || re.MatchString(name)
		}, nil
	}

	if strings.ContainsAny(query, "*?") {
		pattern := regexp.QuoteMeta(query)
		pattern = strings.ReplaceAll(pattern, `\*`, ".*")
		pattern = strings.ReplaceAll(pattern, `\?`, ".")
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return nil, err
		}
		return func(asnValue, name string) bool {
			return re.MatchString(asnValue) || re.MatchString(name)
		}, nil
	}

	needle := strings.ToLower(query)
	return func(asnValue, name string) bool {
		return strings.Contains(strings.ToLower(asnValue), needle) || strings.Contains(strings.ToLower(name), needle)
	}, nil
}

// GetStats returns load statistics
func (e *ASNEngine) GetStats() (v4Count, v6Count int) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, entries := range e.dataV4 {
		v4Count += len(entries)
	}
	v6Count = len(e.dataV6)
	return
}
