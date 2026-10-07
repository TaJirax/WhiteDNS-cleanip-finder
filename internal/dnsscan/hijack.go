package dnsscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type hijackObservation struct {
	Transport string
	Name      string
	Header    DnsHeader
	HeaderOK  bool
	AnswerIPs []string
	Error     string
}

type hijackDetection struct {
	Hijacked   bool
	Confidence string
	Reasons    []string
	IPs        []string
	UDP        bool
	TCP        bool
	Checks     int
	Anomalies  int
	RCodes     []string
}

func detectHijack(ctx context.Context, ip string, timeout time.Duration, dialer *net.Dialer, port int, testUDP, testTCP bool) hijackDetection {
	names := []string{
		"nx-" + randomLabel() + "." + randomLabel() + ".invalid",
		"nx-" + randomLabel() + "." + randomLabel() + ".invalid",
	}
	count := 0
	if testUDP {
		count += len(names)
	}
	if testTCP {
		count += len(names)
	}
	observations := make(chan hijackObservation, count)
	var wg sync.WaitGroup
	for _, qname := range names {
		name := qname
		if testUDP {
			wg.Add(1)
			go func() {
				defer wg.Done()
				observations <- probeNegativeUDP(ctx, ip, name, timeout, dialer, port)
			}()
		}
		if testTCP {
			wg.Add(1)
			go func() {
				defer wg.Done()
				observations <- probeNegativeTCP(ctx, ip, name, timeout, dialer, port)
			}()
		}
	}
	wg.Wait()
	close(observations)

	all := make([]hijackObservation, 0, count)
	for observation := range observations {
		all = append(all, observation)
	}
	return classifyHijackObservations(all)
}

func probeNegativeUDP(ctx context.Context, resolverIP, name string, timeout time.Duration, dialer *net.Dialer, port int) hijackObservation {
	result := hijackObservation{Transport: "udp", Name: name}
	if !waitDNSQuery(ctx, resolverIP) {
		result.Error = "stopped"
		return result
	}
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port)))
	if err != nil {
		result.Error = "dial: " + truncErr(err)
		return result
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	query, txid := buildDnsQuery(name, 1, false)
	if _, err := conn.Write(query); err != nil {
		result.Error = "write: " + truncErr(err)
		return result
	}
	hdr, ips, _, _, err := readUDPResponse(conn, txid, 1, name, false)
	result.Header, result.AnswerIPs = hdr, ips
	result.HeaderOK = trustedResponseHeader(hdr, err)
	if err != nil {
		result.Error = truncErr(err)
	}
	return result
}

func probeNegativeTCP(ctx context.Context, resolverIP, name string, timeout time.Duration, dialer *net.Dialer, port int) hijackObservation {
	result := hijackObservation{Transport: "tcp", Name: name}
	if !waitDNSQuery(ctx, resolverIP) {
		result.Error = "stopped"
		return result
	}
	if dialer == nil {
		dialer = &net.Dialer{Timeout: timeout}
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(resolverIP, fmt.Sprintf("%d", port)))
	if err != nil {
		result.Error = "dial: " + truncErr(err)
		return result
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	query, txid := buildDnsQuery(name, 1, false)
	if err := writeTCPQuery(conn, query); err != nil {
		result.Error = "write: " + truncErr(err)
		return result
	}
	packet, err := readTCPResponse(conn)
	if err != nil {
		result.Error = "read: " + truncErr(err)
		return result
	}
	hdr, ips, _, parseErr := parseDnsMessage(packet, 1, txid, true, name)
	result.Header, result.AnswerIPs = hdr, ips
	result.HeaderOK = trustedResponseHeader(hdr, parseErr)
	if parseErr != nil {
		result.Error = truncErr(parseErr)
	}
	return result
}

func trustedResponseHeader(hdr DnsHeader, err error) bool {
	if !hdr.QR {
		return false
	}
	if err == nil {
		return true
	}
	message := err.Error()
	return !strings.Contains(message, "mismatch") &&
		!strings.Contains(message, "malformed") &&
		!strings.Contains(message, "not a response")
}

func classifyHijackObservations(observations []hijackObservation) hijackDetection {
	result := hijackDetection{Confidence: "none"}
	reasons := make(map[string]bool)
	ips := make(map[string]map[string]bool)
	points := 0

	sort.Slice(observations, func(i, j int) bool {
		if observations[i].Transport != observations[j].Transport {
			return observations[i].Transport < observations[j].Transport
		}
		return observations[i].Name < observations[j].Name
	})
	for _, observation := range observations {
		if !observation.HeaderOK {
			continue
		}
		result.Checks++
		result.RCodes = append(result.RCodes, fmt.Sprintf("%s:%d", observation.Transport, observation.Header.Rcode))
		anomalyPoints := 0
		reason := ""
		switch {
		case len(observation.AnswerIPs) > 0:
			anomalyPoints, reason = 3, "forged-a"
			for _, ip := range observation.AnswerIPs {
				if ips[ip] == nil {
					ips[ip] = make(map[string]bool)
				}
				ips[ip][observation.Name] = true
			}
		case observation.Header.Rcode == 0 && observation.Header.ANCount > 0:
			anomalyPoints, reason = 3, "unexpected-answer"
		case observation.Header.Rcode == 0:
			anomalyPoints, reason = 1, "nxdomain-to-nodata"
		case observation.Header.Rcode != 3 && observation.Header.Rcode != 2 && observation.Header.Rcode != 5:
			anomalyPoints, reason = 1, "unexpected-rcode"
		}
		if anomalyPoints == 0 {
			continue
		}
		result.Anomalies++
		points += anomalyPoints
		reasons[reason] = true
		if observation.Transport == "udp" {
			result.UDP = true
		}
		if observation.Transport == "tcp" {
			result.TCP = true
		}
	}

	for ip, names := range ips {
		result.IPs = append(result.IPs, ip)
		if len(names) >= 2 {
			points += 2
			reasons["stable-redirect"] = true
		}
	}
	if result.UDP != result.TCP && result.Anomalies > 0 {
		reasons["transport-specific"] = true
		points++
	}
	if result.UDP && result.TCP {
		reasons["cross-transport"] = true
		points++
	}
	if result.Checks < len(observations) {
		reasons["incomplete-checks"] = true
	}

	result.Hijacked = points >= 3 || result.Anomalies >= 2
	switch {
	case points >= 6:
		result.Confidence = "high"
	case result.Hijacked:
		result.Confidence = "medium"
	case result.Anomalies > 0:
		result.Confidence = "low"
	case len(observations) > 0 && result.Checks == 0:
		result.Confidence = "inconclusive"
	}
	for reason := range reasons {
		result.Reasons = append(result.Reasons, reason)
	}
	sort.Strings(result.Reasons)
	sort.Strings(result.IPs)
	return result
}
