package tlsprobe

import "time"

// ProbeResult represents a single TLS hostname probe outcome
type ProbeResult struct {
	IP           string    `json:"ip"`
	Hostname     string    `json:"hostname"`
	Port         int       `json:"port"`
	Success      bool      `json:"success"`
	LatencyMs    float64   `json:"latency_ms"`
	TLSVersion   string    `json:"tls_version"`
	CertCN       string    `json:"cert_cn"`
	CertIssuer   string    `json:"cert_issuer"`
	HTTPStatus   int       `json:"http_status"`
	ServerHeader string    `json:"server_header"`
	Error        string    `json:"error"`
	ScannedAt    time.Time `json:"scanned_at"`
}
