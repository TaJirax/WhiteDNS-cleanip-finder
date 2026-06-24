package tlsprobe

// ScanConfig configures a TLS hostname probe run
type ScanConfig struct {
	Targets     []string // IPs or CIDR strings
	Hostnames   []string // SNI hostname values to test
	Port        int      // default 443
	TimeoutSec  float64  // default 5.0
	Concurrency int      // default 50
	OutputPath  string
	Verbose     bool
	// StrictSNI, when true, only counts a pair as a success if the TLS handshake
	// presenting the given SNI is itself accepted. It disables the "retry without
	// SNI" fallback so domain-fronting / SNI-spoofing candidates are not reported
	// just because the IP serves TLS for some other name.
	StrictSNI bool
}
