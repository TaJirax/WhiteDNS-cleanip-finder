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
}
