// Package mobile is the gomobile-facing bridge around the white-proxy scanning
// engine. Every exported symbol uses only gomobile-safe types (string, int,
// bool, []byte, error, and bound struct/interface types) so it can be consumed
// from Kotlin/Java after `gomobile bind`.
//
// Discovery is always in-process ("direct"); masscan/nmap preflight is not
// available on Android.
package mobile

// ScanConfig carries all user-tunable scan options as primitives. Targets and
// SNIDomains are newline/space/comma separated strings; Ports is a comma string
// such as "443,2053,8443" or "8000-8100".
type ScanConfig struct {
	AntiDPI            bool
	DPIFragmentSize    int
	DPIFragmentDelayMs int
	ProxyTestURL       string
	TargetType         string // ip (default) or domain; only IP scans resolve domain targets
	CountTotal         bool   // optional background exact counting
	Targets            string // IPs/CIDRs, newline/space separated
	Ports              string // comma/range string; empty -> sane defaults
	Concurrency        int    // worker count; <=0 -> default
	TimeoutMs          int    // per-probe timeout in ms; <=0 -> default
	TransferModel      string // proxy scans: "old" or "brrr"
	LowBandwidth       bool   // extend timeouts for slow links
	SNIDomains         string // SNI scan: custom domains; empty -> managed defaults
	SNIStrict          bool   // SNI scan: require SNI itself to be accepted
	VerboseLog         bool   // emit per-endpoint probe log lines (slower; for debugging)
	LiteMode           bool   // low-RAM/CPU mode for old/low-end devices (smaller chunks,
	// lower concurrency, sequential domain probing, inter-chunk pauses)

	// FastMode stops probing an endpoint once enough domains have confirmed it
	// and skips retries: the same verdict with less work. Ignored in LiteMode /
	// LowBandwidth, where the extra attempts are what make a hit findable.
	FastMode bool

	// EdgeProvider names a config.EdgeProvider (see EdgeProviderList) whose edge
	// IPs are being scanned. It scopes the probe hostnames to that platform, so an
	// accepted IP is one that really serves it. Empty for plain target scans.
	EdgeProvider string

	// DNS resolver / tunnel scan (StartDNSScan) options.
	DNSProtocol   string // "udp" | "tcp" | "both" | "all" (default "both"); "all" also probes DoT/DoH
	DNSReference  string // truth-table reference resolver: "google" (default) | "cloudflare" | "quad9"
	DNSScanDepth  string // "fast" uses short probes; "full"/"thorough" (default) runs every check
	DNSTestNearby bool   // also expand + rescan the /24 around each tunnel-ready hit (disabled in LiteMode: multiplies scan size ~256x per hit)

	// Optional DNS query rate limit, for networks that drop DNS above a fixed
	// rate (Iran: about 6/s). All zero = unlimited.
	DNSRateLimit            float64 // max queries per second, whole scan
	DNSRateLimitPerResolver float64 // max queries per second to any one resolver
	DNSRateBurst            int     // queries allowed back-to-back (<=1 = evenly spaced)
	DNSTimingJitter         float64 // 0..1: randomly lengthen gaps so probes have no fixed rhythm

	// DNSTT end-to-end tunnel test (StartE2EScan) options. Targets carries the
	// resolver shortlist (one per line) to validate through a live DNSTT server.
	E2EDomain    string // DNSTT server's NS-delegated zone; required
	E2EPubKey    string // DNSTT server public key (hex); empty => reachability-only
	E2ETransport string // "udp" | "tcp" (both supported) | "dot" | "doh" (not yet implemented)
	E2EURL       string // HTTP endpoint fetched through the tunnel; empty => default generate_204
}

// NewScanConfig returns an empty config (convenient constructor for gomobile,
// which cannot allocate Go structs with field literals from Kotlin).
func NewScanConfig() *ScanConfig { return &ScanConfig{} }
