package scanner

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ProbeResult represents a single endpoint probe outcome
type ProbeResult struct {
	Endpoint      string
	Domain        string
	Success       bool
	StatusCode    int
	Latency       time.Duration
	Error         string
	Timestamp     time.Time
	DomainScore   int
	DomainTotal   int
	DomainsTested int
}

// EndpointStats tracks health metrics per endpoint
type EndpointStats struct {
	mu                  sync.RWMutex
	SuccessCount        int
	FailCount           int
	LastOKTime          time.Time
	LastFailTime        time.Time
	AvgLatencyMs        float64
	ConsecutiveFailures int
	QuarantineUntil     time.Time
	QuarantineReason    string
	LastFailReason      string
}

// Scanner manages concurrent endpoint probing
type Scanner struct {
	mu           sync.RWMutex
	endpoints    map[string]*EndpointStats
	config       *ScannerConfig
	activeProbes int
	probeSem     chan struct{} // semaphore for probe concurrency
	resultsChan  chan ProbeResult
	cancelChan   chan struct{}
	wg           sync.WaitGroup
	// paused indicates the scanner is paused (1) or running (0)
	paused int32
	// netGuardActive is 1 while a network-outage guard goroutine is pausing the
	// scan and polling for connectivity to return (prevents duplicate guards).
	netGuardActive int32
	// verboseProbeLogs, when 1, emits the high-volume per-endpoint probe lines
	// ([PROBE]/[SCORE]/[TIMEOUT]/[SKIP]/[NOISE]). Off by default: on large scans
	// the string formatting + callback churn for every endpoint is real CPU.
	// Accept/summary lines are always logged regardless.
	verboseProbeLogs int32
	// stopped, when 1, makes the probe pipelines abort in-flight and return
	// promptly (used for responsive cancellation, e.g. mobile Stop()).
	stopped int32
	logCb   func(string)
	// proxyProgressCb receives proxy-scan progress updates
	proxyProgressCb func(processed, total, hits int, currentIP string, totalIPs int)
	// File logging for debugging
	logFile      *os.File
	logMutex     sync.Mutex
	logFileOwned bool
	// performance helpers
	dialer          *net.Dialer
	tlsSessionCache tls.ClientSessionCache
	httpClient      *http.Client
}

// SetLogCallback registers a callback that receives scanner debug strings.
func (s *Scanner) SetLogCallback(cb func(string)) {
	s.logCb = cb
}

// SetProxyProgressCallback registers a callback that receives proxy scan progress.
func (s *Scanner) SetProxyProgressCallback(cb func(processed, total, hits int, currentIP string, totalIPs int)) {
	s.proxyProgressCb = cb
}

// InitFileLogging opens a log file for writing scanner diagnostics
func (s *Scanner) InitFileLogging(filepath string) error {
	s.logMutex.Lock()
	defer s.logMutex.Unlock()

	f, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	s.logFile = f
	s.logFileOwned = true
	s.logf("[LOG_INIT] Scanner file logging initialized at %s\n", filepath)
	return nil
}

// CloseFileLogging closes the log file gracefully
func (s *Scanner) CloseFileLogging() error {
	s.logMutex.Lock()
	defer s.logMutex.Unlock()

	if s.logFile != nil {
		s.logFile.WriteString("[LOG_CLOSE] Scanner file logging closed\n")
		if s.logFileOwned {
			err := s.logFile.Close()
			s.logFile = nil
			s.logFileOwned = false
			return err
		}
		s.logFile = nil
	}
	return nil
}

// InitFileLoggingWithFile attaches an existing open *os.File for logging.
// The scanner will not close the file when CloseFileLogging is called if
// it was attached via this method.
func (s *Scanner) InitFileLoggingWithFile(f *os.File) error {
	if f == nil {
		return fmt.Errorf("nil file provided")
	}
	s.logMutex.Lock()
	defer s.logMutex.Unlock()
	s.logFile = f
	s.logFileOwned = false
	s.logf("[LOG_INIT] Scanner file logging attached (shared)\n")
	return nil
}

// SetVerboseProbeLogging enables/disables the high-volume per-endpoint probe
// log lines. Off by default for speed; turn on for debugging.
func (s *Scanner) SetVerboseProbeLogging(enabled bool) {
	if s == nil {
		return
	}
	if enabled {
		atomic.StoreInt32(&s.verboseProbeLogs, 1)
	} else {
		atomic.StoreInt32(&s.verboseProbeLogs, 0)
	}
}

// GetVerboseProbeLogging reports whether per-endpoint probe logging is enabled.
func (s *Scanner) GetVerboseProbeLogging() bool {
	return s != nil && atomic.LoadInt32(&s.verboseProbeLogs) == 1
}

// vlogf is logf gated on verbose probe logging. When disabled it returns before
// formatting, so the per-endpoint Sprintf cost is avoided entirely on big scans.
func (s *Scanner) vlogf(format string, a ...interface{}) {
	if s == nil || atomic.LoadInt32(&s.verboseProbeLogs) == 0 {
		return
	}
	s.logf(format, a...)
}

// logf writes formatted log messages to callback and global logger
func (s *Scanner) logf(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)

	// Forward to UI callback if present (no timestamp/prefix)
	if s != nil && s.logCb != nil {
		s.logCb(msg)
	}

	// Use global logger with component prefix; global logger writer will
	// add timestamps and flush.
	log.Printf("[SCANNER] %s", msg)
}

// ScannerConfig holds scanner tuning parameters
type ScannerConfig struct {
	ProbeTimeout          time.Duration
	ProbeRetries          int
	MaxConcurrentProbes   int
	ProbeIntervalMs       int
	HealthCheckIntervalMs int
	QuarantineTTLSec      float64
	// Masscan / Nmap tuning
	MasscanRate    int
	MasscanRetries int
	MasscanWaitSec int
	NmapTiming     string
	NmapRetries    int
	NmapMinRate    int
	NmapMaxRate    int
	// Probe domains
	ProbeDomainsExtra []string
	TargetPorts       []int
	// Conservative robustness flags
	ProbeRequireHTMLForDomainTokens bool // require HTML evidence when using domain token matches
	ProbeAcceptOnCertMatch          bool // accept when TLS certificate matches probe domain
}

// ProbeDomainInfo holds info about a domain to probe
type ProbeDomainInfo struct {
	Domain       string
	Path         string
	RetryMax     int
	CriticalFlag bool
}

// MasscanResult represents a masscan output line
type MasscanResult struct {
	IP   string
	Port int
}

// NmapResult represents parsed nmap output
type NmapResult struct {
	IP       string
	Port     int
	OpenFlag bool
}

// ScanSessionMetrics tracks overall scan session
type ScanSessionMetrics struct {
	mu                   sync.RWMutex
	StartTime            time.Time
	ProbesStarted        int
	ProbesCompleted      int
	ProbesSuccessful     int
	ProbesFailed         int
	TotalLatencyMs       []float64
	EndpointsDiscovered  int
	EndpointsQuarantined int
}
