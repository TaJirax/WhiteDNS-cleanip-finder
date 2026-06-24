package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	androidRootOnce sync.Once
	androidRootPool *x509.CertPool
	androidRootOK   bool
)

// resolveAndroidRoots assembles a certificate pool from the system store plus
// common bundle locations used on Termux/Android. It reports whether the
// resulting pool actually contains any roots.
func resolveAndroidRoots() (*x509.CertPool, bool) {
	androidRootOnce.Do(func() {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}

		candidates := []string{os.Getenv("SSL_CERT_FILE")}
		if prefix := os.Getenv("PREFIX"); prefix != "" {
			candidates = append(candidates,
				filepath.Join(prefix, "etc", "tls", "cert.pem"),
				filepath.Join(prefix, "etc", "tls", "certs.pem"),
			)
		}
		candidates = append(candidates,
			"/data/data/com.termux/files/usr/etc/tls/cert.pem",
			"/etc/ssl/cert.pem",
			"/etc/ssl/certs/ca-certificates.crt",
			"/system/etc/security/cacerts.pem",
		)
		for _, p := range candidates {
			if p == "" {
				continue
			}
			if data, err := os.ReadFile(p); err == nil {
				pool.AppendCertsFromPEM(data)
			}
		}

		androidRootPool = pool
		androidRootOK = len(pool.Subjects()) > 0
	})
	return androidRootPool, androidRootOK
}

// applyScanTLSRoots configures certificate verification appropriate for the
// host platform and returns cfg for convenient inline use.
//
// On desktop OSes it leaves strict system verification untouched. On
// Termux/Android the Go runtime frequently has no usable system trust store, so
// every TLS handshake would fail and the scanner would return zero IPs even for
// manually pasted targets; there we use a pool assembled from common bundle
// locations, or — if none exist on the device — relax chain verification so
// scanning still works (acceptance still relies on the SNI hostname matching
// the presented certificate and on HTTP response classification).
func applyScanTLSRoots(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		cfg = &tls.Config{}
	}
	if runtime.GOOS != "android" {
		return cfg
	}
	if pool, ok := resolveAndroidRoots(); ok {
		cfg.RootCAs = pool
		return cfg
	}
	cfg.InsecureSkipVerify = true
	return cfg
}
