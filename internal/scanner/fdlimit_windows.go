//go:build windows

package scanner

// maxSafeConcurrency returns 0 on Windows: there is no RLIMIT_NOFILE and socket
// usage is not bounded by a low per-process fd limit, so callers keep their own
// concurrency default.
func maxSafeConcurrency() int { return 0 }
