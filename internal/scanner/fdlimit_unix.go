//go:build !windows

package scanner

import "syscall"

// maxSafeConcurrency returns a connection-concurrency ceiling derived from the
// process file-descriptor limit (RLIMIT_NOFILE), or 0 when it cannot be
// determined (callers then keep their own default).
//
// This matters on Termux/Android and some Linux shells where the default soft
// limit is only 1024. Without this cap the IP scanner's automatic fan-out to
// 2000 concurrent dials exhausts the fd table and every connection fails with
// "too many open files", so a scan returns zero results even though the same
// build works fine on Windows (which has no comparable low limit).
func maxSafeConcurrency() int {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0
	}

	// Try to raise the soft limit to the hard limit; on Termux the hard limit
	// is usually far higher than the default soft limit.
	if lim.Cur < lim.Max {
		raised := lim
		raised.Cur = raised.Max
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &raised); err == nil {
			lim = raised
		} else {
			_ = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
		}
	}

	cur := lim.Cur
	const ceiling = 1 << 20 // guard against RLIM_INFINITY overflow
	if cur > ceiling {
		cur = ceiling
	}
	if cur == 0 {
		return 0
	}

	// Leave headroom for listeners, files, DNS sockets, etc.
	safe := int(cur) * 3 / 4
	if safe < 16 {
		safe = 16
	}
	return safe
}
