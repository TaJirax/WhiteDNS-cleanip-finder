package mobile

// ScanListener receives streaming updates during a scan. gomobile maps this Go
// interface to a Kotlin/Java interface; implement it on the Android side.
//
// Design for low-memory devices:
//   - OnProgress fires on every engine update (already throttled by the engine).
//   - OnResult fires at most once per 250 ms for live display only; results are
//     written to disk by the Go side — do NOT accumulate them in Android memory.
//   - OnLog fires at most once per 250 ms; full log is on disk.
//   - OnDone carries the saved-file path; Kotlin reads the file on demand.
//
// All callbacks fire from background goroutines — marshal onto the main thread
// before touching UI state (StateFlow.update is thread-safe and handles this).
type ScanListener interface {
	// OnProgress: cumulative progress. etaSec is best-effort (0 = unknown).
	OnProgress(processed, total, found, uniqueIPs int, currentIP string, etaSec int)
	// OnResult: one accepted endpoint for live display (throttled ≤4/sec).
	// The full result set is in the file at OnDone's savedPath — do not
	// accumulate these in RAM.
	OnResult(line string)
	// OnLog: one log line for live display (throttled ≤4/sec).
	OnLog(line string)
	// OnDone: scan finished. savedPath = results file path ("" if nothing found).
	// errMsg = "" on success.
	OnDone(savedPath string, errMsg string)
}
