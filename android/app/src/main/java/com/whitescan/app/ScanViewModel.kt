package com.whitescan.app

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.whitescan.engine.mobile.Mobile
import com.whitescan.engine.mobile.ScanConfig
import com.whitescan.engine.mobile.ScanHandle
import com.whitescan.engine.mobile.ScanListener
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile

// RAM budgets — never exceeded regardless of scan size.
private const val MAX_LIVE_RESULTS = 50   // recent hits shown on scanning screen
private const val MAX_LOG_LINES    = 50   // recent log lines shown on scanning screen
private const val PREVIEW_LINES    = 100  // lines loaded from file for results screen

enum class ScanKind { IP, SNI, HTTP, SOCKS5, SPEED, DNS, E2E, ASN_EXPORT }

data class ScanUiState(
    val running: Boolean        = false,
    val paused: Boolean         = false,
    // Live progress (from OnProgress callbacks)
    val processed: Int          = 0,
    val total: Int              = 0,
    val found: Int              = 0,      // accepted count — source of truth for count display
    val uniqueIPs: Int          = 0,
    val currentIP: String       = "",
    val etaSec: Int             = 0,
    // Live display buffers — capped at MAX_LIVE_RESULTS / MAX_LOG_LINES
    val liveResults: List<String> = emptyList(),
    val logs: List<String>        = emptyList(),
    // Completion
    val done: Boolean           = false,
    val savedPath: String?      = null,
    val error: String?          = null,
    // Results preview (loaded from file after done, max PREVIEW_LINES)
    val preview: List<String>   = emptyList(),
    val previewLoading: Boolean = false,
)

class ScanViewModel : ViewModel(), ScanListener {

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state

    private var handle: ScanHandle? = null

    // Called by MainActivity — dataDir is the "WhiteDNS Scanner" folder path.
    fun start(kind: ScanKind, dataDir: String, cfg: ScanConfig) {
        if (_state.value.running) return
        _state.value = ScanUiState(running = true)

        handle = when (kind) {
            ScanKind.ASN_EXPORT -> {
                // cfg.targets already holds the expanded IPv4 CIDRs from the ASN picker.
                viewModelScope.launch(Dispatchers.IO) {
                    runCatching { Mobile.exportCIDRs(dataDir, cfg.targets) }
                        .onSuccess { path -> onDone(path ?: "", "") }
                        .onFailure { e -> onDone("", e.message ?: "export failed") }
                }
                null
            }
            ScanKind.IP     -> Mobile.startIPScan(dataDir, cfg, this)
            ScanKind.SNI    -> Mobile.startSNIScan(dataDir, cfg, this)
            ScanKind.HTTP   -> Mobile.startHTTPProxyScan(dataDir, cfg, this)
            ScanKind.SOCKS5 -> Mobile.startSOCKS5Scan(dataDir, cfg, this)
            ScanKind.SPEED  -> Mobile.startSpeedRankScan(dataDir, cfg, this)
            ScanKind.DNS    -> Mobile.startDNSScan(dataDir, cfg, this)
            ScanKind.E2E    -> Mobile.startE2EScan(dataDir, cfg, this)
        }
    }

    fun pauseResume() {
        val h = handle ?: return
        if (_state.value.paused) { h.resume(); _state.update { it.copy(paused = false) } }
        else                     { h.pause();  _state.update { it.copy(paused = true)  } }
    }

    fun stop() {
        handle?.stop()
        handle = null
        _state.update { it.copy(running = false) }
    }

    fun reset() {
        handle?.stop()
        handle = null
        _state.value = ScanUiState()
    }

    // Load last PREVIEW_LINES from the result file into state.preview.
    fun loadPreview(path: String) {
        _state.update { it.copy(previewLoading = true) }
        viewModelScope.launch(Dispatchers.IO) {
            val lines = readLastLines(path, PREVIEW_LINES)
            _state.update { it.copy(preview = lines, previewLoading = false) }
        }
    }

    // ── ScanListener — callbacks from Go background goroutines ───────────────
    // StateFlow.update uses CAS internally — safe to call from any thread.

    override fun onProgress(
        processed: Long, total: Long, found: Long, uniqueIPs: Long,
        currentIP: String, etaSec: Long,
    ) {
        _state.update {
            it.copy(
                processed = processed.toInt(),
                total     = total.toInt(),
                found     = found.toInt(),
                uniqueIPs = uniqueIPs.toInt(),
                currentIP = currentIP,
                etaSec    = etaSec.toInt(),
            )
        }
    }

    // OnResult: throttled by Go (≤4/sec). Just keep the last MAX_LIVE_RESULTS.
    override fun onResult(line: String) {
        if (line.isBlank()) return
        _state.update { s ->
            val updated = if (s.liveResults.size >= MAX_LIVE_RESULTS)
                s.liveResults.drop(1) + line
            else
                s.liveResults + line
            s.copy(liveResults = updated)
        }
    }

    // OnLog: throttled by Go (≤4/sec). Just keep the last MAX_LOG_LINES.
    override fun onLog(line: String) {
        if (line.isBlank()) return
        _state.update { s ->
            val updated = if (s.logs.size >= MAX_LOG_LINES)
                s.logs.drop(1) + line
            else
                s.logs + line
            s.copy(logs = updated)
        }
    }

    override fun onDone(savedPath: String, errMsg: String) {
        Log.d("ScanViewModel", "onDone path=$savedPath err=$errMsg")
        _state.update {
            it.copy(
                running   = false,
                done      = true,
                savedPath = savedPath.ifEmpty { null },
                error     = errMsg.ifEmpty { null },
            )
        }
    }

    override fun onCleared() {
        super.onCleared()
        handle?.stop()
    }
}

// Reads the last n lines of a file efficiently using RandomAccessFile
// (no need to load the whole file into memory).
private fun readLastLines(path: String, n: Int): List<String> {
    val file = File(path)
    if (!file.exists() || file.length() == 0L) return emptyList()
    return try {
        RandomAccessFile(file, "r").use { raf ->
            val lines = ArrayDeque<String>(n + 1)
            var pos = raf.length()
            val buf = StringBuilder()
            // Walk backwards character by character (efficient for small n,
            // acceptable for large files since we stop after n lines).
            while (pos > 0 && lines.size < n) {
                pos--
                raf.seek(pos)
                val b = raf.read()
                if (b == '\n'.code) {
                    if (buf.isNotEmpty()) {
                        lines.addFirst(buf.reversed().toString())
                        buf.clear()
                    }
                } else {
                    buf.append(b.toChar())
                }
            }
            if (buf.isNotEmpty()) lines.addFirst(buf.reversed().toString())
            lines.toList()
        }
    } catch (_: Exception) {
        emptyList()
    }
}
