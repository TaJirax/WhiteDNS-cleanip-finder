package com.whitescan.app

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import com.whitescan.app.ui.FormState
import kotlinx.coroutines.delay
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.Job
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
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
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile

// RAM budgets — never exceeded regardless of scan size.
private const val MAX_LIVE_RESULTS = 50   // recent hits shown on scanning screen
private const val MAX_LOG_LINES    = 50   // recent log lines shown on scanning screen
private const val PREVIEW_LINES    = 100  // lines loaded from file for results screen
private const val SEARCH_LIMIT     = 250  // matches shown per search, like the desktop page size

enum class ScanKind { IP, SNI, HTTP, SOCKS5, SPEED, DNS, E2E, ASN_EXPORT }

data class ScanUiState(
    val activeKind: ScanKind? = null,
    val speedBusy: Boolean = false,
    val speedResult: String? = null,
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
    // Search over the whole result file: -1 = no search, else total matches.
    val matches: Int            = -1,
)

class ScanViewModel(application: Application) : AndroidViewModel(application), ScanListener {

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state

    private var handle: ScanHandle? = null
    private val generation = AtomicLong()
    private val draftPrefs = application.getSharedPreferences("scan_drafts", 0)
    private val drafts = ConcurrentHashMap<String, FormState>()
    private val pendingDrafts = ConcurrentHashMap<String, FormState>()
    private val draftScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var saveJob: Job? = null
    private val writeLock = Any()
    fun draftKey(kind: ScanKind, form: FormState) = "${kind.name}/${form.edgeProvider}/${form.targetType}"
    suspend fun loadDraft(kind: ScanKind, template: FormState): FormState? = withContext(Dispatchers.IO) {
        val key=draftKey(kind,template)
        drafts[key] ?: draftPrefs.getString(key,null)?.let { raw ->
            val parsed=formFromJson(raw);drafts.putIfAbsent(key,parsed);drafts[key]
        }
    }
    fun saveDraft(kind: ScanKind, form: FormState) {
        val key=draftKey(kind,form);drafts[key]=form;pendingDrafts[key]=form
        saveJob?.cancel();saveJob=draftScope.launch { delay(400);flushDrafts() }
    }
    private fun flushDrafts() = synchronized(writeLock) {
        pendingDrafts.entries.toList().forEach { (key,form) ->
            if(draftPrefs.edit().putString(key,form.toJson()).commit()) pendingDrafts.remove(key,form)
        }
    }
    fun testSpeed(line: String, kind: ScanKind, form: FormState) {
        if (_state.value.speedBusy) return
        val run=generation.get();_state.update { it.copy(speedBusy=true,speedResult=null) }
        viewModelScope.launch(Dispatchers.IO) {
            val protocol=when(kind){ScanKind.HTTP->"http";ScanKind.SOCKS5->"socks5";else->"ip"}
            val result=runCatching { Mobile.testEndpointDownload(line,protocol,form.speedDownloadUrl,form.speedDuration.toLong(),form.speedMaxMb.toLong(),form.antiDpi,form.fragmentSize.toLongOrNull()?:64,form.fragmentDelay.toLongOrNull()?:1) }
            if(run==generation.get()) _state.update { it.copy(speedBusy=false,speedResult=result.fold({it},{"Error: ${it.message}"})) }
        }
    }

    // Called by MainActivity — dataDir is the "WhiteDNS Scanner" folder path.
    fun start(kind: ScanKind, dataDir: String, cfg: ScanConfig) {
        if (_state.value.running) return
        _state.value = ScanUiState(running = true, activeKind = kind)

        val run=generation.incrementAndGet()
        val listener=object:ScanListener {
            override fun onProgress(processed:Long,total:Long,found:Long,uniqueIPs:Long,currentIP:String,etaSec:Long){if(generation.get()==run)this@ScanViewModel.onProgress(processed,total,found,uniqueIPs,currentIP,etaSec)}
            override fun onResult(line:String){if(generation.get()==run)this@ScanViewModel.onResult(line)}
            override fun onLog(line:String){if(generation.get()==run)this@ScanViewModel.onLog(line)}
            override fun onDone(savedPath:String,errMsg:String){if(generation.get()==run)this@ScanViewModel.onDone(savedPath,errMsg)}
        }
        viewModelScope.launch(Dispatchers.IO) {
        val created = when (kind) {
            ScanKind.ASN_EXPORT -> {
                // cfg.targets already holds the expanded IPv4 CIDRs from the ASN picker.
                viewModelScope.launch(Dispatchers.IO) {
                    runCatching { Mobile.exportCIDRs(dataDir, cfg.targets) }
                        .onSuccess { path -> onDone(path ?: "", "") }
                        .onFailure { e -> onDone("", e.message ?: "export failed") }
                }
                null
            }
            ScanKind.IP     -> Mobile.startIPScan(dataDir, cfg, listener)
            ScanKind.SNI    -> Mobile.startSNIScan(dataDir, cfg, listener)
            ScanKind.HTTP   -> Mobile.startHTTPProxyScan(dataDir, cfg, listener)
            ScanKind.SOCKS5 -> Mobile.startSOCKS5Scan(dataDir, cfg, listener)
            ScanKind.SPEED  -> Mobile.startSpeedRankScan(dataDir, cfg, listener)
            ScanKind.DNS    -> Mobile.startDNSScan(dataDir, cfg, listener)
            ScanKind.E2E    -> Mobile.startE2EScan(dataDir, cfg, listener)
        }
        if (generation.get()==run && _state.value.running) handle=created else created?.stop()
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
        generation.incrementAndGet()
        handle?.stop()
        handle = null
        _state.value = ScanUiState()
    }

    // Saved result files, newest first, like the desktop Reports page.
    fun savedResults(dataDir: String): List<File> =
        listOf("results", "dns scan").flatMap { File(dataDir, it).listFiles()?.toList().orEmpty() }
            .filter { it.isFile && it.length() > 0 && (it.name.endsWith(".txt") || it.name.endsWith(".csv")) }
            .sortedByDescending { it.lastModified() }
            .take(200)

    // Show a saved file in Results without running anything.
    fun openSaved(path: String) {
        if (_state.value.running) return
        generation.incrementAndGet()
        // File names carry the scan kind (scan-<kind>-<time>.txt), which decides
        // whether the details sheet offers a speed test.
        val kind = when (File(path).name.substringAfter("scan-", "").substringBefore('-')) {
            "ip" -> ScanKind.IP; "http" -> ScanKind.HTTP; "socks5" -> ScanKind.SOCKS5
            "speedrank" -> ScanKind.SPEED; "sni" -> ScanKind.SNI; else -> null
        }
        _state.value = ScanUiState(done = true, savedPath = path, previewLoading = true, activeKind = kind)
        viewModelScope.launch(Dispatchers.IO) {
            val count = runCatching { File(path).useLines { lines -> lines.count { it.isNotBlank() } } }.getOrDefault(0)
            _state.update { if (it.savedPath == path) it.copy(found = count) else it }
        }
        loadPreview(path)
    }

    // Case-insensitive search across the whole file; keeps the first SEARCH_LIMIT matches.
    private var searchJob: Job? = null
    fun search(path: String, query: String) {
        searchJob?.cancel()
        if (query.isBlank()) { _state.update { it.copy(matches = -1) }; loadPreview(path); return }
        _state.update { it.copy(previewLoading = true) }
        searchJob = viewModelScope.launch(Dispatchers.IO) {
            val hits = ArrayList<String>(SEARCH_LIMIT)
            var total = 0
            runCatching {
                File(path).useLines { lines ->
                    for (line in lines) {
                        if (!isActive) return@launch
                        if (line.isNotBlank() && line.contains(query, ignoreCase = true)) {
                            if (total < SEARCH_LIMIT) hits.add(line)
                            total++
                        }
                    }
                }
            }
            _state.update { if (it.savedPath == path) it.copy(preview = hits, matches = total, previewLoading = false) else it }
        }
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
        generation.incrementAndGet()
        handle?.stop()
        saveJob?.cancel()
        draftScope.launch { flushDrafts() }
    }
}

// Reads the last n lines of a file efficiently using RandomAccessFile
// (no need to load the whole file into memory).
internal fun readLastLines(path: String, n: Int): List<String> {
    val file = File(path)
    if (!file.exists() || file.length() == 0L) return emptyList()
    return try {
        RandomAccessFile(file, "r").use { raf ->
            val length = raf.length()
            var size = minOf(length, 64L * 1024)
            var result: List<String>? = null
            // Read a tail chunk; grow it until it holds n complete lines or the whole file.
            while (result == null) {
                val buf = ByteArray(size.toInt())
                raf.seek(length - size)
                raf.readFully(buf)
                val lines = String(buf, Charsets.UTF_8).split('\n')
                    .let { if (size < length) it.drop(1) else it } // first line may be cut mid-way
                    .map { it.trimEnd('\r') }
                    .filter { it.isNotBlank() }
                if (lines.size >= n || size == length) result = lines.takeLast(n)
                else size = minOf(length, size * 4)
            }
            result
        }
    } catch (_: Exception) {
        emptyList()
    }
}
