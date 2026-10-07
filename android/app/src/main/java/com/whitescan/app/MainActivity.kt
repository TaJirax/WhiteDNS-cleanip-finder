package com.whitescan.app

import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.util.Log
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import kotlinx.coroutines.launch
import androidx.compose.ui.unit.dp
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.whitescan.app.ui.*
import com.whitescan.engine.mobile.Mobile
import com.whitescan.engine.mobile.ScanConfig
import java.io.File

sealed class Screen {
    object Home : Screen()
    data class Config(val kind: ScanKind) : Screen()
    object AsnPicker : Screen()
    object EdgePicker : Screen()
    object ConfigMaker : Screen()
    object SavedResults : Screen()
    data class Scanning(val kind: ScanKind) : Screen()
    object Results : Screen()
}

class MainActivity : ComponentActivity() {

    private val vm: ScanViewModel by viewModels()

    // Launcher for the legacy (API <= 29) WRITE_EXTERNAL_STORAGE runtime prompt.
    private val legacyStoragePerm =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* result handled lazily */ }

    // Android 13+ runtime notification permission, so the foreground-service
    // scan notification can actually be shown.
    private val notificationPerm =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* result ignored */ }

    // True when we can write to the public storage root.
    private fun hasAllFilesAccess(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
            Environment.isExternalStorageManager()
        else
            ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) ==
                PackageManager.PERMISSION_GRANTED

    // Ask for storage access so outputs land in a user-visible folder. On API 30+
    // this is "All files access" (Settings screen); on older it's a normal prompt.
    private fun requestStorageAccess() {
        if (hasAllFilesAccess()) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                startActivity(
                    Intent(
                        Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:$packageName"),
                    )
                )
            } catch (_: Exception) {
                try { startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)) }
                catch (_: Exception) {}
            }
        } else {
            legacyStoragePerm.launch(Manifest.permission.WRITE_EXTERNAL_STORAGE)
        }
    }

    // Where all results/logs/exports go. If storage permission is granted, use a
    // user-visible "WhiteDNS Scanner" folder at the root of shared storage;
    // otherwise fall back to the app-specific dir (always writable, just hidden).
    private fun currentScanDir(): File {
        val base = if (hasAllFilesAccess())
            File(Environment.getExternalStorageDirectory(), "WhiteDNS Scanner")
        else
            (getExternalFilesDir(null) ?: filesDir).resolve("WhiteDNS Scanner")
        base.mkdirs()
        return base
    }

    private fun shouldUseConstrainedScanDefaults(): Boolean {
        val arch = System.getProperty("os.arch")?.lowercase().orEmpty()
        val is32BitRuntime = arch == "arm" ||
            arch.startsWith("armv7") ||
            arch == "i686" ||
            arch == "x86"
        return is32BitRuntime || Build.SUPPORTED_64_BIT_ABIS.isEmpty()
    }

    private fun defaultFormState(): FormState =
        if (shouldUseConstrainedScanDefaults())
            FormState(concurrency = "8", lowBandwidth = true, liteMode = true)
        else
            FormState()

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        runCatching { Mobile.setTimeZone(java.util.TimeZone.getDefault().id) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            val appearance = remember { getSharedPreferences("appearance", MODE_PRIVATE) }
            var theme by remember { mutableStateOf(appearance.getString("theme", "system") ?: "system") }
            var accent by remember { mutableStateOf(normalizeAccent(appearance.getString("accent", null))) }
            var showAppearance by remember { mutableStateOf(false) }
            WhiteDNSTheme(theme, accent) {
                val restoredKind = vm.state.value.activeKind
                var screen by remember { mutableStateOf<Screen>(if (vm.state.value.running && restoredKind != null) Screen.Scanning(restoredKind) else if(vm.state.value.done) Screen.Results else Screen.Home) }
                val uiScope = rememberCoroutineScope()
                val snackbar = remember { SnackbarHostState() }
                var pendingKind by remember { mutableStateOf(ScanKind.IP) }
                var form by remember { mutableStateOf(defaultFormState()) }
                val scanState by vm.state.collectAsStateWithLifecycle()
                var selectedResult by remember { mutableStateOf<String?>(null) }
                var speedOptions by remember { mutableStateOf(defaultFormState()) }


                // Auto-advance to results when scan finishes. When a DNS scan with
                // the end-to-end test enabled finishes, chain straight into an E2E
                // test over the tunnel-ready shortlist it just wrote, instead of
                // stopping at the DNS results.
                LaunchedEffect(scanState.done) {
                    if (scanState.done && screen is Screen.Scanning) {
                        val finishedKind = (screen as Screen.Scanning).kind
                        if (finishedKind == ScanKind.DNS && form.e2eEnabled) {
                            val trPath = scanState.savedPath?.let {
                                try { Mobile.tunnelReadyIPsPath(it) } catch (_: Throwable) { null }
                            }
                            if (!trPath.isNullOrEmpty()) {
                                try {
                                    val dir = currentScanDir().absolutePath
                                    val e2eCfg = form.copy(targets = "@$trPath")
                                        .toEngineConfig(shouldUseConstrainedScanDefaults())
                                    stopForegroundScanService()
                                    screen = Screen.Scanning(ScanKind.E2E)
                                    startForegroundScanService(ScanKind.E2E)
                                    vm.start(ScanKind.E2E, dir, e2eCfg)
                                    return@LaunchedEffect
                                } catch (e: Throwable) {
                                    Log.e("MainActivity", "Failed to start E2E test", e)
                                    // Fall through to showing the DNS results below.
                                }
                            }
                        }
                        // When an IP scan with the speed-test toggle enabled finishes,
                        // chain straight into a Speed & Loss rank over the IPs it just
                        // found (its saved ip:port result file), instead of stopping
                        // at the IP results.
                        if (finishedKind == ScanKind.IP && form.speedTestEnabled) {
                            val ipsPath = scanState.savedPath
                            if (!ipsPath.isNullOrEmpty()) {
                                try {
                                    val dir = currentScanDir().absolutePath
                                    val speedCfg = form.copy(targets = "@$ipsPath")
                                        .toEngineConfig(shouldUseConstrainedScanDefaults())
                                    stopForegroundScanService()
                                    screen = Screen.Scanning(ScanKind.SPEED)
                                    startForegroundScanService(ScanKind.SPEED)
                                    vm.start(ScanKind.SPEED, dir, speedCfg)
                                    return@LaunchedEffect
                                } catch (e: Throwable) {
                                    Log.e("MainActivity", "Failed to start speed test", e)
                                    // Fall through to showing the IP results below.
                                }
                            }
                        }
                        screen = Screen.Results
                        stopForegroundScanService()
                        // Kick off preview load immediately
                        scanState.savedPath?.let { vm.loadPreview(it) }
                    }
                }

                // Keep foreground-service notification updated
                LaunchedEffect(scanState.found) {
                    if (scanState.running) {
                        val label = (screen as? Screen.Scanning)?.kind?.label() ?: "Scan"
                        startService(ScanService.intentUpdate(this@MainActivity, label, scanState.found))
                    }
                }

                val screenTitle = when (screen) {
                    Screen.Home -> ""   // banner inside HomeScreen shows branding
                    is Screen.Config -> (screen as Screen.Config).kind.label()
                    Screen.AsnPicker -> "Select ASNs"
                    Screen.EdgePicker -> "Edge networks"
                    Screen.ConfigMaker -> "Config Maker"
                    Screen.SavedResults -> "Saved results"
                    is Screen.Scanning -> "${(screen as Screen.Scanning).kind.label()} · Scanning"
                    Screen.Results -> "Results"
                }

                // Shared by the TopAppBar back arrow AND the system back
                // gesture/button below — without the latter, Android's default
                // back behavior finishes the Activity (closes the app) instead of
                // navigating up through the in-app screen stack.
                val goBack = {
                    when (screen) {
                        is Screen.Scanning -> {
                            vm.stop()
                            stopForegroundScanService()
                            screen = Screen.Home
                        }
                        Screen.AsnPicker -> screen = Screen.Config(pendingKind)
                        Screen.EdgePicker -> screen = Screen.Config(pendingKind)
                        else -> screen = Screen.Home
                    }
                }

                // Only intercept back while inside a sub-screen; on Home, let the
                // system handle back normally (exits the app), matching the
                // TopAppBar's back arrow which is likewise hidden on Home.
                BackHandler(enabled = screen != Screen.Home) { goBack() }

                if (selectedResult != null) {
                    ModalBottomSheet(onDismissRequest = { selectedResult = null }) {
                        Column(Modifier.fillMaxWidth().verticalScroll(androidx.compose.foundation.rememberScrollState()).padding(20.dp),verticalArrangement=Arrangement.spacedBy(12.dp)) {
                            Text("Result details",style=MaterialTheme.typography.titleLarge)
                            androidx.compose.foundation.text.selection.SelectionContainer { Text(selectedResult!!,style=MaterialTheme.typography.bodyMedium) }
                            OutlinedButton(onClick={val clipboard=getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager;clipboard.setPrimaryClip(android.content.ClipData.newPlainText("Endpoint",selectedResult));uiScope.launch{snackbar.copied("result")}},modifier=Modifier.heightIn(min=48.dp)){Text("Copy result")}
                            if(scanState.activeKind in listOf(ScanKind.IP,ScanKind.HTTP,ScanKind.SOCKS5,ScanKind.SPEED)) {
                                OutlinedTextField(speedOptions.speedDownloadUrl,{speedOptions=speedOptions.copy(speedDownloadUrl=it)},label={Text("Direct download URL")},modifier=Modifier.fillMaxWidth())
                                OutlinedTextField(speedOptions.speedDuration,{speedOptions=speedOptions.copy(speedDuration=it)},label={Text("Duration (1–60 seconds)")},modifier=Modifier.fillMaxWidth())
                                OutlinedTextField(speedOptions.speedMaxMb,{speedOptions=speedOptions.copy(speedMaxMb=it)},label={Text("Limit (1–1024 MB)")},modifier=Modifier.fillMaxWidth())
                                Button(onClick={vm.testSpeed(selectedResult!!,scanState.activeKind?:ScanKind.IP,speedOptions)},enabled=!scanState.speedBusy,modifier=Modifier.heightIn(min=48.dp)){Text(if(scanState.speedBusy)"Testing selected endpoint…" else "Test download speed")}
                                scanState.speedResult?.let { raw ->
                                    val label=runCatching{val json=org.json.JSONObject(raw);"${"%.2f".format(json.getDouble("mbps"))} Mbps · ${json.getLong("bytes")} bytes · ${json.getLong("latencyMs")} ms"}.getOrDefault(raw)
                                    Text(label,style=MaterialTheme.typography.bodyLarge)
                                }
                            }
                            Spacer(Modifier.navigationBarsPadding())
                        }
                    }
                }

                CompositionLocalProvider(LocalSnackbar provides snackbar) {
                Scaffold(
                    snackbarHost = { SnackbarHost(snackbar) },
                    topBar = {
                        TopAppBar(
                            title = { Text(screenTitle, maxLines = 1, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis) },
                            actions = {
                                Box {
                                    IconButton(onClick = { showAppearance = true }) { Icon(ScannerIcons.Gear, "Appearance") }
                                    DropdownMenu(showAppearance, { showAppearance = false }) {
                                        // Same choices and names as the desktop Settings page.
                                        val check: @Composable (Boolean) -> Unit = { on -> if (on) Icon(Icons.Outlined.Check, "Selected") }
                                        Text("Appearance", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp))
                                        listOf("system" to "System", "light" to "Light", "dark" to "Dark").forEach { (value,label) -> DropdownMenuItem(text={Text(label)},trailingIcon={check(theme==value)},onClick={theme=value;appearance.edit().putString("theme",value).apply();showAppearance=false}) }
                                        HorizontalDivider()
                                        Text("Bubble tea palette", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp))
                                        listOf("purple" to "Taro purple", "teal" to "Teal tea", "milk" to "Milk tea").forEach { (value,label) -> DropdownMenuItem(text={Text(label)},trailingIcon={check(accent==value)},onClick={accent=value;appearance.edit().putString("accent",value).apply();showAppearance=false}) }
                                    }
                                }
                            },
                            navigationIcon = {
                                if (screen != Screen.Home) {
                                    IconButton(onClick = goBack) {
                                        Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back")
                                    }
                                }
                            },
                        )
                    },
                ) { padding ->
                    Box(
                        Modifier
                            .padding(padding)
                            // The Scaffold already applied the navigation bar; count it once.
                            .consumeWindowInsets(padding)
                            .fillMaxSize()
                            // Keeps content above the soft keyboard
                            .imePadding(),
                        contentAlignment = androidx.compose.ui.Alignment.TopCenter,
                    ) {
                        // ponytail: width cap only; add a navigation rail if tablets become a target.
                        Box(Modifier.widthIn(max = 840.dp).fillMaxSize()) {
                        when (val s = screen) {
                            Screen.Home -> HomeScreen(
                                onSelect = { kind ->
                                    vm.reset()
                                    form = defaultFormState()
                                    uiScope.launch { val saved = vm.loadDraft(kind, form); if(pendingKind == kind && screen is Screen.Config && saved != null) form = saved }
                                    pendingKind = kind
                                    screen = if (kind == ScanKind.ASN_EXPORT) Screen.AsnPicker
                                             else Screen.Config(kind)
                                },
                                onEdgeFinder = {
                                    vm.reset()
                                    form = defaultFormState()
                                    pendingKind = ScanKind.IP
                                    screen = Screen.EdgePicker
                                },
                                onConfigMaker = { screen = Screen.ConfigMaker },
                                onSavedResults = { screen = Screen.SavedResults },
                            )

                            Screen.SavedResults -> SavedResultsScreen(
                                load = { vm.savedResults(currentScanDir().absolutePath) },
                                scanRunning = scanState.running,
                                onOpen = { path -> vm.openSaved(path); screen = Screen.Results },
                            )

                            Screen.ConfigMaker -> ConfigMakerScreen(dataDir = currentScanDir().absolutePath)

                            is Screen.Config -> ScanConfigForm(
                                kind = s.kind,
                                form = form,
                                onFormChange = { next ->
                                    val previous = form;form = next
                                    if(previous.targetType != next.targetType) {
                                        vm.saveDraft(s.kind,previous)
                                        uiScope.launch {
                                            val saved=vm.loadDraft(s.kind,next)
                                            if(vm.draftKey(s.kind,form)==vm.draftKey(s.kind,next)) {
                                                if(saved!=null) form=saved
                                                vm.saveDraft(s.kind,form)
                                            }
                                        }
                                    } else vm.saveDraft(s.kind,next)
                                },
                                onPickASN = {
                                    pendingKind = s.kind
                                    screen = Screen.AsnPicker
                                },
                                onPickEdge = {
                                    pendingKind = s.kind
                                    screen = Screen.EdgePicker
                                },
                                onStart = {
                                    // Build everything that can throw BEFORE navigating, and guard
                                    // the whole launch so a failure shows a message instead of
                                    // crashing the app (some users hit immediate crashes on scan
                                    // start before any logging begins).
                                    try {
                                        val dir = currentScanDir().absolutePath
                                        vm.saveDraft(s.kind, form)
                                        val engineCfg = form.toEngineConfig(shouldUseConstrainedScanDefaults())
                                        screen = Screen.Scanning(s.kind)
                                        startForegroundScanService(s.kind)
                                        vm.start(s.kind, dir, engineCfg)
                                    } catch (e: Throwable) {
                                        Log.e("MainActivity", "Failed to start scan", e)
                                        val reason = e.message ?: e.javaClass.simpleName
                                        uiScope.launch { snackbar.showSnackbar("Could not start scan: $reason", withDismissAction = true, duration = SnackbarDuration.Long) }
                                        screen = Screen.Config(s.kind)
                                    }
                                },
                            )

                            Screen.AsnPicker -> AsnSearchScreen(
                                dataDir = currentScanDir().absolutePath,
                                confirmLabel = if (pendingKind == ScanKind.ASN_EXPORT) "Export IPs" else "Use selection",
                                constrainedDevice = shouldUseConstrainedScanDefaults(),
                                onSelected = { targets ->
                                    val constrainedDevice = shouldUseConstrainedScanDefaults()
                                    val targetRef = try {
                                        targetsForDevice(currentScanDir(), targets, constrainedDevice)
                                    } catch (e: Throwable) {
                                        Log.w("MainActivity", "Could not persist ASN targets; falling back to inline targets", e)
                                        targets
                                    }
                                    form = form.copy(targets = targetRef)
                                    if (pendingKind == ScanKind.ASN_EXPORT) {
                                        vm.reset()
                                        startForegroundScanService(ScanKind.ASN_EXPORT)
                                        vm.start(ScanKind.ASN_EXPORT, currentScanDir().absolutePath,
                                            form.copy(targets = targetRef).toEngineConfig(constrainedDevice))
                                        screen = Screen.Scanning(ScanKind.ASN_EXPORT)
                                    } else {
                                        screen = Screen.Config(pendingKind)
                                    }
                                },
                                onCancel = {
                                    screen = if (pendingKind == ScanKind.ASN_EXPORT) Screen.Home
                                             else Screen.Config(pendingKind)
                                },
                            )

                            Screen.EdgePicker -> EdgePickerScreen(
                                onSelected = { provider, probeDomains, targets ->
                                    val template = form.copy(edgeProvider = provider, targetType = "ip")
                                    uiScope.launch {
                                        val saved = vm.loadDraft(ScanKind.IP, template)
                                        if(form.edgeProvider == provider && saved != null) form = saved.copy(edgeProvider = provider, edgeProbeDomains = probeDomains)
                                    }
                                    form = form.copy(
                                        targetType = "ip",
                                        targets = targets,
                                        edgeProvider = provider,
                                        edgeProbeDomains = probeDomains,
                                    )
                                    screen = Screen.Config(pendingKind)
                                },
                                onCancel = { screen = Screen.Config(pendingKind) },
                            )

                            is Screen.Scanning -> ScanningScreen(
                                state = scanState,
                                onPauseResume = { vm.pauseResume() },
                                onStop = {
                                    vm.stop()
                                    stopForegroundScanService()
                                    screen = Screen.Results
                                },
                                onViewResults = {
                                    screen = Screen.Results
                                    scanState.savedPath?.let { vm.loadPreview(it) }
                                },
                            )

                            Screen.Results -> ResultsScreen(
                                onInspect = { line -> selectedResult = line; speedOptions = form },
                                state = scanState,
                                vm = vm,
                                onBack = { screen = Screen.Home },
                                onNewScan = {
                                    vm.reset()
                                    form = defaultFormState()
                                    screen = Screen.Home
                                },
                            )
                        }
                        }
                    }
                }
                }
            }
        }
    }

    private fun startForegroundScanService(kind: ScanKind) {
        // Starting a foreground service can throw on some OEM ROMs
        // (MIUI/ColorOS/HyperOS), under Android 12+ background-start rules, or
        // when notifications are restricted (ForegroundServiceStartNotAllowed-
        // Exception / SecurityException). The scan itself runs in-process via the
        // ViewModel, so a failure here must NOT crash the app — we just lose the
        // persistent notification while the app is backgrounded.
        try {
            val intent = ScanService.intentStart(this, kind.label())
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent)
            else startService(intent)
        } catch (e: Throwable) {
            Log.w("MainActivity", "Foreground service start failed; continuing without it", e)
        }
    }

    private fun stopForegroundScanService() {
        try {
            startService(ScanService.intentStop(this))
        } catch (e: Throwable) {
            Log.w("MainActivity", "Foreground service stop failed", e)
        }
    }

    private fun targetsForDevice(dataDir: File, targets: String, constrainedDevice: Boolean): String {
        if (!constrainedDevice) return targets
        val trimmed = targets.trim()
        if (trimmed.isBlank()) return trimmed

        val tmpDir = dataDir.resolve("tmp")
        tmpDir.mkdirs()
        val out = tmpDir.resolve("asn-targets-${System.currentTimeMillis()}.txt")
        out.writeText(trimmed + "\n")
        return "@${out.absolutePath}"
    }
}

private fun ScanKind.label() = when (this) {
    ScanKind.IP         -> "Scan IPs"
    ScanKind.SNI        -> "SNI Scanner (TLS Hostname Probe)"
    ScanKind.HTTP       -> "Scan HTTP Proxies"
    ScanKind.SOCKS5     -> "Scan SOCKS5 Proxies"
    ScanKind.SPEED      -> "Speed & Loss Rank (Cloudflare)"
    ScanKind.DNS        -> "DNS Resolver / Tunnel Scan"
    ScanKind.E2E        -> "E2E Tunnel Test"
    ScanKind.ASN_EXPORT -> "Export ASN IPs"
}

// Maps FormState → gomobile ScanConfig (setter names from gomobile Java codegen).
private fun FormState.toEngineConfig(constrainedDevice: Boolean = false): ScanConfig {
    // newScanConfig() is the gomobile factory (struct construction from Kotlin
    // is unreliable). Concurrency/TimeoutMs are Go int -> Java long -> Kotlin Long.
    val cfg = Mobile.newScanConfig()
    val requestedConcurrency = concurrency.toIntOrNull() ?: error("Enter a whole-number worker count")
    require(requestedConcurrency in 1..100) { "Use 1–100 workers (Lite mode uses up to 8)" }
    val effectiveLiteMode = liteMode || constrainedDevice
    val effectiveConcurrency =
        if (effectiveLiteMode) requestedConcurrency.coerceAtMost(8)
        else requestedConcurrency
    cfg.setAntiDPI(antiDpi)
    cfg.setDPIFragmentSize(fragmentSize.toLongOrNull() ?: error("Enter a fragment size"))
    cfg.setDPIFragmentDelayMs(fragmentDelay.toLongOrNull() ?: error("Enter a fragment delay"))
    cfg.setProxyTestURL(proxyTestUrl)
    cfg.setTargetType(targetType)
    cfg.setCountTotal(countTotal)
    cfg.targets       = targets.trim()
    cfg.ports         = ports.trim()
    cfg.concurrency   = effectiveConcurrency.toLong()
    cfg.lowBandwidth  = lowBandwidth || effectiveLiteMode
    cfg.transferModel = transferModel
    cfg.edgeProvider  = edgeProvider.trim()
    cfg.limitedNetwork = limitedNetwork
    cfg.setFastMode(fastMode && !lowBandwidth && !effectiveLiteMode && !limitedNetwork)
    cfg.setSNIDomains(sniDomains.trim())
    cfg.setSNIStrict(sniStrict)
    cfg.setVerboseLog(verboseLog)
    cfg.setLiteMode(effectiveLiteMode)
    cfg.setDNSProtocol(dnsProtocol)
    cfg.setDNSReference(dnsReference)
    cfg.setDNSScanDepth(dnsScanDepth)
    cfg.setDNSTestNearby(dnsTestNearby && !effectiveLiteMode)
    cfg.setDNSRateLimit(dnsRate.toDoubleOrNull()?.takeIf { it >= 0 } ?: error("DNS rate: enter 0 or more queries per second"))
    cfg.setDNSRateLimitPerResolver(dnsRatePerResolver.toDoubleOrNull()?.takeIf { it >= 0 } ?: error("Per-resolver rate: enter 0 or more queries per second"))
    cfg.setDNSRateBurst(dnsBurst.toLongOrNull()?.takeIf { it >= 1 } ?: error("DNS burst: enter 1 or more"))
    cfg.setDNSTimingJitter(dnsJitter.toDoubleOrNull()?.takeIf { it in 0.0..1.0 } ?: error("Timing jitter: enter 0–1"))
    cfg.setE2EDomain(e2eDomain.trim())
    cfg.setE2EPubKey(e2ePubKey.trim())
    cfg.setE2ETransport(e2eTransport.trim())
    return cfg
}
