package com.whitescan.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
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
    object ConfigMaker : Screen()
    data class Scanning(val kind: ScanKind) : Screen()
    object Results : Screen()
}

class MainActivity : ComponentActivity() {

    private val vm: ScanViewModel by viewModels()

    // Launcher for the legacy (API <= 29) WRITE_EXTERNAL_STORAGE runtime prompt.
    private val legacyStoragePerm =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* result handled lazily */ }

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

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        requestStorageAccess()

        setContent {
            WhiteDNSTheme {
                var screen by remember { mutableStateOf<Screen>(Screen.Home) }
                var pendingKind by remember { mutableStateOf(ScanKind.IP) }
                var form by remember { mutableStateOf(FormState()) }
                val scanState by vm.state.collectAsStateWithLifecycle()

                // Auto-advance to results when scan finishes
                LaunchedEffect(scanState.done) {
                    if (scanState.done && screen is Screen.Scanning) {
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
                    is Screen.Config -> "${(screen as Screen.Config).kind.label()} · Config"
                    Screen.AsnPicker -> "Select ASNs"
                    Screen.ConfigMaker -> "Config Maker"
                    is Screen.Scanning -> "${(screen as Screen.Scanning).kind.label()} · Scanning"
                    Screen.Results -> "Results"
                }

                Scaffold(
                    topBar = {
                        TopAppBar(
                            title = { Text(screenTitle) },
                            navigationIcon = {
                                if (screen != Screen.Home) {
                                    IconButton(onClick = {
                                        when (screen) {
                                            is Screen.Scanning -> {
                                                vm.stop()
                                                stopForegroundScanService()
                                                screen = Screen.Home
                                            }
                                            Screen.AsnPicker -> screen = Screen.Config(pendingKind)
                                            else -> screen = Screen.Home
                                        }
                                    }) {
                                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                                    }
                                }
                            },
                        )
                    },
                ) { padding ->
                    Box(
                        Modifier
                            .padding(padding)
                            .fillMaxSize()
                            // Keeps content above the soft keyboard
                            .imePadding()
                    ) {
                        when (val s = screen) {
                            Screen.Home -> HomeScreen(
                                onSelect = { kind ->
                                    vm.reset()
                                    form = FormState()
                                    pendingKind = kind
                                    screen = if (kind == ScanKind.ASN_EXPORT) Screen.AsnPicker
                                             else Screen.Config(kind)
                                },
                                onConfigMaker = { screen = Screen.ConfigMaker },
                            )

                            Screen.ConfigMaker -> ConfigMakerScreen(dataDir = currentScanDir().absolutePath)

                            is Screen.Config -> ScanConfigForm(
                                kind = s.kind,
                                form = form,
                                onFormChange = { form = it },
                                onPickASN = {
                                    pendingKind = s.kind
                                    screen = Screen.AsnPicker
                                },
                                onStart = {
                                    screen = Screen.Scanning(s.kind)
                                    startForegroundScanService(s.kind)
                                    vm.start(s.kind, currentScanDir().absolutePath, form.toEngineConfig())
                                },
                            )

                            Screen.AsnPicker -> AsnSearchScreen(
                                dataDir = currentScanDir().absolutePath,
                                confirmLabel = if (pendingKind == ScanKind.ASN_EXPORT) "Export IPs" else "Use selection",
                                onSelected = { targets ->
                                    form = form.copy(targets = targets)
                                    if (pendingKind == ScanKind.ASN_EXPORT) {
                                        vm.reset()
                                        startForegroundScanService(ScanKind.ASN_EXPORT)
                                        vm.start(ScanKind.ASN_EXPORT, currentScanDir().absolutePath,
                                            form.copy(targets = targets).toEngineConfig())
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
                                state = scanState,
                                vm = vm,
                                onBack = { screen = Screen.Home },
                                onNewScan = {
                                    vm.reset()
                                    form = FormState()
                                    screen = Screen.Home
                                },
                            )
                        }
                    }
                }
            }
        }
    }

    private fun startForegroundScanService(kind: ScanKind) {
        val intent = ScanService.intentStart(this, kind.label())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent)
        else startService(intent)
    }

    private fun stopForegroundScanService() {
        startService(ScanService.intentStop(this))
    }
}

private fun ScanKind.label() = when (this) {
    ScanKind.IP         -> "IP Scan"
    ScanKind.SNI        -> "SNI Scan"
    ScanKind.HTTP       -> "HTTP Proxy"
    ScanKind.SOCKS5     -> "SOCKS5"
    ScanKind.SPEED      -> "Speed & Loss"
    ScanKind.ASN_EXPORT -> "ASN Export"
}

// Maps FormState → gomobile ScanConfig (setter names from gomobile Java codegen).
private fun FormState.toEngineConfig(): ScanConfig {
    // newScanConfig() is the gomobile factory (struct construction from Kotlin
    // is unreliable). Concurrency/TimeoutMs are Go int -> Java long -> Kotlin Long.
    val cfg = Mobile.newScanConfig()
    cfg.targets       = targets.trim()
    cfg.ports         = ports.trim()
    cfg.concurrency   = (concurrency.toIntOrNull() ?: 100).toLong()
    cfg.lowBandwidth  = lowBandwidth
    cfg.transferModel = transferModel
    cfg.setSNIDomains(sniDomains.trim())
    cfg.setSNIStrict(sniStrict)
    cfg.setVerboseLog(verboseLog)
    return cfg
}
