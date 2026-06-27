package com.whitescan.app.ui

import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.whitescan.app.ScanKind

data class FormState(
    val targets: String = "",
    val ports: String = "",
    val concurrency: String = "250",
    val lowBandwidth: Boolean = false,
    val transferModel: String = "old",
    val sniDomains: String = "",
    val sniStrict: Boolean = false,
)

// All 18 port presets from the TUI (portPresets list in tui.go)
private val PORT_PRESETS = listOf(
    "80 · HTTP only"                        to "80",
    "443 · HTTPS only"                      to "443",
    "443,2053,2083,2087,2096,8443 · Cloudflare TLS"     to "443,2053,2083,2087,2096,8443",
    "80,443,2053,2083,2087,2096,8443 · CF HTTP+TLS"     to "80,443,2053,2083,2087,2096,8443",
    "80,443 · HTTP/HTTPS"                   to "80,443",
    "80,443,8080 · Most common"             to "80,443,8080",
    "80,8080,3128 · HTTP proxies"           to "80,8080,3128",
    "443,8443 · HTTPS ports"               to "443,8443",
    "8000-8100 · Dev range"                to "8000-8100",
    "8080-8090 · Proxy range"              to "8080-8090",
    "3000-3500 · App servers"              to "3000-3500",
    "9000-9100 · Services"                 to "9000-9100",
    "1080-1090 · SOCKS"                    to "1080-1090",
    "8000,8001,8008,8080,8888 · Extended HTTP"          to "8000,8001,8008,8080,8888",
    "80,443,3128,8080,8118 · Scan preset"  to "80,443,3128,8080,8118",
    "80,443,2053,2083,2087,2096,8443 · CF scan"        to "80,443,2053,2083,2087,2096,8443",
    "80,443,3128,8000,8080,8888,8118,9000,9050,1080 · All common" to "80,443,3128,8000,8080,8888,8118,9000,9050,1080",
    "1080-1090,3128,8080,8118,9050-9051 · Full SOCKS"  to "1080-1090,3128,8080,8118,9050-9051",
    "Custom…"                               to "",
)

// 7 concurrency presets matching the TUI concurrencyOptions
private data class ConcurrencyPreset(val label: String, val value: String, val lowBw: Boolean = false)
private val CONCURRENCY_PRESETS = listOf(
    ConcurrencyPreset("Low-BW (50)",  "50",   lowBw = true),
    ConcurrencyPreset("Low (50)",     "50"),
    ConcurrencyPreset("Med (250)",    "250"),
    ConcurrencyPreset("High (500)",   "500"),
    ConcurrencyPreset("V.High (1000)","1000"),
    ConcurrencyPreset("Max (2000)",   "2000"),
    ConcurrencyPreset("Extreme (5000)","5000"),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanConfigForm(
    kind: ScanKind,
    form: FormState,
    onFormChange: (FormState) -> Unit,
    onStart: () -> Unit,
    onPickASN: () -> Unit,
) {
    val ctx = LocalContext.current
    var showPortMenu by remember { mutableStateOf(false) }
    var portPresetLabel by remember { mutableStateOf(PORT_PRESETS[2].first) } // default CF TLS
    var showCustomConcurrency by remember { mutableStateOf(false) }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {

        // ── Targets ───────────────────────────────────────────────────────────
        item {
            SectionLabel("Targets  (IPs / CIDRs / ASNs)")
            Spacer(Modifier.height(4.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.Top) {
                OutlinedTextField(
                    value = form.targets,
                    onValueChange = { onFormChange(form.copy(targets = it)) },
                    modifier = Modifier.weight(1f).height(110.dp),
                    placeholder = { Text("1.2.3.0/24\n5.6.7.8") },
                )
                FilledTonalIconButton(
                    onClick = { paste(ctx) { text ->
                        val sep = if (form.targets.isBlank()) text
                                  else "${form.targets.trimEnd()}\n$text"
                        onFormChange(form.copy(targets = sep))
                    } },
                    modifier = Modifier.size(48.dp).align(Alignment.CenterVertically),
                ) { Icon(Icons.Default.ContentPaste, contentDescription = "Paste targets") }
            }
            Spacer(Modifier.height(8.dp))
            // Prominent full-width ASN picker button (big touch target)
            OutlinedButton(
                onClick = onPickASN,
                modifier = Modifier.fillMaxWidth().height(50.dp),
            ) {
                Icon(Icons.Default.Dns, contentDescription = null, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text("Select from ASN list")
            }
        }

        // ── Ports ─────────────────────────────────────────────────────────────
        item {
            SectionLabel("Ports")
            Spacer(Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box {
                    OutlinedButton(
                        onClick = { showPortMenu = true },
                        modifier = Modifier.height(48.dp),
                    ) { Text(portPresetLabel.take(22), maxLines = 1) }
                    DropdownMenu(expanded = showPortMenu, onDismissRequest = { showPortMenu = false }) {
                        PORT_PRESETS.forEach { (label, value) ->
                            DropdownMenuItem(
                                text = { Text(label) },
                                onClick = {
                                    portPresetLabel = label
                                    showPortMenu = false
                                    if (value.isNotEmpty()) onFormChange(form.copy(ports = value))
                                },
                            )
                        }
                    }
                }
                OutlinedTextField(
                    value = form.ports,
                    onValueChange = { onFormChange(form.copy(ports = it)); portPresetLabel = "Custom…" },
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("443,2053") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
            }
        }

        // ── Concurrency + Low-bandwidth ───────────────────────────────────────
        item {
            SectionLabel("Workers")
            Spacer(Modifier.height(4.dp))
            // Two rows of chips — matches TUI's 7 concurrency options
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                CONCURRENCY_PRESETS.take(4).forEach { preset ->
                    ConcurrencyChip(preset, form, showCustomConcurrency,
                        onPick = { showCustomConcurrency = false; onFormChange(it) })
                }
            }
            Spacer(Modifier.height(4.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                CONCURRENCY_PRESETS.drop(4).forEach { preset ->
                    ConcurrencyChip(preset, form, showCustomConcurrency,
                        onPick = { showCustomConcurrency = false; onFormChange(it) })
                }
                FilterChip(
                    selected = showCustomConcurrency,
                    onClick = { showCustomConcurrency = !showCustomConcurrency },
                    label = { Text("Custom") },
                    modifier = Modifier.height(36.dp),
                )
            }
            if (showCustomConcurrency) {
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    value = form.concurrency,
                    onValueChange = { onFormChange(form.copy(concurrency = it)) },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Custom worker count") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
            }
            Spacer(Modifier.height(6.dp))
            // Low-bandwidth switch separate from chips (matching TUI's separate toggle)
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Switch(
                    checked = form.lowBandwidth,
                    onCheckedChange = { onFormChange(form.copy(lowBandwidth = it)) },
                )
                Column {
                    Text("Low bandwidth mode", style = MaterialTheme.typography.bodyMedium)
                    Text(
                        "Extends timeouts for slow / high-latency links",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        // ── Transfer model (HTTP / SOCKS5 only) — matches TUI screenSelectTransfer ─
        if (kind == ScanKind.HTTP || kind == ScanKind.SOCKS5) {
            item {
                SectionLabel("Transfer model")
                Spacer(Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("old" to "Stable (old)", "brrr" to "Fast (goBrrrr)").forEach { (model, label) ->
                        FilterChip(
                            selected = form.transferModel == model,
                            onClick = { onFormChange(form.copy(transferModel = model)) },
                            label = { Text(label) },
                            modifier = Modifier.height(40.dp),
                        )
                    }
                }
            }
        }

        // ── SNI domains + strict mode — matches TUI screenSNISource / screenSNIMode ─
        if (kind == ScanKind.SNI) {
            item {
                SectionLabel("SNI domains  (blank = built-in defaults)")
                Spacer(Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.Top) {
                    OutlinedTextField(
                        value = form.sniDomains,
                        onValueChange = { onFormChange(form.copy(sniDomains = it)) },
                        modifier = Modifier.weight(1f).height(90.dp),
                        placeholder = { Text("workers.dev\npages.dev") },
                    )
                    FilledTonalIconButton(
                        onClick = { paste(ctx) { text ->
                            val sep = if (form.sniDomains.isBlank()) text
                                      else "${form.sniDomains.trimEnd()}\n$text"
                            onFormChange(form.copy(sniDomains = sep))
                        } },
                        modifier = Modifier.size(48.dp).align(Alignment.CenterVertically),
                    ) { Icon(Icons.Default.ContentPaste, contentDescription = "Paste domains") }
                }
                Spacer(Modifier.height(8.dp))
                // SNI match mode — matches TUI's screenSNIMode
                Text("SNI match mode", style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = form.sniStrict,
                        onClick = { onFormChange(form.copy(sniStrict = true)) },
                        label = { Text("Strict") },
                        modifier = Modifier.height(40.dp),
                    )
                    FilterChip(
                        selected = !form.sniStrict,
                        onClick = { onFormChange(form.copy(sniStrict = false)) },
                        label = { Text("Lenient") },
                        modifier = Modifier.height(40.dp),
                    )
                }
                Text(
                    if (form.sniStrict)
                        "Strict: SNI must be accepted — domain fronting / SNI-spoofing discovery"
                    else
                        "Lenient: any TLS handshake counts — reachability only",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // ── Start ─────────────────────────────────────────────────────────────
        item {
            Spacer(Modifier.height(4.dp))
            Button(
                onClick = onStart,
                modifier = Modifier.fillMaxWidth().height(52.dp),
                enabled = form.targets.isNotBlank(),
            ) {
                Text("Start Scan", style = MaterialTheme.typography.titleSmall)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConcurrencyChip(
    preset: ConcurrencyPreset,
    form: FormState,
    customActive: Boolean,
    onPick: (FormState) -> Unit,
) {
    val isSelected = !customActive &&
        form.concurrency == preset.value && form.lowBandwidth == preset.lowBw
    FilterChip(
        selected = isSelected,
        onClick = { onPick(form.copy(concurrency = preset.value, lowBandwidth = preset.lowBw)) },
        label = { Text(preset.label) },
        modifier = Modifier.height(36.dp),
    )
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
    )
}

private fun paste(ctx: Context, apply: (String) -> Unit) {
    val clip = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    val text = clip?.primaryClip?.getItemAt(0)?.coerceToText(ctx)?.toString()
    if (!text.isNullOrBlank()) apply(text)
}
