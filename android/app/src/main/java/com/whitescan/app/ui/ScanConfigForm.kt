package com.whitescan.app.ui

import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
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
    val concurrency: String = "50",   // phone-safe default
    val lowBandwidth: Boolean = false,
    val transferModel: String = "old",
    val sniDomains: String = "",
    val sniStrict: Boolean = false,
    val verboseLog: Boolean = false,
)

// Common single ports offered as checkboxes (multi-select). Ranges / anything
// else can still be typed in the custom field below.
private val COMMON_PORTS = listOf(
    "80", "443", "2053", "2083", "2087", "2096", "8443", "8080", "3128", "8000", "8888",
)

// Parse a ports CSV into its trimmed tokens.
private fun portTokens(csv: String): List<String> =
    csv.split(",").map { it.trim() }.filter { it.isNotEmpty() }

private fun hasPort(csv: String, port: String): Boolean = portTokens(csv).contains(port)

// Toggle a single port in/out of the CSV, preserving any other tokens (ranges).
private fun togglePort(csv: String, port: String): String {
    val parts = portTokens(csv).toMutableList()
    if (parts.contains(port)) parts.remove(port) else parts.add(port)
    return parts.joinToString(",")
}

// Android-safe worker modes. High fanout on a phone saturates the radio and
// disconnects the device, so the modes are tuned down. "Ultra-light" and
// "Gentle" also probe fewer domains per IP (handled in the Go bridge).
private data class ConcurrencyPreset(val label: String, val value: String, val lowBw: Boolean = false)
private val CONCURRENCY_PRESETS = listOf(
    ConcurrencyPreset("Ultra-light (10)", "10", lowBw = true),
    ConcurrencyPreset("Gentle (25)",      "25", lowBw = true),
    ConcurrencyPreset("Safe (50)",        "50"),
    ConcurrencyPreset("Fast (100)",       "100"),
)

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ScanConfigForm(
    kind: ScanKind,
    form: FormState,
    onFormChange: (FormState) -> Unit,
    onStart: () -> Unit,
    onPickASN: () -> Unit,
) {
    val ctx = LocalContext.current
    var showWorkerMenu by remember { mutableStateOf(false) }
    var showCustomConcurrency by remember { mutableStateOf(false) }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {

        // ── Targets ───────────────────────────────────────────────────────────
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                SectionLabel("Targets  (IPs / CIDRs / ASNs)")
                TextButton(onClick = {
                    paste(ctx) { text ->
                        val sep = if (form.targets.isBlank()) text
                                  else "${form.targets.trimEnd()}\n$text"
                        onFormChange(form.copy(targets = sep))
                    }
                }) {
                    Icon(Icons.Default.ContentPaste, contentDescription = "Paste",
                        modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Paste")
                }
            }
            Spacer(Modifier.height(4.dp))
            OutlinedTextField(
                value = form.targets,
                onValueChange = { onFormChange(form.copy(targets = it)) },
                modifier = Modifier.fillMaxWidth().height(120.dp),
                placeholder = { Text("1.2.3.0/24\n5.6.7.8") },
            )
            Spacer(Modifier.height(8.dp))
            // Prominent full-width ASN picker button (big touch target), purple
            Button(
                onClick = onPickASN,
                modifier = Modifier.fillMaxWidth().height(50.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Lavender,
                    contentColor = androidx.compose.ui.graphics.Color(0xFF1A0050),
                ),
            ) {
                Icon(Icons.Default.Dns, contentDescription = null, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text("Select from ASN list")
            }
        }

        // ── Ports (checkbox multi-select) ─────────────────────────────────────
        item {
            SectionLabel("Ports")
            Spacer(Modifier.height(4.dp))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                COMMON_PORTS.forEach { p ->
                    FilterChip(
                        selected = hasPort(form.ports, p),
                        onClick = { onFormChange(form.copy(ports = togglePort(form.ports, p))) },
                        label = { Text(p) },
                        modifier = Modifier.height(36.dp),
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = form.ports,
                onValueChange = { onFormChange(form.copy(ports = it)) },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Selected ports (edit / add ranges)") },
                placeholder = { Text("443,2053,8000-8100") },
                singleLine = true,
            )
        }

        // ── Workers (dropdown) + Low-bandwidth ────────────────────────────────
        item {
            SectionLabel("Workers")
            Spacer(Modifier.height(4.dp))
            val currentLabel = when {
                showCustomConcurrency -> "Custom (${form.concurrency})"
                else -> CONCURRENCY_PRESETS.find {
                    it.value == form.concurrency && it.lowBw == form.lowBandwidth
                }?.label ?: "Custom (${form.concurrency})"
            }
            Box(Modifier.fillMaxWidth()) {
                OutlinedButton(
                    onClick = { showWorkerMenu = true },
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                ) {
                    Text(currentLabel, modifier = Modifier.weight(1f))
                    Icon(Icons.Default.ArrowDropDown, contentDescription = null)
                }
                DropdownMenu(expanded = showWorkerMenu, onDismissRequest = { showWorkerMenu = false }) {
                    CONCURRENCY_PRESETS.forEach { preset ->
                        DropdownMenuItem(
                            text = { Text(preset.label) },
                            onClick = {
                                showCustomConcurrency = false
                                onFormChange(form.copy(concurrency = preset.value, lowBandwidth = preset.lowBw))
                                showWorkerMenu = false
                            },
                        )
                    }
                    DropdownMenuItem(
                        text = { Text("Custom…") },
                        onClick = { showCustomConcurrency = true; showWorkerMenu = false },
                    )
                }
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
            Spacer(Modifier.height(10.dp))
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
            Spacer(Modifier.height(10.dp))
            // Verbose probe logging — off by default for speed.
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Switch(
                    checked = form.verboseLog,
                    onCheckedChange = { onFormChange(form.copy(verboseLog = it)) },
                )
                Column {
                    Text("Verbose probe logging", style = MaterialTheme.typography.bodyMedium)
                    Text(
                        "Logs every IP probe (slower) — turn on only for debugging",
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
