package com.whitescan.app.ui

import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.whitescan.app.ScanKind

data class FormState(
    var targets: String = "",
    var ports: String = "",
    var concurrency: String = "250",
    var lowBandwidth: Boolean = false,
    var transferModel: String = "old",
    var sniDomains: String = "",
    var sniStrict: Boolean = false,
)

private val PORT_PRESETS = listOf(
    "HTTPS only (443)"      to "443",
    "HTTP only (80)"        to "80",
    "Cloudflare TLS"        to "443,2053,2083,2087,2096,8443",
    "HTTP proxy defaults"   to "80,8080,3128,8000,8888",
    "SOCKS5 defaults"       to "1080,1081,9050,9051,10808",
    "All common"            to "80,443,3128,8000,8080,8888,9050",
    "Custom…"               to "",
)

private val CONCURRENCY_PRESETS = listOf(
    "Low (50)"     to "50",
    "Med (250)"    to "250",
    "High (500)"   to "500",
    "Max (1000)"   to "1000",
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
    var portPresetLabel by remember { mutableStateOf(PORT_PRESETS[0].first) }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {

        // — Targets ————————————————————————————————————————————————————————
        item {
            Text("Targets (IPs / CIDRs)", style = MaterialTheme.typography.labelLarge)
            Spacer(Modifier.height(4.dp))
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.Top,
            ) {
                OutlinedTextField(
                    value = form.targets,
                    onValueChange = { onFormChange(form.copy(targets = it)) },
                    modifier = Modifier.weight(1f).height(110.dp),
                    placeholder = { Text("1.2.3.0/24\n5.6.7.8") },
                )
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.align(Alignment.CenterVertically),
                ) {
                    // Paste from clipboard — lets user copy IPs from browser/notes
                    FilledTonalIconButton(
                        onClick = {
                            val clip = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                            val text = clip?.primaryClip?.getItemAt(0)?.coerceToText(ctx)?.toString()
                            if (!text.isNullOrBlank()) {
                                val appended = if (form.targets.isBlank()) text
                                               else "${form.targets.trimEnd()}\n$text"
                                onFormChange(form.copy(targets = appended))
                            }
                        },
                        modifier = Modifier.size(48.dp),
                    ) {
                        Icon(Icons.Default.ContentPaste, contentDescription = "Paste from clipboard")
                    }
                    // ASN picker button
                    FilledTonalButton(
                        onClick = onPickASN,
                        modifier = Modifier.height(40.dp),
                    ) { Text("ASN") }
                }
            }
        }

        // — Ports ──────────────────────────────────────────────────────────
        item {
            Text("Ports", style = MaterialTheme.typography.labelLarge)
            Spacer(Modifier.height(4.dp))
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Box {
                    OutlinedButton(
                        onClick = { showPortMenu = true },
                        modifier = Modifier.height(48.dp),
                    ) { Text(portPresetLabel, maxLines = 1) }
                    DropdownMenu(
                        expanded = showPortMenu,
                        onDismissRequest = { showPortMenu = false },
                    ) {
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
                )
            }
        }

        // — Workers + Low bandwidth ─────────────────────────────────────────
        item {
            Text("Workers", style = MaterialTheme.typography.labelLarge)
            Spacer(Modifier.height(4.dp))
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                CONCURRENCY_PRESETS.forEach { (label, value) ->
                    FilterChip(
                        selected = form.concurrency == value,
                        onClick = { onFormChange(form.copy(concurrency = value)) },
                        label = { Text(label) },
                        modifier = Modifier.height(40.dp),
                    )
                }
            }
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(
                    checked = form.lowBandwidth,
                    onCheckedChange = { onFormChange(form.copy(lowBandwidth = it)) },
                )
                Spacer(Modifier.width(8.dp))
                Text("Low bandwidth (slower connection)", style = MaterialTheme.typography.bodyMedium)
            }
        }

        // — Transfer model (proxy only) ─────────────────────────────────────
        if (kind == ScanKind.HTTP || kind == ScanKind.SOCKS5) {
            item {
                Text("Transfer model", style = MaterialTheme.typography.labelLarge)
                Spacer(Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("old" to "Stable", "brrr" to "Fast (goBrrr)").forEach { (model, label) ->
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

        // — SNI domains + strict mode ───────────────────────────────────────
        if (kind == ScanKind.SNI) {
            item {
                Text("SNI domains (blank = built-in defaults)", style = MaterialTheme.typography.labelLarge)
                Spacer(Modifier.height(4.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.Top,
                ) {
                    OutlinedTextField(
                        value = form.sniDomains,
                        onValueChange = { onFormChange(form.copy(sniDomains = it)) },
                        modifier = Modifier.weight(1f).height(90.dp),
                        placeholder = { Text("workers.dev\npages.dev") },
                    )
                    // Paste SNI domains from clipboard
                    FilledTonalIconButton(
                        onClick = {
                            val clip = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                            val text = clip?.primaryClip?.getItemAt(0)?.coerceToText(ctx)?.toString()
                            if (!text.isNullOrBlank()) {
                                val appended = if (form.sniDomains.isBlank()) text
                                               else "${form.sniDomains.trimEnd()}\n$text"
                                onFormChange(form.copy(sniDomains = appended))
                            }
                        },
                        modifier = Modifier.size(48.dp).align(Alignment.CenterVertically),
                    ) {
                        Icon(Icons.Default.ContentPaste, contentDescription = "Paste domains")
                    }
                }
            }
            item {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Switch(
                        checked = form.sniStrict,
                        onCheckedChange = { onFormChange(form.copy(sniStrict = it)) },
                    )
                    Column {
                        Text("Strict SNI", style = MaterialTheme.typography.bodyMedium)
                        Text(
                            "Require SNI accepted (domain-fronting mode)",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }

        // — Start button ────────────────────────────────────────────────────
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
