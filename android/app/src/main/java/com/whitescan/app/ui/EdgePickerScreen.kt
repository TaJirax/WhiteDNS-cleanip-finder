package com.whitescan.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.whitescan.engine.mobile.Mobile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// One selectable platform, as sent by the engine's EdgeProviderList().
data class EdgeProviderRow(
    val name: String,
    val hosts: Int,
    val ranges: Int,
    val probeDomains: List<String>,
) {
    // Providers that publish their edge ranges hand over a large target set as-is;
    // the rest are mapped from live DNS. That difference decides how long a scan
    // will run, so it drives the row's accent colour and its meta line.
    val publishesRanges: Boolean get() = ranges > 0
}

/**
 * Picks the CDN / PaaS edge network to hunt clean IPs on. Choosing a platform
 * resolves its front hostnames and stages the result as scan targets — the
 * resolve happens inside the row that was tapped, so the answer appears where
 * the question was asked.
 */
@Composable
fun EdgePickerScreen(
    onSelected: (provider: String, probeDomains: String, targets: String) -> Unit,
    onCancel: () -> Unit,
) {
    var rows by remember { mutableStateOf<List<EdgeProviderRow>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var resolving by remember { mutableStateOf<String?>(null) }
    var failed by remember { mutableStateOf<Pair<String, String>?>(null) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        rows = withContext(Dispatchers.IO) { loadEdgeProviders() }
        loading = false
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 16.dp),
        ) {
            Text(
                "Pick a platform. WhiteDNS resolves the hostnames it serves and scans the addresses behind them first, then its wider published ranges.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            Text(
                "The platform stays selected if you swap the targets afterwards — pick an ASN and those addresses get asked whether they serve this platform, and nothing else.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        HorizontalDivider(thickness = 0.5.dp, color = MaterialTheme.colorScheme.outlineVariant)

        if (loading) {
            Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
        }

        LazyColumn(modifier = Modifier.weight(1f)) {
            items(rows, key = { it.name }) { row ->
                EdgeProviderItem(
                    row = row,
                    resolving = resolving == row.name,
                    error = failed?.takeIf { it.first == row.name }?.second,
                    enabled = resolving == null,
                    onClick = {
                        failed = null
                        resolving = row.name
                        scope.launch {
                            val result = withContext(Dispatchers.IO) {
                                runCatching { Mobile.edgeProviderTargets(row.name) }
                            }
                            resolving = null
                            val targets = result.getOrNull().orEmpty()
                            if (result.isFailure || targets.isBlank()) {
                                failed = row.name to
                                    "No edge IPs resolved. Check the connection and try again."
                            } else {
                                onSelected(row.name, row.probeDomains.joinToString(", "), targets)
                            }
                        }
                    },
                )
                HorizontalDivider(thickness = 0.5.dp, color = MaterialTheme.colorScheme.outlineVariant)
            }
        }

        TextButton(
            onClick = onCancel,
            enabled = resolving == null,
            modifier = Modifier
                .fillMaxWidth()
                .padding(8.dp)
                .heightIn(min = 48.dp),
        ) { Text("Cancel") }
    }
}

@Composable
private fun EdgeProviderItem(
    row: EdgeProviderRow,
    resolving: Boolean,
    error: String?,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    // Honey marks a platform that publishes its ranges, so the scan is long;
    // the accent marks one whose targets come from DNS alone, so it is short.
    // Same meaning the scan form gives those colours: honey is what costs you.
    val accent = if (row.publishesRanges) Amber else CyanAccent
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 72.dp)
            .clickable(enabled = enabled, onClick = onClick),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(start = 20.dp, end = 20.dp, top = 14.dp, bottom = 14.dp),
        ) {
            Text(
                row.name,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(5.dp))
            Text(
                probeSignature(row.probeDomains),
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                letterSpacing = 0.4.sp,
                color = accent,
            )
            Spacer(Modifier.height(6.dp))
            when {
                resolving -> {
                    Text(
                        "Resolving ${row.hosts} hostnames…",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(6.dp))
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth().height(2.dp),
                        color = accent,
                        trackColor = Color.Transparent,
                    )
                }
                error != null -> Text(
                    error,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
                else -> Text(
                    metaLine(row),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

// The hostnames a scan probes with — the part of a platform users recognize.
private fun probeSignature(domains: List<String>): String {
    if (domains.isEmpty()) return "—"
    val shown = domains.take(3).joinToString("  ")
    val rest = domains.size - 3
    return if (rest > 0) "$shown  +$rest" else shown
}

private fun metaLine(row: EdgeProviderRow): String =
    if (row.publishesRanges)
        "${row.hosts} hostnames · ${row.ranges} published ranges — long scan, stop it when you have enough"
    else
        "${row.hosts} hostnames · ranges built from DNS — short scan"

private fun loadEdgeProviders(): List<EdgeProviderRow> = runCatching {
    Mobile.edgeProviderList()
        .trimEnd()
        .lines()
        .filter { it.isNotBlank() }
        .mapNotNull { line ->
            val parts = line.split('\t')
            if (parts.size < 4) return@mapNotNull null
            EdgeProviderRow(
                name = parts[0],
                hosts = parts[1].toIntOrNull() ?: 0,
                ranges = parts[2].toIntOrNull() ?: 0,
                probeDomains = parts[3].split(',').map { it.trim() }.filter { it.isNotEmpty() },
            )
        }
}.getOrDefault(emptyList())
