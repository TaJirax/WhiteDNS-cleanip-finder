package com.whitescan.app.ui

import kotlinx.coroutines.launch
import androidx.compose.material.icons.outlined.Share
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.whitescan.app.ScanUiState
import com.whitescan.app.ScanViewModel
import java.io.File

@OptIn(ExperimentalFoundationApi::class, androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
fun ResultsScreen(
    state: ScanUiState,
    vm: ScanViewModel,
    onBack: () -> Unit,
    onNewScan: () -> Unit,
    onInspect: (String) -> Unit = {},
) {
    val ctx = LocalContext.current
    val haptic = LocalHapticFeedback.current
    val snackbar = LocalSnackbar.current
    val scope = androidx.compose.runtime.rememberCoroutineScope()

    // Blank query: last 100 lines. Otherwise search the whole file (debounced).
    var query by rememberSaveable(state.savedPath) { mutableStateOf("") }
    LaunchedEffect(state.savedPath, query) {
        val path = state.savedPath ?: return@LaunchedEffect
        if (query.isNotBlank()) kotlinx.coroutines.delay(300)
        vm.search(path, query)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {


        if (state.error != null) {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer
                ),
            ) {
                Text(
                    "Error: ${state.error}",
                    modifier = Modifier.padding(12.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text(
                    "${state.found} endpoint(s) found",
                    style = MaterialTheme.typography.bodyLarge,
                )
                state.savedPath?.let { path ->
                    Text(
                        path.substringAfterLast('/'),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            state.savedPath?.let { path ->
                FilledTonalButton(
                    onClick = { shareFile(ctx, path) },
                    modifier = Modifier.heightIn(min = 48.dp),
                ) {
                    Icon(Icons.Outlined.Share, contentDescription = "Share",
                        modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Share")
                }
            }
        }

        if (state.savedPath != null) {
            val matchText: (@Composable () -> Unit)? = if (state.matches >= 0) {
                { Text(if (state.matches > state.preview.size) "${state.matches} matches · showing the first ${state.preview.size}" else "${state.matches} match(es)") }
            } else null
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Search all results") },
                placeholder = { Text("IP, port, domain or error") },
                supportingText = matchText,
            )
        }

        HorizontalDivider()

        // The file holds the COMPLETE result set; the live list is throttled
        // (≤4/sec) so it can be far short of the real count. Prefer the file
        // preview. While it is still loading and we know more results exist on
        // disk (found > what the live list captured), show a loading state with
        // the true count instead of flashing a misleading partial list.
        val previewReady = state.preview.isNotEmpty()
        val display = if (previewReady) state.preview else state.liveResults
        // Show the loading state while the full set is being read from disk. Keyed
        // on previewLoading (not the count) so it can never get stuck if the file
        // read returns empty — it then falls through to the normal branches.
        val awaitingFullList = !previewReady && state.previewLoading
        when {
            awaitingFullList -> {
                Column(
                    Modifier.fillMaxWidth().padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    CircularProgressIndicator()
                    Text(
                        if (state.found > 0) "Loading ${state.found} result(s)…" else "Loading results…",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            display.isEmpty() -> {
                Text(
                    if (state.matches == 0) "No results match “$query”." else if (state.found > 0) "Loading ${state.found} result(s)…" else "No results found.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            else -> {
                Text(
                    if (state.matches >= 0)
                        "Tap a result for details, copy and speed"
                    else if (state.found > display.size)
                        "Showing the latest ${display.size} of ${state.found} · search to find any result"
                    else
                        "Tap a result for details, copy and speed",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                LazyColumn(modifier = Modifier.weight(1f).fillMaxWidth()) {
                    items(display) { line ->
                        ResultRow(
                            line = line,
                            onInspect = { onInspect(line) },
                            onCopy = { ip ->
                                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                copyToClipboard(ctx, ip)
                                scope.launch { snackbar.copied(ip) }
                            },
                        )
                        HorizontalDivider(
                            thickness = 0.5.dp,
                            color = MaterialTheme.colorScheme.outlineVariant,
                        )
                    }
                }
            }
        }

        // Keep the actions at the bottom when there is no list to fill the space.
        if (awaitingFullList || display.isEmpty()) Spacer(Modifier.weight(1f))
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp),
            ) { Text("Back") }
            Button(
                onClick = onNewScan,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp),
            ) { Text("New Scan") }
        }
    }
}

// Matches the first IPv4 (with optional :port) anywhere in a line.
private val IP_PORT_REGEX = Regex("""\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b""")

// A result line is usually "IP:port" optionally followed by a TAB and the passed
// probe domains, but Speed-Rank / SNI lines embed the IP inside a longer string.
// Long-press copies ONLY the extracted IP:port — never the whole formatted line
// (which previously made it look like "the whole screen" was copied).
@OptIn(ExperimentalFoundationApi::class, androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun ResultRow(line: String, onCopy: (String) -> Unit,
    onInspect: () -> Unit) {
    val tab = line.indexOf('\t')
    val display = (if (tab >= 0) line.substring(0, tab) else line).trim()
    val domains = if (tab >= 0) line.substring(tab + 1).trim() else ""
    // Always copy just the IP:port, extracted from anywhere in the line.
    val copyTarget = IP_PORT_REGEX.find(line)?.value ?: display

    androidx.compose.foundation.layout.FlowRow(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .combinedClickable(
                onClick = onInspect,
                onLongClickLabel = "Copy IP",
                onLongClick = { onCopy(copyTarget) },
            )
            .padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            display,
            fontSize = 13.sp,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.SemiBold,
            color = MintGreen,
        )
        if (domains.isNotEmpty()) {
            // Show the important domains first (shortened), cap the count, and
            // collapse the rest into a "+N" tag so busy IPs stay readable.
            val (tags, extra) = shortDomains(domains, max = 3)
            tags.forEach { name ->
                Surface(
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    shape = MaterialTheme.shapes.small,
                ) {
                    Text(
                        name,
                        fontSize = MaterialTheme.typography.bodySmall.fontSize,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                    )
                }
            }
            if (extra > 0) {
                Text(
                    "+$extra",
                    fontSize = MaterialTheme.typography.bodySmall.fontSize,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

// Friendly short labels for the common probe domains.
private val DOMAIN_SHORT = mapOf(
    "workers.dev" to "workers",
    "pages.dev" to "pages",
    "claude.ai" to "claude",
    "gemini.google.com" to "gemini",
    "notebooklm.google.com" to "notebook",
    "chatgpt.com" to "chatgpt",
    "instagram.com" to "instagram",
    "web.telegram.org" to "telegram",
    "reddit.com" to "reddit",
)

// Order important domains first; everything else keeps its position after.
private val DOMAIN_PRIORITY = listOf(
    "workers.dev", "pages.dev", "claude.ai", "gemini.google.com",
    "notebooklm.google.com", "chatgpt.com",
)

// Returns (shortened tags to show, count of remaining hidden domains).
private fun shortDomains(raw: String, max: Int): Pair<List<String>, Int> {
    val items = raw.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    val ordered = items.sortedBy { d ->
        DOMAIN_PRIORITY.indexOf(d).let { if (it < 0) Int.MAX_VALUE else it }
    }
    val shown = ordered.take(max).map { DOMAIN_SHORT[it] ?: it.substringBefore('.') }
    val extra = (ordered.size - shown.size).coerceAtLeast(0)
    return shown to extra
}

private fun copyToClipboard(ctx: Context, text: String) {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    cm.setPrimaryClip(ClipData.newPlainText("ip", text))
}

internal fun shareFile(ctx: Context, path: String) {
    val file = File(path)
    if (!file.exists()) return
    val uri = try {
        FileProvider.getUriForFile(ctx, "${ctx.packageName}.provider", file)
    } catch (_: Exception) { return }
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    ctx.startActivity(Intent.createChooser(intent, "Share scan results"))
}
