package com.whitescan.app.ui

import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.Role
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckBox
import androidx.compose.material.icons.filled.CheckBoxOutlineBlank
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.whitescan.engine.mobile.Mobile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class AsnRow(val asn: String, val name: String, val subnets: Int)

private const val CONSTRAINED_ASN_SEARCH_LIMIT = 80
private const val CONSTRAINED_ASN_MIN_QUERY_CHARS = 2
private const val ASN_SEARCH_DEBOUNCE_MS = 300L
private const val ASN_PAGE_QUERY_PREFIX = "__WHITEDNS_ASN_PAGE__\t"
private const val ASN_FAMILY_QUERY_PREFIX = "__WHITEDNS_ASN_FAMILY__\t"

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun AsnSearchScreen(
    dataDir: String,
    confirmLabel: String = "Use selection",
    constrainedDevice: Boolean = false,
    // Returns the expanded CIDRs for the chosen ASNs and selected IP family.
    onSelected: (cidrs: String) -> Unit,
    onCancel: () -> Unit,
) {
    var query by remember { mutableStateOf("") }
    var family by remember { mutableStateOf("ipv4") }
    var rows by remember { mutableStateOf<List<AsnRow>>(emptyList()) }
    var loading by remember { mutableStateOf(false) }
    var loadingMore by remember { mutableStateOf(false) }
    var nextOffset by remember { mutableStateOf(0) }
    var hasMoreRows by remember { mutableStateOf(false) }
    var expanding by remember { mutableStateOf(false) }
    var expandError by remember { mutableStateOf<String?>(null) }
    val selected = remember { mutableStateMapOf<String, AsnRow>() }
    val haptic = LocalHapticFeedback.current
    val scope = rememberCoroutineScope()
    val trimmedQuery = query.trim()
    val listState = rememberLazyListState()

    // Auto-focus search field so keyboard pops up immediately
    val focusRequester = remember { FocusRequester() }
    LaunchedEffect(Unit) {
        focusRequester.requestFocus()
    }

    LaunchedEffect(trimmedQuery, constrainedDevice, family) {
        if (constrainedDevice &&
            trimmedQuery.isNotEmpty() &&
            trimmedQuery != "*" &&
            trimmedQuery.length < CONSTRAINED_ASN_MIN_QUERY_CHARS
        ) {
            rows = emptyList()
            loading = false
            return@LaunchedEffect
        }

        loading = true
        delay(ASN_SEARCH_DEBOUNCE_MS)
        val loaded = loadAsnRows(dataDir, trimmedQuery, constrainedDevice, 0, family)
        rows = loaded
        nextOffset = if (constrainedDevice) loaded.size else 0
        hasMoreRows = constrainedDevice && loaded.size == CONSTRAINED_ASN_SEARCH_LIMIT
        loading = false
    }

    LaunchedEffect(trimmedQuery, constrainedDevice, family) {
        if (!constrainedDevice) return@LaunchedEffect
        snapshotFlow { listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: -1 }
            .collect { lastVisible ->
                val shouldLoad =
                    hasMoreRows &&
                    !loading &&
                    !loadingMore &&
                    rows.isNotEmpty() &&
                    lastVisible >= rows.lastIndex - 8
                if (!shouldLoad) return@collect

                loadingMore = true
                val loaded = loadAsnRows(dataDir, trimmedQuery, constrainedDevice, nextOffset, family)
                if (loaded.isEmpty()) {
                    hasMoreRows = false
                } else {
                    val seen = rows.mapTo(mutableSetOf()) { it.asn }
                    rows = rows + loaded.filterNot { seen.contains(it.asn) }
                    nextOffset += loaded.size
                    hasMoreRows = loaded.size == CONSTRAINED_ASN_SEARCH_LIMIT
                }
                loadingMore = false
            }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        Text(
            "IP family",
            style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(start = 16.dp, top = 8.dp),
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            listOf("ipv4" to "IPv4", "ipv6" to "IPv6", "both" to "Both").forEach { (value, label) ->
                FilterChip(
                    selected = family == value,
                    onClick = {
                        if (family != value) {
                            family = value
                            selected.clear()
                            expandError = null
                        }
                    },
                    label = { Text(label) },
                    modifier = Modifier.weight(1f),
                )
            }
        }

        // Search bar — auto-focused so keyboard pops up on entry
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .focusRequester(focusRequester),
            placeholder = { Text("Search ASN name or number…") },
            leadingIcon = { Icon(ScannerIcons.Search, contentDescription = null) },
            singleLine = true,
        )

        // Selection action bar
        if (selected.isNotEmpty()) {
            Surface(color = MaterialTheme.colorScheme.primaryContainer) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        "${selected.size} selected",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = { selected.clear() },
                            modifier = Modifier.height(44.dp),
                            enabled = !expanding,
                        ) { Text("Clear") }
                        Button(
                            onClick = {
                                if (expanding) return@Button
                                expandError = null
                                val ids = ASN_FAMILY_QUERY_PREFIX + family + "\t" +
                                    selected.values.joinToString("\n") { it.asn }
                                scope.launch {
                                    expanding = true
                                    val result = withContext(Dispatchers.IO) {
                                        runCatching { Mobile.expandASNs(dataDir, ids) }
                                    }
                                    expanding = false
                                    val error = result.exceptionOrNull()
                                    val cidrs = result.getOrNull().orEmpty()
                                    if (error != null) {
                                        expandError = error.message ?: "expand failed"
                                    } else if (cidrs.isBlank()) {
                                        expandError = "No ${family.uppercase()} ranges found for the selected ASN(s)"
                                    } else {
                                        onSelected(cidrs)
                                    }
                                }
                            },
                            modifier = Modifier.height(44.dp),
                            enabled = !expanding,
                        ) {
                            if (expanding) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(18.dp),
                                    strokeWidth = 2.dp,
                                    color = MaterialTheme.colorScheme.onPrimary,
                                )
                            } else {
                                Text(confirmLabel)
                            }
                        }
                    }
                }
            }
        }

        // Expansion error banner
        expandError?.let { err ->
            Surface(color = MaterialTheme.colorScheme.errorContainer) {
                Text(
                    err,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        if (loading) {
            Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
        } else if (constrainedDevice && rows.isEmpty() && trimmedQuery.isBlank()) {
            Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                Text("No ASN rows loaded", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else if (rows.isEmpty() && query.isNotBlank()) {
            Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                Text("No results for \"$query\"", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        // Hint shown when nothing selected
        if (selected.isEmpty() && rows.isNotEmpty()) {
            Text(
                "Tap to select · Double-tap to deselect · Long-press to select",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
            )
        }

        LazyColumn(
            state = listState,
            modifier = Modifier.weight(1f),
        ) {
            items(rows, key = { it.asn }) { row ->
                val isSelected = selected.containsKey(row.asn)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        // Tap = toggle select/deselect; long-press = select with haptic
                        .semantics { stateDescription = if (isSelected) "Selected" else "Not selected" }
                        .combinedClickable(
                            role = Role.Checkbox,
                            onClick = {
                                if (isSelected) selected.remove(row.asn)
                                else selected[row.asn] = row
                            },
                            onDoubleClick = {
                                selected.remove(row.asn)
                            },
                            onLongClick = {
                                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                selected[row.asn] = row
                            },
                        )
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Checkbox(checked = isSelected, onCheckedChange = null)
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            row.name,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal,
                            maxLines = 1,
                        )
                        Text(
                            "${row.asn}  ·  ${row.subnets} subnet(s)",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                HorizontalDivider(thickness = 0.5.dp, color = MaterialTheme.colorScheme.outlineVariant)
            }
            if (loadingMore) {
                item(key = "asn-loading-more") {
                    Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    }
                }
            }
        }

        TextButton(
            onClick = onCancel,
            modifier = Modifier
                .fillMaxWidth()
                .padding(8.dp)
                .heightIn(min = 48.dp),
        ) { Text("Cancel") }
    }
}

private suspend fun loadAsnRows(
    dataDir: String,
    query: String,
    constrainedDevice: Boolean,
    offset: Int,
    family: String,
): List<AsnRow> = withContext(Dispatchers.IO) {
    runCatching {
        val search = query.ifBlank { "*" }
        val engineQuery =
            if (constrainedDevice)
                "$ASN_PAGE_QUERY_PREFIX$offset\t$CONSTRAINED_ASN_SEARCH_LIMIT\t$search"
            else
                search
        Mobile.asnSearch(dataDir, ASN_FAMILY_QUERY_PREFIX + family + "\t" + engineQuery)
            .trimEnd()
            .lines()
            .filter { it.isNotBlank() }
            .mapNotNull { line ->
                val parts = line.split('\t')
                if (parts.size >= 3) AsnRow(parts[0], parts[1], parts[2].toIntOrNull() ?: 0)
                else null
            }
    }.getOrDefault(emptyList())
}
