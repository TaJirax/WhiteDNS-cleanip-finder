package com.whitescan.app.ui

import androidx.compose.material.icons.outlined.Share
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.text.DateFormat
import java.util.Date

// Earlier scans' result files, newest first (the desktop Reports page). Opening
// one shows it in Results — search, details, copy and speed — without rescanning.
@Composable
fun SavedResultsScreen(load: () -> List<File>, scanRunning: Boolean, onOpen: (String) -> Unit) {
    val ctx = LocalContext.current
    val files by produceState<List<File>?>(null) { value = withContext(Dispatchers.IO) { load() } }
    val format = remember { DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT) }
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (scanRunning) Text(
            "A scan is running. Saved results open once it finishes.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        when (val list = files) {
            null -> CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
            emptyList<File>() -> Text("No saved results yet. Finished and stopped scans appear here.", style = MaterialTheme.typography.bodyMedium)
            else -> LazyColumn(Modifier.fillMaxSize()) {
                items(list, key = { it.absolutePath }) { file ->
                    ListItem(
                        modifier = Modifier.fillMaxWidth().heightIn(min = 72.dp)
                            .clickable(enabled = !scanRunning) { onOpen(file.absolutePath) },
                        headlineContent = { Text(file.name, style = MaterialTheme.typography.titleSmall) },
                        supportingContent = {
                            Text("${file.parentFile?.name} · ${format.format(Date(file.lastModified()))} · ${file.length() / 1024} KB",
                                style = MaterialTheme.typography.bodySmall)
                        },
                        trailingContent = {
                            IconButton(onClick = { shareFile(ctx, file.absolutePath) }) {
                                Icon(Icons.Outlined.Share, contentDescription = "Share ${file.name}")
                            }
                        },
                    )
                    HorizontalDivider(thickness = 0.5.dp, color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }
}
