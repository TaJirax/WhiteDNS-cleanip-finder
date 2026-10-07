package com.whitescan.app.ui

import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.whitescan.app.ScanUiState

@Composable
fun ScanningScreen(
    state: ScanUiState,
    onPauseResume: () -> Unit,
    onStop: () -> Unit,
    onViewResults: () -> Unit,
) {
    val logListState = rememberLazyListState()

    // Auto-scroll log to newest entry
    LaunchedEffect(state.logs.size) {
        if (state.logs.isNotEmpty()) {
            logListState.animateScrollToItem(state.logs.lastIndex)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {

        // ── Progress bar: the desktop "boba" fill, brown sugar → accent → honey ──
        val pct = if (state.total > 0) state.processed.toFloat() / state.total else 0f
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    if(state.total>0) "${(pct * 100).toInt()}%  ${state.processed}/${state.total}" else "${state.processed} checked · discovering total",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (state.etaSec > 0) {
                    val m = state.etaSec / 60; val s = state.etaSec % 60
                    Text("ETA ${m}m${s}s", style = MaterialTheme.typography.bodySmall)
                }
            }
            val track = MaterialTheme.colorScheme.surfaceContainerHighest
            val step = (pct * 10).toInt() * 10
            val spoken = if (state.total > 0) "Scan $step percent, ${state.found} found" else "Scanning, ${state.found} found"
            Box(Modifier.semantics { liveRegion = LiveRegionMode.Polite; contentDescription = spoken })
            if (state.total <= 0 && state.running) {
                // Total still being counted: indeterminate, as on desktop.
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth().height(10.dp),
                    color = MaterialTheme.colorScheme.primary,
                    trackColor = track,
                    strokeCap = androidx.compose.ui.graphics.StrokeCap.Round,
                )
            } else Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(10.dp)
                    .background(track, androidx.compose.foundation.shape.CircleShape),
            ) {
                if (pct > 0f) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth(pct)
                            .fillMaxHeight()
                            .background(
                                Brush.horizontalGradient(
                                    0f to ScannerPalette.primaryStrong,
                                    .7f to MaterialTheme.colorScheme.primary,
                                    1f to ScannerPalette.honey,
                                ),
                                androidx.compose.foundation.shape.CircleShape,
                            ),
                    )
                }
            }
        }

        // ── Stats row ──────────────────────────────────────────────────────
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("Found: ${state.found}", style = MaterialTheme.typography.bodySmall)
            Text("Unique IPs: ${state.uniqueIPs}", style = MaterialTheme.typography.bodySmall)
        }

        // ── Current target ─────────────────────────────────────────────────
        if (state.currentIP.isNotEmpty()) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Icon(ScannerIcons.Play, contentDescription = "Now probing", tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(14.dp))
                Text(
                    state.currentIP,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        // ── Live hits (last 6) ─────────────────────────────────────────────
        if (state.liveResults.isNotEmpty()) {
            HorizontalDivider()
            Text(
                "Recent hits  (${state.found} total)",
                style = MaterialTheme.typography.labelMedium,
            )
            state.liveResults.takeLast(6).forEach { line ->
                Text(
                    line,
                    fontSize = MaterialTheme.typography.bodySmall.fontSize,
                    fontFamily = FontFamily.Monospace,
                    color = MintGreen,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        // ── Log tail ───────────────────────────────────────────────────────
        HorizontalDivider()
        Text("Log", style = MaterialTheme.typography.labelMedium)
        LazyColumn(
            state = logListState,
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(
                    MaterialTheme.colorScheme.surfaceVariant,
                    MaterialTheme.shapes.small,
                )
                .padding(6.dp),
        ) {
            items(state.logs) { line ->
                Text(
                    line,
                    fontSize = MaterialTheme.typography.bodySmall.fontSize,
                    fontFamily = FontFamily.Monospace,
                    lineHeight = 14.sp,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        // ── Controls (48 dp touch targets) ────────────────────────────────
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            OutlinedButton(
                onClick = onPauseResume,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp),
            ) {
                Icon(
                    if (state.paused) ScannerIcons.Play else ScannerIcons.Pause,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(6.dp))
                Text(if (state.paused) "Resume" else "Pause")
            }
            Button(
                onClick = onStop,
                // Desktop danger button: strawberry on a soft strawberry tint.
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer,
                    contentColor = MaterialTheme.colorScheme.onErrorContainer,
                ),
                modifier = Modifier.weight(1f).heightIn(min = 48.dp),
            ) {
                Icon(
                    ScannerIcons.Stop,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(6.dp))
                Text("Stop")
            }
        }

        if (state.done) {
            Button(
                onClick = onViewResults,
                modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp),
            ) {
                Text("View Results (${state.found})")
            }
        }
    }
}
