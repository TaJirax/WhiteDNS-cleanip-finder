package com.whitescan.app.ui

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.whitescan.engine.mobile.Mobile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

private enum class CmMode { REWRITE, EXTRACT }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConfigMakerScreen(dataDir: String) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var mode by remember { mutableStateOf(CmMode.REWRITE) }
    var configs by remember { mutableStateOf("") }
    var targets by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var resultPath by remember { mutableStateOf<String?>(null) }
    var resultPreview by remember { mutableStateOf<List<String>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Config Maker", style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.primary)

        // Mode selector
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = mode == CmMode.REWRITE,
                onClick = { mode = CmMode.REWRITE; resultPath = null; error = null },
                label = { Text("Rewrite configs") },
                modifier = Modifier.height(40.dp),
            )
            FilterChip(
                selected = mode == CmMode.EXTRACT,
                onClick = { mode = CmMode.EXTRACT; resultPath = null; error = null },
                label = { Text("Extract IP:ports") },
                modifier = Modifier.height(40.dp),
            )
        }

        Text(
            if (mode == CmMode.REWRITE)
                "Paste working proxy configs (vless/vmess/trojan/ss/hysteria) and a list of clean IP:port targets. Each config is rewritten to point at your targets."
            else
                "Paste proxy configs or text; the IP:port endpoints are extracted to a file.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // Configs input
        LabeledPasteField(
            label = "Proxy configs",
            value = configs,
            onChange = { configs = it },
            placeholder = "vless://...\nvmess://...",
            onPaste = { configs = appendClip(ctx, configs) },
        )

        // Targets input (rewrite only)
        if (mode == CmMode.REWRITE) {
            LabeledPasteField(
                label = "IP:port targets",
                value = targets,
                onChange = { targets = it },
                placeholder = "1.2.3.4:443\n5.6.7.8:8443",
                onPaste = { targets = appendClip(ctx, targets) },
            )
        }

        error?.let {
            Card(colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer)) {
                Text("Error: $it", modifier = Modifier.padding(12.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer)
            }
        }

        Button(
            onClick = {
                if (busy) return@Button
                error = null; resultPath = null
                scope.launch {
                    busy = true
                    val res = withContext(Dispatchers.IO) {
                        runCatching {
                            if (mode == CmMode.REWRITE)
                                Mobile.configMakerRewrite(dataDir, configs, targets)
                            else
                                Mobile.configMakerExtractIPs(dataDir, configs)
                        }
                    }
                    busy = false
                    res.onSuccess { path ->
                        resultPath = path
                        resultPreview = withContext(Dispatchers.IO) {
                            runCatching { File(path).readLines().takeLast(100) }.getOrDefault(emptyList())
                        }
                    }.onFailure { error = it.message ?: "failed" }
                }
            },
            enabled = !busy && configs.isNotBlank(),
            modifier = Modifier.fillMaxWidth().height(50.dp),
        ) {
            if (busy) CircularProgressIndicator(
                modifier = Modifier.size(20.dp), strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.onPrimary,
            ) else Text(if (mode == CmMode.REWRITE) "Generate configs" else "Extract IP:ports")
        }

        // Result
        resultPath?.let { path ->
            HorizontalDivider()
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("${resultPreview.size} line(s) saved",
                        style = MaterialTheme.typography.bodyMedium)
                    Text(path.substringAfterLast('/'),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                FilledTonalButton(onClick = { shareCmFile(ctx, path) },
                    modifier = Modifier.height(40.dp)) {
                    Icon(Icons.Default.Share, contentDescription = "Share",
                        modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Share")
                }
            }
            resultPreview.forEach { line ->
                Text(line, fontSize = 11.sp, fontFamily = FontFamily.Monospace,
                    color = MintGreen, modifier = Modifier.padding(vertical = 2.dp))
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LabeledPasteField(
    label: String,
    value: String,
    onChange: (String) -> Unit,
    placeholder: String,
    onPaste: () -> Unit,
) {
    Text(label, style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.Top) {
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            modifier = Modifier.weight(1f).height(120.dp),
            placeholder = { Text(placeholder) },
            textStyle = androidx.compose.ui.text.TextStyle(
                fontFamily = FontFamily.Monospace, fontSize = 12.sp),
        )
        FilledTonalIconButton(
            onClick = onPaste,
            modifier = Modifier.size(48.dp).align(Alignment.CenterVertically),
        ) { Icon(Icons.Default.ContentPaste, contentDescription = "Paste") }
    }
}

private fun appendClip(ctx: Context, existing: String): String {
    val clip = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    val text = clip?.primaryClip?.getItemAt(0)?.coerceToText(ctx)?.toString()
    return if (text.isNullOrBlank()) existing
    else if (existing.isBlank()) text else "${existing.trimEnd()}\n$text"
}

private fun shareCmFile(ctx: Context, path: String) {
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
    ctx.startActivity(Intent.createChooser(intent, "Share config maker output"))
}
