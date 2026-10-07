package com.whitescan.app.ui
import androidx.compose.ui.graphics.luminance
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import com.whitescan.app.ScanKind
import com.whitescan.app.R

@Composable fun HomeScreen(onSelect:(ScanKind)->Unit,onEdgeFinder:()->Unit,onConfigMaker:()->Unit,onSavedResults:()->Unit={}){
 Box(Modifier.fillMaxSize(),contentAlignment=Alignment.TopCenter){
 LazyColumn(Modifier.widthIn(max=760.dp).fillMaxWidth(),contentPadding=PaddingValues(20.dp),verticalArrangement=Arrangement.spacedBy(8.dp)){
  item { Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(12.dp)) {
   // Desktop brand mark: accent-soft tile at night, solid accent by day, white logo.
   val night=MaterialTheme.colorScheme.background.luminance()<.5f
   Surface(color=if(night) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.primary,shape=MaterialTheme.shapes.small){Image(painterResource(R.drawable.scanner_logo),"WhiteDNS logo",Modifier.size(56.dp).padding(8.dp),colorFilter=ColorFilter.tint(if(night) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onPrimary))}
   Column {Text("WhiteDNS",style=MaterialTheme.typography.headlineMedium);Text("IP Scanner · v1.4.5",style=MaterialTheme.typography.bodyMedium,color=MaterialTheme.colorScheme.onSurfaceVariant)}
  } }
  item { Spacer(Modifier.height(16.dp));Text("Scans",style=MaterialTheme.typography.titleLarge) }
  item { MenuRow(ScannerIcons.Cloud,"Scan IPs","Cloudflare clean IP finder — your IPs, CIDRs or edge domains"){onSelect(ScanKind.IP)} }
  item { MenuRow(ScannerIcons.Globe,"Edge Provider IP Finder","Choose a CDN and keep its own targets and options",onEdgeFinder) }
  item { MenuRow(ScannerIcons.Swap,"Scan HTTP Proxies","Verify forwarding through your proxy endpoints"){onSelect(ScanKind.HTTP)} }
  item { MenuRow(ScannerIcons.Swap,"Scan SOCKS5 Proxies","Verify SOCKS5 proxy forwarding"){onSelect(ScanKind.SOCKS5)} }
  item { MenuRow(ScannerIcons.Globe,"SNI Scanner (TLS Hostname Probe)","Dedicated hostname/certificate checks; separate from IP/proxy scans"){onSelect(ScanKind.SNI)} }
  item { MenuRow(ScannerIcons.Dns,"DNS Resolver / Tunnel Scan","UDP, TCP, DoT, DoH and tunnel readiness"){onSelect(ScanKind.DNS)} }
  item { HorizontalDivider();Spacer(Modifier.height(8.dp));Text("Tools",style=MaterialTheme.typography.titleLarge) }
  item { MenuRow(ScannerIcons.Folder,"Saved results","Review, search and share earlier scans",onSavedResults) }
  item { MenuRow(ScannerIcons.Download,"Speed & Loss Rank (Cloudflare)","Rank the IPs you choose"){onSelect(ScanKind.SPEED)} }
  item { MenuRow(ScannerIcons.File,"Export ASN IPs","IPv4, IPv6 or both"){onSelect(ScanKind.ASN_EXPORT)} }
  item { MenuRow(ScannerIcons.Tune,"Config Maker","Existing proxy and WireGuard configuration tools",onConfigMaker) }
 }
 }
}
@Composable private fun MenuRow(icon:ImageVector,title:String,detail:String,action:()->Unit){
 ListItem(modifier=Modifier.fillMaxWidth().heightIn(min=72.dp).clickable(onClick=action),leadingContent={Icon(icon,null,tint=MaterialTheme.colorScheme.primary)},headlineContent={Text(title,style=MaterialTheme.typography.titleMedium)},supportingContent={Text(detail,style=MaterialTheme.typography.bodyMedium)})
}
