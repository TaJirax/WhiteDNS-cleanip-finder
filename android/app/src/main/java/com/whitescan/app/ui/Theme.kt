package com.whitescan.app.ui

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat

// Bubble tea palettes from the WhiteDNS desktop scanner (scanner-gui style.css):
// quiet taro-tinted night surfaces, milk-cream days, and three accents — Taro
// purple, Teal tea, Milk tea. Desktop tokens map onto Material 3 roles so every
// stock component picks them up; the few desktop colours Material has no role
// for (honey, thai, brown-sugar gradient stop) live in ScannerColors.

/** Desktop colours with no Material role. */
data class ScannerColors(
    val honey: Color,         // paused, warnings, cost-heavy settings
    val thai: Color,          // secondary warm accent
    val primaryStrong: Color, // gradient stop under primary (desktop "brown sugar")
)

private val LocalScannerColors = staticCompositionLocalOf {
    ScannerColors(Color(0xFFF2C76E), Color(0xFFF2A462), Color(0xFF9873C6))
}
val ScannerPalette: ScannerColors @Composable get() = LocalScannerColors.current

/** The app Scaffold's snackbar host, for transient feedback from any screen. */
val LocalSnackbar = staticCompositionLocalOf { SnackbarHostState() }

/** Confirms a copy, unless the system already does (Android 13+). */
suspend fun SnackbarHostState.copied(what: String) {
    if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU) showSnackbar("Copied $what")
}

// Aliases the screens already use, now resolved to the desktop palette.
val CyanAccent: Color @Composable get() = MaterialTheme.colorScheme.primary
val Lavender: Color @Composable get() = MaterialTheme.colorScheme.secondary // taro
val CoralRed: Color @Composable get() = MaterialTheme.colorScheme.error     // strawberry
val Amber: Color @Composable get() = ScannerPalette.honey
val MintGreen: Color @Composable get() = MaterialTheme.colorScheme.tertiary // matcha
val ResultGreen: Color @Composable get() = MintGreen
val DarkBase: Color @Composable get() = MaterialTheme.colorScheme.background
val DarkSurface: Color @Composable get() = MaterialTheme.colorScheme.surface
val DarkSurface2: Color @Composable get() = MaterialTheme.colorScheme.surfaceVariant
val OnDark: Color @Composable get() = MaterialTheme.colorScheme.onSurface
val OnDarkMuted: Color @Composable get() = MaterialTheme.colorScheme.onSurfaceVariant

private data class Accent(val primary: Color, val strong: Color, val onPrimary: Color, val softAlpha: Float)

private fun accent(dark: Boolean, name: String): Accent = when (name) {
    "teal" -> if (dark) Accent(Color(0xFF77C7BC), Color(0xFF4CA497), Color(0xFF102C29), .15f)
              else Accent(Color(0xFF22675D), Color(0xFF25645B), Color(0xFFF4FFFC), .13f)
    "milk" -> if (dark) Accent(Color(0xFFE3B07C), Color(0xFFC98A4F), Color(0xFF2A170D), .16f)
              else Accent(Color(0xFF805027), Color(0xFF7A4A2B), Color(0xFFFFF8EE), .13f)
    else ->   if (dark) Accent(Color(0xFFB99ADD), Color(0xFF9873C6), Color(0xFF21152F), .16f)   // purple
              else Accent(Color(0xFF6D4795), Color(0xFF634784), Color(0xFFFFF8FF), .13f)
}

/** The desktop accent names; older saved values (e.g. "cyan") fall back to Taro purple. */
fun normalizeAccent(name: String?): String = if (name == "teal" || name == "milk") name else "purple"

internal fun appColorScheme(dark: Boolean, accentName: String): ColorScheme {
    val a = accent(dark, normalizeAccent(accentName))
    return if (dark) {
        val bg = Color(0xFF110F16)
        val tint = Color(0xFFDCCDF2) // desktop glass rgba(220,205,242,…)
        val text = Color(0xFFEEE8F3)
        darkColorScheme(
            primary = a.primary, onPrimary = a.onPrimary,
            primaryContainer = a.primary.copy(alpha = a.softAlpha).compositeOver(bg), onPrimaryContainer = text,
            secondary = Color(0xFFBCA0DF), onSecondary = Color(0xFF21152F),
            secondaryContainer = a.primary.copy(alpha = a.softAlpha).compositeOver(bg), onSecondaryContainer = text,
            tertiary = Color(0xFF83C9BD), onTertiary = Color(0xFF102C29),
            tertiaryContainer = Color(0xFF83C9BD).copy(alpha = .13f).compositeOver(bg), onTertiaryContainer = text,
            error = Color(0xFFF0939B), onError = Color(0xFF2A1015),
            errorContainer = Color(0xFFF0939B).copy(alpha = .14f).compositeOver(bg), onErrorContainer = Color(0xFFF0939B),
            background = bg, onBackground = text,
            surface = bg, onSurface = text,
            surfaceVariant = Color(0xFF211C2A), onSurfaceVariant = Color(0xFFB3A5C1),
            surfaceTint = Color.Transparent, // flat tonal levels, as on desktop
            surfaceContainerLowest = bg,
            surfaceContainerLow = tint.copy(alpha = .045f).compositeOver(bg),
            surfaceContainer = Color(0xFF1B1721), // desktop sidebar
            surfaceContainerHigh = Color(0xFF211C2A), // desktop glass-strong
            surfaceContainerHighest = Color(0xFF2A2434),
            outline = Color(0xFFD0BBE7).copy(alpha = .30f).compositeOver(bg),
            outlineVariant = Color(0xFFD0BBE7).copy(alpha = .12f).compositeOver(bg),
            inverseSurface = text, inverseOnSurface = bg, inversePrimary = accent(false, normalizeAccent(accentName)).primary,
        )
    } else {
        val bg = Color(0xFFF7EEE0)  // milk cream
        val cream = Color(0xFFFFFBF4)
        val text = Color(0xFF3A2317)
        val brown = Color(0xFF7A4E30) // desktop border rgba(122,78,48,…)
        lightColorScheme(
            primary = a.primary, onPrimary = a.onPrimary,
            primaryContainer = a.primary.copy(alpha = a.softAlpha).compositeOver(cream), onPrimaryContainer = text,
            secondary = Color(0xFF664486), onSecondary = Color(0xFFFFF8FF),
            secondaryContainer = a.primary.copy(alpha = a.softAlpha).compositeOver(cream), onSecondaryContainer = text,
            tertiary = Color(0xFF365D20), onTertiary = Color(0xFFF4FFEE),
            tertiaryContainer = Color(0xFF5B8838).copy(alpha = .13f).compositeOver(cream), onTertiaryContainer = text,
            error = Color(0xFF983446), onError = Color(0xFFFFF8FA),
            errorContainer = Color(0xFFC24F5B).copy(alpha = .12f).compositeOver(cream), onErrorContainer = Color(0xFF983446),
            background = bg, onBackground = text,
            surface = bg, onSurface = text,
            surfaceVariant = cream.copy(alpha = .78f).compositeOver(bg), onSurfaceVariant = Color(0xFF624A39),
            surfaceTint = Color.Transparent,
            surfaceContainerLowest = cream,
            surfaceContainerLow = cream.copy(alpha = .56f).compositeOver(bg),
            surfaceContainer = cream.copy(alpha = .70f).compositeOver(bg),
            surfaceContainerHigh = cream.copy(alpha = .78f).compositeOver(bg),
            surfaceContainerHighest = cream,
            outline = brown.copy(alpha = .40f).compositeOver(bg),
            outlineVariant = brown.copy(alpha = .14f).compositeOver(bg),
            inverseSurface = text, inverseOnSurface = bg, inversePrimary = accent(true, normalizeAccent(accentName)).primary,
        )
    }
}

// Desktop radii: 8 badges, 14 fields, 20 metrics, 24 panels, 28 sheets.
private val ScannerShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(14.dp),
    medium = RoundedCornerShape(20.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

@Composable fun WhiteDNSTheme(mode: String = "system", accent: String = "purple", content: @Composable () -> Unit) {
    val dark = mode == "dark" || (mode != "light" && isSystemInDarkTheme())
    val scheme = remember(dark, accent) { appColorScheme(dark, accent) }
    val extra = remember(dark, accent) {
        val a = accent(dark, normalizeAccent(accent))
        if (dark) ScannerColors(Color(0xFFF2C76E), Color(0xFFF2A462), a.strong)
        else ScannerColors(Color(0xFF745108), Color(0xFF874010), a.strong)
    }
    val view = LocalView.current
    if (!view.isInEditMode) SideEffect {
        val window = (view.context as Activity).window
        window.statusBarColor = scheme.background.toArgb(); window.navigationBarColor = scheme.background.toArgb()
        WindowCompat.getInsetsController(window, view).apply { isAppearanceLightStatusBars = !dark; isAppearanceLightNavigationBars = !dark }
    }
    CompositionLocalProvider(LocalScannerColors provides extra) {
        MaterialTheme(colorScheme = scheme, shapes = ScannerShapes, content = content)
    }
}
