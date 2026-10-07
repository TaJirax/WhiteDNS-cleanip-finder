package com.whitescan.app.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.unit.dp

// The WhiteDNS desktop scanner's line icons (scanner-gui app.js `paths`):
// 24-unit grid, 1.8 stroke, round caps and joins. Icon() tints the stroke with
// its colour, like the desktop's `stroke: currentColor`.
object ScannerIcons {
    private fun icon(name: String, vararg paths: String): ImageVector =
        ImageVector.Builder(name, 24.dp, 24.dp, 24f, 24f).apply {
            for (d in paths) addPath(
                pathData = PathParser().parsePathString(d).toNodes(),
                fill = null,
                stroke = SolidColor(Color.Black),
                strokeLineWidth = 1.8f,
                strokeLineCap = StrokeCap.Round,
                strokeLineJoin = StrokeJoin.Round,
            )
        }.build()

    val Globe = icon("globe", "M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0", "M3 12h18M12 3c-5 5-5 13 0 18 5-5 5-13 0-18z")
    val Cloud = icon("cloud", "M7 19h11a5 5 0 0 0 1-10 7 7 0 0 0-13-1 6 6 0 0 0 1 11z")
    val Tune = icon("tune", "M4 6h16M4 12h16M4 18h16M8 3v6M16 9v6M10 15v6")
    val Dns = icon("dns", "M5 3h14a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z",
        "M5 14h14a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2z", "M7 6h1M7 17h1")
    val Swap = icon("swap", "M4 7h16l-4-4M20 17H4l4 4")
    val Txt = icon("txt", "M4 5h16M12 5v15M8 20h8")
    val Table = icon("table", "M5 4h14a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z", "M3 9h18M9 9v11M3 14h18")
    val Folder = icon("folder", "M3 7V5h7l2 3h9v12H3z")
    val Gear = icon("gear", "M9 3h6l1 3 3 1 2 5-2 5-3 1-1 3H9l-1-3-3-1-2-5 2-5 3-1z", "M9 12a3 3 0 1 0 6 0a3 3 0 1 0-6 0")
    val Play = icon("play", "M8 4l12 8-12 8z")
    val Pause = icon("pause", "M8 4v16M16 4v16")
    val Stop = icon("stop", "M7 5h10a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2z")
    val Redo = icon("redo", "M20 10a8 8 0 1 0-2 8M20 3v7h-7")
    val Open = icon("open", "M14 3h7v7M21 3 10 14M10 3H3v18h18v-7")
    val File = icon("file", "M14 3H5v18h14V8zM14 3v5h5M8 13h8M8 17h8")
    val Search = icon("search", "M4 10a6 6 0 1 0 12 0a6 6 0 1 0-12 0", "M15 15l6 6")
    val Sort = icon("sort", "M4 6h16M4 12h11M4 18h6")
    val Download = icon("download", "M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4")
    val Left = icon("left", "M15 5l-7 7 7 7")
    val Right = icon("right", "M9 5l7 7-7 7")
    val Copy = icon("copy", "M10 8h9a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-9a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2z", "M16 8V3H3v13h5")
}
