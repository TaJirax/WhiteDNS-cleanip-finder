package com.whitescan.app

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

class ReadLastLinesTest {
    private fun file(text: String) = File.createTempFile("results", ".txt").apply { deleteOnExit(); writeText(text) }

    @Test fun keepsTheLastLinesInOrder() {
        val lines = (0 until 300).map { "10.0.${it / 250}.${it % 250}:443\tworkers.dev" }
        val got = readLastLines(file(lines.joinToString("\n") + "\n").path, 100)
        assertEquals(lines.takeLast(100), got)
    }

    @Test fun growsPastTheFirstChunkAndDropsTheCutLine() {
        // 64 KB+ lines force several reads; a partial first line must never appear.
        val lines = (0 until 40).map { "$it:" + "x".repeat(5000) }
        val got = readLastLines(file(lines.joinToString("\r\n")).path, 30)
        assertEquals(lines.takeLast(30), got)
    }

    @Test fun shortFilesAndUtf8() {
        assertEquals(listOf("café", "ok"), readLastLines(file("\ncafé\n\nok").path, 100))
        assertEquals(emptyList<String>(), readLastLines(file("").path, 100))
    }
}
