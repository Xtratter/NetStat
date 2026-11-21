package io.github.xtratter.netstat.capture

import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class InterruptedFileTest {
    @Test
    fun keepsAllCompletePacketsWhenTheLastPayloadWasInterrupted() {
        val file = Files.createTempFile("netstat-capture", ".pcap").toFile()
        try {
            val payload = byteArrayOf(0x45, 0, 1)
            file.outputStream().use {
                RawPcapWriter(it, 1024).append(PcapdFrame(1, 0, 0, null, false, payload))
            }
            val complete = file.readBytes()
            file.appendBytes(complete.copyOfRange(24, complete.size - 1))
            val summary = recoverPcapPrefix(file)
            assertEquals(1, summary?.packets)
            assertEquals(3L, summary?.payloadBytes)
            assertArrayEquals(complete, file.readBytes())
            assertEquals(summary, recoverPcapPrefix(file))
        } finally {
            file.delete()
        }
    }

    @Test
    fun missingFileDoesNotCreateAnEmptyRecording() {
        val directory = Files.createTempDirectory("netstat-empty").toFile()
        try {
            assertNull(recoverPcapPrefix(File(directory, "missing.pcap")))
            assertEquals(0, directory.list()?.size)
        } finally {
            directory.delete()
        }
    }
}
