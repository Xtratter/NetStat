package io.github.xtratter.netstat.inspect

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import io.github.xtratter.netstat.capture.connectionOf
import org.junit.Assert.*
import org.junit.Test

class PacketFileTest {
    private val raw get() = File("../fixtures/dns-http.pcap").takeIf { it.exists() }?.readBytes()
        ?: File("fixtures/dns-http.pcap").readBytes()

    @Test fun everyPcapngBlockHasCorrectLengthsTimesAndPayload() {
        val capture = PacketFile.parse(raw)
        assertEquals(9, capture.count)
        assertEquals(2, capture.select(connectionOf(capture.bytes(0))).size)
        val output = ByteArrayOutputStream()
        capture.export(output)
        val blocks = ByteBuffer.wrap(output.toByteArray()).order(ByteOrder.LITTLE_ENDIAN)
        val original = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        var originalOffset = 24
        var frame = 0
        while (blocks.hasRemaining()) {
            val start = blocks.position()
            val type = blocks.int
            val length = blocks.int
            assertEquals(0, length % 4)
            when (type) {
                0x0a0d0d0a -> assertEquals(0x1a2b3c4d, blocks.int)
                1 -> assertEquals(101, blocks.short.toInt())
                6 -> {
                    assertEquals(0, blocks.int)
                    val timestamp = (blocks.int.toLong() shl 32) or (blocks.int.toLong() and 0xffffffffL)
                    assertEquals((original.getInt(originalOffset).toLong() and 0xffffffffL) * 1_000_000 +
                        original.getInt(originalOffset + 4), timestamp)
                    val size = blocks.int
                    assertEquals(original.getInt(originalOffset + 8), size)
                    assertEquals(original.getInt(originalOffset + 12), blocks.int)
                    val payload = ByteArray(size).also(blocks::get)
                    assertArrayEquals(raw.copyOfRange(originalOffset + 16, originalOffset + 16 + size), payload)
                    originalOffset += 16 + size
                    frame++
                }
                else -> fail("Unexpected block")
            }
            blocks.position(start + length - 4)
            assertEquals(length, blocks.int)
        }
        assertEquals(9, frame)
        assertEquals(raw.size, originalOffset)
    }

    @Test fun truncationAndInvalidLinkTypeFailBeforeExport() {
        assertThrows(IOException::class.java) { PacketFile.parse(raw.copyOf(raw.size - 1)) }
        val wrong = raw.also { it[20] = 1 }
        assertThrows(IOException::class.java) { PacketFile.parse(wrong) }
        assertEquals(0, PacketFile.parse(raw.copyOf(24)).count)
    }
}
