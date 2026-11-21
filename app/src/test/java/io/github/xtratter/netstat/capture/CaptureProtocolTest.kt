package io.github.xtratter.netstat.capture

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class CaptureProtocolTest {
    private val payload = ipv4Udp()

    @Test
    fun arm64HeaderReadsUnsignedDropsAndTheUnknownUidSentinel() {
        val input = ByteArrayInputStream(record(payload, -1, flags = 1))
        val frame = checkNotNull(readPcapdFrame(input))

        assertEquals(1_795_219_200L, frame.seconds)
        assertEquals(25, frame.micros)
        assertEquals(4_294_967_295L, frame.drops)
        assertNull(frame.uid)
        assertTrue(frame.transmitted)
        assertTrue(payload.contentEquals(frame.bytes))
        assertNull(readPcapdFrame(input))
    }

    @Test
    fun partialOrUnexpectedRecordsFailBeforeBeingReturned() {
        val wrongDatalink = record(payload, 10001, link = 1)
        val wrongInterface = record(payload, 10001, interfaceId = 1)
        val partial = record(payload, 10001).dropLast(1).toByteArray()
        for (invalid in listOf(wrongDatalink, wrongInterface, partial)) {
            assertThrows(IOException::class.java) { readPcapdFrame(ByteArrayInputStream(invalid)) }
        }
    }

    @Test
    fun selectedUidIsCheckedBeforeIndexingOrWritingAnyPacket() {
        val output = ByteArrayOutputStream()
        val ledger = CaptureLedger(CaptureConfig("tun0", 10001), RawPcapWriter(output, 200))

        assertEquals(AcceptResult.SKIPPED, ledger.accept(frame(null)))
        assertEquals(AcceptResult.SKIPPED, ledger.accept(frame(10002)))
        assertEquals(AcceptResult.STORED, ledger.accept(frame(10001)))

        val contents = output.toByteArray()
        assertEquals(24 + 16 + payload.size, contents.size)
        assertEquals(101, ByteBuffer.wrap(contents, 20, 4).order(ByteOrder.LITTLE_ENDIAN).int)
        assertEquals(1, ledger.snapshot().packets)
        assertEquals(2, ledger.snapshot().uidExcluded)
        assertEquals(10001, ledger.snapshot().connections.single().uid)
    }

    @Test
    fun oppositeDirectionsShareAConnectionAndUnknownPacketsLowerAttribution() {
        val ledger = CaptureLedger(CaptureConfig("tun0", null), RawPcapWriter(ByteArrayOutputStream(), 500))

        ledger.accept(frame(10001))
        ledger.accept(frame(null, ipv4Udp(reverse = true), transmitted = false))
        val partial = ledger.snapshot().connections.single()
        assertEquals(2, partial.packets)
        assertEquals(1, partial.unknownPackets)
        assertEquals(UidConfidence.PARTIAL, partial.confidence)
        assertEquals(payload.size.toLong(), partial.sent)
        assertEquals(payload.size.toLong(), partial.received)
        assertEquals(49000, partial.key.first.port)
        assertEquals(53, partial.key.second.port)

        ledger.accept(frame(10002))
        assertEquals(UidConfidence.CONFLICT, ledger.snapshot().connections.single().confidence)
    }

    @Test
    fun truncatedIpHeaderRemainsInspectableWithoutClaimingAConnection() {
        val output = ByteArrayOutputStream()
        val ledger = CaptureLedger(CaptureConfig("tun0", null), RawPcapWriter(output, 200))
        assertEquals(AcceptResult.STORED, ledger.accept(frame(null, byteArrayOf(0x45))))
        assertEquals(1, ledger.snapshot().packets)
        assertEquals(1, ledger.snapshot().malformed)
        assertTrue(ledger.snapshot().connections.isEmpty())
        assertEquals(0x45, output.toByteArray().last().toInt())
    }

    @Test
    fun sizeLimitDoesNotWriteAPartialRecord() {
        val output = ByteArrayOutputStream()
        val exactLimit = 24L + 16 + payload.size
        val ledger = CaptureLedger(CaptureConfig("lo", null), RawPcapWriter(output, exactLimit))

        assertEquals(AcceptResult.STORED, ledger.accept(frame(10001)))
        assertEquals(AcceptResult.LIMIT, ledger.accept(frame(10001)))
        assertEquals(exactLimit, output.size().toLong())
        assertEquals(1, ledger.snapshot().packets)
    }

    @Test
    fun ipv6ExtensionHeaderPrecedesUdpPorts() {
        val packet = ByteBuffer.allocate(56).apply {
            put(0, 0x60)
            putShort(4, 16)
            put(6, 0)
            put(23, 1)
            put(39, 2)
            put(40, 17)
            putShort(48, 40000.toShort())
            putShort(50, 53)
            putShort(52, 8)
        }.array()

        val key = checkNotNull(connectionOf(packet))
        assertEquals(17, key.protocol)
        assertEquals(40000, key.first.port)
        assertEquals(53, key.second.port)
        assertNull(connectionOf(packet.copyOf(51)))
    }

    @Test
    fun configAcceptsOneLiteralInterfaceAndDisallowsAutomaticAndPathInputs() {
        assertTrue(CaptureConfig.isValidInterface("rmnet_data0"))
        for (unsafe in listOf("@inet", "any", "-x", "tun0 wlan0", "../tun0", "tun0;id")) {
            assertThrows(IllegalArgumentException::class.java) { CaptureConfig(unsafe, null) }
        }
    }

    private fun frame(uid: Int?, bytes: ByteArray = payload, transmitted: Boolean = true) =
        PcapdFrame(1_795_219_200L, 25, 0, uid, transmitted, bytes)

    private fun record(bytes: ByteArray, uid: Int, flags: Int = 0, link: Int = 12, interfaceId: Int = 0) =
        ByteBuffer.allocate(32 + bytes.size).order(ByteOrder.LITTLE_ENDIAN).apply {
            putLong(1_795_219_200L)
            putLong(25L)
            putInt(-1)
            putInt(uid)
            putShort(bytes.size.toShort())
            putShort(link.toShort())
            put(flags.toByte())
            put(interfaceId.toByte())
            putShort(0x1234)
            put(bytes)
        }.array()

    private fun ipv4Udp(reverse: Boolean = false) =
        ByteBuffer.allocate(30).apply {
            put(0x45)
            put(0)
            putShort(30)
            putInt(0)
            put(64)
            put(17)
            putShort(0)
            val client = byteArrayOf(10, 0, 0, 2)
            val peer = byteArrayOf(10, 0, 0, 9)
            put(if (reverse) peer else client)
            put(if (reverse) client else peer)
            putShort((if (reverse) 53 else 49000).toShort())
            putShort((if (reverse) 49000 else 53).toShort())
            putShort(10)
            putInt(0)
        }.array()
}
