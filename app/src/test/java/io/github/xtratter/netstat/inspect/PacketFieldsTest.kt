package io.github.xtratter.netstat.inspect

import kotlin.random.Random
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketFieldsTest {
    @Test
    fun ipv4UdpDnsUsesAbsoluteRangesIncludingCompressedNames() {
        val question = hex("076578616d706c6504746573740000010001")
        val answer = hex("c00c000500010000003c0002c00c")
        val dns = hex("123481800001000100000000") + question + answer
        val actual = packetLayers(ipv4(17, udp(dns)))

        assertEquals(listOf("IPv4", "UDP", "DNS"), actual.map(PacketLayer::name))
        assertEquals(PacketField("Source", "192.0.2.10", 12, 16), actual[0].field("Source"))
        assertEquals(PacketField("Destination port", "53", 22, 24), actual[1].field("Destination port"))
        assertEquals(PacketField("Transaction ID", "0x1234", 28, 30), actual[2].field("Transaction ID"))
        assertEquals(PacketField("Question 1 name", "example.test", 40, 54), actual[2].field("Question 1 name"))
        assertEquals(PacketField("Answer 1 name", "example.test", 58, 60), actual[2].field("Answer 1 name"))
        assertEquals(PacketField("Answer 1 data", "example.test", 70, 72), actual[2].field("Answer 1 data"))
    }

    @Test
    fun ipv6ExtensionMovesTcpHeaderAndPortRanges() {
        val extension = hex("0600000000000000")
        val tcp = hex("c350005001020304000000005002100000000000")
        val packet = ipv6(0, extension + tcp)
        val actual = packetLayers(packet)

        assertEquals(listOf("IPv6", "Hop-by-Hop options", "TCP"), actual.map(PacketLayer::name))
        assertEquals(PacketField("Next header", "TCP (6)", 40, 41), actual[1].field("Next header"))
        assertEquals(PacketField("Source port", "50000", 48, 50), actual[2].field("Source port"))
        assertEquals(PacketField("Sequence number", "16909060", 52, 56), actual[2].field("Sequence number"))
        assertEquals(PacketField("Flags", "SYN", 60, 62), actual[2].field("Flags"))
    }

    @Test
    fun tcpDnsCompressionIsRelativeToMessageAfterLengthPrefix() {
        val question = hex("01610000010001")
        val answer = hex("c00c000100010000003c0004c0000201")
        val dns = hex("abcd81800001000100000000") + question + answer
        val tcp = hex("c350003500000001000000005018100000000000")
        val packet = ipv4(6, tcp + u16(dns.size) + dns)

        val actual = packetLayers(packet)
        assertEquals(listOf("IPv4", "TCP", "DNS"), actual.map(PacketLayer::name))
        assertEquals(PacketField("TCP message length", dns.size.toString(), 40, 42), actual[2].field("TCP message length"))
        assertEquals(PacketField("Answer 1 name", "a", 61, 63), actual[2].field("Answer 1 name"))
        assertEquals(PacketField("Answer 1 data", "192.0.2.1", 73, 77), actual[2].field("Answer 1 data"))
    }

    @Test
    fun nonInitialFragmentsNeverInterpretPayloadAsTransportHeader() {
        val opaque = udp(hex("123401000000000000000000"))
        val v4 = ipv4(17, opaque, fragment = 1)
        val v6 = ipv6(44, hex("1100000800000001") + opaque)

        assertEquals(listOf("IPv4", "Fragment payload"), packetLayers(v4).map(PacketLayer::name))
        val actual = packetLayers(v6)
        assertEquals(listOf("IPv6", "IPv6 fragment", "Fragment payload"), actual.map(PacketLayer::name))
        assertEquals(PacketField("Fragment offset", "8 bytes", 42, 44), actual[1].field("Fragment offset"))
    }

    @Test
    fun firstUdpFragmentShowsHeaderButSkipsIncompleteDns() {
        val dns = hex("123481800001000100000000")
        val firstFragment = ipv4(17, udp(dns, declaredLength = 999), fragment = 0x2000)

        assertEquals(listOf("IPv4", "UDP"), packetLayers(firstFragment).map(PacketLayer::name))
    }

    @Test
    fun dnsPointerCyclesAndOutOfMessageTargetsAreRejected() {
        val settings = hex("123401000001000000000000")
        val badNames = listOf(hex("c00c"), hex("c0ff"), hex("0161c00c"))
        for (name in badNames) {
            val actual = packetLayers(ipv4(17, udp(settings + name + hex("00010001")))).last()

            assertEquals("DNS", actual.name)
            assertTrue(actual.fields.any { it.name == "Status" && "name" in it.value })
            assertFalse(actual.fields.any { it.name == "Question 1 class" })
        }
    }

    @Test
    fun dnsNameDataIsBoundedByItsResourceLength() {
        val question = hex("01610000010001")
        val answer = hex("c00c000500010000003c0001c00c")
        val dns = hex("123481800001000100000000") + question + answer

        val field = packetLayers(ipv4(17, udp(dns))).last().field("Answer 1 data")
        assertEquals(PacketField("Answer 1 data", "Invalid DNS name", 59, 60), field)
    }

    @Test
    fun udpAndIpDeclaredLengthsLimitDissectionAndUnknownProtocolsAreVisible() {
        val dns = hex("123401000000000000000000")
        val trailing = ipv4(17, udp(dns, declaredLength = 8))
        val ipv4Padding = ipv4(17, udp(dns), declaredLength = 28)
        val unknown = ipv4(253, hex("00112233"))

        for (packet in listOf(trailing, ipv4Padding)) assertFalse(packetLayers(packet).any { it.name == "DNS" })
        val unknownLayers = packetLayers(unknown)
        assertEquals(listOf("IPv4", "Unknown IP payload"), unknownLayers.map(PacketLayer::name))
        assertEquals(PacketField("Data", "4 bytes", 20, 24), unknownLayers.last().field("Data"))
    }

    @Test
    fun emptyTruncatedAndArbitraryPacketsNeverExposeBytesOutsideInput() {
        val packet = ipv4(6, hex("c350003500000001000000005018100000000000"))
        val partialCases = (0 until packet.size).map { packet.copyOf(it) }
        val random = Random(53)
        val arbitraryCases = List(500) { random.nextBytes(random.nextInt(0, 256)) }

        for (bytes in partialCases + arbitraryCases) {
            val layers = packetLayers(bytes)
            assertTrue(layers.isNotEmpty())
            for (field in layers.flatMap(PacketLayer::fields)) {
                assertTrue(field.start in 0..bytes.size)
                assertTrue(field.end in field.start..bytes.size)
            }
        }
        assertEquals("Unknown packet", packetLayers(hex("0080")).single().name)
        assertTrue(packetLayers(packet.copyOf(10)).first().fields.any { "Truncated" in it.value })
    }

    private fun PacketLayer.field(name: String) = fields.single { it.name == name }

    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun u16(value: Int) = byteArrayOf((value ushr 8).toByte(), value.toByte())

    private fun ipv4(protocol: Int, payload: ByteArray, fragment: Int = 0, declaredLength: Int = 20 + payload.size) =
        hex("4500") + u16(declaredLength) + hex("0123") + u16(fragment) +
            byteArrayOf(64, protocol.toByte()) + hex("0000c000020ac6336414") + payload

    private fun ipv6(next: Int, payload: ByteArray) =
        hex("60000000") + u16(payload.size) + byteArrayOf(next.toByte(), 64) +
            hex("20010db800000000000000000000000120010db8000000000000000000000002") + payload

    private fun udp(payload: ByteArray, declaredLength: Int = 8 + payload.size) =
        hex("c3500035") + u16(declaredLength) + hex("0000") + payload
}
