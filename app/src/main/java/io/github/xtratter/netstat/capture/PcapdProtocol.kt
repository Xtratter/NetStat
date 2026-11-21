package io.github.xtratter.netstat.capture

import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

internal data class PcapdFrame(
    val seconds: Long,
    val micros: Int,
    val drops: Long,
    val uid: Int?,
    val transmitted: Boolean,
    val bytes: ByteArray,
)

internal fun readPcapdFrame(input: InputStream): PcapdFrame? {
    val first = input.read()
    if (first == -1) return null
    val header = ByteArray(32)
    header[0] = first.toByte()
    val stream = DataInputStream(input)
    stream.readFully(header, 1, header.size - 1)

    val fields = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
    val seconds = fields.long
    val micros = fields.long
    val drops = fields.int.toLong() and 0xFFFF_FFFFL
    val uid = fields.int
    val length = fields.short.toInt() and 0xFFFF
    val link = fields.short.toInt() and 0xFFFF
    val flags = fields.get().toInt() and 0xFF
    val interfaceIndex = fields.get().toInt() and 0xFF
    if (seconds !in 0L..0xFFFF_FFFFL || micros !in 0L..999_999L || uid < -1 ||
        length == 0 || link != 12 || flags !in 0..1 || interfaceIndex != 0
    ) {
        throw IOException("Invalid pcapd ARM64 frame header")
    }

    val bytes = ByteArray(length)
    stream.readFully(bytes)
    return PcapdFrame(seconds, micros.toInt(), drops, uid.takeUnless { it == -1 }, flags == 1, bytes)
}

internal class RawPcapWriter(private val output: OutputStream, private val limit: Long) {
    var completedBytes = 24L
        private set

    init {
        require(limit >= completedBytes)
        val header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0xA1B2C3D4.toInt()).putShort(2).putShort(4).putInt(0).putInt(0)
            .putInt(65535).putInt(101)
        output.write(header.array())
    }

    fun append(frame: PcapdFrame): Boolean {
        val length = frame.bytes.size
        val nextSize = completedBytes + 16 + length
        if (nextSize > limit) return false
        val header = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(frame.seconds.toInt()).putInt(frame.micros).putInt(length).putInt(length)
        output.write(header.array())
        output.write(frame.bytes)
        completedBytes = nextSize
        return true
    }
}

internal fun connectionOf(packet: ByteArray): ConnectionKey? {
    val view = ipView(packet) ?: return null

    val ports = when {
        view.fragmentOffset -> null
        view.protocol == 6 -> {
            if (view.offset + 20 > view.end) return null
            val headerLength = (packet.unsigned(view.offset + 12) shr 4) * 4
            if (headerLength < 20 || view.offset + headerLength > view.end) return null
            packet.unsignedShort(view.offset) to packet.unsignedShort(view.offset + 2)
        }
        view.protocol == 17 -> {
            if (view.offset + 8 > view.end) return null
            val udpLength = packet.unsignedShort(view.offset + 4)
            if (udpLength < 8 || (!view.moreFragments && view.offset + udpLength > view.end)) return null
            packet.unsignedShort(view.offset) to packet.unsignedShort(view.offset + 2)
        }
        else -> null
    }

    val source = Endpoint(view.source, ports?.first)
    val destination = Endpoint(view.destination, ports?.second)
    return if (source <= destination) ConnectionKey(view.protocol, source, destination)
    else ConnectionKey(view.protocol, destination, source)
}

internal data class CapturedTcpSegment(
    val source: Endpoint,
    val destination: Endpoint,
    val sequence: Int,
    val flags: Int,
    val payload: ByteArray,
)

internal fun tcpSegment(packet: ByteArray): CapturedTcpSegment? {
    val ip = ipView(packet) ?: return null
    if (ip.protocol != 6 || ip.fragmentOffset || ip.moreFragments || ip.offset + 20 > ip.end) return null
    val offset = ip.offset
    val dataStart = offset + (packet.unsigned(offset + 12) ushr 4) * 4
    if (dataStart < offset + 20 || dataStart > ip.end) return null
    val flags = packet.unsigned(offset + 13)
    if (dataStart == ip.end && flags and 7 == 0) return null
    val sequence = ByteBuffer.wrap(packet, offset + 4, 4).int
    return CapturedTcpSegment(
        Endpoint(ip.source, packet.unsignedShort(offset)),
        Endpoint(ip.destination, packet.unsignedShort(offset + 2)),
        sequence, flags, packet.copyOfRange(dataStart, ip.end),
    )
}

private fun ipView(packet: ByteArray) = when (packet.firstOrNull()?.toInt()?.and(0xF0)) {
    0x40 -> ipv4(packet)
    0x60 -> ipv6(packet)
    else -> null
}

private data class IpView(
    val source: String,
    val destination: String,
    val protocol: Int,
    val offset: Int,
    val end: Int,
    val fragmentOffset: Boolean,
    val moreFragments: Boolean,
)

private fun ipv4(packet: ByteArray): IpView? {
    if (packet.size < 20) return null
    val offset = (packet.unsigned(0) and 0xF) * 4
    val end = packet.unsignedShort(2)
    if (offset < 20 || end < offset || end > packet.size) return null
    val fragment = packet.unsignedShort(6)
    return IpView(
        InetAddress.getByAddress(packet.copyOfRange(12, 16)).hostAddress.orEmpty(),
        InetAddress.getByAddress(packet.copyOfRange(16, 20)).hostAddress.orEmpty(),
        packet.unsigned(9), offset, end, fragment and 0x1FFF != 0, fragment and 0x2000 != 0,
    )
}

private fun ipv6(packet: ByteArray): IpView? {
    if (packet.size < 40) return null
    val end = 40 + packet.unsignedShort(4)
    if (end > packet.size) return null
    val source = Inet6Address.getByAddress(null, packet.copyOfRange(8, 24), -1).hostAddress.orEmpty()
    val destination = Inet6Address.getByAddress(null, packet.copyOfRange(24, 40), -1).hostAddress.orEmpty()
    var protocol = packet.unsigned(6)
    var offset = 40
    var moreFragments = false
    repeat(8) {
        when (protocol) {
            0, 43, 60, 51 -> {
                if (offset + 2 > end) return null
                val length = packet.unsigned(offset + 1)
                val extensionBytes = if (protocol == 51) (length + 2) * 4 else (length + 1) * 8
                if (offset + extensionBytes > end) return null
                protocol = packet.unsigned(offset)
                offset += extensionBytes
            }
            44 -> {
                if (offset + 8 > end) return null
                val fragment = packet.unsignedShort(offset + 2)
                protocol = packet.unsigned(offset)
                offset += 8
                moreFragments = fragment and 1 != 0
                if (fragment and 0xFFF8 != 0) {
                    return IpView(source, destination, protocol, offset, end, true, moreFragments)
                }
            }
            else -> return IpView(source, destination, protocol, offset, end, false, moreFragments)
        }
    }
    return null
}

private fun ByteArray.unsigned(index: Int): Int = this[index].toInt() and 0xFF
private fun ByteArray.unsignedShort(index: Int): Int = (unsigned(index) shl 8) or unsigned(index + 1)
