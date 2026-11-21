package io.github.xtratter.netstat.inspect

import io.github.xtratter.netstat.capture.CAPTURE_BYTES_LIMIT
import io.github.xtratter.netstat.capture.ConnectionKey
import io.github.xtratter.netstat.capture.connectionOf
import java.io.IOException
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** A snapshot of one completed, size-limited NetStat recording. Only offsets are indexed. */
internal class PacketFile private constructor(
    private val data: ByteArray,
    private val offsets: IntArray,
) {
    private val input = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
    val count: Int get() = offsets.size

    fun capturedSize(index: Int) = input.getInt(offsets[index] + 8)
    fun originalSize(index: Int) = input.getInt(offsets[index] + 12)
    fun timestampMicros(index: Int): Long {
        val at = offsets[index]
        return (input.getInt(at).toLong() and 0xffffffffL) * 1_000_000 + input.getInt(at + 4)
    }
    fun bytes(index: Int): ByteArray {
        val start = offsets[index] + 16
        return data.copyOfRange(start, start + capturedSize(index))
    }

    fun select(connection: ConnectionKey?): IntArray {
        if (connection == null) return IntArray(count) { it }
        val result = IntArray(count)
        var found = 0
        for (index in offsets.indices) {
            if (connectionOf(bytes(index)) == connection) result[found++] = index
        }
        return result.copyOf(found)
    }

    fun export(destination: OutputStream) {
        // One RAW interface. PCAPNG defaults to microsecond timestamps on the IDB.
        val header = ByteBuffer.allocate(48).order(ByteOrder.LITTLE_ENDIAN)
        header.putInt(0x0a0d0d0a).putInt(28).putInt(0x1a2b3c4d)
            .putShort(1).putShort(0).putLong(-1).putInt(28)
        header.putInt(1).putInt(20).putShort(101).putShort(0).putInt(65535).putInt(20)
        destination.write(header.array())
        val prefix = ByteBuffer.allocate(28).order(ByteOrder.LITTLE_ENDIAN)
        val padding = ByteArray(3)
        for (index in offsets.indices) {
            val size = capturedSize(index)
            val pad = (4 - size % 4) % 4
            val blockLength = 32 + size + pad
            val timestamp = timestampMicros(index)
            prefix.clear()
            prefix.putInt(6).putInt(blockLength).putInt(0)
                .putInt((timestamp ushr 32).toInt()).putInt(timestamp.toInt())
                .putInt(size).putInt(originalSize(index))
            destination.write(prefix.array())
            destination.write(data, offsets[index] + 16, size)
            destination.write(padding, 0, pad)
            destination.write(prefix.array(), 4, 4)
        }
    }

    companion object {
        fun parse(data: ByteArray): PacketFile {
            val b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
            if (data.size < 24 || data.size > CAPTURE_BYTES_LIMIT || b.getInt(0) != 0xa1b2c3d4.toInt() ||
                b.getShort(4).toInt() != 2 || b.getShort(6).toInt() != 4 ||
                b.getInt(16) != 65535 || b.getInt(20) != 101
            ) throw IOException("Invalid NetStat PCAP header")
            var index = IntArray(128)
            var count = 0
            var offset = 24
            while (offset < data.size) {
                if (data.size - offset < 16) throw IOException("Incomplete packet header")
                val captured = b.getInt(offset + 8)
                if (captured !in 1..65535 || b.getInt(offset + 4) !in 0..999999 ||
                    b.getInt(offset + 12) < captured || captured > data.size - offset - 16
                ) throw IOException("Invalid PCAP packet at $offset")
                if (count == index.size) index = index.copyOf(index.size * 2)
                index[count++] = offset
                offset += 16 + captured
            }
            return PacketFile(data, index.copyOf(count))
        }
    }
}
