package io.github.xtratter.netstat.capture

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

internal data class RecoveredPcap(val packets: Int, val payloadBytes: Long)

// Only our own little-endian, raw-IP PCAP format is stored in the private archive.
internal fun recoverPcapPrefix(file: File): RecoveredPcap? {
    if (!file.isFile) return null
    return RandomAccessFile(file, "rw").use { input ->
        val size = input.length()
        if (size < 24) return null
        val header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
        input.readFully(header.array())
        if (header.getInt(0) != 0xa1b2c3d4.toInt() || header.getShort(4).toInt() != 2 ||
            header.getShort(6).toInt() != 4 || header.getInt(16) != 65535 || header.getInt(20) != 101
        ) return null

        val record = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
        var end = 24L
        var packets = 0
        var bytes = 0L
        while (end + 16 <= size) {
            input.seek(end)
            input.readFully(record.array())
            val captured = record.getInt(8)
            if (captured !in 1..65535 || captured != record.getInt(12) ||
                record.getInt(4) !in 0..999_999 || end + 16 + captured > size
            ) break
            end += 16 + captured
            packets++
            bytes += captured
        }
        if (end < size) {
            input.setLength(end)
            input.fd.sync()
        }
        RecoveredPcap(packets, bytes)
    }
}
