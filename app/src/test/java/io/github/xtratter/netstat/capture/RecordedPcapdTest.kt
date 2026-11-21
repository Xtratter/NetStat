package io.github.xtratter.netstat.capture

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Test

class RecordedPcapdTest {
    @Test
    fun pinnedArm64HelperEventsRestoreTheReferencePcap() {
        val output = ByteArrayOutputStream()
        val ledger = CaptureLedger(CaptureConfig("lo", null), RawPcapWriter(output, 16_384))
        val sample = checkNotNull(javaClass.getResourceAsStream("/pcapd-sample.events"))
        sample.use { input ->
            while (true) {
                val frame = readPcapdFrame(input) ?: break
                assertEquals(AcceptResult.STORED, ledger.accept(frame))
            }
        }
        val result = ledger.snapshot()
        assertEquals(9, result.packets)
        assertEquals(2, result.connections.size)
        assertEquals(9, result.connections.sumOf { it.unknownPackets.toInt() })
        // Official arm64 pcapd replay of fixtures/dns-http.pcap, including both TCP directions.
        val digest = MessageDigest.getInstance("SHA-256").digest(output.toByteArray())
        val hex = digest.joinToString("") { "%02x".format(it) }
        assertEquals("7c37ff91dc0f381c377ec5cbe92eac49e28d092f25ae9ecfec355ec6e6772d5a", hex)
    }
}
