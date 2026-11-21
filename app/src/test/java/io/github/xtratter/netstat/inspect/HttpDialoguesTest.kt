package io.github.xtratter.netstat.inspect

import io.github.xtratter.netstat.capture.Endpoint
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.GZIPOutputStream
import org.junit.Assert.*
import org.junit.Test

class HttpDialoguesTest {
    @Test fun readsTheSplitRequestAndResponseFromTheRecordedPcap() = kotlinx.coroutines.runBlocking {
        val file = File("../fixtures/dns-http.pcap").takeIf(File::exists) ?: File("fixtures/dns-http.pcap")
        val result = PacketFile.parse(file.readBytes()).httpDialogues(null)
        val exchange = result.exchanges.single()
        assertEquals("http://example.test/network-night", exchange.request?.target)
        assertEquals(200, exchange.responses.single().status)
        assertTrue(exchange.matches("network-night"))
        assertTrue(exchange.matches("hello"))
    }

    @Test fun reordersTcpAndDeduplicatesBeforeParsingWithWraparound() {
        val text = "GET /night HTTP/1.1\r\nHost: example.test\r\n\r\n".encodeToByteArray()
        val sequence = 0xfffffff8.toInt()
        val tail = TcpPiece(sequence + 15, text.copyOfRange(15, text.size))
        val stream = assembleTcp(listOf(tail, TcpPiece(sequence, text.copyOf(15)), tail), sequence, null)
        assertArrayEquals(text, stream.bytes)
        assertFalse(stream.damaged)
        assertTrue(assembleTcp(listOf(TcpPiece(sequence + 2, text)), sequence, null).damaged)
    }

    @Test fun pairsHeadInformationalAndChunkedGzipResponsesInOrder() {
        val zipped = ByteArrayOutputStream().apply {
            GZIPOutputStream(this).use { it.write("night traffic".encodeToByteArray()) }
        }.toByteArray()
        val client = "HEAD /first HTTP/1.1\r\nHost: example.test\r\n\r\nGET /second HTTP/1.1\r\n\r\n"
        val server = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\n" +
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\nContent-Type: text/plain\r\n\r\n"
        val response = server.encodeToByteArray() + "${zipped.size.toString(16)};ext=x\r\n".encodeToByteArray() +
            zipped + "\r\n0\r\nX-Test: trailer\r\n\r\n".encodeToByteArray()
        val exchanges = parse(client, TcpStream(response, false, false))
        assertEquals(listOf("/first", "/second"), exchanges.map { it.request?.path })
        assertEquals(0, exchanges[0].responses.single().body.size)
        assertEquals(listOf(103, 200), exchanges[1].responses.map { it.status })
        assertTrue(exchanges[1].matches("NIGHT TRAFFIC"))
        assertTrue(exchanges[1].matches("X-Test: trailer"))
        assertFalse(exchanges.any { it.incomplete })
    }

    @Test fun partialBodyAndConnectionCloseUseCapturedBytes() {
        val request = "GET / HTTP/1.1\r\n\r\n"
        val response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello".encodeToByteArray()
        assertTrue(parse(request, TcpStream(response, false, false)).single().incomplete)
        assertFalse(parse(request, TcpStream(response, false, true)).single().incomplete)
        val truncated = parse(request, TcpStream("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhello".encodeToByteArray(), true, false))
        assertTrue(truncated.single().incomplete)
        assertTrue(truncated.single().matches("hello"))
    }

    @Test fun keepsCapturedPipelinedRequestsWhenResponsesAreMissing() {
        val requests = "GET /one HTTP/1.1\r\n\r\nGET /two HTTP/1.1\r\n\r\n"
        val result = parse(requests, TcpStream(ByteArray(0), false, false))
        assertEquals(listOf("/one", "/two"), result.map { it.request?.path })
        assertTrue(result.all { it.incomplete })
    }

    @Test fun limitsDecodedGzipAndKeepsBinaryBodiesOutOfTextSearch() {
        val large = ByteArrayOutputStream().apply {
            GZIPOutputStream(this).use { it.write(ByteArray(300_000) { 'a'.code.toByte() }) }
        }.toByteArray()
        val requests = "GET /gzip HTTP/1.1\r\n\r\nGET /binary HTTP/1.1\r\n\r\n"
        val gzip = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: text/plain\r\nContent-Length: ${large.size}\r\n\r\n"
        val binary = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\n"
        val result = parse(requests, TcpStream(
            gzip.encodeToByteArray() + large + binary.encodeToByteArray() + "abcd".encodeToByteArray(),
            false, false,
        ))
        val text = result.first().responses.single()
        assertEquals(256 * 1024, text.text?.length)
        assertTrue(text.previewLimited)
        val opaque = result.last().responses.single()
        assertArrayEquals("abcd".encodeToByteArray(), opaque.body)
        assertFalse(result.last().matches("abcd"))
    }

    private fun parse(request: String, response: TcpStream) = parseHttp(
        Endpoint("192.0.2.10", 50000), Endpoint("192.0.2.20", 80),
        TcpStream(request.encodeToByteArray(), false, false), response, HttpBudget(),
    )
}
