package io.github.xtratter.netstat.inspect

import io.github.xtratter.netstat.capture.CapturedTcpSegment
import io.github.xtratter.netstat.capture.ConnectionKey
import io.github.xtratter.netstat.capture.Endpoint
import io.github.xtratter.netstat.capture.tcpSegment
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

internal data class TcpPiece(val sequence: Int, val bytes: ByteArray)
internal data class TcpStream(val bytes: ByteArray, val damaged: Boolean, val closed: Boolean)

// The capture is bounded to 8 MiB, well within the half-range of a TCP sequence number.
internal fun assembleTcp(pieces: List<TcpPiece>, start: Int?, finish: Int?): TcpStream {
    val anchor = start ?: pieces.firstOrNull()?.sequence ?: finish ?: return TcpStream(ByteArray(0), false, false)
    val sorted = pieces.sortedBy { it.sequence - anchor }
    val origin = if (start == null) sorted.firstOrNull()?.sequence ?: anchor else start
    val result = ByteArray(pieces.sumOf { it.bytes.size })
    var length = 0
    var damaged = false
    for (segment in sorted) {
        val offset = segment.sequence - origin
        if (offset > length) {
            damaged = true
            break
        }
        val skip = (-offset.toLong()).coerceIn(0, segment.bytes.size.toLong()).toInt()
        val destination = maxOf(0, offset)
        val overlap = minOf(length - destination, segment.bytes.size - skip)
        for (i in 0 until overlap) {
            if (segment.bytes[skip + i] != result[destination + i]) damaged = true
        }
        val tail = skip + overlap
        if (tail < segment.bytes.size) {
            segment.bytes.copyInto(result, length, tail)
            length += segment.bytes.size - tail
        }
    }
    if (finish != null && finish - origin != length) damaged = true
    return TcpStream(result.copyOf(length), damaged, finish != null && !damaged)
}

internal data class HttpDialogues(val exchanges: List<HttpExchange>, val limitReached: Boolean)

internal suspend fun PacketFile.httpDialogues(connection: ConnectionKey?): HttpDialogues {
    val sessions = mutableListOf<TcpSession>()
    val current = mutableMapOf<ConnectionKey, TcpSession>()
    var limited = false
    for (index in 0 until count) {
        if (index % 256 == 0) currentCoroutineContext().ensureActive()
        val segment = tcpSegment(bytes(index)) ?: continue
        val (first, second) = if (segment.source <= segment.destination)
            segment.source to segment.destination else segment.destination to segment.source
        val key = ConnectionKey(6, first, second)
        if (connection != null && key != connection) continue
        val session = current[key]
        val active = if (session == null || session.newHandshake(segment)) {
            if (sessions.size == 2048) {
                current.remove(key)
                limited = true
                continue
            }
            TcpSession(first, second).also { current[key] = it; sessions.add(it) }
        } else session
        active.add(segment)
    }
    val budget = HttpBudget()
    val exchanges = buildList {
        for (session in sessions) {
            currentCoroutineContext().ensureActive()
            if (budget.full) {
                limited = true
                break
            }
            addAll(session.http(budget))
        }
    }
    return HttpDialogues(exchanges, limited || budget.limited)
}

private class TcpSession(private val first: Endpoint, private val second: Endpoint) {
    private val forward = TcpDirection()
    private val reverse = TcpDirection()
    private var initiator: Endpoint? = null
    private var reset = false

    private fun direction(from: Endpoint) = if (from == first) forward else reverse

    fun newHandshake(segment: CapturedTcpSegment): Boolean {
        if (segment.flags and 0x12 != 2) return false
        val sequence = direction(segment.source).start
        return reset || (forward.finish != null && reverse.finish != null) ||
            (sequence != null && sequence != segment.sequence + 1) ||
            (sequence == null && (forward.pieces.isNotEmpty() || reverse.pieces.isNotEmpty()))
    }

    fun add(segment: CapturedTcpSegment) {
        val side = direction(segment.source)
        val syn = segment.flags and 2 != 0
        val start = segment.sequence + if (syn) 1 else 0
        if (syn) {
            side.start = start
            initiator = if (segment.flags and 0x10 == 0) segment.source else segment.destination
        }
        if (segment.payload.isNotEmpty()) side.pieces.add(TcpPiece(start, segment.payload))
        if (segment.flags and 1 != 0) side.finish = start + segment.payload.size
        if (segment.flags and 4 != 0) reset = true
    }

    fun http(budget: HttpBudget): List<HttpExchange> {
        if (forward.pieces.isEmpty() && reverse.pieces.isEmpty()) return emptyList()
        val a = forward.assemble()
        val b = reverse.assemble()
        val fromFirst = when {
            isHttpRequest(a.bytes) -> true
            isHttpRequest(b.bytes) -> false
            isHttpResponse(b.bytes) -> true
            isHttpResponse(a.bytes) -> false
            else -> return emptyList()
        }
        val client = if (fromFirst) first else second
        val server = if (fromFirst) second else first
        return parseHttp(client, server, if (fromFirst) a else b, if (fromFirst) b else a, budget,
            uncertainStart = initiator != null && initiator != client)
    }
}

private class TcpDirection {
    val pieces = mutableListOf<TcpPiece>()
    var start: Int? = null
    var finish: Int? = null

    fun assemble() = assembleTcp(pieces, start, finish)
}
