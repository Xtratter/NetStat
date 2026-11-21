package io.github.xtratter.netstat.capture

internal enum class AcceptResult { STORED, SKIPPED, LIMIT }

internal class CaptureLedger(private val config: CaptureConfig, private val writer: RawPcapWriter) {
    private val connections = mutableMapOf<ConnectionKey, ConnectionCounters>()
    private var packets = 0
    private var payloadBytes = 0L
    private var uidExcluded = 0
    private var malformed = 0
    private var unlistedPackets = 0
    private var drops: Long? = null

    fun accept(frame: PcapdFrame): AcceptResult {
        drops = maxOf(drops ?: 0L, frame.drops)
        if (config.uid != null && frame.uid != config.uid) {
            uidExcluded++
            return AcceptResult.SKIPPED
        }
        val key = connectionOf(frame.bytes)
        if (key == null) {
            malformed++
            return AcceptResult.SKIPPED
        }
        if (!writer.append(frame)) return AcceptResult.LIMIT

        packets++
        payloadBytes += frame.bytes.size
        val counters = connections[key] ?: if (connections.size < CAPTURE_CONNECTION_LIMIT) {
            ConnectionCounters().also { connections[key] = it }
        } else {
            unlistedPackets++
            return AcceptResult.STORED
        }
        counters.add(frame)
        return AcceptResult.STORED
    }

    fun snapshot() = CaptureSnapshot(
        packets, payloadBytes, uidExcluded, malformed, unlistedPackets, drops,
        connections.map { (key, counters) -> counters.snapshot(key) }
            .sortedByDescending(ConnectionSummary::lastSeenMillis),
    )
}

private class ConnectionCounters {
    private var firstSeen = Long.MAX_VALUE
    private var lastSeen = 0L
    private var received = 0L
    private var sent = 0L
    private var packets = 0
    private var knownUid: Int? = null
    private var unknownPackets = 0
    private var conflicted = false

    fun add(frame: PcapdFrame) {
        val millis = frame.seconds * 1000 + frame.micros / 1000
        firstSeen = minOf(firstSeen, millis)
        lastSeen = maxOf(lastSeen, millis)
        if (frame.transmitted) sent += frame.bytes.size else received += frame.bytes.size
        packets++
        when {
            frame.uid == null -> unknownPackets++
            knownUid == null -> knownUid = frame.uid
            frame.uid != knownUid -> conflicted = true
        }
    }

    fun snapshot(key: ConnectionKey): ConnectionSummary {
        val confidence = when {
            conflicted -> UidConfidence.CONFLICT
            knownUid == null -> UidConfidence.UNKNOWN
            unknownPackets > 0 -> UidConfidence.PARTIAL
            else -> UidConfidence.KNOWN
        }
        return ConnectionSummary(
            key, firstSeen, lastSeen, received, sent, packets,
            knownUid.takeUnless { conflicted }, unknownPackets, confidence,
        )
    }
}
