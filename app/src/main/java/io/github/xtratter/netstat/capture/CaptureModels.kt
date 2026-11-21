package io.github.xtratter.netstat.capture

internal const val CAPTURE_BYTES_LIMIT = 8L * 1024 * 1024
internal const val CAPTURE_DURATION_SECONDS = 180
internal const val CAPTURE_CONNECTION_LIMIT = 300

internal data class CaptureConfig(val interfaceName: String, val uid: Int?, val label: String? = null) {
    init {
        require(isValidInterface(interfaceName))
        require(uid == null || uid >= 0)
    }

    companion object {
        private val interfacePattern = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}")

        fun isValidInterface(name: String) = name != "any" && interfacePattern.matches(name)
    }
}

internal data class Endpoint(val address: String, val port: Int?) : Comparable<Endpoint> {
    override fun compareTo(other: Endpoint): Int =
        compareValuesBy(this, other, Endpoint::address, Endpoint::port)
}

internal data class ConnectionKey(val protocol: Int, val first: Endpoint, val second: Endpoint)

internal enum class UidConfidence { KNOWN, PARTIAL, UNKNOWN, CONFLICT }

internal data class ConnectionSummary(
    val key: ConnectionKey,
    val firstSeenMillis: Long,
    val lastSeenMillis: Long,
    val received: Long,
    val sent: Long,
    val packets: Int,
    val uid: Int?,
    val unknownPackets: Int,
    val confidence: UidConfidence,
)

internal data class CaptureSnapshot(
    val packets: Int = 0,
    val payloadBytes: Long = 0,
    val uidExcluded: Int = 0,
    val malformed: Int = 0,
    val unlistedPackets: Int = 0,
    val drops: Long? = null,
    val connections: List<ConnectionSummary> = emptyList(),
)

internal enum class CaptureEnd {
    USER_STOPPED, TIME_LIMIT, SIZE_LIMIT, ROOT_FAILED, BAD_STREAM, STORAGE_FAILED,
    INTERRUPTED, UNAVAILABLE,
}

internal data class CaptureReport(
    val config: CaptureConfig,
    val startedMillis: Long,
    val endedMillis: Long,
    val snapshot: CaptureSnapshot,
    val reason: CaptureEnd,
    val detail: String? = null,
)

internal sealed interface CaptureState {
    data object Loading : CaptureState
    data object Idle : CaptureState
    data class Preparing(val config: CaptureConfig) : CaptureState
    data class Recording(val config: CaptureConfig, val snapshot: CaptureSnapshot) : CaptureState
    data class Stopping(val config: CaptureConfig, val snapshot: CaptureSnapshot) : CaptureState
    data class Finished(val report: CaptureReport) : CaptureState

    val active: Boolean
        get() = this is Preparing || this is Recording || this is Stopping
}
