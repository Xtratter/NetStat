package io.github.xtratter.netstat.usage

import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId

internal data class UsageWindow(val start: Instant, val end: Instant) {
    init {
        require(!end.isBefore(start))
    }

    fun contains(other: UsageWindow): Boolean = other.start >= start && other.end <= end
}

internal sealed interface UsagePeriod {
    fun window(now: Instant, zone: ZoneId): UsageWindow

    data object Today : UsagePeriod {
        override fun window(now: Instant, zone: ZoneId): UsageWindow =
            UsageWindow(now.atZone(zone).toLocalDate().atStartOfDay(zone).toInstant(), now)
    }

    data object LastNight : UsagePeriod {
        override fun window(now: Instant, zone: ZoneId): UsageWindow {
            var date = now.atZone(zone).toLocalDate()
            while (true) {
                val start = date.atStartOfDay(zone).toInstant()
                val end = date.atTime(7, 0).atZone(zone).withLaterOffsetAtOverlap().toInstant()
                if (end <= now && start < end) return UsageWindow(start, end)
                date = date.minusDays(1)
            }
        }
    }

    data class Custom(val bounds: UsageWindow) : UsagePeriod {
        override fun window(now: Instant, zone: ZoneId): UsageWindow = bounds
    }
}

internal enum class CustomPeriodError { MISSING_LOCAL_TIME, INVALID_ORDER, FUTURE_END }

internal sealed interface CustomPeriodResult {
    val window: UsageWindow?
        get() = (this as? Valid)?.bounds

    val error: CustomPeriodError?
        get() = (this as? Invalid)?.reason

    data class Valid(val bounds: UsageWindow) : CustomPeriodResult
    data class Invalid(val reason: CustomPeriodError) : CustomPeriodResult
}

internal fun customPeriod(
    start: LocalDateTime,
    end: LocalDateTime,
    now: Instant,
    zone: ZoneId,
    laterStart: Boolean = false,
    laterEnd: Boolean = false,
): CustomPeriodResult {
    val startInstant = start.instantIn(zone, laterStart)
    val endInstant = end.instantIn(zone, laterEnd)
    return when {
        startInstant == null || endInstant == null ->
            CustomPeriodResult.Invalid(CustomPeriodError.MISSING_LOCAL_TIME)
        endInstant <= startInstant -> CustomPeriodResult.Invalid(CustomPeriodError.INVALID_ORDER)
        endInstant > now -> CustomPeriodResult.Invalid(CustomPeriodError.FUTURE_END)
        else -> CustomPeriodResult.Valid(UsageWindow(startInstant, endInstant))
    }
}

private fun LocalDateTime.instantIn(zone: ZoneId, later: Boolean): Instant? {
    val offsets = zone.rules.getValidOffsets(this)
    val offset = if (later) offsets.lastOrNull() else offsets.firstOrNull()
    return offset?.let(::toInstant)
}
