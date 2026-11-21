package io.github.xtratter.netstat.usage

import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import org.junit.Assert.assertEquals
import org.junit.Test

class UsagePeriodTest {
    private val berlin = ZoneId.of("Europe/Berlin")

    @Test
    fun todayStartsAtLocalMidnightAndReactsToZoneChanges() {
        val now = Instant.parse("2026-11-21T00:35:00Z")

        assertEquals(
            UsageWindow(Instant.parse("2026-11-20T23:00:00Z"), now),
            UsagePeriod.Today.window(now, berlin),
        )
        assertEquals(
            UsageWindow(Instant.parse("2026-11-20T08:00:00Z"), now),
            UsagePeriod.Today.window(now, ZoneId.of("America/Los_Angeles")),
        )
    }

    @Test
    fun lastNightSwitchesToThisMorningAtSevenLocalTime() {
        val before = Instant.parse("2026-11-21T05:59:59Z")
        val atSeven = Instant.parse("2026-11-21T06:00:00Z")

        assertEquals(
            UsageWindow(Instant.parse("2026-11-19T23:00:00Z"), Instant.parse("2026-11-20T06:00:00Z")),
            UsagePeriod.LastNight.window(before, berlin),
        )
        assertEquals(
            UsageWindow(Instant.parse("2026-11-20T23:00:00Z"), atSeven),
            UsagePeriod.LastNight.window(atSeven, berlin),
        )
    }

    @Test
    fun lastNightUsesLocalBoundariesAcrossDaylightSavingTime() {
        val end = Instant.parse("2026-03-29T05:00:00Z")

        assertEquals(
            UsageWindow(Instant.parse("2026-03-28T23:00:00Z"), end),
            UsagePeriod.LastNight.window(end, berlin),
        )
    }

    @Test
    fun customPeriodRejectsMissingLocalTimeAndFutureEnd() {
        val now = Instant.parse("2026-03-29T05:00:00Z")
        val valid = LocalDateTime.parse("2026-03-29T01:30")
        val missing = LocalDateTime.parse("2026-03-29T02:30")
        val future = LocalDateTime.parse("2026-03-29T07:01")

        assertEquals(CustomPeriodError.MISSING_LOCAL_TIME, customPeriod(valid, missing, now, berlin).error)
        assertEquals(CustomPeriodError.FUTURE_END, customPeriod(valid, future, now, berlin).error)
        assertEquals(CustomPeriodError.INVALID_ORDER, customPeriod(valid, valid, now, berlin).error)
    }

    @Test
    fun customPeriodChoosesFirstOccurrenceAndKeepsInstantsAfterZoneChanges() {
        val now = Instant.parse("2026-10-25T09:00:00Z")
        val result = customPeriod(
            LocalDateTime.parse("2026-10-25T02:10"),
            LocalDateTime.parse("2026-10-25T02:45"),
            now,
            berlin,
        )

        assertEquals(
            UsageWindow(Instant.parse("2026-10-25T00:10:00Z"), Instant.parse("2026-10-25T00:45:00Z")),
            result.window,
        )
        assertEquals(result.window, UsagePeriod.Custom(checkNotNull(result.window)).window(now, ZoneId.of("UTC")))
    }
}
