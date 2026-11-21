package io.github.xtratter.netstat.usage

import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UsageReportTest {
    private val request = range(0, 10)

    @Test
    fun totalsKeepDirectionsRankByTotalAndMapEveryVisiblePackageForSharedUid() {
        val report = summarizeUsage(
            request,
            sequenceOf(bucket(7, 0, 4, 9, 4), bucket(8, 0, 4, 0, 20), bucket(7, 4, 10, 5, 7)),
        ) { uid ->
            if (uid == 7) listOf(AppIdentity("com.fn.second", "Second"), AppIdentity("com.fn.first", "First"))
            else emptyList()
        }

        assertEquals(listOf(7, 8), report.rows.map { it.uid })
        assertEquals(listOf("com.fn.first", "com.fn.second"), report.rows[0].apps.map { it.packageName })
        assertEquals(14L, report.rows[0].received)
        assertEquals(11L, report.rows[0].sent)
        assertTrue(report.rows[0].coverage.covers(request))
        assertTrue(report.rows[1].apps.isEmpty())
        assertEquals(45L, report.total)
    }

    @Test
    fun coverageExcludesPartialBucketsAndCountsActualIntervalsWithoutFillingGaps() {
        val report = summarizeUsage(
            request,
            sequenceOf(
                bucket(7, -1, 2, 100, 100), bucket(7, 1, 3, 5, 2), bucket(7, 2, 4, 1, 0),
                bucket(7, 6, 8, 2, 0), bucket(7, 8, 11, 100, 100),
                bucket(8, 4, 5, 1, 0), bucket(9, 8, 8, 100, 100),
            ),
        ) { emptyList() }

        assertEquals(10L, report.rows[0].total)
        assertEquals(listOf(range(1, 4), range(6, 8)), report.rows[0].coverage.intervals)
        assertEquals(listOf(range(1, 5), range(6, 8)), report.coverage.intervals)
        assertFalse(report.coverage.covers(request))
        assertEquals(1L, report.coverage.shortestBucketSeconds)
        assertEquals(2L, report.coverage.longestBucketSeconds)
    }

    @Test
    fun aReturnedZeroBucketDoesNotBecomeAnEmptyHistory() {
        val empty = summarizeUsage(request, emptySequence()) { emptyList() }
        val zero = summarizeUsage(request, sequenceOf(bucket(-4, 0, 10, 0, 0))) { emptyList() }

        assertTrue(empty.rows.isEmpty())
        assertTrue(empty.coverage.intervals.isEmpty())
        assertEquals(-4, zero.rows.single().uid)
        assertEquals(0L, zero.total)
        assertTrue(zero.coverage.covers(request))
    }

    private fun range(start: Long, end: Long) =
        UsageWindow(Instant.ofEpochSecond(start), Instant.ofEpochSecond(end))

    private fun bucket(uid: Int, start: Long, end: Long, received: Long, sent: Long) =
        UsageBucket(uid, range(start, end), received, sent)
}
