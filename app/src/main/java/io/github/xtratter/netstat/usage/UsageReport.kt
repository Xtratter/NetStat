package io.github.xtratter.netstat.usage

import java.time.Duration
import java.time.ZoneId

internal enum class UsageNetwork { WIFI, MOBILE }

internal data class UsageRequest(
    val network: UsageNetwork,
    val window: UsageWindow,
    val zone: ZoneId,
)

internal sealed interface UsageResult {
    data object Loading : UsageResult
    data object AccessRequired : UsageResult
    data object Unavailable : UsageResult
    data object FuturePeriod : UsageResult
    data class Available(val report: UsageReport) : UsageResult
}

internal data class AppIdentity(val packageName: String, val label: String)

internal data class UsageBucket(
    val uid: Int,
    val window: UsageWindow,
    val received: Long,
    val sent: Long,
)

internal data class UsageCoverage(
    val intervals: List<UsageWindow>,
    val shortestBucketSeconds: Long,
    val longestBucketSeconds: Long,
) {
    fun covers(window: UsageWindow): Boolean = intervals.singleOrNull() == window
}

internal data class AppUsage(
    val uid: Int,
    val apps: List<AppIdentity>,
    val received: Long,
    val sent: Long,
    val coverage: UsageCoverage,
) {
    val total: Long = received + sent
}

internal data class UsageReport(
    val rows: List<AppUsage>,
    val coverage: UsageCoverage,
) {
    val received: Long = rows.sumOf(AppUsage::received)
    val sent: Long = rows.sumOf(AppUsage::sent)
    val total: Long = received + sent
}

internal fun summarizeUsage(
    request: UsageWindow,
    buckets: Sequence<UsageBucket>,
    appsForUid: (Int) -> List<AppIdentity>,
): UsageReport {
    val byUid = mutableMapOf<Int, UsageAccumulator>()
    for (bucket in buckets) {
        val window = bucket.window
        if (window.start == window.end || !request.contains(window)) continue
        if (bucket.received < 0 || bucket.sent < 0) continue
        byUid.getOrPut(bucket.uid, ::UsageAccumulator).add(bucket)
    }

    val rows = byUid.map { (uid, usage) -> usage.toRow(uid, appsForUid(uid)) }
        .sortedWith(compareByDescending(AppUsage::total).thenBy(AppUsage::uid))
    val allCoverage = UsageCoverage(
        intervals = mergeIntervals(rows.flatMap { it.coverage.intervals }),
        shortestBucketSeconds = rows.minOfOrNull { it.coverage.shortestBucketSeconds } ?: 0,
        longestBucketSeconds = rows.maxOfOrNull { it.coverage.longestBucketSeconds } ?: 0,
    )
    return UsageReport(rows, allCoverage)
}

private class UsageAccumulator {
    private var received = 0L
    private var sent = 0L
    private val windows = mutableListOf<UsageWindow>()
    private var shortest = Long.MAX_VALUE
    private var longest = 0L

    fun add(bucket: UsageBucket) {
        received += bucket.received
        sent += bucket.sent
        windows += bucket.window
        val seconds = Duration.between(bucket.window.start, bucket.window.end).seconds
        shortest = minOf(shortest, seconds)
        longest = maxOf(longest, seconds)
    }

    fun toRow(uid: Int, apps: List<AppIdentity>): AppUsage = AppUsage(
        uid,
        apps.sortedWith(compareBy(AppIdentity::label, AppIdentity::packageName)),
        received,
        sent,
        UsageCoverage(mergeIntervals(windows), shortest, longest),
    )
}

private fun mergeIntervals(windows: List<UsageWindow>): List<UsageWindow> {
    val sorted = windows.sortedBy(UsageWindow::start)
    return buildList {
        for (window in sorted) {
            val previous = lastOrNull()
            if (previous == null || previous.end < window.start) {
                add(window)
            } else if (previous.end < window.end) {
                set(lastIndex, UsageWindow(previous.start, window.end))
            }
        }
    }
}
