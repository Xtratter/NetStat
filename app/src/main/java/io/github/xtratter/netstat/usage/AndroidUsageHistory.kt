package io.github.xtratter.netstat.usage

import android.Manifest
import android.app.AppOpsManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Process
import android.os.RemoteException
import android.util.Log
import java.time.Instant
import java.util.concurrent.CancellationException

internal class AndroidUsageHistory(private val context: Context) {
    private val appOps = context.getSystemService(AppOpsManager::class.java)
    private val manager = context.getSystemService(NetworkStatsManager::class.java)

    // NetworkStatsManager's public history API uses these legacy network type constants.
    @Suppress("DEPRECATION")
    fun read(request: UsageRequest): UsageResult {
        if (!hasUsageAccess()) return UsageResult.AccessRequired

        val (start, end) = request.window
        if (end > Instant.now()) return UsageResult.FuturePeriod
        if (start == end) {
            return UsageResult.Available(summarizeUsage(request.window, emptySequence()) { emptyList() })
        }

        val networkType = when (request.network) {
            UsageNetwork.WIFI -> ConnectivityManager.TYPE_WIFI
            UsageNetwork.MOBILE -> ConnectivityManager.TYPE_MOBILE
        }

        return try {
            val stats = manager?.queryDetails(networkType, null, start.toEpochMilli(), end.toEpochMilli())
                ?: return failedRead()
            val report = stats.use {
                val appsByUid by lazy(::installedAppsByUid)
                summarizeUsage(request.window, stats.untaggedBuckets()) { uid ->
                    appsByUid[uid].orEmpty()
                }
            }
            if (hasUsageAccess()) UsageResult.Available(report) else UsageResult.AccessRequired
        } catch (_: CancellationException) {
            UsageResult.Loading
        } catch (exception: SecurityException) {
            failedRead(exception)
        } catch (exception: RemoteException) {
            failedRead(exception)
        } catch (exception: RuntimeException) {
            failedRead(exception)
        }
    }

    private fun hasUsageAccess(): Boolean {
        val mode = appOps?.unsafeCheckOpNoThrow(
            AppOpsManager.OPSTR_GET_USAGE_STATS,
            Process.myUid(),
            context.packageName,
        )
        return when (mode) {
            AppOpsManager.MODE_ALLOWED -> true
            AppOpsManager.MODE_DEFAULT -> context.checkSelfPermission(Manifest.permission.PACKAGE_USAGE_STATS) ==
                PackageManager.PERMISSION_GRANTED
            else -> false
        }
    }

    private fun failedRead(exception: Exception? = null): UsageResult {
        if (!hasUsageAccess()) return UsageResult.AccessRequired
        Log.w("NetStat", "Android could not read usage history", exception)
        return UsageResult.Unavailable
    }

    private fun installedAppsByUid(): Map<Int, List<AppIdentity>> {
        val packages = context.packageManager
        return packages.getInstalledApplications(0).groupBy(
            keySelector = { it.uid },
            valueTransform = { application ->
                val name = application.packageName
                AppIdentity(name, application.loadLabel(packages).toString().ifBlank { name })
            },
        )
    }

    private fun NetworkStats.untaggedBuckets(): Sequence<UsageBucket> = sequence {
        val bucket = NetworkStats.Bucket()
        while (getNextBucket(bucket)) {
            if (Thread.currentThread().isInterrupted) throw CancellationException()
            if (bucket.tag != NetworkStats.Bucket.TAG_NONE ||
                bucket.startTimeStamp >= bucket.endTimeStamp
            ) continue

            yield(
                UsageBucket(
                    bucket.uid,
                    UsageWindow(Instant.ofEpochMilli(bucket.startTimeStamp), Instant.ofEpochMilli(bucket.endTimeStamp)),
                    bucket.rxBytes,
                    bucket.txBytes,
                ),
            )
        }
    }
}
