package io.github.xtratter.netstat

import android.app.AppOpsManager
import android.content.ActivityNotFoundException
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import io.github.xtratter.netstat.capture.CaptureScreen
import io.github.xtratter.netstat.capture.CaptureService
import io.github.xtratter.netstat.usage.AndroidUsageHistory
import io.github.xtratter.netstat.usage.UsageNetwork
import io.github.xtratter.netstat.usage.UsagePeriod
import io.github.xtratter.netstat.usage.UsageRequest
import io.github.xtratter.netstat.usage.UsageResult
import io.github.xtratter.netstat.usage.UsageScreen
import io.github.xtratter.netstat.usage.UsageWindow
import java.time.Instant
import java.time.ZoneId
import java.util.concurrent.Executors
import java.util.concurrent.Future

class MainActivity : ComponentActivity() {
    private val worker = Executors.newSingleThreadExecutor()
    private val history by lazy { AndroidUsageHistory(applicationContext) }
    private val appOps by lazy { getSystemService(AppOpsManager::class.java) }

    private var captureOpen by mutableStateOf(false)
    private var period by mutableStateOf<UsagePeriod>(UsagePeriod.Today)
    private var network by mutableStateOf(UsageNetwork.WIFI)
    private var request by mutableStateOf(currentRequest())
    private var result by mutableStateOf<UsageResult>(UsageResult.Loading)
    private var pendingQuery: Future<*>? = null
    private var generation = 0
    private var active = false

    private val accessListener = AppOpsManager.OnOpChangedListener { _, changedPackage ->
        if (changedPackage == packageName) runOnUiThread { if (active) refresh() }
    }

    private val clockReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (!active) return
            val updated = currentRequest()
            val periodChanged = request.zone != updated.zone ||
                request.window.start != updated.window.start ||
                (period != UsagePeriod.Today && request.window.end != updated.window.end)
            if (intent.action != Intent.ACTION_TIME_TICK || periodChanged) refresh()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        savedInstanceState?.let(::restoreSelection)
        request = currentRequest()
        captureOpen = savedInstanceState?.getBoolean("captureOpen")
            ?: intent.getBooleanExtra(CaptureService.EXTRA_OPEN_CAPTURE, false)

        enableEdgeToEdge()
        setContent {
            if (captureOpen) {
                CaptureScreen(this, onHistory = { captureOpen = false })
            } else {
                UsageScreen(
                    activity = this,
                    period = period,
                    request = request,
                    result = result,
                    onPeriod = {
                        period = it
                        refresh()
                    },
                    onNetwork = {
                        network = it
                        refresh()
                    },
                    onRefresh = ::refresh,
                    onOpenSettings = ::openUsageSettings,
                    onCapture = { captureOpen = true },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra(CaptureService.EXTRA_OPEN_CAPTURE, false)) captureOpen = true
    }

    override fun onStart() {
        super.onStart()
        val clockChanges = IntentFilter().apply {
            addAction(Intent.ACTION_TIME_TICK)
            addAction(Intent.ACTION_TIME_CHANGED)
            addAction(Intent.ACTION_TIMEZONE_CHANGED)
            addAction(Intent.ACTION_DATE_CHANGED)
        }
        ContextCompat.registerReceiver(this, clockReceiver, clockChanges, ContextCompat.RECEIVER_NOT_EXPORTED)
        appOps?.startWatchingMode(AppOpsManager.OPSTR_GET_USAGE_STATS, packageName, accessListener)
    }

    override fun onResume() {
        super.onResume()
        active = true
        refresh()
    }

    override fun onPause() {
        active = false
        pendingQuery?.cancel(true)
        generation++
        super.onPause()
    }

    override fun onStop() {
        appOps?.stopWatchingMode(accessListener)
        unregisterReceiver(clockReceiver)
        super.onStop()
    }

    override fun onDestroy() {
        worker.shutdownNow()
        super.onDestroy()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean("captureOpen", captureOpen)
        outState.putString("network", network.name)
        when (val selected = period) {
            UsagePeriod.Today -> outState.putString("period", "today")
            UsagePeriod.LastNight -> outState.putString("period", "night")
            is UsagePeriod.Custom -> {
                outState.putString("period", "custom")
                outState.putLong("start", selected.bounds.start.toEpochMilli())
                outState.putLong("end", selected.bounds.end.toEpochMilli())
            }
        }
    }

    private fun restoreSelection(state: Bundle) {
        network = if (state.getString("network") == UsageNetwork.MOBILE.name) {
            UsageNetwork.MOBILE
        } else {
            UsageNetwork.WIFI
        }
        period = when (state.getString("period")) {
            "night" -> UsagePeriod.LastNight
            "custom" -> UsagePeriod.Custom(
                UsageWindow(Instant.ofEpochMilli(state.getLong("start")), Instant.ofEpochMilli(state.getLong("end"))),
            )
            else -> UsagePeriod.Today
        }
    }

    private fun currentRequest(): UsageRequest {
        val now = Instant.now()
        val zone = ZoneId.systemDefault()
        return UsageRequest(network, period.window(now, zone), zone)
    }

    private fun refresh() {
        val snapshot = currentRequest()
        val queryGeneration = ++generation
        request = snapshot
        result = UsageResult.Loading
        pendingQuery?.cancel(true)
        pendingQuery = worker.submit {
            if (Thread.currentThread().isInterrupted) return@submit
            val loaded = history.read(snapshot)
            runOnUiThread {
                if (active && queryGeneration == generation) result = loaded
            }
        }
    }

    private fun openUsageSettings() {
        try {
            startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, R.string.access_settings_missing, Toast.LENGTH_SHORT).show()
        }
    }
}
