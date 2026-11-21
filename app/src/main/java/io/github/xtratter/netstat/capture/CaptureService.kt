package io.github.xtratter.netstat.capture

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import io.github.xtratter.netstat.MainActivity
import io.github.xtratter.netstat.R
import java.util.UUID
import java.util.concurrent.Executors

internal object CaptureRuntime {
    var state by mutableStateOf<CaptureState>(CaptureState.Loading)

    fun finishWithoutRecording(config: CaptureConfig, reason: CaptureEnd, detail: String?) {
        val now = System.currentTimeMillis()
        state = CaptureState.Finished(CaptureReport(config, now, now, CaptureSnapshot(), reason, detail?.take(400)))
    }
}

class CaptureService : VpnService() {
    private val main = Handler(Looper.getMainLooper())
    private val executor = Executors.newSingleThreadExecutor()
    private var runner: CaptureWorker? = null
    private var notificationToken: String? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> begin(intent)
            ACTION_STOP -> {
                val token = intent.getStringExtra(EXTRA_NOTIFICATION_TOKEN)
                if (token == null || token == notificationToken) requestStop()
            }
            else -> if (runner == null) stopSelf()
        }
        return START_NOT_STICKY
    }

    private fun begin(intent: Intent) {
        if (runner != null) return
        val config = runCatching {
            CaptureConfig(
                intent.getStringExtra(EXTRA_INTERFACE).orEmpty(),
                intent.getIntExtra(EXTRA_UID, -1).takeUnless { it == -1 },
                intent.getStringExtra(EXTRA_LABEL),
                CaptureMode.valueOf(intent.getStringExtra(EXTRA_MODE) ?: CaptureMode.ROOT.name),
                intent.getStringExtra(EXTRA_PACKAGE),
            )
        }.getOrNull()
        if (config == null) {
            stopSelf()
            return
        }

        val token = UUID.randomUUID().toString()
        notificationToken = token
        try {
            val serviceType = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
            ServiceCompat.startForeground(this, NOTIFICATION_ID, notification(config, token), serviceType)
        } catch (error: RuntimeException) {
            CaptureRuntime.finishWithoutRecording(config, CaptureEnd.UNAVAILABLE, error.message)
            stopSelf()
            return
        }

        CaptureRuntime.state = CaptureState.Preparing(config)
        val progress: (CaptureSnapshot) -> Unit = { snapshot ->
            main.post {
                if (notificationToken == token && CaptureRuntime.state !is CaptureState.Stopping) {
                    CaptureRuntime.state = CaptureState.Recording(config, snapshot)
                }
            }
        }
        val task = when (config.mode) {
            CaptureMode.ROOT -> PcapdCapture(applicationContext, config, progress)
            CaptureMode.VPN -> VpnCapture(this, config, progress)
        }
        runner = task
        executor.execute {
            val report = task.run()
            main.post {
                if (notificationToken != token) return@post
                runner = null
                notificationToken = null
                CaptureRuntime.state = CaptureState.Finished(report)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun requestStop() {
        val task = runner
        if (task == null) {
            stopSelf()
            return
        }
        val state = CaptureRuntime.state
        when (state) {
            is CaptureState.Preparing -> CaptureRuntime.state = CaptureState.Stopping(state.config, CaptureSnapshot())
            is CaptureState.Recording -> CaptureRuntime.state = CaptureState.Stopping(state.config, state.snapshot)
            else -> Unit
        }
        task.stop()
    }

    private fun notification(config: CaptureConfig, token: String): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, getString(R.string.capture_notification_channel), NotificationManager.IMPORTANCE_LOW),
        )
        val open = PendingIntent.getActivity(
            this, 1,
            Intent(this, MainActivity::class.java).putExtra(EXTRA_OPEN_CAPTURE, true)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, token.hashCode(),
            Intent(this, CaptureService::class.java).setAction(ACTION_STOP).putExtra(EXTRA_NOTIFICATION_TOKEN, token),
            PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_capture)
            .setContentTitle(getString(R.string.capture_notification_title))
            .setContentText(if (config.mode == CaptureMode.VPN) getString(R.string.capture_mode_vpn)
                else getString(R.string.capture_notification_interface, config.interfaceName))
            .setContentIntent(open)
            .setOnlyAlertOnce(true)
            .setOngoing(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .addAction(R.drawable.ic_capture, getString(R.string.capture_stop), stop)
            .build()
    }

    override fun onRevoke() {
        main.post {
            val current = runner
            if (current == null) stopSelf()
            else if (current is VpnCapture) current.stop(CaptureEnd.INTERRUPTED)
        }
    }

    override fun onDestroy() {
        runner?.stop(CaptureEnd.INTERRUPTED)
        executor.shutdown()
        super.onDestroy()
    }

    companion object {
        internal const val EXTRA_OPEN_CAPTURE = "io.github.xtratter.netstat.OPEN_CAPTURE"
        private const val ACTION_START = "io.github.xtratter.netstat.START_CAPTURE"
        private const val ACTION_STOP = "io.github.xtratter.netstat.STOP_CAPTURE"
        private const val EXTRA_INTERFACE = "interface"
        private const val EXTRA_UID = "uid"
        private const val EXTRA_MODE = "mode"
        private const val EXTRA_PACKAGE = "package"
        private const val EXTRA_LABEL = "label"
        private const val EXTRA_NOTIFICATION_TOKEN = "notificationToken"
        private const val CHANNEL_ID = "capture"
        private const val NOTIFICATION_ID = 701

        internal fun start(context: Context, config: CaptureConfig) {
            if (CaptureRuntime.state.active) return
            CaptureRuntime.state = CaptureState.Preparing(config)
            val intent = Intent(context, CaptureService::class.java).setAction(ACTION_START)
                .putExtra(EXTRA_INTERFACE, config.interfaceName)
                .putExtra(EXTRA_UID, config.uid ?: -1)
                .putExtra(EXTRA_LABEL, config.label)
                .putExtra(EXTRA_MODE, config.mode.name)
                .putExtra(EXTRA_PACKAGE, config.packageName)
            try {
                ContextCompat.startForegroundService(context, intent)
            } catch (error: RuntimeException) {
                CaptureRuntime.finishWithoutRecording(config, CaptureEnd.UNAVAILABLE, error.message)
            }
        }

        internal fun stop(context: Context) {
            context.startService(Intent(context, CaptureService::class.java).setAction(ACTION_STOP))
        }
    }
}
