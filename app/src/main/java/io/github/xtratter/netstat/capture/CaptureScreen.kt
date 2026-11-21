package io.github.xtratter.netstat.capture

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import android.text.format.DateFormat
import android.text.format.Formatter
import androidx.activity.ComponentActivity
import androidx.compose.foundation.clickable
import io.github.xtratter.netstat.inspect.HttpsImportScreen
import io.github.xtratter.netstat.inspect.PacketInspector
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.app.NotificationManagerCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.LifecycleEventObserver
import io.github.xtratter.netstat.NetStatTheme
import io.github.xtratter.netstat.R
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun CaptureScreen(activity: ComponentActivity, onHistory: () -> Unit) {
    BackHandler(onBack = onHistory)
    val context = activity.applicationContext
    val state = CaptureRuntime.state
    val rootSupported = remember(context) { PcapdCapture.isSupported(context) }
    val vpnSupported = remember { VpnNative.supported }
    val supported = rootSupported || vpnSupported
    var useVpn by rememberSaveable { mutableStateOf(!rootSupported && vpnSupported) }
    var conflict by rememberSaveable { mutableStateOf(false) }
    var consentPending by rememberSaveable { mutableStateOf(false) }
    val managers = remember(context) { NotificationManagerCompat.from(context) }
    var notifications by remember { mutableStateOf(managers.areNotificationsEnabled()) }
    var selectedInterface by rememberSaveable { mutableStateOf<String?>(null) }
    var manualMode by rememberSaveable { mutableStateOf(false) }
    var manualName by rememberSaveable { mutableStateOf("") }
    var showInterfaces by rememberSaveable { mutableStateOf(false) }
    var uid by rememberSaveable { mutableStateOf<Int?>(null) }
    var appLabel by rememberSaveable { mutableStateOf<String?>(null) }
    var appPackage by rememberSaveable { mutableStateOf<String?>(null) }
    val vpnConfig = if (uid == null || appPackage != null) {
        CaptureConfig("vpn", uid, appLabel, CaptureMode.VPN, appPackage)
    } else null
    val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val shouldStart = consentPending && result.resultCode == Activity.RESULT_OK
        consentPending = false
        if (shouldStart && vpnConfig != null) CaptureService.start(activity, vpnConfig)
    }
    var showApps by rememberSaveable { mutableStateOf(false) }
    val notificationPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        notifications = managers.areNotificationsEnabled()
    }
    DisposableEffect(activity) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) notifications = managers.areNotificationsEnabled()
        }
        activity.lifecycle.addObserver(observer)
        onDispose { activity.lifecycle.removeObserver(observer) }
    }
    LaunchedEffect(context) {
        if (CaptureRuntime.state == CaptureState.Loading) {
            val report = withContext(Dispatchers.IO) { CaptureArchive(context.noBackupFilesDir).restore() }
            if (CaptureRuntime.state == CaptureState.Loading) {
                CaptureRuntime.state = if (report == null) CaptureState.Idle else CaptureState.Finished(report)
            }
        }
    }

    var showHttps by rememberSaveable { mutableStateOf(false) }
    var inspectorId by rememberSaveable { mutableStateOf<String?>(null) }
    var connectionIndex by rememberSaveable { mutableStateOf(-1) }
    var choices by remember { mutableStateOf<InterfaceChoices?>(null) }
    LaunchedEffect(activity, rootSupported, useVpn, state.active, inspectorId, showHttps) {
        if (rootSupported && !useVpn && !state.active && inspectorId == null && !showHttps) {
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
            activity.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
                while (isActive) {
                    choices = withContext(Dispatchers.IO) { discoverInterfaces(connectivity) }
                    delay(2_000)
                }
            }
        }
    }
    val target = choices?.target(selectedInterface)
    val interfaceName = if (manualMode) manualName.trim().takeIf(CaptureConfig::isValidInterface) else target?.name
    if (showHttps) {
        HttpsImportScreen(onBack = { showHttps = false })
        return
    }
    val finished = (state as? CaptureState.Finished)?.report
    val selectedId = inspectorId
    if (selectedId != null && finished?.sessionId == selectedId) {
        PacketInspector(selectedId, finished.snapshot.connections.getOrNull(connectionIndex)?.key,
            onBack = { inspectorId = null },
            onDeleted = {
                inspectorId = null
                if ((CaptureRuntime.state as? CaptureState.Finished)?.report?.sessionId == selectedId) {
                    CaptureRuntime.state = CaptureState.Idle
                }
            })
        return
    }

    NetStatTheme {
        Scaffold(
            containerColor = MaterialTheme.colorScheme.background,
            contentWindowInsets = WindowInsets.safeDrawing,
            topBar = {
                TopAppBar(
                    title = { Text(stringResource(R.string.capture_title), Modifier.semantics { heading() }) },
                    actions = {
                        TextButton(onClick = { showHttps = true }) { Text(stringResource(R.string.https_action)) }
                        TextButton(onClick = onHistory) { Text(stringResource(R.string.capture_history)) }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
                )
            },
        ) { insets ->
            LazyColumn(
                modifier = Modifier.padding(insets).consumeWindowInsets(insets),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                if (state == CaptureState.Loading) {
                    item { Text(stringResource(R.string.capture_status_loading)) }
                } else if (!supported) {
                    item { Text(stringResource(R.string.capture_unsupported)) }
                } else if (!state.active) {
                    item {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            if (rootSupported) {
                                FilterChip(selected = !useVpn, onClick = { useVpn = false },
                                    label = { Text(stringResource(R.string.capture_mode_root)) })
                            }
                            if (vpnSupported) {
                                FilterChip(selected = useVpn, onClick = { useVpn = true },
                                    label = { Text(stringResource(R.string.capture_mode_vpn)) })
                            }
                        }
                        CaptureForm(
                            useVpn = useVpn,
                            target = target,
                            missing = selectedInterface?.takeIf { target == null && choices != null },
                            automatic = selectedInterface == null,
                            manualMode = manualMode,
                            manualName = manualName,
                            canStart = if (useVpn) vpnConfig != null && !consentPending else interfaceName != null,
                            uid = uid,
                            appLabel = appLabel,
                            onPickInterface = { showInterfaces = true },
                            onManualName = { manualName = it.take(15) },
                            onSelect = { showApps = true },
                            onStart = {
                                if (!useVpn) {
                                    interfaceName?.let { CaptureService.start(activity, CaptureConfig(it, uid, appLabel)) }
                                } else if (vpnConfig != null) {
                                    if (hasActiveVpn(context.getSystemService(ConnectivityManager::class.java))) {
                                        conflict = true
                                    } else {
                                        try {
                                            val approval = VpnService.prepare(activity)
                                            if (approval == null) CaptureService.start(activity, vpnConfig)
                                            else {
                                                consentPending = true
                                                vpnPermission.launch(approval)
                                            }
                                        } catch (error: RuntimeException) {
                                            consentPending = false
                                            CaptureRuntime.finishWithoutRecording(vpnConfig, CaptureEnd.VPN_FAILED, error.message)
                                        }
                                    }
                                }
                            },
                        )
                    }
                }

                if (supported && !notifications) {
                    item {
                        Text(stringResource(R.string.capture_notifications_disabled))
                        if (!state.active) {
                            TextButton(
                                onClick = {
                                    if (Build.VERSION.SDK_INT >= 33 && activity.checkSelfPermission(
                                            Manifest.permission.POST_NOTIFICATIONS,
                                        ) != android.content.pm.PackageManager.PERMISSION_GRANTED
                                    ) {
                                        notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
                                    } else {
                                        activity.startActivity(
                                            Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                                                .putExtra(Settings.EXTRA_APP_PACKAGE, activity.packageName),
                                        )
                                    }
                                },
                            ) { Text(stringResource(R.string.capture_enable_notifications)) }
                        }
                    }
                }

                if (state.active) {
                    item {
                        Button(
                            onClick = { CaptureService.stop(activity) },
                            enabled = state !is CaptureState.Stopping,
                        ) { Text(stringResource(R.string.capture_stop)) }
                    }
                }
                val snapshot = when (state) {
                    is CaptureState.Preparing -> {
                        item { CaptureStatus(if (state.config.mode == CaptureMode.VPN) R.string.capture_vpn_preparing
                            else R.string.capture_status_preparing, state.config) }
                        null
                    }
                    is CaptureState.Recording -> {
                        item { CaptureStatus(R.string.capture_status_recording, state.config) }
                        state.snapshot
                    }
                    is CaptureState.Stopping -> {
                        item { CaptureStatus(R.string.capture_status_stopping, state.config) }
                        state.snapshot
                    }
                    is CaptureState.Finished -> {
                        item { CaptureStatus(state.report.reason.title(), state.report.config, state.report.detail) }
                        state.report.sessionId?.let { id ->
                            item {
                                OutlinedButton(onClick = { connectionIndex = -1; inspectorId = id }) {
                                    Text(stringResource(R.string.packet_title))
                                }
                            }
                        }
                        state.report.snapshot
                    }
                    CaptureState.Idle, CaptureState.Loading -> null
                }
                if (snapshot != null) {
                    item { CaptureCounters(snapshot) }
                    if (snapshot.connections.isEmpty()) {
                        item { Text(stringResource(R.string.capture_no_connections)) }
                    } else {
                        item {
                            Text(
                                stringResource(R.string.capture_connections),
                                Modifier.semantics { heading() },
                                style = MaterialTheme.typography.titleLarge,
                            )
                        }
                        items(snapshot.connections.size) { index ->
                            val open: (() -> Unit)? = finished?.sessionId?.let { id ->
                                { connectionIndex = index; inspectorId = id }
                            }
                            ConnectionCard(snapshot.connections[index], open)
                        }
                    }
                }
            }
        }

        if (conflict) {
            AlertDialog(
                onDismissRequest = { conflict = false },
                title = { Text(stringResource(R.string.capture_vpn_conflict_title)) },
                text = { Text(stringResource(R.string.capture_vpn_conflict)) },
                confirmButton = {
                    TextButton(onClick = {
                        conflict = false
                        activity.startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
                    }) { Text(stringResource(R.string.capture_vpn_settings)) }
                },
                dismissButton = {
                    TextButton(onClick = { conflict = false }) { Text(stringResource(android.R.string.cancel)) }
                },
            )
        }
        if (showInterfaces) {
            InterfacePicker(
                choices = choices,
                onSelect = { name ->
                    selectedInterface = name
                    manualMode = false
                    showInterfaces = false
                },
                onManual = {
                    if (!manualMode) manualName = target?.name.orEmpty()
                    manualMode = true
                    showInterfaces = false
                },
                onDismiss = { showInterfaces = false },
            )
        }
        if (showApps) {
            CaptureAppPicker(
                exclude = context.packageName.takeIf { useVpn },
                dismiss = { showApps = false },
                select = { app ->
                    uid = app?.uid
                    appLabel = app?.label
                    appPackage = app?.name
                    showApps = false
                },
            )
        }
    }
}

@Composable
private fun CaptureForm(
    useVpn: Boolean,
    target: CaptureInterface?,
    missing: String?,
    automatic: Boolean,
    manualMode: Boolean,
    manualName: String,
    canStart: Boolean,
    uid: Int?,
    appLabel: String?,
    onPickInterface: () -> Unit,
    onManualName: (String) -> Unit,
    onSelect: () -> Unit,
    onStart: () -> Unit,
) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (useVpn) {
                Text(stringResource(R.string.capture_vpn_note), style = MaterialTheme.typography.bodySmall)
            } else {
                Text(stringResource(R.string.capture_interface), style = MaterialTheme.typography.labelLarge)
                OutlinedButton(onClick = onPickInterface, modifier = Modifier.fillMaxWidth()) {
                    Text(if (!manualMode && target != null) target.label() else stringResource(R.string.capture_interface_pick))
                }
                if (manualMode) {
                    OutlinedTextField(
                        value = manualName,
                        onValueChange = onManualName,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(stringResource(R.string.capture_interface_name)) },
                        isError = manualName.isNotBlank() && !canStart,
                        singleLine = true,
                    )
                } else if (missing != null) {
                    Text(stringResource(R.string.capture_interface_missing, missing), color = MaterialTheme.colorScheme.error)
                } else if (automatic && target != null) {
                    Text(stringResource(R.string.capture_interface_default), style = MaterialTheme.typography.bodySmall)
                }
            }
            Text(stringResource(R.string.capture_scope), style = MaterialTheme.typography.labelLarge)
            OutlinedButton(onClick = onSelect) { Text(scopeLabel(uid, appLabel)) }
            if (uid != null) Text(stringResource(if (useVpn) R.string.capture_vpn_filter else R.string.capture_filter_note), style = MaterialTheme.typography.bodySmall)
            Button(onClick = onStart, enabled = canStart) {
                Text(stringResource(if (useVpn) R.string.capture_vpn_start else R.string.capture_start))
            }
            Text(stringResource(R.string.capture_retention), style = MaterialTheme.typography.bodySmall)
        }
    }
}

private data class InstalledApp(val uid: Int, val name: String, val label: String)

@Composable
private fun CaptureAppPicker(exclude: String?, dismiss: () -> Unit, select: (InstalledApp?) -> Unit) {
    val packages = LocalContext.current.packageManager
    var apps by remember(packages) { mutableStateOf<List<InstalledApp>?>(null) }
    LaunchedEffect(packages) {
        apps = withContext(Dispatchers.IO) {
            runCatching {
                packages.getInstalledApplications(0).map { info ->
                    InstalledApp(info.uid, info.packageName, info.loadLabel(packages).toString().ifBlank { info.packageName })
                }.sortedWith(compareBy({ it.label.lowercase() }, InstalledApp::name))
            }.getOrDefault(emptyList())
        }
    }
    var search by rememberSaveable { mutableStateOf("") }
    val listed = remember(apps, search, exclude) {
        apps.orEmpty().filter { it.name != exclude && (it.label.contains(search, ignoreCase = true) || it.name.contains(search, ignoreCase = true)) }
    }

    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(stringResource(R.string.capture_choose_app)) },
        text = {
            Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = search,
                    onValueChange = { search = it },
                    label = { Text(stringResource(R.string.capture_app_search)) },
                    singleLine = true,
                )
                TextButton(onClick = { select(null) }) { Text(stringResource(R.string.capture_all)) }
                if (apps != null && listed.isEmpty()) Text(stringResource(R.string.capture_app_empty))
                LazyColumn(Modifier.heightIn(max = 300.dp)) {
                    items(listed, key = { it.name }) { app ->
                        TextButton(onClick = { select(app) }, modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.fillMaxWidth()) {
                                Text(app.label)
                                Text(scopeLabel(app.uid, app.name), style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = dismiss) { Text(stringResource(R.string.custom_cancel)) } },
    )
}

@Composable
private fun scopeLabel(uid: Int?, label: String?): String = when {
    uid == null -> stringResource(R.string.capture_all)
    label == null -> stringResource(R.string.app_uid, uid)
    else -> stringResource(R.string.capture_filter_label, label, uid)
}

@Composable
private fun CaptureStatus(title: Int, config: CaptureConfig, detail: String? = null) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(title), Modifier.semantics { heading() }, style = MaterialTheme.typography.titleMedium)
            val source = if (config.mode == CaptureMode.VPN) stringResource(R.string.capture_mode_vpn) else config.interfaceName
            Text(stringResource(R.string.capture_session_scope, source, scopeLabel(config.uid, config.label)))
            if (!detail.isNullOrBlank()) Text(detail, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun CaptureCounters(snapshot: CaptureSnapshot) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(R.string.capture_packet_count, snapshot.packets))
        snapshot.drops?.let { Text(stringResource(R.string.capture_drop_count, it)) }
        if (snapshot.malformed > 0) Text(stringResource(R.string.capture_malformed_count, snapshot.malformed))
        if (snapshot.unlistedPackets > 0) Text(stringResource(R.string.capture_unlisted_count, snapshot.unlistedPackets))
    }
}

@Composable
private fun ConnectionCard(connection: ConnectionSummary, open: (() -> Unit)?) {
    val context = LocalContext.current
    val locale = LocalConfiguration.current.locales[0]
    val clock = remember(context, locale) { DateFormat.getTimeFormat(context) }
    val key = connection.key
    val transport = when (key.protocol) {
        6 -> "TCP"
        17 -> "UDP"
        1 -> "ICMP"
        58 -> "ICMPv6"
        else -> stringResource(R.string.capture_protocol_number, key.protocol)
    }
    val uid = when (connection.confidence) {
        UidConfidence.KNOWN -> stringResource(R.string.capture_uid_known, checkNotNull(connection.uid))
        UidConfidence.PARTIAL -> stringResource(R.string.capture_uid_partial, checkNotNull(connection.uid), connection.unknownPackets)
        UidConfidence.UNKNOWN -> stringResource(R.string.capture_uid_unknown)
        UidConfidence.CONFLICT -> stringResource(R.string.capture_uid_conflict)
    }
    OutlinedCard(if (open == null) Modifier.fillMaxWidth() else Modifier.fillMaxWidth().clickable(onClick = open)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("$transport · ${clock.format(Date(connection.firstSeenMillis))}", style = MaterialTheme.typography.labelLarge)
            Text(
                stringResource(R.string.capture_connection_peers, key.first.text(), key.second.text()),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(uid, style = MaterialTheme.typography.bodySmall)
            Text(
                stringResource(
                    R.string.capture_connection_bytes,
                    Formatter.formatShortFileSize(context, connection.received),
                    Formatter.formatShortFileSize(context, connection.sent),
                ),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

private fun Endpoint.text(): String = when {
    port == null -> address
    ':' in address -> "[$address]:$port"
    else -> "$address:$port"
}

private fun CaptureEnd.title(): Int = when (this) {
    CaptureEnd.USER_STOPPED -> R.string.capture_status_stopped
    CaptureEnd.TIME_LIMIT -> R.string.capture_status_time_limit
    CaptureEnd.SIZE_LIMIT -> R.string.capture_status_size_limit
    CaptureEnd.ROOT_FAILED -> R.string.capture_status_root_failed
    CaptureEnd.BAD_STREAM -> R.string.capture_status_stream_failed
    CaptureEnd.STORAGE_FAILED -> R.string.capture_status_storage_failed
    CaptureEnd.INTERRUPTED -> R.string.capture_status_interrupted
    CaptureEnd.UNAVAILABLE -> R.string.capture_status_unavailable
    CaptureEnd.VPN_FAILED -> R.string.capture_status_vpn_failed
}
