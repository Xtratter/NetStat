package io.github.xtratter.netstat.usage

import android.app.usage.NetworkStats
import android.os.Process
import android.text.format.Formatter
import androidx.activity.ComponentActivity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import io.github.xtratter.netstat.R
import java.text.NumberFormat
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

private val DayColors = lightColorScheme(
    primary = Color(0xFF00696B),
    primaryContainer = Color(0xFFC9EFEB),
    onPrimaryContainer = Color(0xFF0B3537),
    background = Color(0xFFF5F9F8),
    surface = Color(0xFFF8FCFB),
    surfaceVariant = Color(0xFFDAE7E5),
    onSurfaceVariant = Color(0xFF3F4949),
)

private val NightColors = darkColorScheme(
    primary = Color(0xFF85DAD8),
    primaryContainer = Color(0xFF194A4B),
    onPrimaryContainer = Color(0xFFC3F2EE),
    background = Color(0xFF101918),
    surface = Color(0xFF151E1D),
    surfaceVariant = Color(0xFF394947),
    onSurfaceVariant = Color(0xFFBECAC8),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun UsageScreen(
    activity: ComponentActivity,
    period: UsagePeriod,
    request: UsageRequest,
    result: UsageResult,
    onPeriod: (UsagePeriod) -> Unit,
    onNetwork: (UsageNetwork) -> Unit,
    onRefresh: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    var customOpen by rememberSaveable { mutableStateOf(false) }

    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) NightColors else DayColors) {
        Scaffold(
            containerColor = MaterialTheme.colorScheme.background,
            contentWindowInsets = WindowInsets.safeDrawing,
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            text = stringResource(R.string.traffic_title),
                            modifier = Modifier.semantics { heading() },
                        )
                    },
                    actions = {
                        TextButton(onClick = onRefresh, enabled = result != UsageResult.Loading) {
                            Text(stringResource(R.string.refresh))
                        }
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
                item {
                    Filters(period, request, onPeriod, onNetwork, onCustom = { customOpen = true })
                }
                when (result) {
                    UsageResult.Loading -> item {
                        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            LinearProgressIndicator(Modifier.fillMaxWidth())
                            Text(stringResource(R.string.loading))
                        }
                    }
                    UsageResult.AccessRequired -> item {
                        StatusCard(R.string.access_title, R.string.access_description) {
                            Button(onClick = onOpenSettings) { Text(stringResource(R.string.access_settings)) }
                        }
                    }
                    UsageResult.Unavailable -> item {
                        StatusCard(R.string.error_title, R.string.error_description)
                    }
                    UsageResult.FuturePeriod -> item {
                        StatusCard(R.string.future_period_title, R.string.future_period_description)
                    }
                    is UsageResult.Available -> {
                        val report = result.report
                        if (report.rows.isEmpty()) {
                            item { StatusCard(R.string.empty_title, R.string.empty_description) }
                        } else {
                            item { SummaryCard(report, request) }
                            item {
                                Text(
                                    text = stringResource(R.string.app_usage_title),
                                    modifier = Modifier.padding(top = 8.dp).semantics { heading() },
                                    style = MaterialTheme.typography.titleLarge,
                                )
                            }
                            items(report.rows, key = { it.uid }) { row -> UsageRow(row, request) }
                        }
                    }
                }
            }
        }

        if (customOpen) {
            CustomPeriodDialog(
                activity = activity,
                zone = request.zone,
                selected = (period as? UsagePeriod.Custom)?.bounds,
                dismiss = { customOpen = false },
                apply = {
                    customOpen = false
                    onPeriod(UsagePeriod.Custom(it))
                },
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun Filters(
    period: UsagePeriod,
    request: UsageRequest,
    onPeriod: (UsagePeriod) -> Unit,
    onNetwork: (UsageNetwork) -> Unit,
    onCustom: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(R.string.period_label), style = MaterialTheme.typography.labelLarge)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(period == UsagePeriod.Today, { onPeriod(UsagePeriod.Today) }, {
                Text(stringResource(R.string.period_today))
            })
            FilterChip(period == UsagePeriod.LastNight, { onPeriod(UsagePeriod.LastNight) }, {
                Text(stringResource(R.string.period_last_night))
            })
            FilterChip(period is UsagePeriod.Custom, onCustom, {
                Text(stringResource(R.string.period_custom))
            })
        }
        Text(windowText(request.window, request), style = MaterialTheme.typography.bodyMedium)
        Caption(request.zone.id)
        Text(
            text = stringResource(R.string.network_label),
            modifier = Modifier.padding(top = 8.dp),
            style = MaterialTheme.typography.labelLarge,
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(request.network == UsageNetwork.WIFI, { onNetwork(UsageNetwork.WIFI) }, {
                Text(stringResource(R.string.network_wifi))
            })
            FilterChip(request.network == UsageNetwork.MOBILE, { onNetwork(UsageNetwork.MOBILE) }, {
                Text(stringResource(R.string.network_mobile))
            })
        }
    }
}

@Composable
private fun StatusCard(title: Int, description: Int, action: @Composable () -> Unit = {}) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(
                text = stringResource(title),
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.titleMedium,
            )
            Text(stringResource(description))
            action()
        }
    }
}

@Composable
private fun SummaryCard(report: UsageReport, request: UsageRequest) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        ),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.total_usage), style = MaterialTheme.typography.labelLarge)
            Text(Formatter.formatShortFileSize(LocalContext.current, report.total), style = MaterialTheme.typography.headlineLarge)
            TrafficDirections(report.received, report.sent)
            Coverage(report.coverage, request, R.string.coverage_all_apps)
            val first = durationText(report.coverage.shortestBucketSeconds)
            val last = durationText(report.coverage.longestBucketSeconds)
            Caption(
                if (first == last) stringResource(R.string.precision_single, first)
                else stringResource(R.string.precision_range, first, last),
            )
            Caption(stringResource(R.string.history_note))
        }
    }
}

@Composable
private fun UsageRow(row: AppUsage, request: UsageRequest) {
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
            val fallback = when (row.uid) {
                NetworkStats.Bucket.UID_REMOVED -> stringResource(R.string.removed_apps)
                NetworkStats.Bucket.UID_TETHERING -> stringResource(R.string.tethering)
                Process.SYSTEM_UID -> stringResource(R.string.android_system)
                else -> null
            }
            val uidText = stringResource(R.string.app_uid, row.uid)
            when {
                row.apps.isEmpty() -> {
                    Text(fallback ?: uidText, style = MaterialTheme.typography.titleMedium)
                    if (fallback != null) Caption(uidText)
                }
                row.apps.size == 1 -> {
                    val app = row.apps.single()
                    Text(app.label, style = MaterialTheme.typography.titleMedium)
                    if (app.label != app.packageName) Caption(app.packageName)
                    Caption(uidText)
                }
                else -> {
                    Text(fallback ?: stringResource(R.string.shared_uid, row.uid), style = MaterialTheme.typography.titleMedium)
                    if (fallback != null) Caption(uidText)
                    for (app in row.apps) {
                        Column {
                            Text(app.label, style = MaterialTheme.typography.bodyMedium)
                            if (app.label != app.packageName) Caption(app.packageName)
                        }
                    }
                }
            }
            TrafficDirections(row.received, row.sent)
            Coverage(row.coverage, request, R.string.coverage_title)
        }
    }
}

@Composable
private fun TrafficDirections(received: Long, sent: Long) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
        ByteCount(R.string.received, received, Modifier.weight(1f))
        ByteCount(R.string.sent, sent, Modifier.weight(1f))
    }
}

@Composable
private fun ByteCount(label: Int, bytes: Long, modifier: Modifier) {
    val locale = LocalConfiguration.current.locales[0]
    val exact = remember(locale, bytes) { NumberFormat.getIntegerInstance(locale).format(bytes) }
    Column(modifier) {
        Text(stringResource(label), style = MaterialTheme.typography.labelMedium)
        if (bytes < 1000) {
            Text(stringResource(R.string.usage_exact_bytes, exact), style = MaterialTheme.typography.titleMedium)
        } else {
            Text(Formatter.formatShortFileSize(LocalContext.current, bytes), style = MaterialTheme.typography.titleMedium)
            Caption(stringResource(R.string.usage_exact_bytes, exact))
        }
    }
}

@Composable
private fun Coverage(coverage: UsageCoverage, request: UsageRequest, label: Int) {
    val intervals = coverage.intervals
    var expanded by rememberSaveable { mutableStateOf(false) }
    val gaps = intervals.size > 1
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(stringResource(label), style = MaterialTheme.typography.labelMedium)
        if (gaps && !expanded) {
            Caption(windowText(UsageWindow(intervals.first().start, intervals.last().end), request))
        } else {
            for (interval in intervals) Caption(windowText(interval, request))
        }
        Caption(
            stringResource(
                when {
                    gaps -> R.string.coverage_gaps
                    coverage.covers(request.window) -> R.string.coverage_full
                    else -> R.string.coverage_partial
                },
            ),
        )
        if (gaps) {
            TextButton(onClick = { expanded = !expanded }) {
                Text(stringResource(if (expanded) R.string.hide_intervals else R.string.show_intervals))
            }
        }
    }
}

@Composable
private fun Caption(text: String) {
    Text(
        text = text,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        style = MaterialTheme.typography.bodySmall,
    )
}

@Composable
private fun windowText(window: UsageWindow, request: UsageRequest): String {
    val locale = LocalConfiguration.current.locales[0]
    val formatter = remember(locale) {
        DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT).withLocale(locale)
    }
    return stringResource(
        R.string.interval_range,
        formatter.formatBound(window.start.atZone(request.zone)),
        formatter.formatBound(window.end.atZone(request.zone)),
    )
}

private fun DateTimeFormatter.formatBound(bound: ZonedDateTime): String {
    val text = format(bound)
    return if (bound.zone.rules.getValidOffsets(bound.toLocalDateTime()).size > 1) {
        "$text (${bound.offset.id})"
    } else {
        text
    }
}

@Composable
private fun durationText(seconds: Long): String {
    val total = seconds.toInt()
    val hours = total / 3600
    val minutes = total % 3600 / 60
    val remaining = total % 60
    return buildList {
        if (hours > 0) add(pluralStringResource(R.plurals.duration_hours, hours, hours))
        if (minutes > 0) add(pluralStringResource(R.plurals.duration_minutes, minutes, minutes))
        if (remaining > 0 || total == 0) {
            add(pluralStringResource(R.plurals.duration_seconds, remaining, remaining))
        }
    }.joinToString(" ")
}
