package io.github.xtratter.netstat.usage

import android.app.DatePickerDialog
import android.app.TimePickerDialog
import android.text.format.DateFormat
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.xtratter.netstat.R
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.time.temporal.ChronoUnit

@Composable
internal fun CustomPeriodDialog(
    activity: ComponentActivity,
    zone: ZoneId,
    selected: UsageWindow?,
    dismiss: () -> Unit,
    apply: (UsageWindow) -> Unit,
) {
    val now = Instant.now().truncatedTo(ChronoUnit.MINUTES)
    val initial = selected ?: UsageWindow(now.minus(1, ChronoUnit.HOURS), now)
    val initialStart = initial.start.atZone(zone)
    val initialEnd = initial.end.atZone(zone)
    var startText by rememberSaveable(zone.id) { mutableStateOf(initialStart.toLocalDateTime().toString()) }
    var endText by rememberSaveable(zone.id) { mutableStateOf(initialEnd.toLocalDateTime().toString()) }
    val start = LocalDateTime.parse(startText)
    val end = LocalDateTime.parse(endText)
    var laterStart by rememberSaveable(zone.id, startText) { mutableStateOf(initialStart.isLater(start)) }
    var laterEnd by rememberSaveable(zone.id, endText) { mutableStateOf(initialEnd.isLater(end)) }
    var error by rememberSaveable { mutableStateOf<CustomPeriodError?>(null) }

    AlertDialog(
        onDismissRequest = dismiss,
        title = { Text(stringResource(R.string.custom_title)) },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth().heightIn(max = 440.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(zone.id, style = MaterialTheme.typography.bodySmall)
                PeriodBoundPicker(
                    activity, R.string.custom_start, start, zone, laterStart,
                    onChange = {
                        startText = it.toString()
                        error = null
                    },
                    onLater = {
                        laterStart = it
                        error = null
                    },
                )
                PeriodBoundPicker(
                    activity, R.string.custom_end, end, zone, laterEnd,
                    onChange = {
                        endText = it.toString()
                        error = null
                    },
                    onLater = {
                        laterEnd = it
                        error = null
                    },
                )
                error?.let {
                    Text(
                        text = stringResource(
                            when (it) {
                                CustomPeriodError.MISSING_LOCAL_TIME -> R.string.custom_invalid_local_time
                                CustomPeriodError.INVALID_ORDER -> R.string.custom_invalid_order
                                CustomPeriodError.FUTURE_END -> R.string.custom_invalid_future
                            },
                        ),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    when (val result = customPeriod(start, end, Instant.now(), zone, laterStart, laterEnd)) {
                        is CustomPeriodResult.Valid -> apply(result.bounds)
                        is CustomPeriodResult.Invalid -> error = result.reason
                    }
                },
            ) { Text(stringResource(R.string.custom_apply)) }
        },
        dismissButton = {
            TextButton(onClick = dismiss) { Text(stringResource(R.string.custom_cancel)) }
        },
    )
}

private fun ZonedDateTime.isLater(local: LocalDateTime): Boolean {
    val offsets = zone.rules.getValidOffsets(local)
    return toLocalDateTime() == local && offsets.size == 2 && offset == offsets.last()
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun PeriodBoundPicker(
    activity: ComponentActivity,
    label: Int,
    bound: LocalDateTime,
    zone: ZoneId,
    later: Boolean,
    onChange: (LocalDateTime) -> Unit,
    onLater: (Boolean) -> Unit,
) {
    val locale = LocalConfiguration.current.locales[0]
    val clock24 = DateFormat.is24HourFormat(activity)
    val dateText = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withLocale(locale).format(bound)
    val timeText = DateTimeFormatter.ofPattern(if (clock24) "HH:mm" else "h:mm a", locale).format(bound)

    Column {
        Text(stringResource(label), style = MaterialTheme.typography.labelLarge)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = {
                DatePickerDialog(
                    activity,
                    { _, year, month, day ->
                        onChange(java.time.LocalDate.of(year, month + 1, day).atTime(bound.toLocalTime()))
                    },
                    bound.year, bound.monthValue - 1, bound.dayOfMonth,
                ).show()
            }) { Text(dateText) }
            OutlinedButton(onClick = {
                TimePickerDialog(
                    activity,
                    { _, hour, minute -> onChange(bound.toLocalDate().atTime(hour, minute)) },
                    bound.hour, bound.minute, clock24,
                ).show()
            }) { Text(timeText) }
        }
        val offsets = zone.rules.getValidOffsets(bound)
        if (offsets.size == 2) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(!later, { onLater(false) }, { Text(stringResource(R.string.custom_earlier, offsets.first().id)) })
                FilterChip(later, { onLater(true) }, { Text(stringResource(R.string.custom_later, offsets.last().id)) })
            }
        }
    }
}
