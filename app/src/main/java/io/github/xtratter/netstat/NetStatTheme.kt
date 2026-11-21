package io.github.xtratter.netstat

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

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

@Composable
internal fun NetStatTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) NightColors else DayColors, content = content)
}
