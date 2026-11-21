package io.github.xtratter.netstat.inspect

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.xtratter.netstat.NetStatTheme
import io.github.xtratter.netstat.R
import io.github.xtratter.netstat.capture.ConnectionKey
import io.github.xtratter.netstat.capture.Endpoint
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun HttpInspector(file: PacketFile, connection: ConnectionKey?, onBack: () -> Unit) {
    var dialogues by remember(file, connection) { mutableStateOf<HttpDialogues?>(null) }
    LaunchedEffect(file, connection) {
        dialogues = withContext(Dispatchers.Default) { file.httpDialogues(connection) }
    }
    HttpDialogueView(dialogues, onBack)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun HttpDialogueView(
    data: HttpDialogues?,
    onBack: () -> Unit,
    title: Int = R.string.http_dialogues,
    searchScope: Int = R.string.http_search_scope,
    empty: Int = R.string.http_empty,
    summary: (@Composable () -> Unit)? = null,
    rememberQuery: Boolean = true,
) {
    var query by if (rememberQuery) rememberSaveable { mutableStateOf("") } else remember { mutableStateOf("") }
    var selected by rememberSaveable { mutableIntStateOf(-1) }
    var matches by remember(data) { mutableStateOf<List<Int>>(emptyList()) }
    var searching by remember(data) { mutableStateOf(false) }
    LaunchedEffect(data, query) {
        if (data != null) {
            searching = true
            val term = query.trim()
            matches = withContext(Dispatchers.Default) {
                data.exchanges.indices.filter { index ->
                    currentCoroutineContext().ensureActive()
                    term.isEmpty() || data.exchanges[index].matches(term)
                }
            }
            searching = false
        }
    }
    val exchange = data?.exchanges?.getOrNull(selected)
    val back = { if (selected >= 0) selected = -1 else onBack() }
    BackHandler(onBack = back)
    NetStatTheme {
        Scaffold(topBar = {
            TopAppBar(
                title = { Text(stringResource(title)) },
                navigationIcon = {
                    TextButton(onClick = back) { Text(stringResource(R.string.packet_back)) }
                },
            )
        }) { insets ->
            Column(Modifier.fillMaxSize().padding(insets).padding(horizontal = 12.dp)) {
                when {
                    data == null -> LinearProgressIndicator(Modifier.fillMaxWidth())
                    exchange != null -> ExchangeDetail(exchange)
                    else -> {
                        summary?.invoke()
                        OutlinedTextField(
                            value = query, onValueChange = { query = it.take(512) },
                            modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp), singleLine = true,
                            label = { Text(stringResource(R.string.http_search)) },
                        )
                        Text(stringResource(searchScope), style = MaterialTheme.typography.bodySmall)
                        if (data.limitReached) Text(stringResource(R.string.http_session_limit))
                        if (searching) LinearProgressIndicator(Modifier.fillMaxWidth())
                        else if (data.exchanges.isEmpty()) Text(stringResource(empty))
                        else Text(stringResource(R.string.http_matches, matches.size, data.exchanges.size))
                        LazyColumn {
                            items(matches, key = { it }) { index ->
                                val item = data.exchanges[index]
                                ListItem(
                                    headlineContent = {
                                        Text(exchangeTitle(item), maxLines = 2, overflow = TextOverflow.Ellipsis)
                                    },
                                    supportingContent = {
                                        val statuses = item.responses.mapNotNull { it.status }.joinToString(" · ")
                                        Text(listOf(item.server.display(), statuses).filter { it.isNotEmpty() }.joinToString(" · "))
                                    },
                                    trailingContent = if (item.incomplete) {
                                        { Text(stringResource(R.string.http_partial)) }
                                    } else null,
                                    modifier = Modifier.clickable { selected = index },
                                )
                                HorizontalDivider()
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun exchangeTitle(exchange: HttpExchange): String {
    val request = exchange.request ?: return stringResource(R.string.http_response_only)
    return "${request.method} ${request.target}"
}

@Composable
private fun ExchangeDetail(exchange: HttpExchange) {
    LazyColumn(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        item {
            Text(exchangeTitle(exchange), style = MaterialTheme.typography.titleMedium)
            Text("${exchange.client.display()} → ${exchange.server.display()}", style = MaterialTheme.typography.bodySmall)
            if (exchange.incomplete) Text(stringResource(R.string.http_partial))
        }
        exchange.request?.let { message(it, R.string.http_request) }
        exchange.responses.forEach { message(it, R.string.http_response) }
    }
}

private fun LazyListScope.message(message: HttpMessage, label: Int) {
    item {
        HorizontalDivider()
        Text(stringResource(label), style = MaterialTheme.typography.titleMedium)
        Text(message.line, fontFamily = FontFamily.Monospace)
    }
    items(message.headers) { header -> Text("${header.name}: ${header.value}", fontFamily = FontFamily.Monospace) }
    if (message.bodySize == 0 && !message.previewLimited) return

    item {
        Text(stringResource(R.string.http_body, message.bodySize), style = MaterialTheme.typography.titleSmall)
        message.contentType?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        if (message.previewLimited) Text(stringResource(R.string.http_preview_limit))
        if (message.encodingUnavailable) Text(stringResource(R.string.http_encoding_unavailable))
    }
    val text = message.text
    if (text != null) {
        items((text.length + 4095) / 4096) { index ->
            val start = index * 4096
            val end = minOf(start + 4096, text.length)
            Text(text.substring(start, end), fontFamily = FontFamily.Monospace)
        }
    } else {
        items((message.body.size + 15) / 16) { index ->
            val start = index * 16
            val row = remember(message, index) {
                (start until minOf(start + 16, message.body.size)).joinToString(" ") {
                    "%02X".format(Locale.ROOT, message.body[it].toInt() and 0xff)
                }
            }
            Text(row, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
        }
    }
}

private fun Endpoint.display(): String = when {
    port == null -> address
    ':' in address -> "[$address]:$port"
    else -> "$address:$port"
}
