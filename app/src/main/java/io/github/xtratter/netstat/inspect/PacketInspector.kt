package io.github.xtratter.netstat.inspect

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.xtratter.netstat.NetStatTheme
import io.github.xtratter.netstat.R
import io.github.xtratter.netstat.capture.CaptureArchive
import io.github.xtratter.netstat.capture.ConnectionKey
import io.github.xtratter.netstat.capture.connectionOf
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

private val clock = DateTimeFormatter.ofPattern("HH:mm:ss.SSSSSS")
private data class PacketList(val file: PacketFile, val indices: IntArray)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun PacketInspector(
    session: String, connection: ConnectionKey?, onBack: () -> Unit, onDeleted: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val archive = remember(context) { CaptureArchive(context.noBackupFilesDir) }
    var list by remember(session, connection) { mutableStateOf<PacketList?>(null) }
    var error by remember(session) { mutableStateOf<String?>(null) }
    var selected by rememberSaveable(session, connection.toString()) { mutableIntStateOf(-1) }
    var confirmDelete by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var saved by remember { mutableStateOf(false) }

    LaunchedEffect(session, connection) {
        try {
            list = withContext(Dispatchers.IO) {
                val file = PacketFile.parse(archive.readPackets(session))
                PacketList(file, file.select(connection))
            }
        } catch (e: IOException) { error = e.localizedMessage }
    }
    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri != null) scope.launch {
            busy = true
            saved = false
            error = null
            try {
                withContext(Dispatchers.IO) {
                    val file = list?.file ?: PacketFile.parse(archive.readPackets(session))
                    val out = context.contentResolver.openOutputStream(uri, "wt") ?: throw IOException("Cannot open document")
                    out.buffered().use(file::export)
                }
                saved = true
            } catch (e: CancellationException) { throw e }
            catch (e: Exception) { error = e.localizedMessage ?: e.javaClass.simpleName }
            finally { busy = false }
        }
    }
    val packetScroll = rememberLazyListState()
    val back = { if (!busy) { if (selected >= 0) selected = -1 else onBack() } }
    BackHandler(onBack = back)
    NetStatTheme {
        Scaffold(topBar = {
            TopAppBar(title = { Text(if (selected >= 0) "#${selected + 1}" else stringResource(R.string.packet_title)) },
                navigationIcon = { TextButton(onClick = back, enabled = !busy) { Text(stringResource(R.string.packet_back)) } })
        }) { insets ->
            Column(Modifier.fillMaxSize().padding(insets).padding(horizontal = 12.dp)) {
                val data = list
                if (selected < 0) {
                    Row {
                        TextButton(enabled = data != null && !busy, onClick = { export.launch("NetStat-$session.pcapng") }) {
                            Text(stringResource(R.string.packet_export))
                        }
                        TextButton(enabled = !busy, onClick = { confirmDelete = true }) { Text(stringResource(R.string.packet_delete)) }
                    }
                }
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                if (saved) Text(stringResource(R.string.packet_exported))
                if (data == null) {
                    if (error == null) CircularProgressIndicator()
                } else if (selected in 0 until data.file.count) {
                    val bytes = remember(data, selected) { data.file.bytes(selected) }
                    PacketDetail(bytes)
                } else {
                    Text(stringResource(R.string.packet_total, data.indices.size), style = MaterialTheme.typography.labelLarge)
                    val zone = remember { ZoneId.systemDefault() }
                    LazyColumn(state = packetScroll) {
                        items(data.indices.size, key = { data.indices[it] }) { row ->
                            val n = data.indices[row]
                            val summary = remember(data, n) {
                                val key = connectionOf(data.file.bytes(n))
                                val proto = when (key?.protocol) { 6 -> "TCP"; 17 -> "UDP"; null -> "IP"; else -> "IP ${key.protocol}" }
                                val time = data.file.timestampMicros(n)
                                val instant = Instant.ofEpochSecond(time / 1_000_000, time % 1_000_000 * 1000)
                                "#${n+1}    ${clock.format(instant.atZone(zone))}    $proto"
                            }
                            ListItem(headlineContent = { Text(summary, style = MaterialTheme.typography.bodyMedium) },
                                trailingContent = { Text("${data.file.capturedSize(n)} B") },
                                modifier = Modifier.clickable { selected = n })
                            HorizontalDivider()
                        }
                    }
                }
            }
        }
        if (confirmDelete) AlertDialog(onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(R.string.packet_confirm)) },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text(stringResource(android.R.string.cancel)) } },
            confirmButton = { TextButton(onClick = {
                confirmDelete = false
                busy = true
                scope.launch {
                    try {
                        withContext(Dispatchers.IO) { archive.deleteSession(session) }
                        onDeleted()
                    } catch (e: IOException) { error = e.localizedMessage }
                    finally { busy = false }
                }
            }) { Text(stringResource(R.string.packet_delete)) } })
    }
}

@Composable
private fun PacketDetail(bytes: ByteArray) {
    val layers = remember(bytes) { packetLayers(bytes) }
    var selected by remember(bytes) { mutableStateOf<PacketField?>(null) }
    val hexScroll = rememberLazyListState()
    val treeScroll = rememberLazyListState()
    LaunchedEffect(selected) {
        selected?.takeIf { it.start in bytes.indices }?.let { hexScroll.scrollToItem(it.start / 8) }
    }
    Column {
        LazyColumn(Modifier.weight(1f), state = treeScroll) {
            layers.forEach { layer ->
                item { Text(layer.name, Modifier.padding(vertical = 4.dp), style = MaterialTheme.typography.titleMedium) }
                items(layer.fields) { field ->
                    Text("${field.name}   ${field.value}",
                        Modifier.fillMaxWidth().clickable { selected = field }.padding(start = 12.dp, top = 4.dp, bottom = 4.dp),
                        color = if (selected == field) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface)
                }
            }
        }
        HorizontalDivider()
        Text("Hex", style = MaterialTheme.typography.titleMedium)
        val highlight = SpanStyle(background = MaterialTheme.colorScheme.primary, color = MaterialTheme.colorScheme.onPrimary)
        LazyColumn(Modifier.weight(1f), state = hexScroll) {
            items((bytes.size + 7) / 8) { row ->
                val start = row * 8
                val line = remember(bytes, row, selected, highlight) {
                    buildAnnotatedString {
                        append("%04X  ".format(Locale.ROOT, start))
                        for (i in start until minOf(start + 8, bytes.size)) {
                            val value = "%02X".format(Locale.ROOT, bytes[i].toInt() and 255)
                            if (selected?.let { i >= it.start && i < it.end } == true) withStyle(highlight) { append(value) }
                            else append(value)
                            append(' ')
                        }
                    }
                }
                Text(line, fontFamily = FontFamily.Monospace, fontSize = 14.sp)
            }
        }
    }
}
