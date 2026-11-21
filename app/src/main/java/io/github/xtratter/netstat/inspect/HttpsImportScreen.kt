package io.github.xtratter.netstat.inspect

import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.xtratter.netstat.NetStatTheme
import io.github.xtratter.netstat.R
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal const val HTTPS_SESSION_MIME = "application/vnd.netstat.https+json"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun HttpsImportScreen(onBack: () -> Unit, initialDocument: Uri? = null) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var session by remember(initialDocument) { mutableStateOf<HttpsSession?>(null) }
    var loading by remember(initialDocument) { mutableStateOf(false) }
    var failed by remember(initialDocument) { mutableStateOf(false) }
    suspend fun read(uri: Uri) {
        loading = true
        failed = false
        try {
            session = withContext(Dispatchers.IO) {
                val input = context.contentResolver.openInputStream(uri) ?: throw IOException("No document stream")
                input.use(::readHttpsSession)
            }
        } catch (_: IOException) {
            failed = true
        } catch (_: SecurityException) {
            failed = true
        } finally {
            loading = false
        }
    }
    val open = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch { read(uri) }
    }
    LaunchedEffect(initialDocument) {
        if (initialDocument != null) read(initialDocument)
    }
    session?.let { imported ->
        HttpDialogueView(
            imported.dialogues, onBack = { if (initialDocument == null) session = null else onBack() },
            title = R.string.https_title, searchScope = R.string.https_search_scope,
            empty = R.string.https_empty, rememberQuery = false,
            summary = {
                Text(stringResource(R.string.https_session_scope, imported.client, imported.host, imported.port))
                if (imported.clientTlsFailures > 0 || imported.serverTlsFailures > 0) {
                    Text(stringResource(R.string.https_tls_failures, imported.clientTlsFailures, imported.serverTlsFailures))
                }
                if (imported.clientTlsWithoutHttp > 0) {
                    Text(stringResource(R.string.https_tls_without_http, imported.clientTlsWithoutHttp))
                }
            },
        )
        return
    }
    BackHandler(onBack = onBack)
    NetStatTheme {
        Scaffold(topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.https_title)) },
                navigationIcon = { TextButton(onClick = onBack) { Text(stringResource(R.string.packet_back)) } },
            )
        }) { insets ->
            Column(
                Modifier.fillMaxSize().padding(insets).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(stringResource(R.string.https_instructions))
                Button(enabled = !loading, onClick = { open.launch(arrayOf("*/*")) }) {
                    Text(stringResource(R.string.https_import))
                }
                if (loading) LinearProgressIndicator(Modifier.fillMaxWidth())
                if (failed) Text(stringResource(R.string.https_import_error), color = MaterialTheme.colorScheme.error)
            }
        }
    }
}
