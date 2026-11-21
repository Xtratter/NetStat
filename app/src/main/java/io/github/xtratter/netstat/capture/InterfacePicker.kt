package io.github.xtratter.netstat.capture

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ListItem
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.foundation.clickable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.xtratter.netstat.R

@Composable
internal fun InterfacePicker(
    choices: InterfaceChoices?,
    onSelect: (String?) -> Unit,
    onManual: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.capture_interface_pick)) },
        text = {
            Column(Modifier.fillMaxWidth()) {
                when {
                    choices == null -> Text(stringResource(R.string.capture_interface_loading))
                    choices.items.isEmpty() -> Text(stringResource(R.string.capture_interface_empty))
                    else -> LazyColumn(Modifier.heightIn(max = 320.dp)) {
                        choices.target(null)?.let { current ->
                            item {
                                ListItem(
                                    headlineContent = { Text(stringResource(R.string.capture_interface_default)) },
                                    supportingContent = { Text(current.label()) },
                                    modifier = Modifier.clickable { onSelect(null) },
                                )
                            }
                        }
                        items(choices.items, key = CaptureInterface::name) { link ->
                            ListItem(
                                headlineContent = { Text(link.label()) },
                                modifier = Modifier.clickable { onSelect(link.name) },
                            )
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onManual) { Text(stringResource(R.string.capture_interface_manual)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(android.R.string.cancel)) } },
    )
}

@Composable
internal fun CaptureInterface.label(): String {
    val kindLabel = when (kind) {
        InterfaceKind.VPN -> R.string.capture_interface_vpn
        InterfaceKind.WIFI -> R.string.capture_interface_wifi
        InterfaceKind.MOBILE -> R.string.capture_interface_mobile
        InterfaceKind.ETHERNET -> R.string.capture_interface_ethernet
        InterfaceKind.TUNNEL -> R.string.capture_interface_tunnel
        InterfaceKind.OTHER -> return name
        InterfaceKind.LOOPBACK -> R.string.capture_interface_loopback
    }
    return stringResource(R.string.capture_interface_option, stringResource(kindLabel), name)
}
