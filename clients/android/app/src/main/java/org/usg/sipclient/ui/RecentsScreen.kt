package org.usg.sipclient.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallMade
import androidx.compose.material.icons.automirrored.filled.CallMissed
import androidx.compose.material.icons.automirrored.filled.CallReceived
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.usg.sipclient.AppViewModel
import uniffi.client_ffi.CallDirection
import uniffi.client_ffi.CallHistoryEntry
import java.text.DateFormat
import java.util.Date

/**
 * Recents tab: call history with direction icons, missed calls in red,
 * tap-to-call, and a Clear button. Ports RecentsView.swift.
 */
@Composable
fun RecentsScreen(model: AppViewModel) {
    val recents by model.recents.collectAsState()
    LaunchedEffect(Unit) { model.refreshRecents() }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Recents", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            TextButton(enabled = recents.isNotEmpty(), onClick = { model.clearRecents() }) {
                Text("Clear")
            }
        }
        Divider()

        if (recents.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("No recent calls", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                // Key on index too: call-history entries can share an id
                // (the same call logged more than once), and LazyColumn
                // throws on duplicate keys.
                itemsIndexed(recents, key = { index, entry -> "$index:${entry.id}" }) { _, entry ->
                    RecentRow(entry) { model.call(entry.remoteUri) }
                    Divider()
                }
            }
        }
    }
}

@Composable
private fun RecentRow(entry: CallHistoryEntry, onCall: () -> Unit) {
    val isMissed = entry.direction == CallDirection.INBOUND && entry.connectTimeUnixMs == null
    val icon = when {
        entry.direction == CallDirection.OUTBOUND -> Icons.AutoMirrored.Filled.CallMade
        isMissed -> Icons.AutoMirrored.Filled.CallMissed
        else -> Icons.AutoMirrored.Filled.CallReceived
    }
    val accent = if (isMissed) Color(0xFFFF3B30) else MaterialTheme.colorScheme.onSurfaceVariant

    val detail = when {
        isMissed -> "Missed"
        entry.durationSecs != null -> formatDuration(entry.durationSecs!!.toInt())
        entry.direction == CallDirection.OUTBOUND -> "No answer"
        else -> "—"
    }
    val time = remember(entry.startTimeUnixMs) {
        DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
            .format(Date(entry.startTimeUnixMs))
    }

    Row(
        Modifier.fillMaxWidth().clickable(onClick = onCall).padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null, tint = accent, modifier = Modifier.size(18.dp))
        Column(Modifier.weight(1f).padding(start = 10.dp)) {
            Text(
                entry.remoteDisplayName ?: entry.remoteUri,
                fontWeight = FontWeight.Medium,
                color = if (isMissed) Color(0xFFFF3B30) else MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
            )
        }
        Text(time, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
