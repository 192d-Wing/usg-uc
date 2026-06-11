package org.usg.sipclient.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Backspace
import androidx.compose.material.icons.filled.Call
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.usg.sipclient.AppViewModel

/**
 * Dialpad tab: number readout + 3x4 keypad. While a call is active the keys send
 * DTMF instead of editing the dial string. Ports DialpadView.swift (the macOS
 * hardware-keyboard monitor is desktop-only and has no Android equivalent).
 */
@Composable
fun DialpadScreen(model: AppViewModel) {
    val activeCall by model.activeCall.collectAsState()
    val inCall = activeCall != null
    var dialString by remember { mutableStateOf("") }

    Column(
        Modifier.fillMaxSize().padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Spacer(Modifier.size(8.dp))

        Text(
            text = dialString.ifEmpty { "Number or sip:user@host" },
            fontSize = 24.sp,
            color = if (dialString.isEmpty()) {
                MaterialTheme.colorScheme.onSurfaceVariant
            } else {
                MaterialTheme.colorScheme.onSurface
            },
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp),
        )

        Spacer(Modifier.size(16.dp))

        DtmfPad { key ->
            if (inCall) model.sendDtmf(key) else dialString += key
        }

        Spacer(Modifier.size(16.dp))

        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            // Spacer to keep the call button centered against the delete button.
            Spacer(Modifier.size(44.dp))

            val canCall = !inCall && dialString.trim().isNotEmpty()
            Box(
                Modifier
                    .size(64.dp)
                    .clip(CircleShape)
                    .background(if (canCall) Color(0xFF34C759) else Color(0xFF34C759).copy(alpha = 0.4f))
                    .clickable(enabled = canCall) { model.call(dialString) },
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Filled.Call, contentDescription = "Call", tint = Color.White)
            }

            Box(
                Modifier
                    .size(44.dp)
                    .clip(CircleShape)
                    .clickable(enabled = dialString.isNotEmpty()) {
                        if (dialString.isNotEmpty()) dialString = dialString.dropLast(1)
                    },
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Backspace,
                    contentDescription = "Delete",
                    tint = if (dialString.isEmpty()) {
                        MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.3f)
                    } else {
                        MaterialTheme.colorScheme.onSurface
                    },
                )
            }
        }
    }
}
