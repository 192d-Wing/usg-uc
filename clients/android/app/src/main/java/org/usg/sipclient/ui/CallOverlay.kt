package org.usg.sipclient.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CallEnd
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.MicOff
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import org.usg.sipclient.AppViewModel
import uniffi.client_ffi.CallState

/** Full-screen overlay shown while a call is active or ringing inbound. Ports CallView.swift. */
@Composable
fun CallOverlay(model: AppViewModel) {
    val activeCall by model.activeCall.collectAsState()
    val incoming by model.incomingCall.collectAsState()
    val isMuted by model.isMuted.collectAsState()
    val isOnHold by model.isOnHold.collectAsState()
    var showKeypad by remember { mutableStateOf(false) }

    if (activeCall == null) showKeypad = false

    val remoteName = activeCall?.let { it.remoteDisplayName ?: it.remoteUri }
        ?: incoming?.let { it.displayName ?: it.remoteUri } ?: ""
    val remoteDetail = activeCall?.remoteUri ?: incoming?.remoteUri ?: ""

    Surface(Modifier.fillMaxSize(), tonalElevation = 3.dp) {
        Column(
            Modifier.fillMaxSize().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            Spacer(Modifier.size(1.dp))

            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    Icons.Filled.Person,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(72.dp),
                )
                Text(
                    remoteName,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.SemiBold,
                    textAlign = TextAlign.Center,
                    maxLines = 2,
                )
                if (remoteDetail != remoteName) {
                    Text(
                        remoteDetail,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                    )
                }
                Spacer(Modifier.size(4.dp))
                StatusLine(model)
            }

            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                AnimatedVisibility(visible = showKeypad && activeCall != null) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        DtmfPad { model.sendDtmf(it) }
                        Spacer(Modifier.size(18.dp))
                    }
                }

                if (activeCall == null && incoming != null) {
                    // Ringing inbound: Answer / Reject.
                    Row(horizontalArrangement = Arrangement.spacedBy(48.dp)) {
                        RoundButton(Icons.Filled.CallEnd, "Reject", Color(0xFFFF3B30)) { model.reject() }
                        RoundButton(Icons.Filled.Call, "Answer", Color(0xFF34C759)) { model.answer() }
                    }
                } else {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(18.dp),
                    ) {
                        Row(horizontalArrangement = Arrangement.spacedBy(32.dp)) {
                            ToggleButton(
                                if (isMuted) Icons.Filled.MicOff else Icons.Filled.Mic,
                                "Mute", isMuted,
                            ) { model.toggleMute() }
                            ToggleButton(Icons.Filled.Pause, "Hold", isOnHold) { model.toggleHold() }
                            ToggleButton(Icons.Filled.Apps, "Keypad", showKeypad) {
                                showKeypad = !showKeypad
                            }
                        }
                        RoundButton(Icons.Filled.CallEnd, "Hang Up", Color(0xFFFF3B30)) { model.hangup() }
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusLine(model: AppViewModel) {
    val call by model.activeCall.collectAsState()
    val incoming by model.incomingCall.collectAsState()
    val c = call
    if (c != null) {
        val connectMs = c.connectTimeUnixMs
        if (connectMs != null && (c.state == CallState.CONNECTED || c.state == CallState.ON_HOLD)) {
            // Tick once a second from the connect timestamp.
            val elapsed by produceState(initialValue = 0L, c.id) {
                while (true) {
                    value = (System.currentTimeMillis() - connectMs) / 1000
                    delay(1000)
                }
            }
            val text = if (c.state == CallState.ON_HOLD) {
                "On Hold — ${formatDuration(elapsed.toInt())}"
            } else {
                formatDuration(elapsed.toInt())
            }
            Text(text, color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            Text(c.state.displayName(), color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    } else if (incoming != null) {
        Text("Incoming Call…", color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun RoundButton(icon: ImageVector, label: String, color: Color, onClick: () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            Modifier.size(60.dp).clip(CircleShape).background(color).clickable(onClick = onClick),
            contentAlignment = Alignment.Center,
        ) {
            Icon(icon, contentDescription = label, tint = Color.White)
        }
        Text(label, fontSize = 12.sp)
    }
}

@Composable
private fun ToggleButton(icon: ImageVector, label: String, active: Boolean, onClick: () -> Unit) {
    val bg = if (active) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant
    val fg = if (active) Color.White else MaterialTheme.colorScheme.onSurface
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            Modifier.size(48.dp).clip(CircleShape).background(bg).clickable(onClick = onClick),
            contentAlignment = Alignment.Center,
        ) {
            Icon(icon, contentDescription = label, tint = fg)
        }
        Text(label, fontSize = 12.sp)
    }
}
