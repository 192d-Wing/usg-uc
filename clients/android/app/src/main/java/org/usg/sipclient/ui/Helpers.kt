package org.usg.sipclient.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import uniffi.client_ffi.CallState
import uniffi.client_ffi.CodecKind
import uniffi.client_ffi.PhoneNumberKind
import uniffi.client_ffi.TransportKind

/** Formats a duration in seconds as `m:ss` (or `h:mm:ss`). */
fun formatDuration(seconds: Int): String {
    val s = seconds.coerceAtLeast(0)
    return if (s >= 3600) {
        "%d:%02d:%02d".format(s / 3600, (s / 60) % 60, s % 60)
    } else {
        "%d:%02d".format(s / 60, s % 60)
    }
}

fun CallState.displayName(): String = when (this) {
    CallState.IDLE -> "Idle"
    CallState.DIALING -> "Dialing…"
    CallState.RINGING -> "Ringing…"
    CallState.EARLY_MEDIA -> "Ringing…"
    CallState.CONNECTING -> "Connecting…"
    CallState.CONNECTED -> "Connected"
    CallState.ON_HOLD -> "On Hold"
    CallState.TRANSFERRING -> "Transferring…"
    CallState.TERMINATING -> "Ending…"
    CallState.TERMINATED -> "Ended"
}

fun TransportKind.displayName(): String = when (this) {
    TransportKind.TLS -> "TLS"
    TransportKind.UDP -> "UDP"
    TransportKind.TCP -> "TCP"
}

fun CodecKind.displayName(): String = when (this) {
    CodecKind.OPUS -> "Opus"
    CodecKind.G722 -> "G.722"
    CodecKind.G711_ULAW -> "G.711 µ-law"
    CodecKind.G711_ALAW -> "G.711 A-law"
}

fun PhoneNumberKind.displayName(): String = when (this) {
    PhoneNumberKind.WORK -> "Work"
    PhoneNumberKind.MOBILE -> "Mobile"
    PhoneNumberKind.HOME -> "Home"
    PhoneNumberKind.FAX -> "Fax"
    PhoneNumberKind.OTHER -> "Other"
}

/**
 * 3x4 telephone keypad (1-9, star, 0, hash) shared by the dialpad and the in-call
 * DTMF area. Ports DtmfPad from DialpadView.swift.
 */
@Composable
fun DtmfPad(onKey: (String) -> Unit) {
    val rows = listOf(
        listOf("1" to " ", "2" to "ABC", "3" to "DEF"),
        listOf("4" to "GHI", "5" to "JKL", "6" to "MNO"),
        listOf("7" to "PQRS", "8" to "TUV", "9" to "WXYZ"),
        listOf("*" to " ", "0" to "+", "#" to " "),
    )
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        rows.forEach { row ->
            Row(horizontalArrangement = Arrangement.spacedBy(24.dp)) {
                row.forEach { (key, letters) ->
                    Box(
                        Modifier
                            .size(60.dp)
                            .clip(CircleShape)
                            .background(MaterialTheme.colorScheme.surfaceVariant)
                            .clickable { onKey(key) },
                        contentAlignment = Alignment.Center,
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(key, fontSize = 22.sp, fontWeight = FontWeight.Medium)
                            Text(
                                letters,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }
}
