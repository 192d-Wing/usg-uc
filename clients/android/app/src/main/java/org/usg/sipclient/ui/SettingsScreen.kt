package org.usg.sipclient.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.usg.sipclient.AppViewModel
import uniffi.client_ffi.AudioDevice
import uniffi.client_ffi.CodecKind
import uniffi.client_ffi.RegistrationState
import uniffi.client_ffi.SipAccountConfig
import uniffi.client_ffi.TransportKind

/** Settings tab: SIP account form, registration controls, audio prefs. Ports SettingsView.swift. */
@Composable
fun SettingsScreen(model: AppViewModel) {
    val account by model.account.collectAsState()
    val registration by model.registration.collectAsState()
    val registrationText by model.registrationText.collectAsState()
    val audioSettings by model.audioSettings.collectAsState()
    val inputDevices by model.inputDevices.collectAsState()
    val outputDevices by model.outputDevices.collectAsState()

    LaunchedEffect(Unit) {
        model.refreshAccount()
        model.refreshAudio()
    }

    var displayName by remember { mutableStateOf("") }
    var sipUri by remember { mutableStateOf("") }
    var registrarUri by remember { mutableStateOf("") }
    var transport by remember { mutableStateOf(TransportKind.UDP) }
    var callerId by remember { mutableStateOf("") }
    var digestUsername by remember { mutableStateOf("") }
    var digestPassword by remember { mutableStateOf("") }
    var registerExpiry by remember { mutableStateOf("300") }
    var enabled by remember { mutableStateOf(true) }
    var loadedAccountId by remember { mutableStateOf<String?>(null) }

    // Load the form from the stored account once (or when identity changes);
    // user edits are otherwise preserved.
    LaunchedEffect(account?.id) {
        val a = account
        if (a != null && a.id != loadedAccountId) {
            loadedAccountId = a.id
            displayName = a.displayName
            sipUri = a.sipUri
            registrarUri = a.registrarUri
            transport = a.transport
            callerId = a.callerId ?: ""
            digestUsername = a.digestUsername ?: ""
            registerExpiry = a.registerExpiry.toString()
            enabled = a.enabled
        }
    }

    Column(
        Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        SectionHeader("Registration")
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(8.dp).clip(CircleShape).background(statusColor(registration)),
            )
            Text("  $registrationText", modifier = Modifier.weight(1f))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { model.registerNow() }) { Text("Register") }
            OutlinedButton(
                enabled = registration == RegistrationState.REGISTERED,
                onClick = { model.unregisterNow() },
            ) { Text("Unregister") }
        }

        Divider()
        SectionHeader("SIP Account")
        Field(displayName, "Display Name") { displayName = it }
        Field(sipUri, "SIP URI (sip:user@host)") { sipUri = it }
        Field(registrarUri, "Registrar (sip:registrar.host)") { registrarUri = it }
        EnumPicker(
            label = "Transport",
            value = transport,
            options = listOf(TransportKind.TLS, TransportKind.UDP, TransportKind.TCP),
            display = { it.displayName() },
        ) { transport = it }
        Field(callerId, "Caller ID (E.164 or digits)") { callerId = it }
        Field(digestUsername, "Auth Username") { digestUsername = it }
        Field(
            digestPassword, "Auth Password (unchanged if blank)",
            visual = PasswordVisualTransformation(),
        ) { digestPassword = it }
        Field(registerExpiry, "Register Expiry (s)", keyboard = KeyboardType.Number) {
            registerExpiry = it.filter(Char::isDigit)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Enabled (auto-register)", Modifier.weight(1f))
            Switch(checked = enabled, onCheckedChange = { enabled = it })
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            Button(
                enabled = sipUri.isNotBlank() && registrarUri.isNotBlank(),
                onClick = {
                    val cfg = SipAccountConfig(
                        id = account?.id ?: "default",
                        displayName = displayName,
                        sipUri = sipUri.trim(),
                        registrarUri = registrarUri.trim(),
                        transport = transport,
                        registerExpiry = (registerExpiry.toIntOrNull() ?: 300).coerceAtLeast(60).toUInt(),
                        enabled = enabled,
                        callerId = callerId.ifBlank { null },
                        digestUsername = digestUsername.ifBlank { null },
                    )
                    model.saveAccount(cfg, digestPassword)
                    digestPassword = ""
                },
            ) { Text("Save & Re-register") }
        }

        Divider()
        SectionHeader("Audio")
        DevicePicker("Microphone", audioSettings?.inputDevice, inputDevices) {
            model.selectInputDevice(it)
        }
        DevicePicker("Speaker", audioSettings?.outputDevice, outputDevices) {
            model.selectOutputDevice(it)
        }
        EnumPicker(
            label = "Preferred Codec",
            value = audioSettings?.preferredCodec ?: CodecKind.OPUS,
            options = listOf(CodecKind.OPUS, CodecKind.G722, CodecKind.G711_ULAW, CodecKind.G711_ALAW),
            display = { it.displayName() },
        ) { model.selectCodec(it) }
        Text(
            "Audio devices and live media require the Android Oboe backend, which " +
                "is still landing. Calls connect (SIP signaling works) but no audio " +
                "flows yet.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
}

@Composable
private fun Field(
    value: String,
    label: String,
    keyboard: KeyboardType = KeyboardType.Text,
    visual: androidx.compose.ui.text.input.VisualTransformation =
        androidx.compose.ui.text.input.VisualTransformation.None,
    onChange: (String) -> Unit,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = keyboard),
        visualTransformation = visual,
        modifier = Modifier.fillMaxWidth(),
    )
}

@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
private fun <T> EnumPicker(
    label: String,
    value: T,
    options: List<T>,
    display: (T) -> String,
    onSelect: (T) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
            value = display(value),
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.fillMaxWidth().menuAnchor(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(display(option)) },
                    onClick = { onSelect(option); expanded = false },
                )
            }
        }
    }
}

@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
private fun DevicePicker(
    label: String,
    selected: String?,
    devices: List<AudioDevice>,
    onSelect: (String?) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val display = devices.firstOrNull { it.name == selected }?.displayName ?: "System Default"
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
            value = display,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.fillMaxWidth().menuAnchor(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            DropdownMenuItem(text = { Text("System Default") }, onClick = { onSelect(null); expanded = false })
            devices.forEach { device ->
                DropdownMenuItem(
                    text = { Text(device.displayName) },
                    onClick = { onSelect(device.name); expanded = false },
                )
            }
        }
    }
}

private fun statusColor(state: RegistrationState?): Color = when (state) {
    RegistrationState.REGISTERED -> Color(0xFF34C759)
    RegistrationState.REGISTERING, RegistrationState.REFRESH_PENDING -> Color(0xFFFFCC00)
    RegistrationState.FAILED, RegistrationState.CERTIFICATE_INVALID,
    RegistrationState.SMART_CARD_NOT_PRESENT -> Color(0xFFFF3B30)
    else -> Color(0xFF8E8E93)
}
