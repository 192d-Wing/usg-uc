package org.usg.sipclient.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Divider
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.usg.sipclient.AppViewModel
import uniffi.client_ffi.Contact
import uniffi.client_ffi.PhoneNumber
import uniffi.client_ffi.PhoneNumberKind

/** Contacts tab: searchable list, tap-to-call, add/edit dialog, delete. Ports ContactsView.swift. */
@Composable
fun ContactsScreen(model: AppViewModel) {
    val contacts by model.contacts.collectAsState()
    var search by remember { mutableStateOf("") }
    var editorTarget by remember { mutableStateOf<Contact?>(null) }
    var showEditor by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) { model.refreshContacts() }

    val filtered = remember(contacts, search) {
        val needle = search.trim().lowercase()
        if (needle.isEmpty()) {
            contacts
        } else {
            contacts.filter {
                it.name.lowercase().contains(needle) ||
                    it.sipUri.lowercase().contains(needle) ||
                    it.phoneNumbers.any { p -> p.number.lowercase().contains(needle) }
            }
        }
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Filled.Search, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
            OutlinedTextField(
                value = search,
                onValueChange = { search = it },
                placeholder = { Text("Search contacts") },
                singleLine = true,
                modifier = Modifier.weight(1f).padding(horizontal = 8.dp),
            )
            IconButton(onClick = { editorTarget = null; showEditor = true }) {
                Icon(Icons.Filled.Add, contentDescription = "Add Contact")
            }
        }
        Divider()

        if (filtered.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    if (contacts.isEmpty()) "No contacts yet" else "No matches",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(filtered, key = { it.id }) { contact ->
                    ContactRow(
                        contact = contact,
                        onCall = { model.call(contact.sipUri) },
                        onEdit = { editorTarget = contact; showEditor = true },
                        onDelete = { model.removeContact(contact.id) },
                    )
                    Divider()
                }
            }
        }
    }

    if (showEditor) {
        ContactEditorDialog(
            existing = editorTarget,
            onDismiss = { showEditor = false },
            onSave = { name, uri, phones ->
                val target = editorTarget
                if (target == null) {
                    model.addContact(name, uri, phones)
                } else {
                    model.updateContact(target.copy(name = name, sipUri = uri, phoneNumbers = phones))
                }
                showEditor = false
            },
        )
    }
}

@Composable
private fun ContactRow(contact: Contact, onCall: () -> Unit, onEdit: () -> Unit, onDelete: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onCall).padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(contact.name, fontWeight = FontWeight.Medium)
            Text(
                contact.sipUri,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        IconButton(onClick = onEdit) {
            Icon(Icons.Filled.Search, contentDescription = "Edit", tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        IconButton(onClick = onDelete) {
            Icon(Icons.Filled.Delete, contentDescription = "Delete", tint = androidx.compose.ui.graphics.Color(0xFFFF3B30))
        }
        IconButton(onClick = onCall) {
            Icon(Icons.Filled.Call, contentDescription = "Call", tint = androidx.compose.ui.graphics.Color(0xFF34C759))
        }
    }
}

private data class EditablePhone(var number: String, var kind: PhoneNumberKind)

@Composable
private fun ContactEditorDialog(
    existing: Contact?,
    onDismiss: () -> Unit,
    onSave: (name: String, sipUri: String, phones: List<PhoneNumber>) -> Unit,
) {
    var name by remember { mutableStateOf(existing?.name ?: "") }
    var sipUri by remember { mutableStateOf(existing?.sipUri ?: "") }
    val phones = remember {
        mutableStateListOf<EditablePhone>().apply {
            existing?.phoneNumbers?.forEach { add(EditablePhone(it.number, it.kind)) }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (existing == null) "Add Contact" else "Edit Contact") },
        text = {
            Column(
                Modifier.heightIn(max = 420.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Name") }, singleLine = true)
                OutlinedTextField(
                    value = sipUri,
                    onValueChange = { sipUri = it },
                    label = { Text("SIP URI (sip:user@host)") },
                    singleLine = true,
                )
                phones.forEachIndexed { index, phone ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        PhoneKindPicker(phone.kind) { phones[index] = phone.copy(kind = it) }
                        OutlinedTextField(
                            value = phone.number,
                            onValueChange = { phones[index] = phone.copy(number = it) },
                            label = { Text("Number") },
                            singleLine = true,
                            modifier = Modifier.weight(1f).padding(start = 8.dp),
                        )
                        IconButton(onClick = { phones.removeAt(index) }) {
                            Icon(Icons.Filled.Delete, contentDescription = "Remove number")
                        }
                    }
                }
                TextButton(onClick = { phones.add(EditablePhone("", PhoneNumberKind.WORK)) }) {
                    Icon(Icons.Filled.Add, contentDescription = null)
                    Text("  Add Number")
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = name.trim().isNotEmpty() && sipUri.trim().isNotEmpty(),
                onClick = {
                    val numbers = phones
                        .filter { it.number.trim().isNotEmpty() }
                        .map { PhoneNumber(number = it.number.trim(), kind = it.kind, label = null) }
                    onSave(name.trim(), sipUri.trim(), numbers)
                },
            ) { Text(if (existing == null) "Add" else "Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
private fun PhoneKindPicker(kind: PhoneNumberKind, onChange: (PhoneNumberKind) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
            value = kind.displayName(),
            onValueChange = {},
            readOnly = true,
            modifier = Modifier
                .menuAnchor()
                .width(110.dp),
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            listOf(
                PhoneNumberKind.WORK, PhoneNumberKind.MOBILE, PhoneNumberKind.HOME,
                PhoneNumberKind.FAX, PhoneNumberKind.OTHER,
            ).forEach { option ->
                DropdownMenuItem(
                    text = { Text(option.displayName()) },
                    onClick = { onChange(option); expanded = false },
                )
            }
        }
    }
}
