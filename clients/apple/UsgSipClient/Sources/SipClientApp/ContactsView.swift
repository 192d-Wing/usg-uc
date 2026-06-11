// Contacts tab: searchable list, tap-to-call, add/edit sheet, delete.

import SwiftUI
import UsgSipClient

struct ContactsView: View {
    @EnvironmentObject var model: AppModel
    @State private var search = ""
    @State private var editorTarget: ContactEditorTarget?

    private var filtered: [Contact] {
        let needle = search.trimmingCharacters(in: .whitespaces).lowercased()
        guard !needle.isEmpty else { return model.contacts }
        return model.contacts.filter { contact in
            contact.name.lowercased().contains(needle)
                || contact.sipUri.lowercased().contains(needle)
                || contact.phoneNumbers.contains {
                    $0.number.lowercased().contains(needle)
                }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "magnifyingglass").foregroundColor(.secondary)
                TextField("Search contacts", text: $search)
                    .textFieldStyle(.plain)
                Button {
                    editorTarget = .new
                } label: {
                    Image(systemName: "plus")
                }
                .help("Add Contact")
            }
            .padding(10)

            Divider()

            if filtered.isEmpty {
                Spacer()
                Text(model.contacts.isEmpty ? "No contacts yet" : "No matches")
                    .foregroundColor(.secondary)
                Spacer()
            } else {
                List(filtered, id: \.id) { contact in
                    ContactRow(contact: contact)
                        .contentShape(Rectangle())
                        .onTapGesture { model.call(contact.sipUri) }
                        .contextMenu {
                            Button("Call") { model.call(contact.sipUri) }
                            ForEach(
                                Array(contact.phoneNumbers.enumerated()), id: \.offset
                            ) { _, phone in
                                Button("Call \(phone.kind.displayName): \(phone.number)") {
                                    model.call(phone.number)
                                }
                            }
                            Divider()
                            Button("Edit…") { editorTarget = .edit(contact) }
                            Button("Delete", role: .destructive) {
                                model.removeContact(id: contact.id)
                            }
                        }
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) {
                                model.removeContact(id: contact.id)
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                }
                .listStyle(.inset)
            }
        }
        .sheet(item: $editorTarget) { target in
            ContactEditorView(target: target)
                .environmentObject(model)
        }
        .onAppear { model.refreshContacts() }
    }
}

private struct ContactRow: View {
    let contact: Contact

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(contact.name).font(.body.weight(.medium))
                Text(contact.sipUri)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Image(systemName: "phone.fill")
                .foregroundColor(.green)
                .font(.caption)
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Add/edit sheet

enum ContactEditorTarget: Identifiable {
    case new
    case edit(Contact)

    var id: String {
        switch self {
        case .new: return "new"
        case let .edit(contact): return contact.id
        }
    }
}

/// One editable phone-number row.
private struct EditablePhone: Identifiable {
    let id = UUID()
    var number = ""
    var kind = PhoneNumberKind.work
}

struct ContactEditorView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let target: ContactEditorTarget
    @State private var name = ""
    @State private var sipUri = ""
    @State private var phones: [EditablePhone] = []
    @State private var loaded = false

    private var isNew: Bool {
        if case .new = target { return true }
        return false
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section("Contact") {
                    TextField("Name", text: $name)
                    TextField("SIP URI (sip:user@host)", text: $sipUri)
                }
                Section("Phone Numbers") {
                    ForEach($phones) { $phone in
                        HStack {
                            Picker("", selection: $phone.kind) {
                                ForEach(
                                    [
                                        PhoneNumberKind.work, .mobile, .home,
                                        .fax, .other,
                                    ], id: \.self
                                ) { kind in
                                    Text(kind.displayName).tag(kind)
                                }
                            }
                            .labelsHidden()
                            .frame(width: 90)
                            TextField("Number", text: $phone.number)
                            Button {
                                phones.removeAll { $0.id == phone.id }
                            } label: {
                                Image(systemName: "minus.circle.fill")
                                    .foregroundColor(.red)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    Button {
                        phones.append(EditablePhone())
                    } label: {
                        Label("Add Number", systemImage: "plus.circle.fill")
                    }
                    .buttonStyle(.plain)
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(isNew ? "Add" : "Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(
                        name.trimmingCharacters(in: .whitespaces).isEmpty
                            || sipUri.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(12)
        }
        .frame(width: 380, height: 420)
        .onAppear(perform: load)
    }

    private func load() {
        guard !loaded else { return }
        loaded = true
        if case let .edit(contact) = target {
            name = contact.name
            sipUri = contact.sipUri
            phones = contact.phoneNumbers.map {
                EditablePhone(number: $0.number, kind: $0.kind)
            }
        }
    }

    private func save() {
        let numbers = phones
            .filter { !$0.number.trimmingCharacters(in: .whitespaces).isEmpty }
            .map {
                PhoneNumber(
                    number: $0.number.trimmingCharacters(in: .whitespaces),
                    kind: $0.kind, label: nil)
            }
        let trimmedName = name.trimmingCharacters(in: .whitespaces)
        let trimmedUri = sipUri.trimmingCharacters(in: .whitespaces)

        switch target {
        case .new:
            model.addContact(
                name: trimmedName, sipUri: trimmedUri, phoneNumbers: numbers)
        case let .edit(original):
            var updated = original
            updated.name = trimmedName
            updated.sipUri = trimmedUri
            updated.phoneNumbers = numbers
            model.updateContact(updated)
        }
        dismiss()
    }
}
