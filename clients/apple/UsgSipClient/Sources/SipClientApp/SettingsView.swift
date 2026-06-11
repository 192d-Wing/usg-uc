// Settings tab: SIP account form, registration controls, audio preferences.

import SwiftUI
import UsgSipClient

struct SettingsView: View {
    @EnvironmentObject var model: AppModel

    // Local editable copy of the account (committed on Save).
    @State private var displayName = ""
    @State private var sipUri = ""
    @State private var registrarUri = ""
    @State private var transport = TransportKind.udp
    @State private var callerId = ""
    @State private var digestUsername = ""
    @State private var digestPassword = ""
    @State private var registerExpiry = 300
    @State private var enabled = true
    @State private var loadedAccountId: String?

    var body: some View {
        Form {
            Section("Registration") {
                LabeledContent("Status") {
                    HStack(spacing: 6) {
                        Circle()
                            .fill(statusColor)
                            .frame(width: 8, height: 8)
                        Text(model.registrationText)
                    }
                }
                HStack {
                    Button("Register") { model.registerNow() }
                    Button("Unregister") { model.unregisterNow() }
                        .disabled(model.registration != .registered)
                }
            }

            Section("SIP Account") {
                TextField("Display Name", text: $displayName)
                TextField("SIP URI", text: $sipUri, prompt: Text("sip:user@host"))
                TextField(
                    "Registrar", text: $registrarUri, prompt: Text("sip:registrar.host"))
                Picker("Transport", selection: $transport) {
                    ForEach([TransportKind.tls, .udp, .tcp], id: \.self) { kind in
                        Text(kind.displayName).tag(kind)
                    }
                }
                TextField("Caller ID", text: $callerId, prompt: Text("E.164 or digits"))
                TextField("Auth Username", text: $digestUsername)
                SecureField(
                    "Auth Password", text: $digestPassword,
                    prompt: Text("unchanged if blank"))
                TextField("Register Expiry (s)", value: $registerExpiry, format: .number)
                Toggle("Enabled (auto-register)", isOn: $enabled)
                HStack {
                    Spacer()
                    Button("Save & Re-register") { save() }
                        .disabled(sipUri.isEmpty || registrarUri.isEmpty)
                }
            }

            Section("Audio") {
                Picker(
                    "Microphone",
                    selection: Binding(
                        get: { model.audioSettings?.inputDevice },
                        set: { model.selectInputDevice($0) }
                    )
                ) {
                    Text("System Default").tag(String?.none)
                    ForEach(model.inputDevices, id: \.name) { device in
                        Text(device.displayName).tag(String?.some(device.name))
                    }
                }
                Picker(
                    "Speaker",
                    selection: Binding(
                        get: { model.audioSettings?.outputDevice },
                        set: { model.selectOutputDevice($0) }
                    )
                ) {
                    Text("System Default").tag(String?.none)
                    ForEach(model.outputDevices, id: \.name) { device in
                        Text(device.displayName).tag(String?.some(device.name))
                    }
                }
                Picker(
                    "Preferred Codec",
                    selection: Binding(
                        get: { model.audioSettings?.preferredCodec ?? .opus },
                        set: { model.selectCodec($0) }
                    )
                ) {
                    ForEach(
                        [CodecKind.opus, .g722, .g711Ulaw, .g711Alaw], id: \.self
                    ) { codec in
                        Text(codec.displayName).tag(codec)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .onAppear {
            model.refreshAccount()
            model.refreshAudio()
            populate(from: model.account)
        }
        .onChange(of: model.account?.id) { _ in
            populate(from: model.account)
        }
    }

    private var statusColor: Color {
        switch model.registration {
        case .registered: return .green
        case .registering, .refreshPending: return .yellow
        case .failed, .certificateInvalid, .smartCardNotPresent: return .red
        default: return .gray
        }
    }

    /// Loads the form from the stored account once (or when the account
    /// identity changes); user edits are otherwise preserved.
    private func populate(from account: SipAccountConfig?) {
        guard let account, account.id != loadedAccountId else { return }
        loadedAccountId = account.id
        displayName = account.displayName
        sipUri = account.sipUri
        registrarUri = account.registrarUri
        transport = account.transport
        callerId = account.callerId ?? ""
        digestUsername = account.digestUsername ?? ""
        registerExpiry = Int(account.registerExpiry)
        enabled = account.enabled
    }

    private func save() {
        let account = SipAccountConfig(
            id: model.account?.id ?? "default",
            displayName: displayName,
            sipUri: sipUri.trimmingCharacters(in: .whitespaces),
            registrarUri: registrarUri.trimmingCharacters(in: .whitespaces),
            transport: transport,
            registerExpiry: UInt32(max(60, registerExpiry)),
            enabled: enabled,
            callerId: callerId.isEmpty ? nil : callerId,
            digestUsername: digestUsername.isEmpty ? nil : digestUsername
        )
        model.saveAccount(account, digestPassword: digestPassword)
        digestPassword = ""
    }
}
