// Observable model bridging the Rust SIP core (UsgSipClient FFI) to SwiftUI.
//
// Threading contract (same as SipClientDemo):
//   - Every FFI call blocks on the Rust runtime, so all of them run on a
//     private serial DispatchQueue — never the main thread.
//   - The `client` ivar is only touched on that queue.
//   - All @Published state is mutated on the main thread only.
//   - Rust pushes events on a runtime worker thread; the Listener hops to
//     main before touching the model.

import Foundation
import UsgSipClient

/// A ringing inbound call that has not been answered or rejected yet.
struct RingingCall: Equatable {
    let id: String
    let remoteUri: String
    let displayName: String?
}

final class AppModel: ObservableObject, @unchecked Sendable {
    // MARK: Published state (main thread only)

    @Published var registration: RegistrationState?
    @Published var registrationText = "not started"
    @Published var activeCall: CallInfo?
    @Published var incomingCall: RingingCall?
    @Published var isMuted = false
    @Published var isOnHold = false
    @Published var contacts: [Contact] = []
    @Published var recents: [CallHistoryEntry] = []
    @Published var account: SipAccountConfig?
    @Published var audioSettings: AudioSettings?
    @Published var inputDevices: [AudioDevice] = []
    @Published var outputDevices: [AudioDevice] = []
    @Published var eventLog: [String] = []
    @Published var errorMessage: String?
    @Published var classificationBanner: ClassificationBanner?

    var hasCallUi: Bool { activeCall != nil || incomingCall != nil }

    // MARK: FFI plumbing

    /// Only accessed on `queue`.
    private var client: SipClient?
    private let queue = DispatchQueue(label: "AppModel.ffi", qos: .userInitiated)

    /// Constructs and starts the client. Safe to call repeatedly.
    func start() {
        queue.async { [self] in
            guard client == nil else { return }
            do {
                let client = try SipClient(
                    config: ClientConfig(
                        sipListenAddr: "0.0.0.0:5060",
                        mediaAddr: "0.0.0.0:16384",
                        configDir: nil,
                        dataDir: nil,
                        preferIpv6: false
                    ))
                try client.setEventListener(listener: Listener(model: self))
                try client.initialize()
                self.client = client
                DispatchQueue.main.async {
                    self.registrationText = "initialized"
                }
            } catch {
                DispatchQueue.main.async { self.errorMessage = "\(error)" }
                return
            }
            refreshAll()
        }
    }

    /// Runs an FFI call on the serial queue; errors surface as the banner.
    private func run(_ body: @escaping (SipClient) throws -> Void) {
        queue.async { [self] in
            guard let client else { return }
            do { try body(client) } catch {
                DispatchQueue.main.async { self.errorMessage = "\(error)" }
            }
        }
    }

    /// Runs an FFI query on the serial queue and publishes the result on main.
    private func fetch<T>(
        _ body: @escaping (SipClient) throws -> T,
        publish: @escaping (T) -> Void
    ) {
        run { client in
            let value = try body(client)
            DispatchQueue.main.async { publish(value) }
        }
    }

    // MARK: Calls

    func call(_ target: String) {
        let trimmed = target.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        run { _ = try $0.makeCall(remoteUri: trimmed) }
    }

    func hangup() { run { try $0.hangup() } }

    func answer() {
        guard let id = incomingCall?.id else { return }
        run { try $0.acceptIncomingCall(callId: id) }
    }

    func reject() {
        guard let id = incomingCall?.id else { return }
        incomingCall = nil
        run { try $0.rejectIncomingCall(callId: id) }
    }

    func sendDtmf(_ digit: String) { run { try $0.sendDtmf(digit: digit) } }

    func toggleMute() {
        fetch { $0.toggleMute() } publish: { self.isMuted = $0 }
    }

    func toggleHold() {
        fetch { try $0.toggleHold() } publish: { self.isOnHold = $0 }
    }

    // MARK: Contacts

    func refreshContacts() {
        fetch { $0.listContacts() } publish: { self.contacts = $0 }
    }

    func addContact(name: String, sipUri: String, phoneNumbers: [PhoneNumber]) {
        run { client in
            _ = try client.addContact(
                name: name, sipUri: sipUri, phoneNumbers: phoneNumbers)
        }
        refreshContacts()
    }

    func updateContact(_ contact: Contact) {
        run { try $0.updateContact(contact: contact) }
        refreshContacts()
    }

    func removeContact(id: String) {
        run { try $0.removeContact(contactId: id) }
        refreshContacts()
    }

    // MARK: Recents

    func refreshRecents() {
        fetch { $0.callHistory(limit: 200) } publish: { self.recents = $0 }
    }

    func clearRecents() {
        run { try $0.clearCallHistory() }
        refreshRecents()
    }

    // MARK: Account / registration

    func refreshAccount() {
        fetch { $0.getAccount() } publish: { self.account = $0 }
    }

    /// Persists the account (and password, if non-empty), then re-registers
    /// when the account is enabled.
    func saveAccount(_ account: SipAccountConfig, digestPassword: String) {
        run { client in
            let password = digestPassword.isEmpty ? nil : digestPassword
            try client.updateAccount(account: account, digestPassword: password)
            if account.enabled {
                try client.register()
            }
        }
        refreshAccount()
    }

    func registerNow() { run { try $0.register() } }
    func unregisterNow() { run { try $0.unregister() } }

    // MARK: Audio

    func refreshAudio() {
        fetch { $0.getAudioSettings() } publish: { self.audioSettings = $0 }
        fetch { _ in try listInputDevices() } publish: { self.inputDevices = $0 }
        fetch { _ in try listOutputDevices() } publish: { self.outputDevices = $0 }
    }

    /// Persists the input device preference; retargets a live call too.
    func selectInputDevice(_ name: String?) {
        let inCall = activeCall != nil
        run { client in
            var settings = client.getAudioSettings()
            settings.inputDevice = name
            try client.updateAudioSettings(settings: settings)
            if inCall { try client.switchInputDevice(deviceName: name) }
        }
        refreshAudio()
    }

    /// Persists the output device preference; retargets a live call too.
    func selectOutputDevice(_ name: String?) {
        let inCall = activeCall != nil
        run { client in
            var settings = client.getAudioSettings()
            settings.outputDevice = name
            try client.updateAudioSettings(settings: settings)
            if inCall { try client.switchOutputDevice(deviceName: name) }
        }
        refreshAudio()
    }

    func selectCodec(_ codec: CodecKind) {
        run { client in
            var settings = client.getAudioSettings()
            settings.preferredCodec = codec
            try client.updateAudioSettings(settings: settings)
        }
        refreshAudio()
    }

    private func refreshAll() {
        refreshContacts()
        refreshRecents()
        refreshAccount()
        refreshAudio()
        fetch { $0.classificationBanner() } publish: { self.classificationBanner = $0 }
        fetch { $0.registrationState() } publish: { state in
            if let state {
                self.registration = state
                self.registrationText = Self.describe(state)
            }
        }
    }

    // MARK: Events

    fileprivate func handle(_ event: AppEvent) {
        eventLog.append(String(describing: event))
        if eventLog.count > 300 { eventLog.removeFirst(eventLog.count - 300) }

        switch event {
        case let .registrationStateChanged(_, state):
            registration = state
            registrationText = Self.describe(state)
        case let .callStateChanged(_, _, info):
            if info.state == .terminated {
                if activeCall?.id == info.id { activeCall = nil }
            } else {
                activeCall = info
                isMuted = info.isMuted
                isOnHold = info.isOnHold
            }
            // Once an inbound call leaves ringing (we answered it), the
            // incoming banner is obsolete.
            if let ringing = incomingCall, ringing.id == info.id,
                info.state != .ringing
            {
                incomingCall = nil
            }
        case let .incomingCall(callId, remoteUri, remoteDisplayName):
            incomingCall = RingingCall(
                id: callId, remoteUri: remoteUri, displayName: remoteDisplayName)
        case let .incomingCallCancelled(callId):
            if incomingCall?.id == callId { incomingCall = nil }
        case let .callEnded(callId, _):
            if activeCall?.id == callId || activeCall == nil { activeCall = nil }
            if incomingCall?.id == callId { incomingCall = nil }
            isMuted = false
            isOnHold = false
            refreshRecents()
        case let .error(message):
            errorMessage = message
        case .contactsChanged:
            refreshContacts()
            refreshRecents()
        case .settingsChanged:
            refreshAccount()
            refreshAudio()
        default:
            break
        }
    }

    static func describe(_ state: RegistrationState) -> String {
        switch state {
        case .unregistered: return "Unregistered"
        case .waitingForPin: return "Waiting for PIN"
        case .registering: return "Registering…"
        case .registered: return "Registered"
        case .refreshPending: return "Refreshing…"
        case .failed: return "Registration failed"
        case .smartCardNotPresent: return "Smart card not present"
        case .certificateInvalid: return "Certificate invalid"
        }
    }

    /// Rust pushes events on a runtime worker thread; hop to main.
    /// @unchecked: `model` is weak-only and every access hops to main.
    private final class Listener: EventListener, @unchecked Sendable {
        weak var model: AppModel?
        init(model: AppModel) { self.model = model }
        func onEvent(event: AppEvent) {
            print("event: \(event)")  // mirror to stdout for headless log-watching
            DispatchQueue.main.async { self.model?.handle(event) }
        }
    }
}

// MARK: - Display helpers shared by views

extension CallState {
    var displayName: String {
        switch self {
        case .idle: return "Idle"
        case .dialing: return "Dialing…"
        case .ringing: return "Ringing…"
        case .earlyMedia: return "Ringing…"
        case .connecting: return "Connecting…"
        case .connected: return "Connected"
        case .onHold: return "On Hold"
        case .transferring: return "Transferring…"
        case .terminating: return "Ending…"
        case .terminated: return "Ended"
        }
    }
}

extension TransportKind {
    var displayName: String {
        switch self {
        case .tls: return "TLS"
        case .udp: return "UDP"
        case .tcp: return "TCP"
        }
    }
}

extension CodecKind {
    var displayName: String {
        switch self {
        case .opus: return "Opus"
        case .g722: return "G.722"
        case .g711Ulaw: return "G.711 µ-law"
        case .g711Alaw: return "G.711 A-law"
        }
    }
}

extension PhoneNumberKind {
    var displayName: String {
        switch self {
        case .work: return "Work"
        case .mobile: return "Mobile"
        case .home: return "Home"
        case .fax: return "Fax"
        case .other: return "Other"
        }
    }
}

/// Formats a duration in seconds as `m:ss` (or `h:mm:ss`).
func formatDuration(_ seconds: Int) -> String {
    let s = max(0, seconds)
    if s >= 3600 {
        return String(format: "%d:%02d:%02d", s / 3600, (s / 60) % 60, s % 60)
    }
    return String(format: "%d:%02d", s / 60, s % 60)
}
