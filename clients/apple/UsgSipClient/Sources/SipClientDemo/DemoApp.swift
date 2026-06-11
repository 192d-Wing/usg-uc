// Minimal SwiftUI smoke-test shell for the Rust SIP core.
//
// Proves the Phase 1 FFI path end to end on macOS: construct SipClient,
// receive push events, register, place/answer/end calls. This is NOT the
// product UI — it exists so every layer below the UI is exercised before the
// real SwiftUI app is built.
//
// Run from clients/apple/UsgSipClient:  swift run SipClientDemo
// (macOS mic permission is inherited from the terminal, as with cargo run.)

import AppKit
import SwiftUI
import UsgSipClient

@main
struct SipClientDemoApp: App {
    @StateObject private var model = ClientModel()

    init() {
        setvbuf(stdout, nil, _IOLBF, 0)  // line-buffer events when piped to a log
        initLogging(filter: nil)  // Rust core logs -> stderr (RUST_LOG honored)
        // Bare executables (no .app bundle) are never activated by macOS, so
        // the window can't take keyboard focus and clicks are swallowed by
        // focus changes. Activate explicitly.
        DispatchQueue.main.async {
            NSApp.setActivationPolicy(.regular)
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    var body: some Scene {
        WindowGroup("USG SIP Client (FFI smoke test)") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 420, minHeight: 560)
        }
    }
}

/// Bridges the Rust core to SwiftUI. Owns the SipClient and republishes
/// pushed events as @Published state on the main thread.
final class ClientModel: ObservableObject, @unchecked Sendable {
    @Published var registration: String = "not started"
    @Published var activeCall: CallInfo?
    @Published var incomingCallId: String?
    @Published var eventLog: [String] = []
    @Published var lastError: String?

    private var client: SipClient?

    func start() {
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
            registration = "initialized (auto-register if account configured)"
        } catch {
            lastError = "\(error)"
        }
    }

    func call(_ uri: String) { run { try self.client?.makeCall(remoteUri: uri) } }
    func hangup() { run { try self.client?.hangup() } }
    func answer() {
        guard let id = incomingCallId else { return }
        run { try self.client?.acceptIncomingCall(callId: id) }
    }
    func sendDtmf(_ digit: String) { run { try self.client?.sendDtmf(digit: digit) } }
    func toggleMute() { _ = client?.toggleMute() }

    /// FFI calls block on the Rust runtime; keep them off the main thread.
    private func run(_ body: @escaping () throws -> some Any) {
        DispatchQueue.global(qos: .userInitiated).async {
            do { _ = try body() } catch {
                DispatchQueue.main.async { self.lastError = "\(error)" }
            }
        }
    }

    fileprivate func handle(_ event: AppEvent) {
        eventLog.append(String(describing: event))
        if eventLog.count > 200 { eventLog.removeFirst() }

        switch event {
        case let .registrationStateChanged(_, state):
            registration = String(describing: state)
        case let .callStateChanged(_, _, info):
            activeCall = info.state == .terminated ? nil : info
        case let .incomingCall(callId, remoteUri, _):
            incomingCallId = callId
            eventLog.append("INCOMING from \(remoteUri)")
        case .callEnded, .incomingCallCancelled:
            activeCall = nil
            incomingCallId = nil
        case let .error(message):
            lastError = message
        default:
            break
        }
    }

    /// Rust pushes events on a runtime worker thread; hop to main.
    /// @unchecked: `model` is weak-only and every access hops to main.
    private final class Listener: EventListener, @unchecked Sendable {
        weak var model: ClientModel?
        init(model: ClientModel) { self.model = model }
        func onEvent(event: AppEvent) {
            print("event: \(event)")  // mirror to stdout for headless log-watching
            DispatchQueue.main.async { self.model?.handle(event) }
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var model: ClientModel
    @State private var dialString = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            GroupBox("Registration") {
                Text(model.registration).frame(maxWidth: .infinity, alignment: .leading)
            }

            GroupBox("Call") {
                HStack {
                    TextField("sip:user@host or number", text: $dialString)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { model.call(dialString) }
                    Button("Call") { model.call(dialString) }
                        .disabled(dialString.isEmpty)
                }
                HStack {
                    Button("Answer") { model.answer() }
                        .disabled(model.incomingCallId == nil)
                    Button("Hang Up") { model.hangup() }
                        .disabled(model.activeCall == nil)
                    Button("Mute") { model.toggleMute() }
                        .disabled(model.activeCall == nil)
                    Spacer()
                    if let call = model.activeCall {
                        Text("\(String(describing: call.state)) — \(call.remoteUri)")
                            .font(.callout)
                    }
                }
            }

            if let error = model.lastError {
                Text(error).foregroundColor(.red).font(.callout)
            }

            GroupBox("Events") {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(model.eventLog.enumerated()), id: \.offset) { _, line in
                            Text(line).font(.system(.caption2, design: .monospaced))
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .frame(maxHeight: .infinity)
        }
        .padding()
        .onAppear { model.start() }
    }
}
