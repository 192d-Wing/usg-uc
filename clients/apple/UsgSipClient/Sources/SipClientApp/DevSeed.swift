import Foundation
import UsgSipClient

/// Debug-only account seeding for the iOS Simulator (and any fresh sandbox).
///
/// A real device build authenticates with a CAC/PIV-derived credential and a
/// user-configured account; the macOS app reads the user's existing
/// `settings.toml`. A fresh iOS Simulator has neither, so registration can't
/// happen without typing the account in by hand on every clean install.
///
/// To avoid that friction during development — and WITHOUT ever committing
/// credentials — this loads a **gitignored** `DevSeed.json` bundled as an app
/// resource. It runs only in DEBUG builds, only when no account is already
/// configured. If the file is absent, seeding is silently skipped.
///
/// Create `Sources/SipClientApp/Resources/DevSeed.json` locally:
/// ```json
/// {
///   "displayName": "John",
///   "sipUri": "sip:user@sip.example.com",
///   "registrarUri": "sip:sip.example.com",
///   "transport": "udp",
///   "callerId": "+15555550123",
///   "username": "user",
///   "password": "secret"
/// }
/// ```
enum DevSeed {
    struct Payload: Decodable {
        let displayName: String
        let sipUri: String
        let registrarUri: String
        let transport: String
        let callerId: String?
        let username: String
        let password: String
    }

    /// Loads the gitignored seed payload, or nil if absent/unreadable.
    static func load() -> Payload? {
        guard
            let url = Bundle.appResources.url(forResource: "DevSeed", withExtension: "json"),
            let data = try? Data(contentsOf: url),
            let payload = try? JSONDecoder().decode(Payload.self, from: data)
        else { return nil }
        return payload
    }

    private static func transportKind(_ raw: String) -> TransportKind {
        switch raw.lowercased() {
        case "tls": return .tls
        case "tcp": return .tcp
        default: return .udp
        }
    }

    /// Builds the FFI account config from the payload.
    static func account(from p: Payload) -> SipAccountConfig {
        SipAccountConfig(
            id: "default",
            displayName: p.displayName,
            sipUri: p.sipUri,
            registrarUri: p.registrarUri,
            transport: transportKind(p.transport),
            registerExpiry: 3600,
            enabled: true,
            callerId: p.callerId,
            digestUsername: p.username
        )
    }
}
