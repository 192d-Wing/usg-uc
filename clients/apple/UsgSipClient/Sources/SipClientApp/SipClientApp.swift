// USG SIP client — SwiftUI app shell (macOS).
//
// Run from clients/apple/UsgSipClient:  swift run SipClientApp
// (macOS mic permission is inherited from the terminal, as with cargo run.)

#if canImport(AppKit)
import AppKit
#endif
#if os(iOS)
import AVFoundation
#endif
import SwiftUI
import UsgSipClient

@main
struct SipClientApp: App {
    @StateObject private var model = AppModel()

    init() {
        setvbuf(stdout, nil, _IOLBF, 0)  // line-buffer events when piped to a log
        initLogging(filter: nil)  // Rust core logs -> stderr (RUST_LOG honored)
        #if os(iOS)
        configureAudioSession()
        #endif
        #if os(macOS)
        // Bare executables (no .app bundle) are never activated by macOS, so
        // the window can't take keyboard focus and clicks are swallowed by
        // focus changes. Activate explicitly. (iOS apps are always foregrounded
        // by the system; no equivalent is needed.)
        DispatchQueue.main.async {
            NSApp.setActivationPolicy(.regular)
            NSApp.activate(ignoringOtherApps: true)
        }
        #endif
    }

    #if os(iOS)
    /// The Rust audio backend (cpal/VPIO) requires an active AVAudioSession
    /// before it can open input/output units. Configure it once at launch:
    /// `.playAndRecord` + `.voiceChat` is the standard VoIP profile (echo
    /// cancellation, ducking, default-to-speaker disabled for earpiece use).
    private func configureAudioSession() {
        let session = AVAudioSession.sharedInstance()
        do {
            try session.setCategory(
                .playAndRecord,
                mode: .voiceChat,
                options: [.allowBluetooth, .allowBluetoothA2DP])
            try session.setActive(true)
        } catch {
            print("AVAudioSession configuration failed: \(error)")
        }
    }
    #endif

    var body: some Scene {
        WindowGroup("USG SIP Client") {
            RootView()
                .environmentObject(model)
                // Window sizing only applies on macOS; iOS is full-screen.
                .modifier(WindowSizing())
        }
        #if os(macOS)
        .windowResizability(.contentSize)
        #endif
    }
}

/// macOS fixed-window sizing; a no-op on iOS (full-screen).
private struct WindowSizing: ViewModifier {
    func body(content: Content) -> some View {
        #if os(macOS)
        content
            .frame(minWidth: 420, minHeight: 640)
            .frame(idealWidth: 420, idealHeight: 640)
        #else
        content
        #endif
    }
}

/// The app's tabs, shown in the custom bottom tab bar.
enum AppTab: String, CaseIterable {
    case dialpad = "Dialpad"
    case contacts = "Contacts"
    case recents = "Recents"
    case settings = "Settings"

    var icon: String {
        switch self {
        case .dialpad: return "circle.grid.3x3.fill"
        case .contacts: return "person.2.fill"
        case .recents: return "clock.fill"
        case .settings: return "gearshape.fill"
        }
    }
}

/// Tab content plus the bottom tab bar, the call overlay, and the error
/// banner, all sandwiched between the classification banner strips (DoD
/// convention: banner top AND bottom — nothing may cover either strip).
/// The call overlay may cover the content area and the tab bar.
struct RootView: View {
    @EnvironmentObject var model: AppModel
    @State private var selectedTab: AppTab = .dialpad

    var body: some View {
        VStack(spacing: 0) {
            ClassificationBannerView(banner: model.classificationBanner)
            BrandingHeaderView()
            Divider()

            ZStack {
                VStack(spacing: 0) {
                    tabContent
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    Divider()
                    TabBarView(selection: $selectedTab)
                }

                if model.hasCallUi {
                    CallView()
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .animation(.easeInOut(duration: 0.2), value: model.hasCallUi)
            .overlay(alignment: .top) { errorBanner }

            ClassificationBannerView(banner: model.classificationBanner)
        }
        .onAppear { model.start() }
    }

    @ViewBuilder
    private var tabContent: some View {
        switch selectedTab {
        case .dialpad: DialpadView()
        case .contacts: ContactsView()
        case .recents: RecentsView()
        case .settings: SettingsView()
        }
    }

    @ViewBuilder
    private var errorBanner: some View {
        if let message = model.errorMessage {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                Text(message)
                    .lineLimit(3)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button {
                    model.errorMessage = nil
                } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .buttonStyle(.plain)
            }
            .font(.callout)
            .padding(10)
            .background(.red.opacity(0.85), in: RoundedRectangle(cornerRadius: 8))
            .foregroundColor(.white)
            .padding(.horizontal, 12)
            .padding(.top, 8)
            .transition(.move(edge: .top).combined(with: .opacity))
        }
    }
}

/// Custom bottom navigation bar: a row of equal-size square buttons, one per
/// tab — icon above a small caption label. Sits directly above the bottom
/// classification strip.
struct TabBarView: View {
    @Binding var selection: AppTab

    var body: some View {
        HStack(spacing: 12) {
            ForEach(AppTab.allCases, id: \.self) { tab in
                tabButton(tab)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .background(.bar)
    }

    private func tabButton(_ tab: AppTab) -> some View {
        let selected = selection == tab
        return Button {
            selection = tab
        } label: {
            VStack(spacing: 4) {
                Image(systemName: tab.icon)
                    .font(.system(size: 20))
                Text(tab.rawValue)
                    .font(.system(size: 10, weight: .medium))
            }
            .frame(width: 60, height: 60)
            .foregroundColor(selected ? .accentColor : .secondary)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(selected ? Color.accentColor.opacity(0.15) : Color.clear)
            )
            .contentShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
        .accessibilityLabel(tab.rawValue)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// DoD-standard classification banner: a full-width strip pinned to the very
/// top and bottom of the window, above/below all tabs and the call overlay.
struct ClassificationBannerView: View {
    /// `nil` until the core loads; fail safe to the CUI marking meanwhile.
    let banner: ClassificationBanner?

    /// Marking text per banner conventions: `LEVEL//CAVEATS//DISSEM`.
    private var text: String {
        guard let banner else { return "CUI" }
        var parts = [banner.level]
        if !banner.caveats.isEmpty { parts.append(banner.caveats.joined(separator: "/")) }
        if !banner.dissem.isEmpty { parts.append(banner.dissem.joined(separator: "/")) }
        return parts.joined(separator: "//")
    }

    /// Standard banner colors; unrecognized levels fall back to CUI purple.
    private var color: Color {
        switch banner?.level {
        case "UNCLASSIFIED": return Color(red: 0x00 / 255, green: 0x7A / 255, blue: 0x33 / 255)
        case "CONFIDENTIAL": return Color(red: 0x00 / 255, green: 0x33 / 255, blue: 0xA0 / 255)
        case "SECRET": return Color(red: 0xC8 / 255, green: 0x10 / 255, blue: 0x2E / 255)
        case "TOP SECRET": return Color(red: 0xFF / 255, green: 0x8C / 255, blue: 0x00 / 255)
        default: return Color(red: 0x50 / 255, green: 0x2B / 255, blue: 0x85 / 255)  // CUI
        }
    }

    var body: some View {
        Text(text)
            .font(.system(size: 12, weight: .bold))
            .foregroundColor(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 3)
            .background(color)
            .accessibilityLabel("Classification: \(text)")
    }
}

/// Compact branding row: DoW seal (bundled resource) plus the app title.
/// Falls back to an SF Symbol shield if the seal asset is missing.
struct BrandingHeaderView: View {
    private static let seal: PlatformImage? = Bundle.appResources
        .url(forResource: "DOW-Seal", withExtension: "png")
        .flatMap { PlatformImage.load(contentsOf: $0) }

    var body: some View {
        HStack(spacing: 8) {
            if let seal = Self.seal {
                Image(platformImage: seal)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFit()
                    .frame(width: 24, height: 24)
            } else {
                Image(systemName: "shield.fill")
                    .font(.system(size: 18))
                    .foregroundColor(.secondary)
            }
            Text("USG SIP Client")
                .font(.system(size: 13, weight: .semibold))
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }
}
