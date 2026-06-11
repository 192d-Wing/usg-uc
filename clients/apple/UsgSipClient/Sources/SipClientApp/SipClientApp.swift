// USG SIP client — SwiftUI app shell (macOS).
//
// Run from clients/apple/UsgSipClient:  swift run SipClientApp
// (macOS mic permission is inherited from the terminal, as with cargo run.)

import AppKit
import SwiftUI
import UsgSipClient

@main
struct SipClientApp: App {
    @StateObject private var model = AppModel()

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
        WindowGroup("USG SIP Client") {
            RootView()
                .environmentObject(model)
                .frame(minWidth: 420, minHeight: 640)
                .frame(idealWidth: 420, idealHeight: 640)
        }
        .windowResizability(.contentSize)
    }
}

/// Tab container plus the call overlay and the error banner, all beneath the
/// classification banner strip (which nothing may cover).
struct RootView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            ClassificationBannerView(banner: model.classificationBanner)
            BrandingHeaderView()
            Divider()

            ZStack {
                TabView {
                    DialpadView()
                        .tabItem { Label("Dialpad", systemImage: "circle.grid.3x3.fill") }
                    ContactsView()
                        .tabItem { Label("Contacts", systemImage: "person.2.fill") }
                    RecentsView()
                        .tabItem { Label("Recents", systemImage: "clock.fill") }
                    SettingsView()
                        .tabItem { Label("Settings", systemImage: "gearshape.fill") }
                }

                if model.hasCallUi {
                    CallView()
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .animation(.easeInOut(duration: 0.2), value: model.hasCallUi)
            .overlay(alignment: .top) { errorBanner }
        }
        .onAppear { model.start() }
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

/// DoD-standard classification banner: a full-width strip pinned to the very
/// top of the window, above all tabs and the call overlay.
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
    private static let seal: NSImage? = Bundle.module
        .url(forResource: "DOW-Seal", withExtension: "png")
        .flatMap { NSImage(contentsOf: $0) }

    var body: some View {
        HStack(spacing: 8) {
            if let seal = Self.seal {
                Image(nsImage: seal)
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
