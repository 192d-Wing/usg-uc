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

/// Tab container plus the call overlay and the error banner.
struct RootView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
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
