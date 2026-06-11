// Dialpad tab: number readout + 3x4 keypad. While a call is active the keys
// send DTMF instead of editing the dial string (the in-call overlay also has
// its own keypad).
//
// The readout is a plain Text (not a TextField) so there is no blinking text
// cursor; digits come from the keypad buttons, and a window-level NSEvent
// monitor keeps physical-keyboard entry working while the tab is visible.

#if canImport(AppKit)
import AppKit
#endif
import SwiftUI

struct DialpadView: View {
    @EnvironmentObject var model: AppModel
    @State private var dialString = ""
    #if os(macOS)
    @State private var keyMonitor: Any?
    #endif

    private var inCall: Bool { model.activeCall != nil }

    var body: some View {
        VStack(spacing: 16) {
            Spacer(minLength: 8)

            // Non-focusable display readout (no text cursor).
            Text(dialString.isEmpty ? "Number or sip:user@host" : dialString)
                .font(.system(size: 24, weight: .light, design: .rounded))
                .foregroundColor(dialString.isEmpty ? .secondary : .primary)
                .lineLimit(1)
                .truncationMode(.head)
                .frame(maxWidth: .infinity)
                .padding(.horizontal, 24)
                .accessibilityLabel(
                    dialString.isEmpty ? "Number to dial" : "Dialing \(dialString)")

            DtmfPad { key in
                if inCall {
                    model.sendDtmf(key)
                } else {
                    dialString.append(key)
                }
            }

            HStack(spacing: 24) {
                // Balance the delete button so the call button stays centered.
                Circle().fill(.clear).frame(width: 44, height: 44)

                Button(action: placeCall) {
                    Image(systemName: "phone.fill")
                        .font(.title2)
                        .frame(width: 64, height: 64)
                        .background(Circle().fill(.green))
                        .foregroundColor(.white)
                }
                .buttonStyle(.plain)
                .disabled(inCall || dialString.trimmingCharacters(in: .whitespaces).isEmpty)
                .opacity(inCall || dialString.isEmpty ? 0.5 : 1)
                .keyboardShortcut(.defaultAction)

                Button {
                    if !dialString.isEmpty { dialString.removeLast() }
                } label: {
                    Image(systemName: "delete.left")
                        .font(.title3)
                        .frame(width: 44, height: 44)
                }
                .buttonStyle(.plain)
                .disabled(dialString.isEmpty)
                .opacity(dialString.isEmpty ? 0.3 : 1)
            }

            Spacer(minLength: 12)
        }
        .padding()
        .modifier(HardwareKeyboardMonitor(install: installKeyMonitor, remove: removeKeyMonitor))
    }

    private func placeCall() {
        guard !inCall else { return }
        model.call(dialString)
    }

    // MARK: Physical keyboard entry (macOS only)
    //
    // iOS has no hardware-keyboard monitor here — entry is via the on-screen
    // keypad buttons only — so these become no-ops and the modifier below skips
    // the .onAppear/.onDisappear wiring on iOS.

    #if os(macOS)
    /// Window-level key capture: digits/*/#/+ append to the dial string (or
    /// send DTMF in-call), delete is backspace. Installed only while the
    /// dialpad tab is on screen.
    private func installKeyMonitor() {
        guard keyMonitor == nil else { return }
        keyMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            handleKey(event) ? nil : event
        }
    }

    private func removeKeyMonitor() {
        if let keyMonitor { NSEvent.removeMonitor(keyMonitor) }
        keyMonitor = nil
    }

    /// Returns true when the event was consumed.
    private func handleKey(_ event: NSEvent) -> Bool {
        // Leave shortcuts (Cmd-Q etc.) and any focused text editor alone.
        guard event.modifierFlags.intersection([.command, .control, .option]).isEmpty,
            !(NSApp.keyWindow?.firstResponder is NSTextView)
        else { return false }

        if event.keyCode == 51 {  // delete (backspace)
            guard !inCall, !dialString.isEmpty else { return false }
            dialString.removeLast()
            return true
        }
        guard let key = event.charactersIgnoringModifiers, key.count == 1 else {
            return false
        }
        if inCall {
            guard "0123456789*#".contains(key) else { return false }
            model.sendDtmf(key)
        } else {
            guard "0123456789*#+".contains(key) else { return false }
            dialString.append(key)
        }
        return true
    }
    #else
    private func installKeyMonitor() {}
    private func removeKeyMonitor() {}
    #endif
}

/// Wires the hardware-keyboard monitor's lifecycle to the view on macOS; a
/// no-op on iOS (on-screen keypad only).
private struct HardwareKeyboardMonitor: ViewModifier {
    let install: () -> Void
    let remove: () -> Void

    func body(content: Content) -> some View {
        #if os(macOS)
        content
            .onAppear(perform: install)
            .onDisappear(perform: remove)
        #else
        content
        #endif
    }
}

/// 3x4 telephone keypad (123/456/789/*0#) shared by the dialpad and the
/// in-call DTMF sheet.
struct DtmfPad: View {
    let action: (String) -> Void

    private static let rows: [[(key: String, letters: String)]] = [
        [("1", " "), ("2", "ABC"), ("3", "DEF")],
        [("4", "GHI"), ("5", "JKL"), ("6", "MNO")],
        [("7", "PQRS"), ("8", "TUV"), ("9", "WXYZ")],
        [("*", " "), ("0", "+"), ("#", " ")],
    ]

    var body: some View {
        VStack(spacing: 12) {
            ForEach(Self.rows, id: \.first!.key) { row in
                HStack(spacing: 24) {
                    ForEach(row, id: \.key) { entry in
                        Button {
                            action(entry.key)
                        } label: {
                            VStack(spacing: 0) {
                                Text(entry.key)
                                    .font(.system(size: 22, weight: .medium, design: .rounded))
                                Text(entry.letters)
                                    .font(.system(size: 9, weight: .semibold))
                                    .foregroundColor(.secondary)
                            }
                            .frame(width: 56, height: 56)
                            .background(Circle().fill(Color.gray.opacity(0.15)))
                            .contentShape(Circle())
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
    }
}
