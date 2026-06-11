// Dialpad tab: number entry + 3x4 keypad. While a call is active the keys
// send DTMF instead of editing the dial string (the in-call overlay also has
// its own keypad).

import SwiftUI

struct DialpadView: View {
    @EnvironmentObject var model: AppModel
    @State private var dialString = ""

    private var inCall: Bool { model.activeCall != nil }

    var body: some View {
        VStack(spacing: 16) {
            Spacer(minLength: 8)

            TextField("Number or sip:user@host", text: $dialString)
                .textFieldStyle(.plain)
                .font(.system(size: 24, weight: .light, design: .rounded))
                .multilineTextAlignment(.center)
                .onSubmit(placeCall)
                .padding(.horizontal, 24)

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
    }

    private func placeCall() {
        guard !inCall else { return }
        model.call(dialString)
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
