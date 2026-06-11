// Full-window overlay shown while a call is active or ringing inbound.

import SwiftUI
import UsgSipClient

struct CallView: View {
    @EnvironmentObject var model: AppModel
    @State private var showKeypad = false

    var body: some View {
        VStack(spacing: 20) {
            Spacer()

            VStack(spacing: 6) {
                Image(systemName: "person.crop.circle.fill")
                    .font(.system(size: 56))
                    .foregroundColor(.secondary)
                Text(remoteName)
                    .font(.title2.weight(.semibold))
                    .lineLimit(2)
                    .multilineTextAlignment(.center)
                if remoteDetail != remoteName {
                    Text(remoteDetail)
                        .font(.callout)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
                statusLine
                    .font(.callout.monospacedDigit())
                    .foregroundColor(.secondary)
                    .padding(.top, 4)
            }
            .padding(.horizontal, 24)

            Spacer()

            if showKeypad, model.activeCall != nil {
                DtmfPad { model.sendDtmf($0) }
                    .transition(.opacity)
            }

            controls
                .padding(.bottom, 28)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.regularMaterial)
        .onChange(of: model.activeCall == nil) { _ in showKeypad = false }
    }

    // MARK: Header

    private var remoteName: String {
        if let call = model.activeCall {
            return call.remoteDisplayName ?? call.remoteUri
        }
        if let ringing = model.incomingCall {
            return ringing.displayName ?? ringing.remoteUri
        }
        return ""
    }

    private var remoteDetail: String {
        model.activeCall?.remoteUri ?? model.incomingCall?.remoteUri ?? ""
    }

    @ViewBuilder
    private var statusLine: some View {
        if let call = model.activeCall {
            if let connectMs = call.connectTimeUnixMs,
                call.state == .connected || call.state == .onHold
            {
                // Tick once a second from the connect timestamp.
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let elapsed = Int(
                        context.date.timeIntervalSince1970
                            - Double(connectMs) / 1000.0)
                    Text(
                        call.state == .onHold
                            ? "On Hold — \(formatDuration(elapsed))"
                            : formatDuration(elapsed))
                }
            } else {
                Text(call.state.displayName)
            }
        } else if model.incomingCall != nil {
            Text("Incoming Call…")
        }
    }

    // MARK: Controls

    @ViewBuilder
    private var controls: some View {
        if model.activeCall == nil, model.incomingCall != nil {
            // Ringing inbound: Answer / Reject.
            HStack(spacing: 48) {
                roundButton(
                    "phone.down.fill", label: "Reject", color: .red
                ) { model.reject() }
                roundButton(
                    "phone.fill", label: "Answer", color: .green
                ) { model.answer() }
            }
        } else {
            VStack(spacing: 18) {
                HStack(spacing: 32) {
                    toggleButton(
                        model.isMuted ? "mic.slash.fill" : "mic.fill",
                        label: "Mute", active: model.isMuted
                    ) { model.toggleMute() }
                    toggleButton(
                        "pause.fill", label: "Hold", active: model.isOnHold
                    ) { model.toggleHold() }
                    toggleButton(
                        "circle.grid.3x3.fill", label: "Keypad", active: showKeypad
                    ) {
                        withAnimation(.easeInOut(duration: 0.15)) {
                            showKeypad.toggle()
                        }
                    }
                }
                roundButton(
                    "phone.down.fill", label: "Hang Up", color: .red
                ) { model.hangup() }
            }
        }
    }

    private func roundButton(
        _ systemImage: String, label: String, color: Color,
        action: @escaping () -> Void
    ) -> some View {
        VStack(spacing: 6) {
            Button(action: action) {
                Image(systemName: systemImage)
                    .font(.title2)
                    .frame(width: 60, height: 60)
                    .background(Circle().fill(color))
                    .foregroundColor(.white)
            }
            .buttonStyle(.plain)
            Text(label).font(.caption)
        }
    }

    private func toggleButton(
        _ systemImage: String, label: String, active: Bool,
        action: @escaping () -> Void
    ) -> some View {
        VStack(spacing: 6) {
            Button(action: action) {
                Image(systemName: systemImage)
                    .font(.title3)
                    .frame(width: 48, height: 48)
                    .background(
                        Circle().fill(
                            active
                                ? Color.accentColor
                                : Color.gray.opacity(0.25))
                    )
                    .foregroundColor(active ? .white : .primary)
            }
            .buttonStyle(.plain)
            Text(label).font(.caption)
        }
    }
}
