// Recents tab: call history list with direction icons, missed calls in red,
// tap-to-call, and a Clear button.

import SwiftUI
import UsgSipClient

struct RecentsView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Recents").font(.headline)
                Spacer()
                Button("Clear") { model.clearRecents() }
                    .disabled(model.recents.isEmpty)
            }
            .padding(10)

            Divider()

            if model.recents.isEmpty {
                Spacer()
                Text("No recent calls")
                    .foregroundColor(.secondary)
                Spacer()
            } else {
                List(model.recents, id: \.id) { entry in
                    RecentRow(entry: entry)
                        .contentShape(Rectangle())
                        .onTapGesture { model.call(entry.remoteUri) }
                        .contextMenu {
                            Button("Call") { model.call(entry.remoteUri) }
                        }
                }
                .listStyle(.inset)
            }
        }
        .onAppear { model.refreshRecents() }
    }
}

private struct RecentRow: View {
    let entry: CallHistoryEntry

    /// Inbound and never connected = missed (includes local rejects).
    private var isMissed: Bool {
        entry.direction == .inbound && entry.connectTimeUnixMs == nil
    }

    private var directionIcon: String {
        switch entry.direction {
        case .outbound: return "arrow.up.right"
        case .inbound: return isMissed ? "phone.arrow.down.left" : "arrow.down.left"
        }
    }

    private static let timeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        formatter.doesRelativeDateFormatting = true
        return formatter
    }()

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: directionIcon)
                .font(.caption.weight(.bold))
                .foregroundColor(isMissed ? .red : .secondary)
                .frame(width: 18)

            VStack(alignment: .leading, spacing: 2) {
                Text(entry.remoteDisplayName ?? entry.remoteUri)
                    .font(.body.weight(.medium))
                    .foregroundColor(isMissed ? .red : .primary)
                    .lineLimit(1)
                Text(detailLine)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            Text(
                Self.timeFormatter.string(
                    from: Date(
                        timeIntervalSince1970: Double(entry.startTimeUnixMs) / 1000.0))
            )
            .font(.caption)
            .foregroundColor(.secondary)
        }
        .padding(.vertical, 2)
    }

    private var detailLine: String {
        if isMissed { return "Missed" }
        if let duration = entry.durationSecs {
            return formatDuration(Int(duration))
        }
        return entry.direction == .outbound ? "No answer" : "—"
    }
}
