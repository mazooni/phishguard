import SwiftUI

/// Rounded, grouped-background container used for header and reason cards.
struct Card<Content: View>: View {
    var tint: Color?
    let content: Content

    init(tint: Color? = nil, @ViewBuilder content: () -> Content) {
        self.tint = tint
        self.content = content()
    }

    var body: some View {
        // The VStack keeps multi-child content as one view: modifiers on a bare TupleView would apply per child
        // (splitting the card into several rows inside a List).
        VStack(alignment: .leading, spacing: 0) {
            content
        }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background {
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .fill(Color(.secondarySystemGroupedBackground))
                    .overlay {
                        if let tint {
                            RoundedRectangle(cornerRadius: 20, style: .continuous)
                                .fill(tint.opacity(0.08))
                        }
                    }
            }
            .overlay {
                if let tint {
                    RoundedRectangle(cornerRadius: 20, style: .continuous)
                        .strokeBorder(tint.opacity(0.35), lineWidth: 1)
                }
            }
    }
}

/// Heading + optional icon used at the top of a `Card`.
struct CardTitle: View {
    let title: String
    var systemImage: String?
    var tint: Color = .accentColor

    var body: some View {
        HStack(spacing: 8) {
            if let systemImage {
                Image(systemName: systemImage)
                    .foregroundStyle(tint)
                    .accessibilityHidden(true)
            }
            Text(title)
                .font(.headline)
        }
    }
}

#Preview {
    ScrollView {
        VStack(spacing: 12) {
            Card {
                CardTitle(title: "Plain card", systemImage: "square.text.square")
                Text("Body text").foregroundStyle(.secondary)
            }
            Card(tint: .red) {
                CardTitle(title: "Tinted card", systemImage: "exclamationmark.octagon.fill", tint: .red)
                Text("Body text").foregroundStyle(.secondary)
            }
        }
        .padding()
    }
    .background(Color(.systemGroupedBackground))
}
