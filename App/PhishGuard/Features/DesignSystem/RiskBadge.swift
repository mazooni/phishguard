import PhishCore
import SwiftUI

/// Capsule badge for a `RiskLevel` (high red, medium orange, low yellow).
struct RiskBadge: View {
    enum Size { case compact, regular }

    let level: RiskLevel
    var size: Size = .regular

    var body: some View {
        Label(size == .compact ? level.shortName : level.displayName, systemImage: level.symbolName)
            .labelStyle(.titleAndIcon)
            .font(size == .compact ? .caption2.weight(.bold) : .caption.weight(.bold))
            .padding(.horizontal, size == .compact ? 6 : 8)
            .padding(.vertical, size == .compact ? 2 : 4)
            .background(level.color.opacity(0.16), in: Capsule())
            .foregroundStyle(level.color)
            .accessibilityLabel(level.displayName)
    }
}

/// Small capsule showing the threat category with its icon.
struct CategoryChip: View {
    let category: ThreatCategory

    var body: some View {
        Label(category.displayName, systemImage: category.symbolName)
            .labelStyle(.titleAndIcon)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(category.color.opacity(0.14), in: Capsule())
            .foregroundStyle(category.color)
            .accessibilityLabel("Category: \(category.displayName)")
    }
}

/// "Heuristic" / "AI" source tag for a reason card.
struct SourceTag: View {
    let source: ReasonSource

    var body: some View {
        Label(source.tagName, systemImage: source.symbolName)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(.quaternary, in: Capsule())
            .foregroundStyle(.secondary)
            .accessibilityLabel(source == .model ? "Found by the on-device model" : "Found by heuristics")
    }
}

/// Circular avatar with the provider's monogram.
struct ProviderAvatar: View {
    let provider: MailProvider
    var diameter: CGFloat = 36

    var body: some View {
        ZStack {
            Circle().fill(provider.brandColor.gradient)
            Text(provider.monogram)
                .font(.system(size: diameter * 0.5, weight: .bold, design: .rounded))
                .foregroundStyle(.white)
        }
        .frame(width: diameter, height: diameter)
        .accessibilityHidden(true)
    }
}

#Preview("Badges") {
    VStack(alignment: .leading, spacing: 12) {
        ForEach(RiskLevel.allCases, id: \.self) { RiskBadge(level: $0) }
        HStack { ForEach(RiskLevel.allCases, id: \.self) { RiskBadge(level: $0, size: .compact) } }
        HStack { ForEach(ThreatCategory.allCases, id: \.self) { CategoryChip(category: $0) } }
        HStack { SourceTag(source: .heuristic); SourceTag(source: .model) }
        HStack { ProviderAvatar(provider: .gmail); ProviderAvatar(provider: .microsoft) }
    }
    .padding()
}
