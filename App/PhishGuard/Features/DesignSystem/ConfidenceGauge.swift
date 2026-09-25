import PhishCore
import SwiftUI

/// Circular gauge showing 0–100 % confidence that an email is malicious, colored by risk level.
struct ConfidenceGauge: View {
    /// 0...1
    let confidence: Double
    let level: RiskLevel
    var diameter: CGFloat = 132
    var lineWidth: CGFloat = 12

    private var clamped: Double { min(max(confidence, 0), 1) }
    private var percent: Int { Int((clamped * 100).rounded()) }

    var body: some View {
        ZStack {
            Circle()
                .stroke(level.color.opacity(0.18), lineWidth: lineWidth)
            Circle()
                .trim(from: 0, to: clamped)
                .stroke(level.color.gradient, style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.easeOut(duration: 0.6), value: clamped)
            VStack(spacing: 2) {
                Text("\(percent)%")
                    .font(.system(.title, design: .rounded, weight: .bold))
                    .monospacedDigit()
                    .minimumScaleFactor(0.6)
                    .lineLimit(1)
                Text("confidence")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
            }
            .padding(lineWidth + 6)
        }
        .frame(width: diameter, height: diameter)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Confidence")
        .accessibilityValue("\(percent) percent, \(level.displayName)")
    }
}

#Preview {
    HStack(spacing: 20) {
        ConfidenceGauge(confidence: 0.92, level: .high)
        ConfidenceGauge(confidence: 0.61, level: .medium, diameter: 90, lineWidth: 8)
        ConfidenceGauge(confidence: 0.35, level: .low, diameter: 70, lineWidth: 6)
    }
    .padding()
}
