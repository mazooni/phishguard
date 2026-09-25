import PhishCore
import SwiftUI

/// Chooses the classifier and manages downloaded MLX models.
struct ModelSettingsView: View {
    @Environment(AppEnvironment.self) private var environment
    @Environment(\.scenePhase) private var scenePhase
    @State private var availability: [ClassifierChoice: ClassifierAvailability] = [:]
    @State private var controller = ModelDownloadController()
    @State private var pendingSelection: ModelManager.CatalogEntry?
    private let recommendation = DeviceModelRecommendation.current

    /// Says plainly that a downloaded model is a foreground-only detector, and names the one model option that
    /// also works while PhishGuard is closed when this iPhone has it. No GPU/Metal wording: the user only needs to
    /// know which checks the model takes part in.
    private var classifierFooter: String {
        var text = "PhishGuard's heuristics always run; the model adds a second opinion. "
            + "Using both models is slower and uses a little more battery, but catches more: each one can "
            + "raise the risk on its own and neither can talk the other down. "
            + "When the chosen model is unavailable, verdicts fall back to heuristics only. "
            + "A downloaded model only runs while PhishGuard is open — checks that happen in the background use "
            + "the built-in rules."
        if availability[.appleFoundation]?.isAvailable == true {
            text += " Apple Intelligence also works in the background on this iPhone."
        }
        return text
    }

    private var modelsFooter: String {
        #if targetEnvironment(simulator)
        return "\(recommendation.memoryDescription) Models are downloaded once and run entirely on this device. They cannot run in the Simulator; use a physical iPhone."
        #else
        return "\(recommendation.memoryDescription) Models are downloaded once and run entirely on this device."
        #endif
    }

    var body: some View {
        @Bindable var settings = environment.settings
        Form {
            Section {
                ForEach(ClassifierChoice.allCases, id: \.self) { choice in
                    Button {
                        settings.classifierChoice = choice
                    } label: {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: choice.symbolName)
                                .foregroundStyle(.tint)
                                .frame(width: 24)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(choice.shortName)
                                    .foregroundStyle(.primary)
                                Text(availabilityText(for: choice))
                                    .font(.footnote)
                                    .foregroundStyle(availability[choice]?.isAvailable == true ? Color.green : Color.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer()
                            if settings.classifierChoice == choice {
                                Image(systemName: "checkmark")
                                    .foregroundStyle(.tint)
                                    .accessibilityHidden(true)
                            }
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(settings.classifierChoice == choice ? [.isSelected] : [])
                }
            } header: {
                Text("Classifier")
            } footer: {
                Text(classifierFooter)
            }

            Section {
                ForEach(ModelManager.catalog) { entry in
                    ModelRow(
                        entry: entry,
                        state: environment.modelManager.downloadStates[entry.id] ?? .notDownloaded,
                        isDownloading: controller.isDownloading(entry.id),
                        isSelected: selectedModelID == entry.id,
                        isPreferred: preferredModelID == entry.id,
                        // The badge names the model PhishGuard ships with, which is what the registry falls back
                        // to, rather than the largest entry this device could hold.
                        isRecommended: ModelManager.recommendedModelID() == entry.id,
                        fitsDevice: recommendation.fits(entry),
                        errorMessage: controller.errorMessages[entry.id],
                        select: { select(entry) },
                        download: { startDownload(of: entry) },
                        cancel: { controller.cancel(entry.id, using: environment.modelManager) },
                        delete: { Task { await controller.delete(entry.id, using: environment.modelManager) } }
                    )
                }
            } header: {
                HStack {
                    Text("Downloadable models (MLX)")
                    Spacer()
                    Text("\(ByteFormat.string(controller.storageUsedBytes)) used")
                        .textCase(nil)
                }
            } footer: {
                Text(modelsFooter)
            }

            Section("Trade-offs") {
                tradeoffRow(.both, "The default where Apple Intelligence is available. The downloaded model decides and Apple Intelligence gives a second opinion, which can confirm something the first model or the built-in rules already found but never raises an alarm on its own. Slower per email and a little more battery; in the background only the second opinion keeps going.")
                tradeoffRow(.mlx, "The default. Works on any recent iPhone, including ones without Apple Intelligence, and never refuses a message. A 2.28 GB one-time download for the default model (the list spans 0.8–2.6 GB); slower and uses more battery than Apple Intelligence, and it only runs while the app is open.")
                tradeoffRow(.appleFoundation, "Free, fast and needs no download. Requires an iPhone 15 Pro or newer with Apple Intelligence turned on and the device language set to a supported language, and its guardrails sometimes decline to read a threatening email.")
                tradeoffRow(.heuristicsOnly, "Instant and needs no model. Catches obvious phishing (bad links, failed authentication) but misses subtler scams.")
            }
        }
        .navigationTitle("Detection model")
        .task {
            await refreshAvailability()
            await controller.refreshStorage(using: environment.modelManager)
        }
        .onChange(of: settings.classifierChoice) { _, _ in
            Task { await refreshAvailability() }
        }
        .onChange(of: settings.selectedMLXModelID) { _, _ in
            Task { await refreshAvailability() }
        }
        .onChange(of: environment.modelManager.downloadStates) { _, _ in
            Task { await refreshAvailability() }
        }
        .onChange(of: scenePhase) { _, phase in
            // A downloaded model reports itself unavailable while PhishGuard is not frontmost, so the reason shown
            // here has to be re-read when the user comes back (e.g. from Control Centre or the app switcher).
            if phase == .active {
                Task { await refreshAvailability() }
            }
        }
        .alert(
            "Larger than recommended",
            isPresented: Binding(get: { pendingSelection != nil }, set: { if !$0 { pendingSelection = nil } }),
            presenting: pendingSelection
        ) { entry in
            Button("Use anyway") {
                settings.selectedMLXModelID = entry.id
                pendingSelection = nil
            }
            Button("Cancel", role: .cancel) {
                pendingSelection = nil
            }
        } message: { entry in
            Text(recommendation.warning(for: entry) ?? "")
        }
    }

    // MARK: - Helpers

    /// The model scans actually use, straight from the registry, so the checkmark and the "Ready:" name can never
    /// disagree with the classifier (nil = nothing usable is downloaded, so no row is checked).
    private var selectedModelID: String? {
        environment.classifierRegistry.effectiveMLXModelID
    }

    /// The model that would run once it is on disk — the default entry until the user picks another one. Its row
    /// says "chosen, not downloaded" while `selectedModelID` is nil, so the screen still names the model the app
    /// intends to use without claiming a model the scans cannot load.
    private var preferredModelID: String {
        environment.classifierRegistry.preferredMLXModelID
    }

    /// Downloading a model while nothing usable is on disk makes it the selection, so the multi-GB download the
    /// user just started is the model that runs. A model that is already downloaded keeps the selection.
    private func startDownload(of entry: ModelManager.CatalogEntry) {
        if selectedModelID == nil {
            environment.settings.selectedMLXModelID = entry.id
        }
        controller.download(entry.id, using: environment.modelManager)
    }

    private func select(_ entry: ModelManager.CatalogEntry) {
        if recommendation.fits(entry) {
            environment.settings.selectedMLXModelID = entry.id
        } else {
            pendingSelection = entry
        }
    }

    private func availabilityText(for choice: ClassifierChoice) -> String {
        switch availability[choice] {
        case .available?:
            if choice == .mlx, let id = selectedModelID, let entry = ModelManager.entry(for: id) {
                return "Ready: \(entry.displayName)"
            }
            return "Ready"
        case .unavailable(let reason)?:
            return reason
        case nil:
            return "Checking availability…"
        }
    }

    private func refreshAvailability() async {
        var result: [ClassifierChoice: ClassifierAvailability] = [:]
        for choice in ClassifierChoice.allCases {
            result[choice] = await environment.classifierRegistry.classifier(for: choice).availability()
        }
        availability = result
    }

    private func tradeoffRow(_ choice: ClassifierChoice, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: choice.symbolName)
                .foregroundStyle(.tint)
                .frame(width: 24)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(choice.shortName)
                    .font(.subheadline.weight(.semibold))
                Text(text)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 2)
    }
}

struct ModelRow: View {
    /// VoiceOver reads each button on its own, so the bare verb would be "Download, button" once per catalog row.
    static func downloadAccessibilityLabel(for entry: ModelManager.CatalogEntry) -> String {
        "Download \(entry.displayName), \(ByteFormat.string(entry.approxSizeBytes))"
    }

    static func deleteAccessibilityLabel(for entry: ModelManager.CatalogEntry) -> String {
        "Delete \(entry.displayName)"
    }

    static func cancelAccessibilityLabel(for entry: ModelManager.CatalogEntry) -> String {
        "Cancel download of \(entry.displayName)"
    }

    /// Radio label for a model that is chosen but not on disk yet, so VoiceOver does not read it as unselected.
    static func pendingAccessibilityLabel(for entry: ModelManager.CatalogEntry) -> String {
        "\(entry.displayName) chosen, not downloaded"
    }

    let entry: ModelManager.CatalogEntry
    let state: ModelManager.DownloadState
    let isDownloading: Bool
    let isSelected: Bool
    /// The model `.mlx` would run once it is downloaded; only meaningful while `isSelected` is false.
    let isPreferred: Bool
    let isRecommended: Bool
    let fitsDevice: Bool
    let errorMessage: String?
    let select: () -> Void
    let download: () -> Void
    let cancel: () -> Void
    let delete: () -> Void

    private var downloading: Bool {
        if case .downloading = state { return true }
        return isDownloading
    }

    private var progress: Double? {
        if case .downloading(let progress) = state { return progress }
        return nil
    }

    private var failureText: String? {
        if case .failed(let message) = state { return message }
        return errorMessage
    }

    private var radioSymbol: String {
        if isSelected { return "checkmark.circle.fill" }
        return isPreferred ? "circle.dashed" : "circle"
    }

    private var radioLabel: String {
        if isSelected { return "\(entry.displayName) selected" }
        if isPreferred { return Self.pendingAccessibilityLabel(for: entry) }
        return "Select \(entry.displayName)"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 12) {
                Button(action: select) {
                    Image(systemName: radioSymbol)
                        .font(.title3)
                        .foregroundStyle(isSelected || isPreferred ? Color.accentColor : Color.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(radioLabel)

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(entry.displayName)
                            .font(.headline)
                        if isRecommended {
                            Text("Recommended")
                                .font(.caption2.weight(.bold))
                                // Without this the capsule hyphenates ("Recommend-ed") as soon as the name next
                                // to it is long or the text size is large.
                                .lineLimit(1)
                                .fixedSize()
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.accentColor.opacity(0.15), in: Capsule())
                                .foregroundStyle(Color.accentColor)
                        }
                    }
                    Text("\(ByteFormat.string(entry.approxSizeBytes)) · \(entry.hfRepo)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(entry.notes)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if !fitsDevice {
                        Label("Above this device's recommendation", systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
                Spacer(minLength: 8)
                actionButton
            }
            if downloading {
                HStack(spacing: 8) {
                    if let progress {
                        ProgressView(value: progress)
                        Text("\(Int((progress * 100).rounded()))%")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    } else {
                        ProgressView()
                            .controlSize(.small)
                        Text("Starting download…")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .accessibilityElement(children: .combine)
            }
            if let failureText {
                Text(failureText)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private var actionButton: some View {
        if downloading {
            Button("Cancel", role: .cancel, action: cancel)
                .buttonStyle(.bordered)
                .controlSize(.small)
                .accessibilityLabel(Self.cancelAccessibilityLabel(for: entry))
        } else {
            switch state {
            case .downloaded:
                Button("Delete", role: .destructive, action: delete)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .accessibilityLabel(Self.deleteAccessibilityLabel(for: entry))
            case .downloading, .notDownloaded, .failed:
                Button("Download", action: download)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .accessibilityLabel(Self.downloadAccessibilityLabel(for: entry))
            }
        }
    }
}

extension ClassifierChoice {
    var shortName: String {
        switch self {
        case .both: return "Both (most accurate)"
        case .appleFoundation: return "Apple Intelligence"
        case .mlx: return "Downloaded model"
        case .heuristicsOnly: return "Heuristics only"
        }
    }

    var symbolName: String {
        switch self {
        case .both: return "square.stack.3d.up"
        case .appleFoundation: return "apple.intelligence"
        case .mlx: return "arrow.down.circle"
        case .heuristicsOnly: return "function"
        }
    }
}

#Preview {
    NavigationStack {
        ModelSettingsView()
    }
    .environment(AppEnvironment.preview())
}
