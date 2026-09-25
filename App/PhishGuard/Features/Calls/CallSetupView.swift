import PhishCore
import SwiftUI

/// Registers (or changes, or removes) this device's line with the relay: the protected phone number, the level
/// at which to warn, whether to speak the warning into the call — and what happens once it is on.
struct CallSetupView: View {
    @Environment(AppEnvironment.self) private var environment
    @Environment(\.dismiss) private var dismiss
    @State private var phoneNumber: String
    @State private var minimumLevel: RiskLevel
    @State private var spokenWarning: Bool
    @State private var isWorking = false
    @State private var errorMessage: String?
    @State private var showRemoveConfirmation = false
    private let line: CallLine?

    private static let alertLevels: [RiskLevel] = [.low, .medium, .high]

    /// `line` is the current registration (nil when there is none); the other values are the stored defaults the
    /// form starts from when there is no line.
    init(line: CallLine?, phoneNumber: String?, minimumLevel: RiskLevel, spokenWarning: Bool) {
        self.line = line
        _phoneNumber = State(initialValue: line?.phoneNumber ?? phoneNumber ?? "")
        _minimumLevel = State(initialValue: line?.minimumLevel ?? max(minimumLevel, .low))
        _spokenWarning = State(initialValue: line?.spokenWarning ?? spokenWarning)
    }

    private var normalizedNumber: String? { PhoneNumberFormat.normalize(phoneNumber) }

    private var numberFooter: String {
        if let normalizedNumber {
            return "Will be registered as \(PhoneNumberFormat.display(normalizedNumber)). Calls to the guard number ring this number."
        }
        if phoneNumber.trimmingCharacters(in: .whitespaces).isEmpty {
            return "The number of the phone that should ring — usually this iPhone. Include the country code, e.g. +1 415 555 0134."
        }
        return "Enter the full number with its country code, e.g. +1 415 555 0134."
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("+1 415 555 0134", text: $phoneNumber)
                        .keyboardType(.phonePad)
                        .textContentType(.telephoneNumber)
                        .autocorrectionDisabled()
                } header: {
                    Text("Your phone number")
                } footer: {
                    Text(numberFooter)
                }

                Section {
                    ForEach(Self.alertLevels, id: \.self) { level in
                        Button {
                            minimumLevel = level
                        } label: {
                            HStack(alignment: .top, spacing: 12) {
                                Image(systemName: level.symbolName)
                                    .foregroundStyle(level.color)
                                    .frame(width: 24)
                                    .accessibilityHidden(true)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("\(level.displayName) and above")
                                        .foregroundStyle(.primary)
                                    Text(level.callAlertDescription)
                                        .font(.footnote)
                                        .foregroundStyle(.secondary)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                                Spacer()
                                if minimumLevel == level {
                                    Image(systemName: "checkmark")
                                        .foregroundStyle(.tint)
                                        .accessibilityHidden(true)
                                }
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(minimumLevel == level ? [.isSelected] : [])
                    }
                } header: {
                    Text("Warn when")
                } footer: {
                    Text("Every call is still checked; calls below this level are neither listed nor notified.")
                }

                Section {
                    Toggle(isOn: $spokenWarning) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Speak a warning into the call")
                            Text("Only you hear it — the caller does not.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                } footer: {
                    Text("\"This is PhishGuard. This call shows signs of a scam. Do not share codes, card numbers or passwords, and do not buy gift cards. It is safe to hang up now.\" The urgent notification on this phone is sent either way.")
                }

                Section {
                    step(1, "Give people the guard number instead of your own. Calls to it ring your phone as usual.")
                    step(2, "While you talk, the call is transcribed and checked for scam patterns as it happens.")
                    step(3, "If it looks like a scam you get an urgent notification — and, if turned on, the spoken warning.")
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: "lock.shield")
                            .foregroundStyle(.tint)
                            .frame(width: 24)
                            .accessibilityHidden(true)
                        Text("The call audio is processed by the PhishGuard relay and OpenAI to do this. The relay keeps only the numbers, the times and the verdict — never the transcript.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } header: {
                    Text("What happens")
                }

                if let line {
                    Section {
                        LabeledContent("Guard number", value: PhoneNumberFormat.display(line.guardNumber))
                    } footer: {
                        Text("The number to hand out. It is the relay's phone number and stays the same.")
                    }
                    Section {
                        Button(role: .destructive) {
                            showRemoveConfirmation = true
                        } label: {
                            Label("Remove protection", systemImage: "phone.down")
                        }
                        .disabled(isWorking)
                    } footer: {
                        Text("Calls to the guard number will no longer reach you. Flagged calls already listed are kept.")
                    }
                }

                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle")
                            .font(.footnote)
                            .foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .navigationTitle(line == nil ? "Call protection" : "Call protection settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .disabled(isWorking)
                }
                ToolbarItem(placement: .confirmationAction) {
                    if isWorking {
                        ProgressView()
                    } else {
                        Button("Save") { save() }
                            .disabled(normalizedNumber == nil)
                    }
                }
            }
            .confirmationDialog("Remove call protection?", isPresented: $showRemoveConfirmation, titleVisibility: .visible) {
                Button("Remove protection", role: .destructive) { remove() }
            } message: {
                Text("The relay forgets your number. You can set it up again at any time.")
            }
            .interactiveDismissDisabled(isWorking)
        }
    }

    private func step(_ number: Int, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(number)")
                .font(.subheadline.weight(.bold))
                .foregroundStyle(.tint)
                .frame(width: 24)
                .accessibilityHidden(true)
            Text(text)
                .font(.subheadline)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 2)
        .accessibilityLabel("Step \(number): \(text)")
    }

    // MARK: - Actions

    private func save() {
        guard let number = normalizedNumber else { return }
        isWorking = true
        errorMessage = nil
        Task {
            do {
                try await environment.callGuard.registerLine(phoneNumber: number, minimumLevel: minimumLevel, spokenWarning: spokenWarning)
                // The alert on a scam call is a notification: a line without notification permission is silent
                // protection. Ask now if the phone was never asked (the mail onboarding may have been skipped).
                if await environment.notificationManager.authorizationStatus() == .notDetermined {
                    _ = await environment.notificationManager.requestAuthorization()
                }
                dismiss()
            } catch {
                errorMessage = CallGuardCoordinator.message(for: error)
            }
            isWorking = false
        }
    }

    private func remove() {
        isWorking = true
        errorMessage = nil
        Task {
            do {
                try await environment.callGuard.removeLine()
                dismiss()
            } catch {
                errorMessage = CallGuardCoordinator.message(for: error)
            }
            isWorking = false
        }
    }
}

#Preview("New") {
    CallSetupView(line: nil, phoneNumber: nil, minimumLevel: .medium, spokenWarning: true)
        .environment(AppEnvironment.preview())
}

#Preview("Existing") {
    CallSetupView(
        line: CallLine(lineID: "line-1", guardNumber: DemoCalls.guardNumber, phoneNumber: "+14155550100", minimumLevel: .medium, spokenWarning: true, createdAt: 0),
        phoneNumber: nil, minimumLevel: .medium, spokenWarning: true
    )
    .environment(AppEnvironment.preview())
}
