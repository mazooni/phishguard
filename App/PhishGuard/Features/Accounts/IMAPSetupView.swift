import PhishCore
import SwiftUI
import UIKit

/// Result of a connection attempt, already rendered for the screen.
enum IMAPValidationOutcome: Sendable, Equatable {
    case success
    case failure(String)
}

/// Pure helpers behind the setup form, kept out of the view so they can be tested.
enum IMAPSetupFields {
    /// True when the server fields no longer match what the address alone would fill in — i.e. the user
    /// overrode them and auto-fill must stop writing over their work.
    ///
    /// Deliberately derived from the values rather than from "a field changed": auto-fill itself writes those
    /// fields on every keystroke in the address, so a change alone would mean nothing.
    static func serverWasEditedManually(host: String, port: String, security: IMAPSecurity, email: String) -> Bool {
        if host.isEmpty { return false }
        guard let suggestion = IMAPServerDirectory.suggestedSettings(forEmail: email) else { return true }
        return host != suggestion.host || port != String(suggestion.port) || security != suggestion.security
    }
}

/// Collects an IMAP mailbox's details and proves they work before the account is added.
///
/// The server is auto-filled from the address domain (`IMAPServerDirectory`) and can be overridden under
/// "Server settings". Nothing is stored until the connection test succeeds — `IMAPProvider.signIn` only
/// returns once the mailbox actually opened read-only.
struct IMAPSetupView: View {
    /// Connects, authenticates and opens INBOX read-only.
    var validate: @Sendable (IMAPCredentials) async -> IMAPValidationOutcome
    var onCancel: @MainActor () -> Void
    var onSubmit: @MainActor (IMAPCredentials) -> Void

    @State private var email = ""
    @State private var password = ""
    @State private var displayName = ""
    @State private var host = ""
    @State private var portText = "993"
    @State private var security: IMAPSecurity = .tls
    @State private var showsServerSettings = false
    @State private var serverEditedManually = false
    @State private var isWorking = false
    @State private var outcome: IMAPValidationOutcome?

    private var preset: IMAPServerPreset? { IMAPServerDirectory.preset(forEmail: email) }

    private var credentials: IMAPCredentials? {
        guard let port = Int(portText.trimmingCharacters(in: .whitespaces)) else { return nil }
        let settings = IMAPAccountSettings(
            host: host, port: port, security: security,
            username: email, email: email,
            displayName: displayName
        ).normalized
        guard settings.validationProblem == nil, !password.isEmpty else { return nil }
        return IMAPCredentials(settings: settings, password: password)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("you@example.com", text: $email)
                        .textContentType(.emailAddress)
                        .keyboardType(.emailAddress)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onChange(of: email) { _, newValue in applySuggestion(for: newValue) }
                    SecureField("Password", text: $password)
                        .textContentType(.password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Name (optional)", text: $displayName)
                        .textContentType(.name)
                } header: {
                    Text("Mail account")
                } footer: {
                    Text(passwordFooter)
                }

                Section {
                    DisclosureGroup("Server settings", isExpanded: $showsServerSettings) {
                        LabeledContent("Server") {
                            TextField("imap.example.com", text: $host)
                                .multilineTextAlignment(.trailing)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .keyboardType(.URL)
                                .onChange(of: host) { _, _ in noteServerEdit() }
                        }
                        LabeledContent("Port") {
                            TextField("993", text: $portText)
                                .multilineTextAlignment(.trailing)
                                .keyboardType(.numberPad)
                                .onChange(of: portText) { _, _ in noteServerEdit() }
                        }
                        Picker("Encryption", selection: $security) {
                            ForEach(IMAPSecurity.userSelectable, id: \.self) { option in
                                Text(option.displayName).tag(option)
                            }
                        }
                        .onChange(of: security) { _, newValue in
                            if portText == "993" || portText == "143" { portText = String(newValue.defaultPort) }
                            noteServerEdit()
                        }
                    }
                } footer: {
                    Text(serverFooter)
                }

                Section {
                    Button {
                        runTest()
                    } label: {
                        HStack {
                            Text("Test connection")
                            Spacer()
                            if isWorking { ProgressView() }
                        }
                    }
                    .disabled(credentials == nil || isWorking)

                    if let outcome {
                        switch outcome {
                        case .success:
                            Label("Connected. The mailbox opened read-only.", systemImage: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                                .font(.callout)
                                .fixedSize(horizontal: false, vertical: true)
                        case .failure(let message):
                            Label(message, systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                                .font(.callout)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                } footer: {
                    Text("PhishGuard opens your mailbox read-only — it never marks mail as read, moves it or deletes it — and your password is stored only on this device, in the iOS Keychain.")
                }
            }
            .navigationTitle("Add mail account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { onCancel() }
                        .disabled(isWorking)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") { submit() }
                        .disabled(credentials == nil || isWorking)
                }
            }
        }
        .interactiveDismissDisabled(isWorking)
    }

    private var passwordFooter: String {
        if let preset { return preset.passwordHint ?? "\(preset.name) accounts sign in with your email address and password." }
        return "Most providers need an app-specific password rather than the password you type into their website."
    }

    private var serverFooter: String {
        guard let preset else {
            return host.isEmpty
                ? "Enter your address and PhishGuard fills in the usual server for that domain."
                : "PhishGuard guessed this server from your address. Change it if your provider uses a different one."
        }
        return "Filled in for \(preset.name). Change it only if your provider told you to."
    }

    /// Fills the server fields from the address domain until the user edits them.
    private func applySuggestion(for address: String) {
        outcome = nil
        guard !serverEditedManually else { return }
        guard let suggestion = IMAPServerDirectory.suggestedSettings(forEmail: address) else { return }
        host = suggestion.host
        portText = String(suggestion.port)
        security = suggestion.security
    }

    /// Recomputes whether the server fields are the user's own, so auto-fill stops overwriting them.
    private func noteServerEdit() {
        serverEditedManually = IMAPSetupFields.serverWasEditedManually(
            host: host, port: portText, security: security, email: email
        )
    }

    private func runTest() {
        guard let credentials else { return }
        isWorking = true
        outcome = nil
        Task {
            let result = await validate(credentials)
            isWorking = false
            outcome = result
            if case .failure = result { showsServerSettings = true }
        }
    }

    /// "Add" is the same connection test; the account is only created once it succeeds.
    private func submit() {
        guard let credentials else { return }
        isWorking = true
        outcome = nil
        Task {
            let result = await validate(credentials)
            isWorking = false
            switch result {
            case .success:
                onSubmit(credentials)
            case .failure:
                outcome = result
                showsServerSettings = true
            }
        }
    }
}

// MARK: - Presentation

/// Presents `IMAPSetupView` from a UIKit view controller and returns what the user entered, so
/// `IMAPProvider.signIn` can look like every other provider's sign-in to `AccountLinker`.
@MainActor
enum IMAPSetupPresenter {
    /// Throws `ProviderError.cancelled` when the user backs out (button or swipe-down).
    static func present(
        from presenter: UIViewController,
        validate: @escaping @Sendable (IMAPCredentials) async -> IMAPValidationOutcome
    ) async throws -> IMAPCredentials {
        let box = IMAPSetupBox()
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<IMAPCredentials, Error>) in
            box.continuation = continuation
            let view = IMAPSetupView(
                validate: validate,
                onCancel: { box.finish(.failure(ProviderError.cancelled)) },
                onSubmit: { box.finish(.success($0)) }
            )
            let controller = UIHostingController(rootView: view)
            let delegate = IMAPSetupDismissDelegate { box.finish(.failure(ProviderError.cancelled)) }
            box.hostingController = controller
            box.delegate = delegate
            controller.presentationController?.delegate = delegate
            presenter.present(controller, animated: true)
        }
    }
}

/// Owns the continuation so it is resumed exactly once, whichever way the sheet goes away.
@MainActor
final class IMAPSetupBox {
    var continuation: CheckedContinuation<IMAPCredentials, Error>?
    weak var hostingController: UIViewController?
    /// Retains the presentation-controller delegate, which UIKit only holds weakly.
    var delegate: AnyObject?

    func finish(_ result: Result<IMAPCredentials, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        hostingController?.presentingViewController?.dismiss(animated: true)
        hostingController = nil
        delegate = nil
        continuation.resume(with: result)
    }
}

/// Reports a swipe-to-dismiss as a cancellation.
@MainActor
final class IMAPSetupDismissDelegate: NSObject, UIAdaptivePresentationControllerDelegate {
    private let onDismiss: @MainActor () -> Void

    init(onDismiss: @escaping @MainActor () -> Void) {
        self.onDismiss = onDismiss
    }

    func presentationControllerDidDismiss(_ presentationController: UIPresentationController) {
        onDismiss()
    }
}

#Preview {
    IMAPSetupView(
        validate: { _ in .failure("The mail server rejected the email address or password.") },
        onCancel: {},
        onSubmit: { _ in }
    )
}
