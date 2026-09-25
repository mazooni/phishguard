import Foundation
import MSAL
import UIKit

/// Errors from the MSAL layer, mapped to `ProviderError` by the provider.
enum MicrosoftAuthError: Error, Sendable, Equatable {
    case noResult
    case noAccount
    case interactionRequired
    case cancelled
    case msal(code: Int, description: String)
}

extension ProviderError {
    init(auth error: MicrosoftAuthError) {
        switch error {
        case .interactionRequired, .noAccount:
            self = .notAuthenticated
        case .cancelled:
            self = .cancelled
        case .noResult:
            self = .network("Microsoft sign-in returned no result")
        case .msal(let code, let description):
            self = .network("Microsoft sign-in failed (\(code)): \(description)")
        }
    }
}

/// Thin wrapper around `MSALPublicClientApplication`. MSAL's types are Objective-C and not `Sendable`, so every
/// use stays on the main actor and only `Sendable` values (identifiers, usernames, access tokens) leave.
@MainActor
final class MicrosoftAuthClient {
    /// Personal Microsoft accounts (Outlook.com / Hotmail).
    nonisolated static let authorityURL = URL(string: "https://login.microsoftonline.com/consumers")!

    struct SignInResult: Sendable {
        var accountIdentifier: String
        var username: String?
        var displayName: String?
        var accessToken: String
    }

    private let application: MSALPublicClientApplication
    private let scopes: [String]

    init(clientID: String, bundleIdentifier: String, scopes: [String]) throws {
        self.application = try Self.makeApplication(clientID: clientID, bundleIdentifier: bundleIdentifier)
        self.scopes = scopes
    }

    nonisolated static func redirectURI(bundleIdentifier: String) -> String {
        "msauth.\(bundleIdentifier)://auth"
    }

    nonisolated static func makeApplication(clientID: String, bundleIdentifier: String) throws -> MSALPublicClientApplication {
        let authority = try MSALAADAuthority(url: authorityURL)
        let configuration = MSALPublicClientApplicationConfig(
            clientId: clientID,
            redirectUri: redirectURI(bundleIdentifier: bundleIdentifier),
            authority: authority
        )
        return try MSALPublicClientApplication(configuration: configuration)
    }

    // MARK: - Redirects

    /// True when `url` is the MSAL broker/web redirect for this app (`msauth.<bundle id>://auth`).
    nonisolated static func isRedirectURL(_ url: URL, bundleIdentifier: String) -> Bool {
        guard let scheme = url.scheme?.lowercased() else { return false }
        return scheme == "msauth.\(bundleIdentifier.lowercased())"
    }

    /// MSAL requires this to be called exactly once per redirect URL.
    static func handleRedirect(_ url: URL) -> Bool {
        MSALPublicClientApplication.handleMSALResponse(url, sourceApplication: nil)
    }

    // MARK: - Tokens

    func signIn(presenting viewController: UIViewController) async throws -> SignInResult {
        let webviewParameters = MSALWebviewParameters(authPresentationViewController: viewController)
        let parameters = MSALInteractiveTokenParameters(scopes: scopes, webviewParameters: webviewParameters)
        parameters.promptType = .selectAccount
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<SignInResult, any Error>) in
            application.acquireToken(with: parameters) { @Sendable (result: MSALResult?, error: (any Error)?) in
                if let error {
                    continuation.resume(throwing: Self.mapError(error))
                    return
                }
                guard let result, let identifier = result.account.identifier, !identifier.isEmpty else {
                    continuation.resume(throwing: MicrosoftAuthError.noResult)
                    return
                }
                continuation.resume(returning: SignInResult(
                    accountIdentifier: identifier,
                    username: result.account.username,
                    displayName: result.account.accountClaims?["name"] as? String,
                    accessToken: result.accessToken
                ))
            }
        }
    }

    func silentAccessToken(accountIdentifier: String) async throws -> String {
        guard let account = try account(identifier: accountIdentifier) else { throw MicrosoftAuthError.noAccount }
        let parameters = MSALSilentTokenParameters(scopes: scopes, account: account)
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, any Error>) in
            application.acquireTokenSilent(with: parameters) { @Sendable (result: MSALResult?, error: (any Error)?) in
                if let error {
                    continuation.resume(throwing: Self.mapError(error))
                    return
                }
                guard let result else {
                    continuation.resume(throwing: MicrosoftAuthError.noResult)
                    return
                }
                continuation.resume(returning: result.accessToken)
            }
        }
    }

    // MARK: - Accounts

    func removeAccount(identifier: String) throws {
        guard let account = try account(identifier: identifier) else { return }
        try application.remove(account)
    }

    private func account(identifier: String) throws -> MSALAccount? {
        try application.allAccounts().first { $0.identifier == identifier }
    }

    // MARK: - Errors

    nonisolated static func mapError(_ error: any Error) -> MicrosoftAuthError {
        let nsError = error as NSError
        guard nsError.domain == MSALErrorDomain else {
            return .msal(code: nsError.code, description: nsError.localizedDescription)
        }
        switch nsError.code {
        case MSALError.interactionRequired.rawValue:
            return .interactionRequired
        case MSALError.userCanceled.rawValue:
            return .cancelled
        default:
            return .msal(code: nsError.code, description: nsError.localizedDescription)
        }
    }
}
