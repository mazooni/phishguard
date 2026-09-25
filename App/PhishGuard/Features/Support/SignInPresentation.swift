import UIKit

extension UIApplication {
    /// The frontmost view controller of the key window, used to present OAuth sign-in (AppAuth / MSAL).
    var phishGuardTopViewController: UIViewController? {
        let scenes = connectedScenes.compactMap { $0 as? UIWindowScene }
        let keyWindow = scenes.flatMap(\.windows).first(where: \.isKeyWindow) ?? scenes.first?.windows.first
        var top = keyWindow?.rootViewController
        while let presented = top?.presentedViewController { top = presented }
        return top
    }
}
