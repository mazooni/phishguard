import SwiftData
import SwiftUI

@main
struct PhishGuardApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @Environment(\.scenePhase) private var scenePhase

    private var environment: AppEnvironment { AppEnvironment.shared }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(environment)
                .onOpenURL { url in
                    environment.handleOpenURL(url)
                }
        }
        .modelContainer(environment.container)
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .active:
                environment.scanOnActivate()
            case .background:
                environment.didEnterBackground()
            case .inactive:
                // Not frontmost any more (Control Centre, app switcher, incoming call, screen lock): iOS refuses
                // GPU work from here on, so the local model must stop before `.background` is ever reached.
                environment.willResignActive()
            @unknown default:
                break
            }
        }
    }
}
