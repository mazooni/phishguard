import SwiftData
import SwiftUI

/// Chooses between onboarding and the main tab UI.
struct RootView: View {
    @Environment(AppEnvironment.self) private var environment

    var body: some View {
        Group {
            if environment.settings.hasCompletedOnboarding {
                MainTabView()
                    .transition(.opacity)
            } else {
                OnboardingView()
                    .transition(.opacity)
            }
        }
        .animation(.default, value: environment.settings.hasCompletedOnboarding)
        .task {
            // First launch only: "Both models" is the default where Apple Intelligence is available, which
            // cannot be decided synchronously in `SettingsStore`.
            await environment.applyDefaultClassifierChoiceIfNeeded()
        }
        .onAppear {
            #if DEBUG
            DemoData.seedIfRequested(into: environment)
            DemoData.openNewestRecordIfRequested(in: environment)
            DemoData.openNewestCallIfRequested(in: environment)
            DemoData.startDemoCallIfRequested(in: environment)
            #endif
        }
    }
}

enum AppTab: String, Hashable {
    case alerts
    case calls
    case settings
}

private struct MainTabView: View {
    @Environment(AppEnvironment.self) private var environment
    @Query(filter: #Predicate<FlaggedEmailRecord> { !$0.isRead }) private var unread: [FlaggedEmailRecord]
    @Query(filter: #Predicate<FlaggedCallRecord> { !$0.isRead }) private var unreadCalls: [FlaggedCallRecord]
    @State private var selection: AppTab = MainTabView.initialTab

    var body: some View {
        TabView(selection: $selection) {
            Tab("Alerts", systemImage: "shield.lefthalf.filled", value: .alerts) {
                HomeView()
            }
            .badge(unread.count)

            Tab("Calls", systemImage: "phone.badge.waveform", value: .calls) {
                CallsView()
            }
            .badge(unreadCalls.count)

            Tab("Settings", systemImage: "gearshape", value: .settings) {
                NavigationStack {
                    SettingsView()
                }
            }
        }
        .onChange(of: environment.pendingRecordID) { _, pending in
            // A tapped alert notification always lands on the Alerts tab; HomeView then opens the record.
            if pending != nil { selection = .alerts }
        }
        .onChange(of: environment.callGuard.pendingCallID, initial: true) { _, pending in
            // A tapped call alert lands on the Calls tab; CallsView then opens the call. `initial` covers a cold
            // launch from the banner, where the tap can be delivered before this view first appears — the Alerts
            // tab is the default, so without it the call would stay hidden.
            if pending != nil { selection = .calls }
        }
    }

    /// Debug builds honor `-PGInitialTab settings` (used for screenshots).
    private static var initialTab: AppTab {
        #if DEBUG
        if let raw = UserDefaults.standard.string(forKey: "PGInitialTab"), let tab = AppTab(rawValue: raw) {
            return tab
        }
        #endif
        return .alerts
    }
}

#Preview("Main") {
    let environment = AppEnvironment.preview()
    environment.settings.hasCompletedOnboarding = true
    DemoData.seed(into: environment.container)
    return RootView()
        .environment(environment)
        .modelContainer(environment.container)
}

#Preview("Onboarding") {
    let environment = AppEnvironment.preview()
    environment.settings.hasCompletedOnboarding = false
    return RootView()
        .environment(environment)
        .modelContainer(environment.container)
}
