import SwiftUI
import UserNotifications

@main
struct IDPApproverApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    var body: some Scene {
        WindowGroup { RootView().environmentObject(appDelegate.mfa) }
    }
}

/// Handles APNs registration + delivers device token and pushes into the MFAManager.
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    let mfa = MFAManager()

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
            if granted { DispatchQueue.main.async { application.registerForRemoteNotifications() } }
        }
        return true
    }

    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Task { @MainActor in mfa.registerPushToken(deviceToken) }
    }

    func application(_ application: UIApplication,
                     didReceiveRemoteNotification userInfo: [AnyHashable: Any],
                     fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        Task { @MainActor in mfa.handleRemoteNotification(userInfo); completionHandler(.newData) }
    }

    // Foreground push → still surface the approval.
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        Task { @MainActor in mfa.handleRemoteNotification(notification.request.content.userInfo) }
        completionHandler([.banner, .sound])
    }
}

/// Routes between pairing, idle, and the payment-approval screen.
struct RootView: View {
    @EnvironmentObject var mfa: MFAManager
    @State private var pairingKey = ""

    var body: some View {
        switch mfa.state {
        case .approving:
            if let p = mfa.pending {
                ApprovalView(payment: p, onApprove: mfa.approve, onDecline: mfa.deny)
            }
        case .paired:
            VStack(spacing: 14) {
                IDPWordmark(size: 24); Text("Bank").foregroundColor(Brand.muted)
                Image(systemName: "checkmark.shield.fill").font(.system(size: 44)).foregroundColor(Brand.orange)
                Text("Device paired").font(.title3.bold()).foregroundColor(Brand.ink)
                Text("You'll be notified to approve payments.").foregroundColor(Brand.muted)
            }.frame(maxWidth: .infinity, maxHeight: .infinity).background(Brand.paper.ignoresSafeArea())
        case .unpaired:
            VStack(spacing: 16) {
                IDPWordmark(size: 26)
                Text("Pair this device").font(.title2.bold()).foregroundColor(Brand.ink)
                Text("Enter the pairing key from ID Partners Bank.").foregroundColor(Brand.muted)
                TextField("Pairing key", text: $pairingKey)
                    .textFieldStyle(.roundedBorder).padding(.horizontal, 40)
                Button { mfa.pair(pairingKey: pairingKey) } label: {
                    Text("Pair").font(.headline).foregroundColor(.white)
                        .frame(maxWidth: .infinity).padding().background(Brand.orange)
                        .clipShape(RoundedRectangle(cornerRadius: 10)).padding(.horizontal, 40)
                }
            }.frame(maxWidth: .infinity, maxHeight: .infinity).background(Brand.paper.ignoresSafeArea())
        }
    }
}
