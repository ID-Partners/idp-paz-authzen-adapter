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

    // User TAPPED the banner (app was backgrounded/terminated) → iOS calls THIS, not
    // didReceiveRemoteNotification/willPresent. Process the push so the approval screen opens.
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        Task { @MainActor in mfa.handleRemoteNotification(response.notification.request.content.userInfo) }
        completionHandler()
    }
}

/// A clean branded home; pairing lives behind the profile button; the approval is a full-screen
/// cover driven off the pending payment (so nothing can pop over it, and it survives state races).
struct RootView: View {
    @EnvironmentObject var mfa: MFAManager
    @State private var showProfile = false

    var body: some View {
        HomeView(showProfile: $showProfile)
            .sheet(isPresented: $showProfile) { ProfileView().environmentObject(mfa) }
            .fullScreenCover(item: $mfa.pending) { payment in
                ApprovalView(payment: payment, onApprove: mfa.approve, onDecline: mfa.deny)
            }
    }
}

/// The default screen: wordmark + profile button up top, brand monogram and a short status below.
struct HomeView: View {
    @EnvironmentObject var mfa: MFAManager
    @Binding var showProfile: Bool

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                IDPWordmark(size: 20)
                Text("Bank").font(.system(size: 15, weight: .semibold)).foregroundColor(Brand.muted)
                Spacer()
                Button { showProfile = true } label: {
                    Image(systemName: "person.crop.circle")
                        .font(.system(size: 26)).foregroundColor(Brand.ink)
                }
                .accessibilityLabel("Profile")
            }
            .padding(.horizontal, 22).padding(.top, 14).padding(.bottom, 10)
            Divider().overlay(Brand.hair)

            Spacer()
            IDPMonogram(size: 78)
            if mfa.isPaired {
                Text("You're all set").font(.title3.bold()).foregroundColor(Brand.ink).padding(.top, 18)
                Text("You'll be notified to approve payments.")
                    .foregroundColor(Brand.muted).multilineTextAlignment(.center).padding(.horizontal, 44)
            } else {
                Text("Set up this device").font(.title3.bold()).foregroundColor(Brand.ink).padding(.top, 18)
                Text("Pair to start approving payments.").foregroundColor(Brand.muted)
                Button { showProfile = true } label: {
                    Text("Get started").font(.headline).foregroundColor(.white)
                        .frame(maxWidth: .infinity).padding(.vertical, 14).background(Brand.orange)
                        .clipShape(RoundedRectangle(cornerRadius: 10)).padding(.horizontal, 56)
                }.padding(.top, 16)
            }
            Spacer(); Spacer()
            Text("Secured by PingFederate · Face ID required")
                .font(.system(size: 11)).foregroundColor(Brand.muted).padding(.bottom, 18)
        }
        .background(Brand.paper.ignoresSafeArea())
    }
}

/// Profile / settings sheet — account context and device pairing.
struct ProfileView: View {
    @EnvironmentObject var mfa: MFAManager
    @Environment(\.dismiss) private var dismiss
    @State private var pairingKey = ""
    @State private var repairing = false

    var body: some View {
        NavigationView {
            List {
                Section("Account") {
                    row("Signed in as", "Bob")
                    row("Role", "Bank staff")
                    row("Bank", Brand.bankName)
                }
                Section("Device") {
                    if mfa.isPaired && !repairing {
                        HStack(spacing: 10) {
                            Image(systemName: "checkmark.shield.fill").foregroundColor(Brand.orange)
                            Text("This device is paired").foregroundColor(Brand.ink)
                        }
                        Button("Re-pair this device") { repairing = true }
                            .foregroundColor(Brand.orange)
                    } else {
                        Text("Enter the pairing key from ID Partners Bank.")
                            .font(.footnote).foregroundColor(Brand.muted)
                        TextField("Pairing key", text: $pairingKey).textFieldStyle(.roundedBorder)
                        Button {
                            mfa.pair(pairingKey: pairingKey); repairing = false; dismiss()
                        } label: { Text("Pair device").fontWeight(.semibold) }
                            .disabled(pairingKey.isEmpty)
                    }
                }
                if let err = mfa.lastError {
                    Section("Status") { Text(err).font(.footnote).foregroundColor(.red) }
                }
            }
            .navigationTitle("Profile")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack { Text(k).foregroundColor(Brand.ink); Spacer(); Text(v).foregroundColor(Brand.muted) }
    }
}
