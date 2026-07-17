import SwiftUI
import UserNotifications
import AVFoundation

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
            .fullScreenCover(item: $mfa.pendingProofing) { proofing in
                ProofingView(proofing: proofing,
                             onPresent: mfa.openWalletForProofing,
                             onDecline: mfa.dismissProofing)
            }
            // Onboarding by QR: the web app shows a QR encoding
            // idpapprover://enroll?user=<u>&key=<pairingKey>&dt=<deviceToken>. Scanning it with
            // the iPhone camera opens the app here, which stores the device token and pairs that
            // identity. The device token scopes this phone to that one user on every BFF call.
            .onOpenURL { url in
                guard url.scheme == "idpapprover", url.host == "enroll" else { return }
                let q = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems
                let user = q?.first(where: { $0.name == "user" })?.value ?? ""
                let key = q?.first(where: { $0.name == "key" })?.value ?? ""
                let token = q?.first(where: { $0.name == "dt" })?.value ?? ""
                if !user.isEmpty, !key.isEmpty {
                    mfa.pairFromLink(user: user, key: key, token: token)
                }
            }
    }
}

/// mDL identity-proofing request: the bank needs a verified mobile Driver's Licence
/// before opening an account. "Present" hands off app2app to the wallet (openid4vp://).
struct ProofingView: View {
    let proofing: PendingProofing
    let onPresent: () -> Void
    let onDecline: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                IDPWordmark(size: 20)
                Text("Bank").font(.system(size: 15, weight: .semibold)).foregroundColor(Brand.muted)
                Spacer()
            }
            .padding(.horizontal, 22).padding(.top, 16).padding(.bottom, 12)
            Divider().overlay(Brand.hair)

            Spacer()
            Image(systemName: "person.text.rectangle")
                .font(.system(size: 56)).foregroundColor(Brand.orange)
            Text("Verify your identity").font(.title2.bold())
                .foregroundColor(Brand.ink).padding(.top, 18)
            Text("Opening your account needs a verified mobile Driver's Licence. "
                 + "Present it from your wallet — only your name and licence number are shared.")
                .font(.callout).foregroundColor(Brand.muted)
                .multilineTextAlignment(.center).padding(.horizontal, 36).padding(.top, 6)

            VStack(spacing: 8) {
                HStack { Text("Document").foregroundColor(Brand.muted); Spacer()
                         Text(proofing.doctype).font(.footnote.monospaced()).foregroundColor(Brand.ink) }
                HStack { Text("Reference").foregroundColor(Brand.muted); Spacer()
                         Text(proofing.code).font(.footnote.monospaced()).foregroundColor(Brand.ink) }
                if !proofing.subject.isEmpty {
                    HStack { Text("For").foregroundColor(Brand.muted); Spacer()
                             Text(proofing.subject.capitalized).foregroundColor(Brand.ink) }
                }
                if !proofing.account.isEmpty {
                    HStack { Text("Account").foregroundColor(Brand.muted); Spacer()
                             Text("New \(proofing.account) account").foregroundColor(Brand.ink) }
                }
            }
            .font(.subheadline)
            .padding(16)
            .background(RoundedRectangle(cornerRadius: 12).stroke(Brand.hair))
            .padding(.horizontal, 28).padding(.top, 22)

            Spacer()
            Button(action: onPresent) {
                Label("Present my licence", systemImage: "wallet.pass")
                    .font(.headline).foregroundColor(.white)
                    .frame(maxWidth: .infinity).padding(.vertical, 15)
                    .background(Brand.orange).clipShape(RoundedRectangle(cornerRadius: 12))
            }
            .padding(.horizontal, 28)
            Button(action: onDecline) {
                Text("Not now").font(.subheadline).foregroundColor(Brand.muted)
            }
            .padding(.top, 12).padding(.bottom, 26)
        }
        .background(Brand.paper.ignoresSafeArea())
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
            if mfa.isSignedIn {
                Text("You're all set").font(.title3.bold()).foregroundColor(Brand.ink).padding(.top, 18)
                Text("You'll be notified to approve payments.")
                    .foregroundColor(Brand.muted).multilineTextAlignment(.center).padding(.horizontal, 44)
            } else if let last = mfa.identities.first {
                // Signed out, but the account is still paired on this phone — sign back in with
                // Face ID, no re-scan needed.
                Text("Signed out").font(.title3.bold()).foregroundColor(Brand.ink).padding(.top, 18)
                Text("Sign back in to keep approving payments.")
                    .foregroundColor(Brand.muted).multilineTextAlignment(.center).padding(.horizontal, 44)
                Button { mfa.signInLocal(user: last.userName) } label: {
                    Text("Sign in as \(last.displayName)").font(.headline).foregroundColor(.white)
                        .frame(maxWidth: .infinity).padding(.vertical, 14).background(Brand.orange)
                        .clipShape(RoundedRectangle(cornerRadius: 10)).padding(.horizontal, 40)
                }.padding(.top, 16)
                if mfa.identities.count > 1 {
                    Button("Choose another account") { showProfile = true }
                        .font(.subheadline).foregroundColor(Brand.orange).padding(.top, 6)
                }
            } else {
                Text("Sign in").font(.title3.bold()).foregroundColor(Brand.ink).padding(.top, 18)
                Text("Use the passkey or security key (YubiKey) you set up on the bank website.")
                    .foregroundColor(Brand.muted).multilineTextAlignment(.center).padding(.horizontal, 40)
                Button { mfa.signInWithPasskey() } label: {
                    Label(mfa.signingIn ? "Signing in…" : "Sign in with a passkey", systemImage: "person.badge.key.fill")
                        .font(.headline).foregroundColor(.white)
                        .frame(maxWidth: .infinity).padding(.vertical, 14).background(Brand.orange)
                        .clipShape(RoundedRectangle(cornerRadius: 10)).padding(.horizontal, 44)
                }.padding(.top, 16).disabled(mfa.signingIn)
                Button("Pair with a QR instead") { showProfile = true }
                    .font(.subheadline).foregroundColor(Brand.orange).padding(.top, 8)
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
    @State private var showScanner = false
    @State private var scanError: String?

    var body: some View {
        NavigationView {
            List {
                Section("Account") {
                    if mfa.identities.contains(where: { $0.userName == mfa.activeUser }) {
                        row("Signed in as", mfa.identities.first(where: { $0.userName == mfa.activeUser })?
                            .displayName ?? mfa.activeUser.capitalized)
                        row("Role", mfa.activeUser == "bob" ? "Bank staff" : "Customer")
                    }
                    row("Bank", Brand.bankName)
                }
                // Accounts THIS phone has been paired to — held on-device. The app has no
                // directory read, so it can only ever show accounts it was explicitly paired
                // to (by scanned QR or username enrol), never the bank's whole roster.
                Section("Accounts on this device") {
                    if mfa.identities.isEmpty {
                        Text("No accounts paired on this phone yet. Scan the QR the bank website "
                             + "showed you, or add one below.")
                            .font(.footnote).foregroundColor(Brand.muted)
                    }
                    ForEach(mfa.identities) { ident in
                        let isActive = ident.userName == mfa.activeUser
                        HStack(spacing: 10) {
                            Image(systemName: isActive
                                  ? "person.crop.circle.badge.checkmark" : "person.crop.circle")
                                .foregroundColor(isActive ? Brand.orange : Brand.muted)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(ident.displayName).foregroundColor(Brand.ink)
                                Text(isActive ? "Signed in on this device" : "Signed out — paired on this device")
                                    .font(.caption).foregroundColor(Brand.muted)
                            }
                            Spacer()
                            if isActive {
                                Text("Active").font(.caption.bold()).foregroundColor(Brand.orange)
                            } else {
                                Button("Sign in") { mfa.signInLocal(user: ident.userName) }
                                    .font(.caption.bold()).foregroundColor(Brand.orange)
                                    .buttonStyle(.borderless)
                            }
                        }
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) { mfa.removeAccount(user: ident.userName) } label: {
                                Label("Remove", systemImage: "trash")
                            }
                        }
                    }
                    if let active = mfa.identities.first(where: { $0.userName == mfa.activeUser }) {
                        Button("Sign out \(active.displayName)") { mfa.signOut(user: active.userName) }
                            .font(.footnote).foregroundColor(.red)
                    }
                }
                // Add an account: scan the onboarding QR the website shows. That QR carries the
                // pairing key AND a device token that scopes this phone to that one user — there
                // is deliberately no "type a username" path (a phone can't enrol an arbitrary
                // account; the key + token come only from that user's own signed-in web session).
                Section("Add an account") {
                    Button { mfa.signInWithPasskey() } label: {
                        Label(mfa.signingIn ? "Signing in…" : "Sign in with a passkey",
                              systemImage: "person.badge.key.fill").fontWeight(.semibold)
                    }
                    .disabled(mfa.signingIn)
                    Text("Uses the passkey or security key (YubiKey) you set up on the bank website — no QR needed.")
                        .font(.footnote).foregroundColor(Brand.muted)
                    Button { scanError = nil; showScanner = true } label: {
                        Label("Scan QR code instead", systemImage: "qrcode.viewfinder")
                    }
                    if let scanError {
                        Text(scanError).font(.footnote).foregroundColor(.red)
                    }
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
            .sheet(isPresented: $showScanner) {
                ScannerSheet(
                    onScan: { code in
                        showScanner = false
                        if mfa.handleScanned(code) { dismiss() }
                        else { scanError = "That QR code isn't an ID Partners pairing code." }
                    },
                    onCancel: { showScanner = false },
                    onError: { msg in showScanner = false; scanError = msg })
            }
        }
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack { Text(k).foregroundColor(Brand.ink); Spacer(); Text(v).foregroundColor(Brand.muted) }
    }
}

/// A presented sheet hosting the camera QR scanner with a branded header and a Cancel button.
struct ScannerSheet: View {
    let onScan: (String) -> Void
    let onCancel: () -> Void
    let onError: (String) -> Void

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                IDPWordmark(size: 18)
                Spacer()
                Button("Cancel", action: onCancel).foregroundColor(Brand.orange)
            }
            .padding(.horizontal, 20).padding(.vertical, 14)
            Divider().overlay(Brand.hair)
            ZStack {
                QRScannerView(onScan: onScan, onError: onError)
                RoundedRectangle(cornerRadius: 18)
                    .strokeBorder(Color.white.opacity(0.9), lineWidth: 3)
                    .frame(width: 220, height: 220)
            }
            Text("Point the camera at the QR code the bank website is showing.")
                .font(.footnote).foregroundColor(Brand.muted)
                .multilineTextAlignment(.center).padding(20)
        }
        .background(Brand.paper.ignoresSafeArea())
    }
}

/// Minimal AVFoundation QR scanner wrapped for SwiftUI. Fires `onScan` once with the decoded
/// string, then stops the session. Requires NSCameraUsageDescription in Info.plist.
struct QRScannerView: UIViewControllerRepresentable {
    let onScan: (String) -> Void
    let onError: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let vc = ScannerViewController()
        vc.onScan = onScan
        vc.onError = onError
        return vc
    }
    func updateUIViewController(_ vc: ScannerViewController, context: Context) {}
}

final class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onScan: ((String) -> Void)?
    var onError: ((String) -> Void)?
    private let session = AVCaptureSession()
    private var preview: AVCaptureVideoPreviewLayer?
    private var handled = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            configure()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    granted ? self?.configure()
                            : self?.onError?("Camera access is needed to scan the QR code.")
                }
            }
        default:
            onError?("Camera access is off. Enable it for ID Partners in Settings to scan.")
        }
    }

    private func configure() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else {
            onError?("No camera available on this device."); return
        }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { onError?("Scanner unavailable."); return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let p = AVCaptureVideoPreviewLayer(session: session)
        p.videoGravity = .resizeAspectFill
        p.frame = view.layer.bounds
        view.layer.addSublayer(p)
        preview = p
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in self?.session.startRunning() }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.layer.bounds
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning { session.stopRunning() }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput,
                        didOutput metadataObjects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        guard !handled,
              let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let str = obj.stringValue else { return }
        handled = true
        session.stopRunning()
        onScan?(str)
    }
}
