import Foundation
import SwiftUI
import UIKit
import LocalAuthentication
import AuthenticationServices   // native passkey (WebAuthn) sign-in
import PingOneSDK   // github.com/pingidentity/pingone-mobile-sdk-ios (SPM), v2.3.2

/// Wraps the PingOne MFA iOS SDK. Isolates every SDK call so the branded UI (ApprovalView)
/// stays independent. Push-approval flow (verified against the 2.3.2 swiftinterface):
///   configure(geo:) → pair(pairingKey) → setDeviceToken(APNs)
///   push → processRemoteNotification → NotificationObject(.authentication, clientContext)
///   approve/deny → notificationObject.approve(withAuthenticationMethod:…) / .deny(completionHandler:)
///
/// The decision MUST be reported on the NotificationObject itself — that round-trips to PingOne,
/// which resolves the device authentication so PF's CIBA poll returns Bob's token.
@MainActor
final class MFAManager: ObservableObject {
    enum State: Equatable { case unpaired, paired, approving }

    @Published var state: State = .unpaired
    @Published var pending: PendingPayment?
    @Published var lastError: String?

    /// mDL identity-proofing request pushed via CIBA — the approver opens the wallet
    /// app2app (openid4vp://) so the customer presents their mobile Driver's Licence.
    @Published var pendingProofing: PendingProofing?

    /// The identities THIS device has paired — held ON-DEVICE (UserDefaults), never fetched
    /// from the directory. The approver app is not entitled to enumerate the bank's roster;
    /// it only knows accounts it was explicitly paired to (by scanned QR or username enrol).
    @Published var identities: [BankIdentity] = []

    /// Which identity this device currently acts for. The PingOne SDK supports multiple
    /// concurrent pairings on one device, so signing in as alice does NOT tear down bob —
    /// this selects whose sign-ins/pairings the profile drives and what the UI displays.
    @Published var activeUser: String = UserDefaults.standard.string(forKey: "activeUser") ?? "bob" {
        didSet { UserDefaults.standard.set(activeUser, forKey: "activeUser") }
    }

    /// Paired for the purposes of the home/profile UI — true whenever the device is set up,
    /// including mid-approval (`.approving` is a paired device with a pending payment).
    var isPaired: Bool { state != .unpaired }

    /// Show the pairing entry again (used by the profile menu's "re-pair" action).
    func showPairing() { state = .unpaired }

    /// The live NotificationObject for the pending authentication. Approve/deny are methods ON
    /// this object (`approve(withAuthenticationMethod:…)` / `deny(completionHandler:)`) — that's
    /// what actually reports the decision back to PingOne so PF's CIBA poll resolves and the
    /// orchestrator progresses. (The older processRemoteNotificationAction(<string>,…) path needs
    /// UNNotificationAction identifiers we never registered, so it silently no-ops.)
    private var pendingNotification: NotificationObject?

    /// The APNs device token, cached so it can be (re-)applied AFTER pairing. The token
    /// arrives at app launch (didRegisterForRemoteNotifications) but pairing happens later
    /// when the user enters the key — if setDeviceToken runs before pair(), the token never
    /// attaches to the created device (PingOne shows the device with no push registration →
    /// no notification is ever delivered). So we stash it and apply it post-pair too.
    private var deviceToken: Data?

    /// The SDK must finish `configure` before `processRemoteNotification` will work. On a COLD
    /// launch (app terminated, user taps the banner) iOS fires didReceive almost immediately —
    /// often before configure returns — so we gate push processing on this flag and replay the
    /// queued push once the SDK is ready.
    private var sdkReady = false
    private var queuedPush: [AnyHashable: Any]?

    init() {
        Self.phoneLog("init", "app launched")
        loadLocalIdentities()
        // AP tenant (console.pingone.asia) → Singapore data center.
        // CONFIRM: .Singapore vs .Australia for this tenant's home region.
        PingOne.configure(geo: .Singapore) { [weak self] error in
            if let error { print("PingOne.configure error:", error) }
            Task { @MainActor in
                self?.sdkReady = true
                Self.phoneLog("sdk_ready", error == nil ? "" : "configure error: \(error!.localizedDescription)")
                if let queued = self?.queuedPush {   // replay a push that arrived pre-configure
                    self?.queuedPush = nil
                    self?.handleRemoteNotification(queued)
                }
            }
        }
        // If this device already paired on a previous launch, DON'T show the pairing screen
        // again (re-pairing mints a brand-new PingOne device every time — that's why Bob
        // accumulated several). Reflect the persisted pairing so we reuse the same device.
        // Use the labelled `completion:` overload (deviceInfo + errors array) — the unlabelled
        // getInfo(_:) overload is a different callback shape and makes the call ambiguous.
        PingOne.getInfo(completion: { [weak self] deviceInfo, errors in
            Task { @MainActor in
                if deviceInfo != nil, (errors == nil || errors!.isEmpty) {
                    // getInfo returns async and can land AFTER a cold-launch push has already
                    // opened the approval screen — only reflect "paired" if we're idle, never
                    // clobber an in-progress approval (that's the "paired screen pops over the
                    // consent" bug).
                    if self?.state == .unpaired { self?.state = .paired }
                    self?.applyDeviceToken()   // re-assert the push token on the existing device
                }
            }
        })
    }

    /// Pair with PingOne using the pairing key minted for Bob (scanned QR or typed).
    func pair(pairingKey: String) {
        PingOne.pair(pairingKey) { [weak self] _, error in
            Task { @MainActor in
                if let error { self?.lastError = error.localizedDescription; return }
                self?.state = .paired
                // CRITICAL: apply the cached APNs token now that the device exists, so
                // PingOne registers a push target for it. Without this the device pairs
                // but can never receive a notification.
                self?.applyDeviceToken()
            }
        }
    }

    /// Give the APNs device token to the SDK so PingOne can target this device. Called both
    /// when the token arrives AND after pairing (whichever is later wins), so a token that
    /// arrives before pairing isn't dropped.
    func registerPushToken(_ token: Data) {
        deviceToken = token
        applyDeviceToken()
    }

    private func applyDeviceToken() {
        guard let token = deviceToken else { return }
        // The entitlement is aps-environment: development, so a dev/sandbox build gets a
        // SANDBOX APNs token → must register it as .sandbox or APNs silently drops delivery.
        #if DEBUG
        let type: PingOne.APNSDeviceTokenType = .sandbox
        #else
        let type: PingOne.APNSDeviceTokenType = .production
        #endif
        PingOne.setDeviceToken(token: token, type: type) { errors in
            if let errors, !errors.isEmpty { print("setDeviceToken errors:", errors) }
        }
    }

    /// The orchestrator that holds the full authorization consent. The CIBA push can carry
    /// only a 20-char reference code (PingOne/PF limit), so the rich payment detail — amount,
    /// debtor/creditor, account owner, the RFC 9396 authorization_details — is pulled from here
    /// by that code over this out-of-band channel. Mirrors how real bank approval apps work.
    private static let consentBase = URL(string: "https://autonomous-agent-staging.up.railway.app")!

    /// The web app (BFF) — identity roster (SCIM proxy), per-user enrolment (pairing keys),
    /// and the mDL proofing requests (the openid4vp:// URI resolved by reference code).
    private static let bffBase = URL(string: "https://northwind-app-staging.up.railway.app")!

    /// Process an incoming push → surface the payment for approval.
    func handleRemoteNotification(_ userInfo: [AnyHashable: Any]) {
        guard sdkReady else {                     // cold launch: replay once configure completes
            queuedPush = userInfo
            Self.phoneLog("push_queued", "SDK not ready yet")
            return
        }
        Self.phoneLog("push_received", "processing")
        // Diagnostic breadcrumb: what does the push payload actually contain? (The binding
        // code routing depends on where PingOne puts it — clientContext vs alert text vs a
        // custom key — so log the raw shape, truncated.)
        if let payload = try? JSONSerialization.data(withJSONObject: userInfo.reduce(into: [String: Any]()) { $0["\($1.key)"] = $1.value }),
           let s = String(data: payload, encoding: .utf8) {
            Self.phoneLog("push_payload", String(s.prefix(700)))
        }
        PingOne.processRemoteNotification(userInfo) { [weak self] notification, error in
            Task { @MainActor in
                if let error {
                    if error.code != 10002 { self?.lastError = error.localizedDescription } // 10002 = not a Ping push
                    Self.phoneLog("push_error", "code=\(error.code) \(error.localizedDescription)")
                    return
                }
                guard let n = notification else {
                    Self.phoneLog("push_no_notification", "nil notification, no error"); return
                }
                guard n.notificationType == .authentication else {
                    Self.phoneLog("push_wrong_type", "type=\(n.notificationType.rawValue)"); return
                }
                self?.pendingNotification = n
                // The push carries only the ≤20-char reference code. An "MDL-…" code is an
                // mDL identity-proofing request (open the wallet app2app); anything else is
                // a payment consent (the existing approve/deny flow).
                let first = Self.payment(fromClientContext: n.clientContext)
                var code = first.bindingMessage
                // The pi.flow push does NOT deliver the binding message via clientContext
                // (verified: only the aps alert text carries it — same limitation as the
                // payment detail). So if the context gave us nothing useful, scan the
                // push's visible alert text for the MDL reference code.
                if !code.hasPrefix("MDL-") {
                    let aps = userInfo["aps"] as? [String: Any]
                    var alertText = ""
                    if let a = aps?["alert"] as? [String: Any] {
                        alertText = ["title", "subtitle", "body"]
                            .compactMap { a[$0] as? String }.joined(separator: " ")
                    } else if let s = aps?["alert"] as? String {
                        alertText = s
                    }
                    if let m = alertText.range(of: #"MDL-[A-Za-z0-9]+"#, options: .regularExpression) {
                        code = String(alertText[m])
                    }
                }
                if code.hasPrefix("MDL-") {
                    Self.phoneLog("proofing_push", "code=\(code)")
                    let p = await Self.fetchProofing(code: code, user: self?.activeUser ?? "")
                    self?.pendingProofing = p ?? PendingProofing(
                        id: code, code: code, requestURI: "", subject: "", doctype: "")
                    self?.state = .approving
                    return
                }
                // No code in the push at all (pi.flow drops clientContext and the alert text
                // is template-dependent) — ask the web app whether a FRESH proofing request
                // is pending. If so, this push is that request: open the proofing view and
                // hand off app2app via its openid4vp:// link. Payment consents keep working
                // because they never register a proofing.
                if let p = await Self.fetchLatestProofing(user: self?.activeUser ?? "") {
                    Self.phoneLog("proofing_push", "latest code=\(p.code)")
                    self?.pendingProofing = p
                    self?.state = .approving
                    return
                }
                // Show whatever the push itself carried immediately, then enrich from the
                // orchestrator's consent detail (the source of truth for the full breakdown).
                self?.pending = first
                self?.state = .approving
                Self.phoneLog("approval_shown", "screen opened")
                if let rich = await Self.fetchConsent(code: code) {
                    self?.pending = rich
                }
            }
        }
    }

    /// Fire-and-forget lifecycle breadcrumb to the orchestrator (POST /phone-log) so we can see
    /// how far a push got even when nothing else fires. Never blocks the UI.
    static func phoneLog(_ event: String, _ detail: String) {
        Task {
            var req = consentAuthed(consentBase.appendingPathComponent("phone-log"), method: "POST")
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try? JSONSerialization.data(withJSONObject: ["event": event, "detail": detail])
            _ = try? await URLSession.shared.data(for: req)
        }
    }

    /// Pull the full authorization consent from the orchestrator. `code` picks a specific
    /// payment; nil/unknown falls back to the latest pending consent (fine for the demo,
    /// which approves one payment at a time).
    private static func fetchConsent(code: String?) async -> PendingPayment? {
        var url = consentBase.appendingPathComponent("consent")
        if let code, !code.isEmpty, code.range(of: #"^[a-zA-Z0-9\-._+/!?#]{1,20}$"#,
                                                options: .regularExpression) != nil {
            url.appendPathComponent(code)
        }
        do {
            let (data, resp) = try await URLSession.shared.data(for: consentAuthed(url))
            guard (resp as? HTTPURLResponse)?.statusCode == 200,
                  let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { return nil }
            let num: (Any?) -> Double = { ($0 as? Double) ?? (($0 as? NSNumber)?.doubleValue ?? 0) }
            return PendingPayment(
                id: (j["paymentId"] as? String) ?? UUID().uuidString,
                amount: num(j["amount"]),
                currency: (j["currency"] as? String) ?? "AUD",
                fromAccount: (j["debtorAccount"] as? String) ?? "",
                toAccount: (j["creditorAccount"] as? String) ?? "",
                bindingMessage: (j["code"] as? String) ?? "",
                accountOwner: (j["accountOwner"] as? String) ?? "",
                reference: (j["code"] as? String) ?? "")
        } catch { return nil }
    }

    /// Approve after Face ID, then report the approval to PingOne on the NotificationObject.
    /// This is what completes the device authentication → PF's CIBA poll returns Bob's elevated
    /// token → the orchestrator resumes the chain and the dashboard progresses.
    func approve() {
        let code = pending?.reference
        Self.phoneLog("approve_tapped", "code=\(code ?? "-")")
        biometric { [weak self] ok in
            Self.phoneLog("biometric", ok ? "passed" : "failed/cancelled")
            guard let self, ok, let n = self.pendingNotification else {
                Task { @MainActor in
                    await Self.report(code: code, decision: "biometric_failed", error: nil, deviceReq: nil)
                    self?.reset()
                }
                return
            }
            Self.phoneLog("sdk_approve_call", "sending to PingOne")
            // Non-deprecated approve: withAuthenticationMethod nil (amr hint only); the two-arg
            // `completion:` returns the server's deviceRequirementsEvaluation so a device-posture
            // rejection surfaces here instead of silently failing the auth.
            n.approve(withAuthenticationMethod: nil, numberMatchingPickedValue: nil,
                      completion: { [weak self] info, error in
                Task { @MainActor in
                    let status = (info?["deviceRequirementsEvaluation"] as? [String: Any])?["status"] as? String
                    if let error { self?.lastError = "Approve failed: \(error.localizedDescription)" }
                    else if let status, status.caseInsensitiveCompare("Passed") != .orderedSame {
                        self?.lastError = "Approve rejected by device requirements: \(status)"
                    }
                    await Self.report(code: code, decision: "approve",
                                      error: error?.localizedDescription, deviceReq: status)
                    self?.reset()
                }
            })
        }
    }

    func deny() {
        guard let n = pendingNotification else { reset(); return }
        let code = pending?.reference
        n.deny(reason: .none, completionHandler: { [weak self] error in
            Task { @MainActor in
                if let error { self?.lastError = "Deny failed: \(error.localizedDescription)" }
                await Self.report(code: code, decision: "deny",
                                  error: error?.localizedDescription, deviceReq: nil)
                self?.reset()
            }
        })
    }

    /// Tell the orchestrator what happened on the phone (decision + any SDK error + device-
    /// requirements verdict), so the dashboard reflects the phone side even when PF's poll
    /// only sees a generic invalid_grant.
    private static func report(code: String?, decision: String, error: String?, deviceReq: String?) async {
        guard let code, !code.isEmpty else { return }
        let url = consentBase.appendingPathComponent("consent")
            .appendingPathComponent(code).appendingPathComponent("report")
        var req = consentAuthed(url, method: "POST")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        var body: [String: Any] = ["decision": decision]
        if let error { body["error"] = error }
        if let deviceReq { body["deviceRequirements"] = deviceReq }
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        _ = try? await URLSession.shared.data(for: req)
    }

    // MARK: - mDL identity proofing (CIBA push → app2app wallet presentation)

    /// Resolve the push's reference code to the full proofing request — most importantly
    /// the openid4vp:// request URI to open app2app into the wallet.
    private static func fetchProofing(code: String, user: String) async -> PendingProofing? {
        let req = deviceRequest("proofing/code/\(code)", user: user)
        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            guard (resp as? HTTPURLResponse)?.statusCode == 200,
                  let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { return nil }
            return PendingProofing(
                id: code, code: code,
                requestURI: (j["request_uri"] as? String) ?? "",
                subject: (j["subject"] as? String) ?? "",
                doctype: (j["doctype"] as? String) ?? "org.iso.18013.5.1.mDL",
                account: (j["account"] as? String) ?? "")
        } catch { return nil }
    }

    /// The no-code fallback: the most recent FRESH proofing request pending at the web app
    /// (the push itself can't reliably carry even the reference code — see the routing above).
    private static func fetchLatestProofing(user: String) async -> PendingProofing? {
        let req = deviceRequest("proofing/latest", user: user)
        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            guard (resp as? HTTPURLResponse)?.statusCode == 200,
                  let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let code = j["code"] as? String else { return nil }
            return PendingProofing(
                id: code, code: code,
                requestURI: (j["request_uri"] as? String) ?? "",
                subject: (j["subject"] as? String) ?? "",
                doctype: (j["doctype"] as? String) ?? "org.iso.18013.5.1.mDL",
                account: (j["account"] as? String) ?? "")
        } catch { return nil }
    }

    /// "Present my mDL": approve the CIBA notification (the push consent), then hand off
    /// app2app to the wallet via the openid4vp:// request URI. Verification completes at
    /// the verifier — the bank's web app polls it and resumes account opening.
    func openWalletForProofing() {
        guard let p = pendingProofing else { return }
        Self.phoneLog("proofing_present", "code=\(p.code)")
        if let n = pendingNotification {
            n.approve(withAuthenticationMethod: nil, numberMatchingPickedValue: nil,
                      completion: { _, _ in })   // completion signal only — token is discarded
        }
        if let url = URL(string: p.requestURI), !p.requestURI.isEmpty {
            UIApplication.shared.open(url)
        } else {
            lastError = "No wallet request available for \(p.code)."
        }
        pendingProofing = nil; pendingNotification = nil; state = .paired
    }

    func dismissProofing() {
        Self.phoneLog("proofing_declined", "code=\(pendingProofing?.code ?? "-")")
        pendingNotification?.deny(reason: .none, completionHandler: { _ in })
        pendingProofing = nil; pendingNotification = nil; state = .paired
    }

    // MARK: - identities (ON-DEVICE — only the accounts this phone was paired to)

    private static let pairedKey = "pairedIdentities"

    /// A friendly label for a username. The app deliberately has no directory read, so it
    /// derives the display name locally (special-casing the demo principals).
    static func displayName(for user: String) -> String {
        switch user {
        case "bob": return "Bob"
        case "alice": return "Alice"
        default: return user.capitalized
        }
    }

    /// Load the identities this device has paired from local storage (no network, no roster).
    func loadLocalIdentities() {
        let raw = UserDefaults.standard.array(forKey: Self.pairedKey) as? [[String: Any]] ?? []
        identities = raw.map {
            BankIdentity(userName: ($0["userName"] as? String) ?? "",
                         displayName: ($0["displayName"] as? String) ?? "",
                         paired: true,
                         pingOneUserId: $0["pingOneUserId"] as? String)
        }
    }

    private func persistLocalIdentities() {
        let raw = identities.map { ["userName": $0.userName, "displayName": $0.displayName,
                                    "pingOneUserId": $0.pingOneUserId ?? ""] }
        UserDefaults.standard.set(raw, forKey: Self.pairedKey)
    }

    /// Record that this device is now paired for `user` — adds it to the on-device list.
    func recordPaired(user: String) {
        let name = Self.displayName(for: user)
        if let i = identities.firstIndex(where: { $0.userName == user }) {
            identities[i] = BankIdentity(userName: user, displayName: name, paired: true,
                                         pingOneUserId: identities[i].pingOneUserId)
        } else {
            identities.append(BankIdentity(userName: user, displayName: name,
                                           paired: true, pingOneUserId: nil))
        }
        persistLocalIdentities()
    }

    /// Forget an identity on THIS device (sign-out).
    func forgetPaired(user: String) {
        identities.removeAll { $0.userName == user }
        persistLocalIdentities()
    }

    /// True while a pairing is in flight (gate to one attempt at a time — racing pairing keys
    /// invalidate each other).
    @Published var signingIn = false

    // MARK: - device tokens (this phone's proof it may act for ONE user)

    // The BFF mints a device token when the signed-in web user shows the pairing QR; it rides
    // in the QR (dt=), is stored here per user, and is sent as a Bearer on EVERY BFF call so the
    // phone can only ever act for that user. There is no way for the app to mint a pairing key
    // for an arbitrary user any more — the key + token come only from a user's own web session.
    private static func storeDeviceToken(_ token: String, for user: String) {
        guard !token.isEmpty else { return }
        UserDefaults.standard.set(token, forKey: "deviceToken.\(user.lowercased())")
    }
    static func deviceToken(for user: String) -> String? {
        UserDefaults.standard.string(forKey: "deviceToken.\(user.lowercased())")
    }
    private static func forgetDeviceToken(for user: String) {
        UserDefaults.standard.removeObject(forKey: "deviceToken.\(user.lowercased())")
    }

    /// A request to the BFF carrying this phone's device token for `user` as a Bearer.
    private static func deviceRequest(_ path: String, user: String, method: String = "GET") -> URLRequest {
        var req = URLRequest(url: bffBase.appendingPathComponent(path))
        req.httpMethod = method
        if let t = deviceToken(for: user) {
            req.setValue("Bearer \(t)", forHTTPHeaderField: "Authorization")
        }
        return req
    }

    /// The identity this phone is currently acting as (readable from a static context).
    private static func activeUserName() -> String {
        UserDefaults.standard.string(forKey: "activeUser") ?? "bob"
    }

    /// A request to the AUTONOMOUS-AGENT (consent) service carrying the active user's device
    /// token — so its consent/report/phone-log endpoints authorize this phone as that user.
    private static func consentAuthed(_ url: URL, method: String = "GET") -> URLRequest {
        var req = URLRequest(url: url)
        req.httpMethod = method
        if let t = deviceToken(for: activeUserName()) {
            req.setValue("Bearer \(t)", forHTTPHeaderField: "Authorization")
        }
        return req
    }

    /// Handle a QR string scanned by the in-app scanner. The onboarding QR encodes
    /// idpapprover://enroll?user=&key=&dt= — the same payload the iPhone camera deep-links.
    /// Returns false if the string isn't an ID Partners pairing code.
    @discardableResult
    func handleScanned(_ raw: String) -> Bool {
        guard let url = URL(string: raw.trimmingCharacters(in: .whitespacesAndNewlines)),
              url.scheme == "idpapprover", url.host == "enroll",
              let q = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems else { return false }
        let user = q.first(where: { $0.name == "user" })?.value ?? ""
        let key = q.first(where: { $0.name == "key" })?.value ?? ""
        let token = q.first(where: { $0.name == "dt" })?.value ?? ""
        guard !user.isEmpty, !key.isEmpty else { return false }
        pairFromLink(user: user, key: key, token: token)
        return true
    }

    /// Pair from a scanned onboarding QR (idpapprover://enroll?user=&key=&dt=): the web app
    /// already minted this identity's pairing key AND a device token. Binding is gated by
    /// DEVICE AUTHENTICATION (Face ID / passcode) first — scanning the QR is not enough; the
    /// person holding the phone must authenticate to bind the profile, exactly like an approval.
    /// Only then do we store the token and pair — no enrol fetch, no arbitrary-user key minting.
    func pairFromLink(user: String, key: String, token: String = "") {
        guard !signingIn else { return }
        biometric(reason: "Enrol this device as \(Self.displayName(for: user))") { [weak self] ok in
            guard let self else { return }
            guard ok else {
                self.lastError = "Enrolment needs Face ID — the phone must authenticate to bind an account."
                Self.phoneLog("enrol_biometric", "failed/cancelled for \(user)")
                return
            }
            Self.phoneLog("enrol_biometric", "passed for \(user)")
            self.startPairing(user: user, key: key, token: token)
        }
    }

    private func startPairing(user: String, key: String, token: String) {
        guard !signingIn else { return }
        signingIn = true
        Self.storeDeviceToken(token, for: user)
        Self.phoneLog("qr_pair", user)
        PingOne.pair(key) { [weak self] _, error in
            Task { @MainActor in
                defer { self?.signingIn = false }
                if let error {
                    Self.phoneLog("qr_pair_error", "\(user): code=\(error.code) \(error.localizedDescription)")
                    if await Self.reconcilePairing(user: user) {
                        self?.recordPaired(user: user)
                        self?.activeUser = user
                        self?.state = .paired
                        self?.applyDeviceToken()
                        self?.lastError = nil
                        return
                    }
                    self?.lastError = "QR pairing failed: \(error.localizedDescription)"
                    return
                }
                Self.phoneLog("qr_pair_ok", user)
                self?.recordPaired(user: user)
                self?.activeUser = user
                self?.state = .paired
                self?.applyDeviceToken()
                await Self.reportPairing(user: user, paired: true)
            }
        }
    }

    // MARK: - passkey sign-in (native WebAuthn — the SAME passkey the user made on the web)

    private var passkeyCoordinator: PasskeyCoordinator?

    static func b64url(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    static func b64urlDecode(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }

    /// Sign in on THIS device with the user's passkey (Associated Domains → rp.id = the web host,
    /// so iOS offers the same credential created on the web front door). A verified assertion
    /// mints a pairing key + device token at the BFF; we then pair and scope the phone to that
    /// user. The passkey IS the sign-in — no QR, and its own Face ID covers user verification.
    /// Pass an empty `user` for a usernameless (discoverable-credential) sign-in.
    func signInWithPasskey(user: String = "") {
        guard !signingIn else { return }
        signingIn = true; lastError = nil
        Self.phoneLog("passkey_signin", user.isEmpty ? "(usernameless)" : user)
        Task { @MainActor in
            defer { if self.signingIn { self.signingIn = false } }
            // 1) begin — get the challenge + allowed credentials
            var beginReq = URLRequest(url: Self.bffBase.appendingPathComponent("device/passkey/begin"))
            beginReq.httpMethod = "POST"
            beginReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
            beginReq.httpBody = try? JSONSerialization.data(withJSONObject: ["user": user])
            guard let (bd, br) = try? await URLSession.shared.data(for: beginReq),
                  (br as? HTTPURLResponse)?.statusCode == 200,
                  let j = try? JSONSerialization.jsonObject(with: bd) as? [String: Any],
                  let ro = j["requestOptions"] as? [String: Any],
                  let rpId = j["rpId"] as? String,
                  let challenge = (ro["challenge"] as? String).flatMap(Self.b64urlDecode),
                  let challengeToken = j["challengeToken"] as? String else {
                self.lastError = "Couldn't start passkey sign-in."; return
            }
            // 2) native assertion (Face ID unlocks the passkey)
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
            let request = provider.createCredentialAssertionRequest(challenge: challenge)
            if let allow = ro["allowCredentials"] as? [[String: Any]], !allow.isEmpty {
                request.allowedCredentials = allow.compactMap {
                    ($0["id"] as? String).flatMap(Self.b64urlDecode)
                        .map { ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0) }
                }
            }
            let coordinator = PasskeyCoordinator()
            self.passkeyCoordinator = coordinator
            let assertion: ASAuthorizationPlatformPublicKeyCredentialAssertion?
            do { assertion = try await coordinator.assertion(for: request) }
            catch {
                self.lastError = "Passkey sign-in cancelled."
                Self.phoneLog("passkey_signin_cancel", error.localizedDescription)
                self.passkeyCoordinator = nil; return
            }
            self.passkeyCoordinator = nil
            guard let a = assertion else { self.lastError = "No passkey assertion."; return }
            // 3) finish — verify server-side, get {user, pairingKey, deviceToken}
            let assertionObj: [String: Any] = [
                "id": Self.b64url(a.credentialID), "rawId": Self.b64url(a.credentialID), "type": "public-key",
                "response": ["clientDataJSON": Self.b64url(a.rawClientDataJSON),
                             "authenticatorData": Self.b64url(a.rawAuthenticatorData),
                             "signature": Self.b64url(a.signature),
                             "userHandle": Self.b64url(a.userID)],
                "clientExtensionResults": [:]]
            guard let assertionData = try? JSONSerialization.data(withJSONObject: assertionObj),
                  let assertionStr = String(data: assertionData, encoding: .utf8) else {
                self.lastError = "Couldn't encode the passkey assertion."; return
            }
            var finReq = URLRequest(url: Self.bffBase.appendingPathComponent("device/passkey/finish"))
            finReq.httpMethod = "POST"
            finReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
            finReq.httpBody = try? JSONSerialization.data(withJSONObject:
                ["assertion": assertionStr, "challengeToken": challengeToken])
            guard let (fd, fr) = try? await URLSession.shared.data(for: finReq),
                  (fr as? HTTPURLResponse)?.statusCode == 200,
                  let fj = try? JSONSerialization.jsonObject(with: fd) as? [String: Any],
                  let signedUser = fj["user"] as? String,
                  let key = fj["pairingKey"] as? String,
                  let token = fj["deviceToken"] as? String else {
                self.lastError = "Passkey verification failed."; return
            }
            // 4) pair + store. The passkey ceremony already did user verification, so pair directly
            //    (startPairing gates on signingIn, so release it first).
            Self.phoneLog("passkey_signin_ok", signedUser)
            self.signingIn = false
            self.startPairing(user: signedUser, key: key, token: token)
        }
    }

    /// Ask the web app to check PingOne directly for THIS user's device state (scoped to the
    /// one user the device is pairing — not a roster read) and sync the directory. Recovers
    /// the "pair() errored but the device actually paired" case. Returns the paired state.
    @discardableResult
    private static func reconcilePairing(user: String) async -> Bool {
        let req = deviceRequest("identities/\(user)/reconcile", user: user, method: "POST")
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
        return (j["paired"] as? Bool) ?? false
    }

    /// Signed in = an active identity that's actually paired on this phone.
    var isSignedIn: Bool { !activeUser.isEmpty && identities.contains(where: { $0.userName == activeUser }) }

    /// Sign OUT but KEEP the account (and its device token) on the phone, so signing back in is
    /// a local Face ID away — no re-scan. Clears the active selection; the account stays in the
    /// list as available. The PingOne pairing is left intact.
    func signOut(user: String) {
        Self.phoneLog("sign_out", user)
        Task { @MainActor in
            await Self.reportPairing(user: user, paired: false)
            if activeUser == user { activeUser = "" }
        }
    }

    /// Sign back IN to an account already paired on this phone: Face ID, then make it active.
    /// No network, no QR — the pairing and device token are already stored on the device.
    func signInLocal(user: String) {
        guard identities.contains(where: { $0.userName == user }), Self.deviceToken(for: user) != nil else {
            lastError = "That account isn't paired on this phone. Scan the QR from the website."
            return
        }
        biometric(reason: "Sign in as \(Self.displayName(for: user))") { [weak self] ok in
            guard let self else { return }
            guard ok else {
                self.lastError = "Sign-in needs Face ID."
                Self.phoneLog("sign_in_biometric", "failed/cancelled for \(user)")
                return
            }
            Self.phoneLog("sign_in_local", user)
            self.activeUser = user
            self.state = .paired
            self.applyDeviceToken()
            Task { @MainActor in await Self.reportPairing(user: user, paired: true) }
        }
    }

    /// Remove an account from this phone entirely (forget its device token + local record). Use
    /// to hand the phone on / unpair; signing back in then needs a fresh QR from the website.
    func removeAccount(user: String) {
        Self.phoneLog("remove_account", user)
        Task { @MainActor in
            await Self.reportPairing(user: user, paired: false)
            forgetPaired(user: user)
            Self.forgetDeviceToken(for: user)
            if activeUser == user { activeUser = identities.first?.userName ?? "" }
        }
    }

    private static func reportPairing(user: String, paired: Bool) async {
        var req = deviceRequest("identities/\(user)/pairing", user: user, method: "POST")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["paired": paired])
        _ = try? await URLSession.shared.data(for: req)
    }

    // MARK: - helpers

    /// The payment to display comes from `clientContext` (server→device string). The CIBA
    /// layer sends JSON; fall back to showing it verbatim as the binding message.
    private static func payment(fromClientContext ctx: String) -> PendingPayment {
        if let data = ctx.data(using: .utf8),
           let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            return PendingPayment(
                id: (j["paymentId"] as? String) ?? UUID().uuidString,
                amount: (j["amount"] as? Double) ?? ((j["amount"] as? NSNumber)?.doubleValue ?? 0),
                currency: (j["currency"] as? String) ?? "AUD",
                fromAccount: (j["debtorAccount"] as? String) ?? "",
                toAccount: (j["creditorAccount"] as? String) ?? "",
                bindingMessage: (j["binding_message"] as? String) ?? ctx)
        }
        return PendingPayment(id: UUID().uuidString, amount: 0, currency: "",
                              fromAccount: "", toAccount: "", bindingMessage: ctx)
    }

    private func biometric(reason: String = "Approve this payment", _ done: @escaping (Bool) -> Void) {
        let c = LAContext()
        c.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, _ in
            Task { @MainActor in done(ok) }
        }
    }

    private func reset() { pending = nil; pendingNotification = nil; state = .paired }
}

/// An identity THIS device has paired to (tracked on-device, not read from the directory).
struct BankIdentity: Identifiable, Equatable {
    var id: String { userName }
    let userName: String
    let displayName: String
    let paired: Bool
    let pingOneUserId: String?
}

/// An mDL identity-proofing request (CIBA push → wallet app2app presentation).
struct PendingProofing: Identifiable, Equatable {
    let id: String
    let code: String
    let requestURI: String
    let subject: String
    let doctype: String
    /// The specific account the proofing is FOR (e.g. "savings") — account-scoped.
    var account: String = ""
}

/// Bridges the ASAuthorization delegate callbacks to async/await for the passkey sign-in.
final class PasskeyCoordinator: NSObject, ASAuthorizationControllerDelegate,
                                ASAuthorizationControllerPresentationContextProviding {
    private var cont: CheckedContinuation<ASAuthorizationPlatformPublicKeyCredentialAssertion?, Error>?

    func assertion(for request: ASAuthorizationPlatformPublicKeyCredentialAssertionRequest)
        async throws -> ASAuthorizationPlatformPublicKeyCredentialAssertion? {
        try await withCheckedThrowingContinuation { c in
            self.cont = c
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization) {
        cont?.resume(returning: authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion)
        cont = nil
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        cont?.resume(throwing: error); cont = nil
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow } ?? ASPresentationAnchor()
    }
}
