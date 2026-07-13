import Foundation
import SwiftUI
import LocalAuthentication
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

    /// Process an incoming push → surface the payment for approval.
    func handleRemoteNotification(_ userInfo: [AnyHashable: Any]) {
        guard sdkReady else {                     // cold launch: replay once configure completes
            queuedPush = userInfo
            Self.phoneLog("push_queued", "SDK not ready yet")
            return
        }
        Self.phoneLog("push_received", "processing")
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
                // Show whatever the push itself carried immediately, then enrich from the
                // orchestrator's consent detail (the source of truth for the full breakdown).
                self?.pending = Self.payment(fromClientContext: n.clientContext)
                self?.state = .approving
                Self.phoneLog("approval_shown", "screen opened")
                if let rich = await Self.fetchConsent(code: self?.pending?.bindingMessage) {
                    self?.pending = rich
                }
            }
        }
    }

    /// Fire-and-forget lifecycle breadcrumb to the orchestrator (POST /phone-log) so we can see
    /// how far a push got even when nothing else fires. Never blocks the UI.
    static func phoneLog(_ event: String, _ detail: String) {
        Task {
            var req = URLRequest(url: consentBase.appendingPathComponent("phone-log"))
            req.httpMethod = "POST"
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
            let (data, resp) = try await URLSession.shared.data(from: url)
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
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        var body: [String: Any] = ["decision": decision]
        if let error { body["error"] = error }
        if let deviceReq { body["deviceRequirements"] = deviceReq }
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
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

    private func biometric(_ done: @escaping (Bool) -> Void) {
        let c = LAContext()
        c.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Approve this payment") { ok, _ in
            Task { @MainActor in done(ok) }
        }
    }

    private func reset() { pending = nil; pendingNotification = nil; state = .paired }
}
