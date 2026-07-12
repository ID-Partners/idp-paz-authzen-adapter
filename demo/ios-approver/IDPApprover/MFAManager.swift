import Foundation
import SwiftUI
import LocalAuthentication
import PingOneSDK   // github.com/pingidentity/pingone-mobile-sdk-ios (SPM), v2.3.2

/// Wraps the PingOne MFA iOS SDK. Isolates every SDK call so the branded UI (ApprovalView)
/// stays independent. Push-approval flow (verified against the 2.3.2 swiftinterface):
///   configure(geo:) → pair(pairingKey) → setDeviceToken(APNs)
///   push → processRemoteNotification → NotificationObject(.authentication, clientContext)
///   approve/deny → processRemoteNotificationAction(<action>, forRemoteNotification: userInfo)
///
/// `CONFIRM:` the two action-identifier strings against the pingone-sample-app-ios (the SDK
/// registers notification actions; the exact identifiers are what the buttons pass back).
@MainActor
final class MFAManager: ObservableObject {
    enum State: Equatable { case unpaired, paired, approving }

    // CONFIRM: action identifiers the SDK expects for in-app approve/deny.
    private static let actionApprove = "PING_APPROVE"
    private static let actionDeny    = "PING_DENY"

    @Published var state: State = .unpaired
    @Published var pending: PendingPayment?
    @Published var lastError: String?

    /// The push payload for the pending authentication, needed to send the action back.
    private var pendingUserInfo: [AnyHashable: Any]?

    /// The APNs device token, cached so it can be (re-)applied AFTER pairing. The token
    /// arrives at app launch (didRegisterForRemoteNotifications) but pairing happens later
    /// when the user enters the key — if setDeviceToken runs before pair(), the token never
    /// attaches to the created device (PingOne shows the device with no push registration →
    /// no notification is ever delivered). So we stash it and apply it post-pair too.
    private var deviceToken: Data?

    init() {
        // AP tenant (console.pingone.asia) → Singapore data center.
        // CONFIRM: .Singapore vs .Australia for this tenant's home region.
        PingOne.configure(geo: .Singapore) { error in
            if let error { print("PingOne.configure error:", error) }
        }
        // If this device already paired on a previous launch, DON'T show the pairing screen
        // again (re-pairing mints a brand-new PingOne device every time — that's why Bob
        // accumulated several). Reflect the persisted pairing so we reuse the same device.
        // Use the labelled `completion:` overload (deviceInfo + errors array) — the unlabelled
        // getInfo(_:) overload is a different callback shape and makes the call ambiguous.
        PingOne.getInfo(completion: { [weak self] deviceInfo, errors in
            Task { @MainActor in
                if deviceInfo != nil, (errors == nil || errors!.isEmpty) {
                    self?.state = .paired
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

    /// Process an incoming push → surface the payment for approval.
    func handleRemoteNotification(_ userInfo: [AnyHashable: Any]) {
        PingOne.processRemoteNotification(userInfo) { [weak self] notification, error in
            Task { @MainActor in
                if let error {
                    if error.code != 10002 { self?.lastError = error.localizedDescription } // 10002 = not a Ping push
                    return
                }
                guard let n = notification, n.notificationType == .authentication else { return }
                self?.pendingUserInfo = userInfo
                self?.pending = Self.payment(fromClientContext: n.clientContext)
                self?.state = .approving
            }
        }
    }

    /// Approve after Face ID, then send the approve action back to PingOne.
    func approve() {
        biometric { [weak self] ok in
            guard let self, ok, let ui = self.pendingUserInfo else { self?.reset(); return }
            PingOne.processRemoteNotificationAction(Self.actionApprove, forRemoteNotification: ui) { _, _ in
                Task { @MainActor in self.reset() }
            }
        }
    }

    func deny() {
        if let ui = pendingUserInfo {
            PingOne.processRemoteNotificationAction(Self.actionDeny, forRemoteNotification: ui) { _, _ in }
        }
        reset()
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

    private func reset() { pending = nil; pendingUserInfo = nil; state = .paired }
}
