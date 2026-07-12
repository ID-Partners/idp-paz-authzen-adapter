import SwiftUI

/// A pending payment the user must approve — populated from the CIBA push's transaction
/// context (binding_message / authorization_details) once the SDK integration lands.
struct PendingPayment: Identifiable, Equatable {
    let id: String
    let amount: Double
    let currency: String
    let fromAccount: String
    let toAccount: String
    var bindingMessage: String
}

/// ID Partners Bank — payment approval screen shown when a CIBA push arrives.
/// Approve triggers Face ID, then confirms to PingOne (see MFAManager).
struct ApprovalView: View {
    let payment: PendingPayment
    var onApprove: () -> Void
    var onDecline: () -> Void
    @State private var working = false

    private var amountText: String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        f.minimumFractionDigits = 2; f.maximumFractionDigits = 2
        return (f.string(from: NSNumber(value: payment.amount)) ?? "\(payment.amount)") + " " + payment.currency
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                IDPWordmark(size: 20)
                Text("Bank").font(.system(size: 15, weight: .semibold)).foregroundColor(Brand.ink)
                    .padding(.leading, 2)
                Spacer()
            }
            .padding(.horizontal, 22).padding(.top, 18).padding(.bottom, 6)

            Spacer(minLength: 8)

            VStack(alignment: .leading, spacing: 0) {
                Rectangle().fill(Brand.orange).frame(height: 4)
                VStack(alignment: .leading, spacing: 16) {
                    Text("Approve this payment")
                        .font(.system(size: 22, weight: .bold)).foregroundColor(Brand.ink)

                    VStack(alignment: .leading, spacing: 0) {
                        label("AMOUNT")
                        Text(amountText)
                            .font(.system(size: 30, weight: .heavy)).foregroundColor(Brand.money)
                            .padding(.top, 2).padding(.bottom, 12)
                        row("From account", payment.fromAccount)
                        row("To account", payment.toAccount)
                        Text("Rich Authorization Request · RFC 9396 · governed by Ping Authorize")
                            .font(.system(size: 11)).foregroundColor(Brand.muted).padding(.top, 12)
                    }
                    .padding(16)
                    .background(Brand.panel)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(Brand.hair, lineWidth: 1))
                    .clipShape(RoundedRectangle(cornerRadius: 10))

                    HStack(spacing: 10) {
                        Button(action: onDecline) { btnLabel("Don't Allow", filled: false) }
                        Button { working = true; onApprove() } label: { btnLabel("Approve", filled: true) }
                            .disabled(working)
                    }
                }
                .padding(20)
            }
            .background(Brand.paper)
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(Brand.hair, lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .shadow(color: Brand.ink.opacity(0.10), radius: 24, y: 14)
            .padding(.horizontal, 20)

            Spacer(minLength: 12)
            Text("Secured by PingFederate · Face ID required")
                .font(.system(size: 11)).foregroundColor(Brand.muted).padding(.bottom, 18)
        }
        .background(Brand.paper.ignoresSafeArea())
    }

    private func label(_ s: String) -> some View {
        Text(s).font(.system(size: 10.5, weight: .semibold)).kerning(1.4).foregroundColor(Brand.muted)
    }
    private func row(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k).font(.system(size: 14)).foregroundColor(Brand.muted)
            Spacer()
            Text(v).font(.system(size: 14, weight: .medium)).foregroundColor(Brand.ink)
        }
        .padding(.vertical, 7)
        .overlay(Rectangle().fill(Brand.hair).frame(height: 1), alignment: .top)
    }
    private func btnLabel(_ t: String, filled: Bool) -> some View {
        Text(t).font(.system(size: 15, weight: .semibold))
            .frame(maxWidth: .infinity).padding(.vertical, 13)
            .foregroundColor(filled ? .white : Brand.ink)
            .background(filled ? Brand.orange : Color.clear)
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(filled ? Brand.orange : Brand.hair, lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

#Preview {
    ApprovalView(
        payment: PendingPayment(id: "p1", amount: 150, currency: "AUD",
            fromAccount: "CHK-1001", toAccount: "SAV-1002",
            bindingMessage: "Approve payment 150.00 AUD from CHK-1001 to SAV-1002"),
        onApprove: {}, onDecline: {})
}
