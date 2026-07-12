import SwiftUI

/// ID Partners brand tokens — the single source of truth for the app's look.
/// Swap `orange` when the exact brand hex arrives (currently the provisional #FF6600).
enum Brand {
    static let orange      = Color(hex: 0xFF6600)   // ID Partners accent (provisional)
    static let orangePress = Color(hex: 0xE65C00)
    static let ink         = Color(hex: 0x141210)   // warm near-black
    static let muted       = Color(hex: 0x6E6A63)
    static let paper       = Color(hex: 0xFFFFFF)
    static let panel       = Color(hex: 0xF4F2EE)
    static let hair        = Color(hex: 0xE7E3DC)
    static let money       = Color(hex: 0x0F7A4F)   // semantic (amount), not the accent

    static let bankName    = "ID Partners Bank"
}

extension Color {
    init(hex: UInt, alpha: Double = 1) {
        self.init(.sRGB,
                  red:   Double((hex >> 16) & 0xFF) / 255,
                  green: Double((hex >> 8) & 0xFF) / 255,
                  blue:  Double(hex & 0xFF) / 255,
                  opacity: alpha)
    }
}

/// The ID Partners wordmark: ▪ orange square · "ID" ink · "PARTNERS" orange.
struct IDPWordmark: View {
    var size: CGFloat = 20
    var body: some View {
        HStack(spacing: size * 0.34) {
            RoundedRectangle(cornerRadius: 2)
                .fill(Brand.orange)
                .frame(width: size * 0.7, height: size * 0.7)
            (Text("ID").foregroundColor(Brand.ink)
             + Text("PARTNERS").foregroundColor(Brand.orange))
                .font(.system(size: size, weight: .heavy)).kerning(0.5)
        }
    }
}
