import SwiftUI

/// ID Partners brand tokens — the single source of truth for the app's look.
enum Brand {
    static let orange      = Color(hex: 0xFF6600)   // ID Partners accent
    static let orangePress = Color(hex: 0xE65C00)
    static let ink         = Color(hex: 0x111111)   // wordmark black
    static let muted       = Color(hex: 0x6E6A63)
    static let paper       = Color(hex: 0xFFFFFF)
    static let panel       = Color(hex: 0xF4F2EE)
    static let hair        = Color(hex: 0xE7E3DC)
    static let money       = Color(hex: 0x0F7A4F)   // semantic (amount), not the accent

    static let bankName    = "ID Partners"
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

/// How a mark is coloured for its background.
enum IDPTone {
    case primary   // "iD" ink · "PARTNERS" orange  (the main light-bg lockup)
    case ink       // whole wordmark ink, orange i-dot
    case onDark    // whole wordmark white, orange i-dot

    var letter: Color { self == .onDark ? .white : Brand.ink }
    var partners: Color {
        switch self {
        case .primary: return Brand.orange
        case .ink:     return Brand.ink
        case .onDark:  return .white
        }
    }
}

/// The lowercase geometric "i" from the ID Partners mark: a square dot (brand orange) over a
/// short stem in the letter colour. Sized so its stem sits on the text baseline.
private struct IDPeye: View {
    let size: CGFloat
    let tone: IDPTone
    var body: some View {
        let unit = size * 0.9                 // cap-height reference for the heavy face
        VStack(alignment: .leading, spacing: unit * 0.16) {
            RoundedRectangle(cornerRadius: unit * 0.05)
                .fill(Brand.orange)
                .frame(width: unit * 0.24, height: unit * 0.24)   // the square dot
            RoundedRectangle(cornerRadius: unit * 0.03)
                .fill(tone.letter)
                .frame(width: unit * 0.24, height: unit * 0.5)    // the stem (x-height)
        }
        .alignmentGuide(.firstTextBaseline) { $0.height }         // stem bottom → baseline
    }
}

/// The ID Partners wordmark: ▪ orange square i-dot · "iD" · "PARTNERS".
struct IDPWordmark: View {
    var size: CGFloat = 20
    var tone: IDPTone = .primary
    /// The real ID Partners artwork (branding/assets/idp-monogram-onlight.png), not a
    /// SwiftUI approximation. `tone` is kept so existing call sites compile unchanged; the
    /// supplied asset is the on-light lockup (black ink + orange dot) and the app renders on
    /// Brand.paper (#FFFFFF), so every current call site wants exactly that. An on-dark
    /// variant exists in branding/assets if a dark surface is ever introduced.
    var body: some View {
        Image("IDPMark")
            .resizable()
            .aspectRatio(contentMode: .fit)
            .frame(height: size)
            .accessibilityLabel("ID Partners")
    }
}

/// The compact "iDP" monogram in a rounded badge — for the paired/idle screen and as the
/// reference for the app icon. Orange badge with white marks on dark; ink marks on light.
struct IDPMonogram: View {
    var size: CGFloat = 64
    var onOrange: Bool = true
    var body: some View {
        Image("IDPMark")
            .resizable()
            .aspectRatio(contentMode: .fit)
            .frame(width: size)
            .accessibilityLabel("ID Partners")
    }
}
