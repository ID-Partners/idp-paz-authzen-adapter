# ID Partners branding — iOS approver

## In-app marks (already wired, no assets needed)
`Theme.swift` renders the brand marks as SwiftUI vectors — scalable, theme-aware, self-contained:

- `IDPWordmark(size:tone:)` — the horizontal lockup (orange square i-dot · `iD` · `PARTNERS`).
  Tones: `.primary` (iD ink + PARTNERS orange, the light-bg lockup), `.ink` (all ink), `.onDark`
  (all white, for dark backgrounds).
- `IDPMonogram(size:onOrange:)` — the compact `iDP` badge (used on the paired/idle screen).
- Brand colours live in `enum Brand` (accent `#FF6600`).

## App icon (needs a rasterised asset — one Xcode step)
iOS app icons must be PNGs in an asset catalog; they can't be drawn in code. `idp-appicon.svg`
(1024×1024, full-bleed orange + white `iDP`) is the source:

1. Rasterise it to `1024×1024` PNG (any SVG→PNG tool, or open the SVG and export).
2. In Xcode: **File ▸ New ▸ Asset Catalog** → add an **iOS App Icon** set → drop the PNG on the
   1024 slot (single-size icons work on iOS 15+).
3. Target ▸ **General ▸ App Icons and Launch Screen ▸ App Icon** → select the set.

## Files
- `idp-appicon.svg` — app-icon source (full-bleed orange badge).
- `idp-wordmark.svg` — horizontal lockup (swap `#111111`→`#FFFFFF` for the on-dark variant).

## Exact fidelity
These reproduce the brand **structure** — the orange square i-dot, the `iD PARTNERS` lockup, and
the accent colour — using a heavy geometric system font, not the official ID Partners typeface.
For pixel-perfect marks, drop the official logo PNGs into an asset catalog and reference them with
`Image("idp-wordmark")`, or add the official font to the target and set it on the `Text` runs in
`Theme.swift`. Confirm the accent hex too — `#FF6600` is the working value in `Brand.orange`.
