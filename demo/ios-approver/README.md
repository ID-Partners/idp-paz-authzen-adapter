# IDPApprover — ID Partners Bank approval app (iOS)

The phone app Bob uses to approve payments. When the autonomous agent starts a CIBA request,
PingFederate → PingOne MFA sends a **push** here; Bob sees the payment (amount, from, to),
approves with **Face ID**, and the agent receives its delegated token.

SwiftUI. The PingOne MFA SDK is wrapped in `MFAManager.swift`; the branded approval UI is
`ApprovalView.swift`; brand tokens (ID Partners orange, wordmark) live in `Theme.swift`.

## Source files
| File | Role |
|------|------|
| `IDPApprover/Theme.swift` | brand tokens + the `IDPWordmark` view |
| `IDPApprover/ApprovalView.swift` | the payment-approval screen (branded) |
| `IDPApprover/MFAManager.swift` | PingOne MFA SDK wrapper (pair / push / approve) — SDK calls marked `INTEGRATION POINT`, finalised from the SDK research |
| `IDPApprover/IDPApproverApp.swift` | app entry, APNs registration (AppDelegate), routing |

## Open it
The Xcode project is generated (via XcodeGen — spec is `project.yml`):

```bash
open IDPApprover.xcodeproj          # already generated; re-run `xcodegen generate` after editing project.yml
```

It comes pre-wired: the **PingOne MFA SDK** package
(`github.com/pingidentity/pingone-mobile-sdk-ios`, `import PingOneSDK`, `MFAManager.swift`),
bundle id `com.idpartners.bankapprover`, **Push Notifications** + **remote-notification**
background mode, and the **Face ID** usage string.

Then, in Xcode:
1. **Signing & Capabilities → Team** = your Apple team (or set `DEVELOPMENT_TEAM` in `project.yml`).
   On first open Xcode resolves the PingOneSDK Swift package (needs network) — give it a minute.
2. Confirm the region in `MFAManager.swift`: `PingOne.configure(geo: .Singapore)` (AP tenant →
   Singapore DC; switch to `.Australia` if that's your tenant's home).
3. Run on a **physical device** — push doesn't work in the Simulator.

## What I need from you (Apple)
- **Bundle ID** you want (default `com.idpartners.bankapprover`).
- **Apple Team ID** (Membership page in the Apple Developer portal).
- An **APNs Auth Key**: create a `.p8` key (Keys → +, enable Apple Push Notifications service)
  and send me the **`.p8` file contents + its Key ID** (10 chars). I upload these to the
  PingOne Native app so PingOne can push to the device. (The `.p8` is a signing key, not a
  password — but treat it as a secret; you can also upload it in the PingOne console yourself.)

## Status
- ✅ Branded UI + app shell + APNs plumbing scaffolded (preview-able in Xcode with mock data).
- ⏳ SDK pairing/push/approve calls — finalising from the PingOne MFA iOS SDK research.
- ⏳ PingOne **Native application** + APNs push credentials + MFA-policy `mobile` wiring — I
  create these via the Management API once you send the Apple bits.
