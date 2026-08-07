// swift-tools-version: 5.9
// Thin local wrapper whose only job is to pull the Recognize SDK in from the Cloudsmith Swift
// REGISTRY. Xcode can consume a local package by relative path with a well-defined project-file
// shape; a registry dependency added straight to the .xcodeproj is not something that can be
// hand-authored reliably. SwiftPM resolves the registry dependency here using the global
// registry config written by ../setup-keyless-sdk.sh.
import PackageDescription

let package = Package(
    name: "KeylessBridge",
    platforms: [.iOS(.v16)],
    products: [.library(name: "KeylessBridge", targets: ["KeylessBridge"])],
    dependencies: [.package(id: "keyless.mobile-sdk", from: "6.0.0")],
    targets: [.target(name: "KeylessBridge", dependencies: [
        .product(name: "KeylessSDK", package: "keyless.mobile-sdk")])]
)
