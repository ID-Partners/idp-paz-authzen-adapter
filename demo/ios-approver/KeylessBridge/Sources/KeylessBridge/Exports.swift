// Re-export so the app can `import KeylessSDK` directly and keep #if canImport(KeylessSDK)
// as the single switch that turns the real verifier on.
@_exported import KeylessSDK
