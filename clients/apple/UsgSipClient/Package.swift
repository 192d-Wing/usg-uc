// swift-tools-version:5.9
import PackageDescription

// The aws-lc FIPS module is a dylib by design (FIPS boundary); it is staged
// per-platform by ../build-xcframework.sh and linked dynamically. macOS host
// builds (swift build / swift run) use the macOS slice; the iOS app embeds
// the iOS slice as a framework in its bundle instead.
let nativeLibDir = "\(Context.packageDirectory)/Frameworks/native/aarch64-apple-darwin"

let package = Package(
    name: "UsgSipClient",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "UsgSipClient", targets: ["UsgSipClient"]),
        .executable(name: "SipClientDemo", targets: ["SipClientDemo"]),
        .executable(name: "SipClientApp", targets: ["SipClientApp"]),
    ],
    targets: [
        // Rust core, built by ../build-xcframework.sh
        .binaryTarget(name: "ClientFFI", path: "Frameworks/ClientFFI.xcframework"),
        // Generated UniFFI bindings re-exported as a Swift module.
        .target(
            name: "UsgSipClient",
            dependencies: ["ClientFFI"],
            linkerSettings: [
                // System frameworks the Rust staticlib expects (cpal/CoreAudio,
                // VPIO, rustls-native-certs/Security).
                .linkedFramework("CoreAudio"),
                .linkedFramework("AudioToolbox"),
                .linkedFramework("Security"),
                .linkedFramework("SystemConfiguration"),
                .linkedFramework("AVFoundation"),
                .unsafeFlags([
                    "-L", nativeLibDir,
                    "-laws_lc_fips_0_13_14_crypto",
                    "-Xlinker", "-rpath", "-Xlinker", nativeLibDir,
                ]),
            ]
        ),
        // Minimal SwiftUI smoke-test app (macOS): registration + dialpad.
        .executableTarget(
            name: "SipClientDemo",
            dependencies: ["UsgSipClient"]
        ),
        // The real SwiftUI client app (macOS): dialpad, contacts, recents,
        // settings, in-call UI.
        .executableTarget(
            name: "SipClientApp",
            dependencies: ["UsgSipClient"],
            resources: [.process("Resources")]
        ),
    ]
)
