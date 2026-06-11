// Cross-platform image loading helper.
//
// The shared SwiftUI sources run on both macOS (AppKit `NSImage`) and iOS
// (UIKit `UIImage`). This file hides the platform image type behind a single
// `PlatformImage` alias and a SwiftUI `Image(platformImage:)` initializer so
// the views never branch on the OS.

import SwiftUI

#if canImport(AppKit)
import AppKit
typealias PlatformImage = NSImage
#elseif canImport(UIKit)
import UIKit
typealias PlatformImage = UIImage
#endif

extension PlatformImage {
    /// Loads a `PlatformImage` from a bundle resource URL on either platform.
    static func load(contentsOf url: URL) -> PlatformImage? {
        #if canImport(AppKit)
        return NSImage(contentsOf: url)
        #elseif canImport(UIKit)
        return (try? Data(contentsOf: url)).flatMap(UIImage.init(data:))
        #else
        return nil
        #endif
    }
}

extension Image {
    /// Wraps a `PlatformImage` as a SwiftUI `Image` on either platform.
    init(platformImage: PlatformImage) {
        #if canImport(AppKit)
        self.init(nsImage: platformImage)
        #elseif canImport(UIKit)
        self.init(uiImage: platformImage)
        #endif
    }
}

extension Bundle {
    /// The bundle holding the app's bundled resources (e.g. DOW-Seal.png).
    ///
    /// SwiftPM targets generate `Bundle.module`; a plain Xcode app target does
    /// not, so the iOS app project defines the `XCODE_APP` compilation
    /// condition and copies the resources into the app bundle (`Bundle.main`).
    static var appResources: Bundle {
        #if XCODE_APP
        return .main
        #else
        return .module
        #endif
    }
}
