import Foundation
import NetworkExtension

// Entry point for the System Extension.
// NEProvider.startSystemExtensionMode() registers with the system
// and waits for the NETransparentProxyManager to activate us.
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
