import Foundation
@preconcurrency import NetworkExtension
@preconcurrency import SystemExtensions

/// Cleanup-only remnant of the System Extension that used to back
/// "extreme mode" (system-wide transparent-proxy interception, removed).
/// Bouclier no longer ships a System Extension — this type exists solely
/// so `ProxyManager`'s one-shot migration (`ExtremeModeMigration`) can
/// detect an extension left active from a pre-removal install, disable
/// its `NETransparentProxyManager` tunnel, and deactivate the extension
/// itself. Safe to delete entirely once confidence exists that every
/// install has migrated (there's no telemetry, so in practice: after a
/// few releases with no reports of stale extension state).
@MainActor
final class ExtensionManager: NSObject, ObservableObject {
    @Published var extensionInstalled = false
    @Published var proxyEnabled = false
    @Published var errorMessage: String?

    static let extensionBundleID = "ai.bouclier.app.extension"

    /// Deactivate the System Extension.
    func removeExtension() {
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionBundleID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Stop routing traffic through the transparent-proxy tunnel.
    func disableProxy() async {
        do {
            let managers = try await NETransparentProxyManager.loadAllFromPreferences()
            for manager in managers {
                manager.connection.stopVPNTunnel()
                manager.isEnabled = false
                try await manager.saveToPreferences()
            }
            proxyEnabled = false
        } catch {
            errorMessage = "Failed to disable proxy: \(error.localizedDescription)"
        }
    }

    /// Check whether the extension is currently installed/active — the
    /// migration's gate for whether cleanup is needed at all.
    func checkStatus() async {
        do {
            let managers = try await NETransparentProxyManager.loadAllFromPreferences()
            if let manager = managers.first {
                extensionInstalled = true
                proxyEnabled = manager.isEnabled && manager.connection.status == .connected
            } else {
                extensionInstalled = false
                proxyEnabled = false
            }
        } catch {
            extensionInstalled = false
            proxyEnabled = false
        }
    }
}

// MARK: - OSSystemExtensionRequestDelegate

extension ExtensionManager: OSSystemExtensionRequestDelegate {
    // Required by the protocol but only meaningful for activation
    // requests, which this cleanup-only manager never issues.
    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {}

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        let success = result == .completed
        NSLog("[bouclier.ai-ext] Extension deactivation result: \(result)")
        Task { @MainActor in
            if success { extensionInstalled = false }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        NSLog("[bouclier.ai-ext] Extension deactivation error: \(error)")
        Task { @MainActor in
            errorMessage = error.localizedDescription
        }
    }
}
