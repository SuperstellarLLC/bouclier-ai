import Foundation
@preconcurrency import NetworkExtension
@preconcurrency import SystemExtensions

/// Manages the Bouclier System Extension lifecycle.
///
/// Handles:
/// 1. Installing/activating the System Extension (triggers macOS approval prompt)
/// 2. Configuring NETransparentProxyManager (tells macOS to route traffic through it)
/// 3. Starting/stopping the transparent proxy provider
/// 4. Checking extension status
@MainActor
final class ExtensionManager: NSObject, ObservableObject {
    @Published var extensionInstalled = false
    @Published var proxyEnabled = false
    @Published var errorMessage: String?

    static let extensionBundleID = "com.bouclier.app.extension"

    private var activationCompletion: ((Bool) -> Void)?

    // MARK: - Install Extension

    /// Request installation of the System Extension.
    /// macOS will prompt: "Bouclier would like to add network configurations."
    /// User approves in System Settings > General > Login Items & Extensions.
    func installExtension(completion: @escaping (Bool) -> Void) {
        errorMessage = nil
        activationCompletion = completion

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionBundleID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Remove the System Extension.
    func removeExtension() {
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionBundleID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: - Configure Proxy

    /// Configure and enable the NETransparentProxyManager.
    /// This tells macOS to start routing traffic through our extension.
    func enableProxy() async -> Bool {
        do {
            let managers = try await NETransparentProxyManager.loadAllFromPreferences()
            let manager = managers.first ?? NETransparentProxyManager()

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.extensionBundleID
            proto.serverAddress = "127.0.0.1" // required but we use local proxy

            manager.protocolConfiguration = proto
            manager.localizedDescription = "Bouclier AI Traffic Scanner"
            manager.isEnabled = true

            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            try await manager.connection.startVPNTunnel()

            proxyEnabled = true
            return true
        } catch {
            errorMessage = "Failed to enable proxy: \(error.localizedDescription)"
            return false
        }
    }

    /// Disable the transparent proxy.
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

    /// Check if the extension is currently active.
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
    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        // Always replace with newer version
        return .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        NSLog("[bouclier.ai-ext] Extension needs user approval in System Settings")
        Task { @MainActor in
            errorMessage = "Please approve Bouclier in System Settings > General > Login Items & Extensions"
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        let success = result == .completed
        NSLog("[bouclier.ai-ext] Extension activation result: \(result)")
        Task { @MainActor in
            extensionInstalled = success
            if !success {
                errorMessage = "Extension activation failed"
            }
            activationCompletion?(success)
            activationCompletion = nil
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        NSLog("[bouclier.ai-ext] Extension error: \(error)")
        Task { @MainActor in
            extensionInstalled = false
            errorMessage = error.localizedDescription
            activationCompletion?(false)
            activationCompletion = nil
        }
    }
}
