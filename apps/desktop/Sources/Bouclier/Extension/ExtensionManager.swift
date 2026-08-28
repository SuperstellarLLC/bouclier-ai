import Foundation
@preconcurrency import NetworkExtension
@preconcurrency import SystemExtensions

/// Cleanup-only remnant of the System Extension that used to back
/// "extreme mode" (system-wide transparent-proxy interception, removed).
/// Bouclier no longer ships a System Extension — this type exists solely
/// so `ProxyManager` can remove an extension and transparent-proxy preference
/// left by a pre-removal install. Safe to delete once confidence exists that
/// every install has migrated.
@MainActor
final class ExtensionManager: NSObject, ObservableObject {
    @Published var extensionInstalled = false
    @Published var proxyEnabled = false
    @Published var errorMessage: String?
    @Published private(set) var cleanupRequiresRestart = false

    nonisolated static let extensionBundleID = "ai.bouclier.app.extension"

    private enum PresenceResult {
        case present(Bool)
        case failed(String)
    }

    private enum DeactivationResult {
        case complete
        case notFound(String)
        case restartRequired
        case failed(String)
    }

    private var presenceRequest: OSSystemExtensionRequest?
    private var presenceContinuation: CheckedContinuation<PresenceResult, Never>?
    private var deactivationRequest: OSSystemExtensionRequest?
    private var deactivationContinuation: CheckedContinuation<DeactivationResult, Never>?
    private var cleanupInProgress = false
    private var cleanupProgressHandler: (@MainActor (String) -> Void)?

    /// Stop routing traffic through the retired transparent-proxy tunnel.
    @discardableResult
    func disableProxy() async -> Bool {
        do {
            let managers = try await NETransparentProxyManager.loadAllFromPreferences()
            for manager in managers where Self.isBouclierManager(manager) {
                manager.connection.stopVPNTunnel()
                manager.isEnabled = false
                try await manager.saveToPreferences()
            }
            proxyEnabled = false
            errorMessage = nil
            return true
        } catch {
            errorMessage = "Failed to disable Bouclier's legacy proxy: \(error.localizedDescription)"
            return false
        }
    }

    /// Remove Bouclier's retired Network Extension preference and System
    /// Extension in a safe order. The transparent-proxy preference goes first:
    /// deactivating its executable while a tunnel still routes to it can strand
    /// traffic. Every step is idempotent, so partial removal can be retried
    /// without touching another vendor's manager.
    @discardableResult
    func removeLegacyConfiguration(
        onProgress: (@MainActor (String) -> Void)? = nil
    ) async -> Bool {
        guard !cleanupInProgress else {
            errorMessage = "Legacy extension cleanup is already in progress. Wait for it to finish, then retry."
            return false
        }
        cleanupInProgress = true
        cleanupRequiresRestart = false
        cleanupProgressHandler = onProgress
        defer {
            cleanupProgressHandler = nil
            cleanupInProgress = false
        }

        guard await removeProxyPreference() else { return false }

        switch await inspectExtensionPresence() {
        case .failed(let message):
            errorMessage = message
            return false
        case .present(false):
            extensionInstalled = false
            errorMessage = nil
            return true
        case .present(true):
            extensionInstalled = true
        }

        switch await requestDeactivation() {
        case .complete:
            // Verify the postcondition instead of equating a successful
            // request callback with absence. This also protects against a
            // future OS behavior where completion precedes registry removal.
            switch await inspectExtensionPresence() {
            case .present(false):
                extensionInstalled = false
                cleanupRequiresRestart = false
                errorMessage = nil
                return true
            case .present(true):
                extensionInstalled = true
                errorMessage = "The legacy Bouclier System Extension is still registered after deactivation. Retry configuration removal."
                return false
            case .failed(let message):
                errorMessage = message
                return false
            }
        case .notFound(let message):
            // The current app intentionally no longer bundles the retired
            // extension, so systemextensiond may report not-found even when a
            // previously installed copy is still registered. Re-query before
            // deciding; only actual absence is success.
            switch await inspectExtensionPresence() {
            case .present(false):
                extensionInstalled = false
                errorMessage = nil
                return true
            case .present(true):
                extensionInstalled = true
                errorMessage = "Could not deactivate the legacy Bouclier System Extension: \(message). It remains registered; retry configuration removal or remove it in System Settings."
                return false
            case .failed(let verificationMessage):
                errorMessage = "System Extension deactivation failed: \(message). \(verificationMessage)"
                return false
            }
        case .restartRequired:
            // Apple's result explicitly says the extension may remain
            // operational until reboot. Treat the request as pending, not as
            // removal success; the next retry verifies absence.
            extensionInstalled = true
            cleanupRequiresRestart = true
            errorMessage = "Legacy System Extension removal will finish after restart. Restart this Mac, reopen Bouclier, and retry configuration removal to verify it is gone."
            return false
        case .failed(let message):
            extensionInstalled = true
            cleanupRequiresRestart = false
            errorMessage = message
            return false
        }
    }

    /// Inspect both pieces of retired state. A Network Extension preference is
    /// not proof that its System Extension is still installed (or vice versa),
    /// so status must query each source rather than infer one from the other.
    @discardableResult
    func checkStatus() async -> Bool {
        do {
            let managers = try await NETransparentProxyManager.loadAllFromPreferences()
            let manager = managers.first(where: Self.isBouclierManager)
            proxyEnabled = manager?.isEnabled == true
                && manager?.connection.status == .connected
        } catch {
            errorMessage = "Failed to inspect legacy proxy state: \(error.localizedDescription)"
            return false
        }

        switch await inspectExtensionPresence() {
        case .present(let present):
            extensionInstalled = present
            if !present { cleanupRequiresRestart = false }
            errorMessage = nil
            return true
        case .failed(let message):
            errorMessage = message
            return false
        }
    }

    /// `loadAllFromPreferences()` returns every transparent proxy configured
    /// for this user. Cleanup for Bouclier's retired extension must never
    /// disable another vendor's tunnel.
    private static func isBouclierManager(_ manager: NETransparentProxyManager) -> Bool {
        guard let provider = manager.protocolConfiguration as? NETunnelProviderProtocol
        else { return false }
        return provider.providerBundleIdentifier == extensionBundleID
    }

    /// Disable, remove, then re-read the exact retired manager. Removing the
    /// preference (rather than merely saving it disabled) is what makes the
    /// Settings promise of removing legacy extension configuration true.
    private func removeProxyPreference() async -> Bool {
        do {
            let managers = try await NETransparentProxyManager.loadAllFromPreferences()
            for manager in managers where Self.isBouclierManager(manager) {
                manager.connection.stopVPNTunnel()
                manager.isEnabled = false
                try await manager.saveToPreferences()
                try await manager.removeFromPreferences()
            }
            let remaining = try await NETransparentProxyManager.loadAllFromPreferences()
            guard !remaining.contains(where: Self.isBouclierManager) else {
                errorMessage = "The legacy Bouclier network-extension preference is still present. Check System Settings ▸ Network ▸ VPN & Filters, then retry."
                return false
            }
            proxyEnabled = false
            return true
        } catch {
            errorMessage = "Could not remove the legacy Bouclier network-extension preference: \(error.localizedDescription). Check System Settings ▸ Network ▸ VPN & Filters, then retry."
            return false
        }
    }

    private func inspectExtensionPresence() async -> PresenceResult {
        guard presenceContinuation == nil else {
            return .failed("Could not verify the legacy System Extension because another status request is in progress. Wait a moment, then retry.")
        }
        return await withCheckedContinuation { continuation in
            let request = OSSystemExtensionRequest.propertiesRequest(
                forExtensionWithIdentifier: Self.extensionBundleID,
                queue: .main
            )
            request.delegate = self
            presenceRequest = request
            presenceContinuation = continuation
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    private func requestDeactivation() async -> DeactivationResult {
        guard deactivationContinuation == nil else {
            return .failed("Legacy System Extension removal is already in progress. Wait for it to finish, then retry.")
        }
        return await withCheckedContinuation { continuation in
            let request = OSSystemExtensionRequest.deactivationRequest(
                forExtensionWithIdentifier: Self.extensionBundleID,
                queue: .main
            )
            request.delegate = self
            deactivationRequest = request
            deactivationContinuation = continuation
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    private func finishPresenceRequest(
        _ request: OSSystemExtensionRequest,
        result: PresenceResult
    ) {
        guard presenceRequest === request, let continuation = presenceContinuation else { return }
        presenceRequest = nil
        presenceContinuation = nil
        continuation.resume(returning: result)
    }

    private func finishDeactivationRequest(
        _ request: OSSystemExtensionRequest,
        result: DeactivationResult
    ) {
        guard deactivationRequest === request,
              let continuation = deactivationContinuation else { return }
        deactivationRequest = nil
        deactivationContinuation = nil
        continuation.resume(returning: result)
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

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        MainActor.assumeIsolated {
            guard deactivationRequest === request else { return }
            let message = "Approve removal of the legacy Bouclier System Extension in System Settings to continue."
            errorMessage = message
            cleanupProgressHandler?(message)
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        let completion: DeactivationResult = result == .completed
            ? .complete
            : .restartRequired
        NSLog("[bouclier.ai-ext] Extension deactivation result: \(result)")
        MainActor.assumeIsolated {
            if presenceRequest === request {
                // A properties request normally finishes through
                // `foundProperties`. Resolve an empty successful completion
                // too so an OS variation cannot strand the cleanup Task.
                finishPresenceRequest(request, result: .present(false))
            } else {
                finishDeactivationRequest(request, result: completion)
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        NSLog("[bouclier.ai-ext] System Extension request error: \(error)")
        let nsError = error as NSError
        let notFound = nsError.domain == OSSystemExtensionErrorDomain
            && nsError.code == OSSystemExtensionError.extensionNotFound.rawValue
        let description = nsError.localizedDescription
        MainActor.assumeIsolated {
            if presenceRequest === request {
                finishPresenceRequest(
                    request,
                    result: notFound
                        ? .present(false)
                        : .failed("Could not verify the legacy Bouclier System Extension: \(description). Retry configuration removal.")
                )
            } else if deactivationRequest === request {
                finishDeactivationRequest(
                    request,
                    result: notFound
                        ? .notFound(description)
                        : .failed("Could not deactivate the legacy Bouclier System Extension: \(description). Approve removal in System Settings if prompted, then retry.")
                )
            }
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        foundProperties properties: [OSSystemExtensionProperties]
    ) {
        // Even though the request is targeted, keep the ownership check at
        // the mutation boundary in case an OS implementation returns a wider
        // property set.
        let present = properties.contains {
            $0.bundleIdentifier == ExtensionManager.extensionBundleID
        }
        MainActor.assumeIsolated {
            finishPresenceRequest(request, result: .present(present))
        }
    }
}
