import Testing
@testable import Bouclier

@Suite("Desktop protection journey state")
@MainActor
struct DesktopJourneyStateTests {
    @Test("Onboarding completes only with a live protected gateway and healthy CLI capture")
    func onboardingReadinessRequiresEveryBoundary() {
        #expect(OnboardingView.setupIsReady(
            isRunning: true,
            protectionActive: true,
            cliCaptureHealthy: true
        ))
        #expect(!OnboardingView.setupIsReady(
            isRunning: false,
            protectionActive: true,
            cliCaptureHealthy: true
        ))
        #expect(!OnboardingView.setupIsReady(
            isRunning: true,
            protectionActive: false,
            cliCaptureHealthy: true
        ))
        #expect(!OnboardingView.setupIsReady(
            isRunning: true,
            protectionActive: true,
            cliCaptureHealthy: false
        ))
    }

    @Test("Persisted intent is not reported as operational before the gateway binds")
    func operationalProtectionRequiresTheListener() {
        #expect(DesktopProtectionState.resolve(
            protectionActive: true,
            gatewayRunning: false,
            detectionEngineDegraded: false
        ) == .requested)
        #expect(DesktopProtectionState.resolve(
            protectionActive: true,
            gatewayRunning: true,
            detectionEngineDegraded: false
        ) == .operational)
        #expect(DesktopProtectionState.resolve(
            protectionActive: true,
            gatewayRunning: true,
            detectionEngineDegraded: true
        ) == .degraded)
    }

    @Test("Protection off stays distinct from gateway passthrough")
    func offStateRetainsGatewayTruth() {
        #expect(DesktopProtectionState.resolve(
            protectionActive: false,
            gatewayRunning: false,
            detectionEngineDegraded: false
        ) == .off(gatewayRunning: false))
        #expect(DesktopProtectionState.resolve(
            protectionActive: false,
            gatewayRunning: true,
            detectionEngineDegraded: true
        ) == .off(gatewayRunning: true))
    }

    @Test("Menu-bar presentation reserves active mode claims for operational protection")
    func menuBarPresentationUsesEffectiveState() {
        let inactiveStates: [DesktopProtectionState] = [
            .off(gatewayRunning: false),
            .off(gatewayRunning: true),
            .requested,
            .degraded,
        ]

        for state in inactiveStates {
            for blockingEnabled in [false, true] {
                let presentation = DesktopMenuBarPresentation.resolve(
                    state: state,
                    blockingEnabled: blockingEnabled,
                    errorMessage: nil
                )
                #expect(presentation.iconName != "checkmark.shield.fill")
                #expect(presentation.iconName != "eye.fill")
                #expect(!presentation.accessibilityLabel.contains("blocking suspicious requests"))
                #expect(!presentation.accessibilityLabel.contains("monitoring suspicious requests"))
            }
        }

        #expect(DesktopMenuBarPresentation.resolve(
            state: .operational,
            blockingEnabled: true,
            errorMessage: nil
        ) == DesktopMenuBarPresentation(
            iconName: "checkmark.shield.fill",
            accessibilityLabel: "Bouclier.ai — blocking suspicious requests"
        ))
        #expect(DesktopMenuBarPresentation.resolve(
            state: .operational,
            blockingEnabled: false,
            errorMessage: nil
        ) == DesktopMenuBarPresentation(
            iconName: "eye.fill",
            accessibilityLabel: "Bouclier.ai — monitoring suspicious requests"
        ))
    }

    @Test("Menu-bar errors override otherwise operational presentation")
    func menuBarErrorWins() {
        #expect(DesktopMenuBarPresentation.resolve(
            state: .operational,
            blockingEnabled: true,
            errorMessage: "Gateway failed"
        ) == DesktopMenuBarPresentation(
            iconName: "exclamationmark.shield.fill",
            accessibilityLabel: "Bouclier.ai — needs attention: Gateway failed"
        ))
    }

    @Test("Finding-action prose describes inactive selections without claiming live action")
    func findingActionCopyUsesEffectiveState() {
        let inactiveStates: [DesktopProtectionState] = [
            .off(gatewayRunning: false),
            .off(gatewayRunning: true),
            .requested,
            .degraded,
        ]

        for state in inactiveStates {
            for blockingEnabled in [false, true] {
                let description = state.findingActionDescription(
                    blockingEnabled: blockingEnabled,
                    detectorDisabledByPolicy: false
                )
                #expect(!description.hasPrefix("Blocking:"))
                #expect(!description.hasPrefix("Monitoring:"))
            }
        }

        #expect(DesktopProtectionState.degraded.findingActionDescription(
            blockingEnabled: true,
            detectorDisabledByPolicy: true
        ).contains("disabled by managed policy"))
        #expect(DesktopProtectionState.operational.findingActionDescription(
            blockingEnabled: true,
            detectorDisabledByPolicy: false
        ).hasPrefix("Blocking:"))
        #expect(DesktopProtectionState.operational.findingActionDescription(
            blockingEnabled: false,
            detectorDisabledByPolicy: false
        ).hasPrefix("Monitoring:"))
    }
}
