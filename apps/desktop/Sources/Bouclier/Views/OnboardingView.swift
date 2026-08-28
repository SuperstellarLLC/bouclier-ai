import SwiftUI

struct OnboardingView: View {
    @ObservedObject var proxyManager: ProxyManager
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @AppStorage("injectionBlockEnabled") private var userBlockingEnabled = false
    @State private var currentStep = 0
    @State private var isSettingUp = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 4) {
                ForEach(0..<2, id: \.self) { step in
                    Capsule()
                        .fill(step <= currentStep ? Color.accentColor : Color.secondary.opacity(0.3))
                        .frame(height: 4)
                }
            }
            .padding(.horizontal)
            .padding(.top, 20)

            Group {
                if currentStep == 0 {
                    welcomeStep
                        .transition(.asymmetric(
                            insertion: .move(edge: .leading).combined(with: .opacity),
                            removal: .move(edge: .leading).combined(with: .opacity)
                        ))
                } else {
                    protectStep
                        .transition(.asymmetric(
                            insertion: .move(edge: .trailing).combined(with: .opacity),
                            removal: .move(edge: .trailing).combined(with: .opacity)
                        ))
                }
            }
            .padding(32)
            .animation(.spring(response: 0.45, dampingFraction: 0.85), value: currentStep)
        }
        .frame(width: 480, height: 460)
    }

    private var welcomeStep: some View {
        VStack(spacing: 16) {
            Spacer()
            HStack(spacing: 8) {
                Image(systemName: "shield.checkered")
                    .font(.system(size: 64))
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
            }
            HStack(spacing: 8) {
                Text("Welcome to Bouclier.ai")
                    .font(.title.bold())
                Text("BETA")
                    .font(.system(size: 10, weight: .semibold))
                    .tracking(0.6)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.orange.opacity(0.15), in: RoundedRectangle(cornerRadius: 4))
                    .foregroundStyle(.orange)
                    .accessibilityLabel("Beta release")
            }
            Text("A local prompt-injection firewall for your AI agent. Bouclier inspects the tool results your agent reads — web pages, files, MCP output — and flags anything trying to give your model orders. You choose whether findings are monitored or blocked. In Monitoring, your own prompt content is inspected but allowed through unchanged; detection runs entirely on your Mac.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 380)
            Spacer()
            Button("Continue") { currentStep = 1 }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
    }

    private var protectStep: some View {
        VStack(spacing: 16) {
            Spacer()

            if setupReady {
                Image(systemName: proxyManager.detectionEngineDegraded
                      ? "exclamationmark.shield.fill"
                      : (blockingEnabled ? "checkmark.shield.fill" : "eye.fill"))
                    .font(.system(size: 56))
                    .foregroundStyle(proxyManager.detectionEngineDegraded
                                     ? Color.orange
                                     : (blockingEnabled ? Color.green : Color.blue))
                    .accessibilityHidden(true)
                Text(proxyManager.detectionEngineDegraded
                     ? "Protection Is Degraded"
                     : (blockingEnabled ? "Blocking is Active" : "Monitoring is Active"))
                    .font(.title2.bold())
                Text(activeSetupDescription)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 380)
            } else {
                Image(systemName: pendingSetupIcon)
                    .font(.system(size: 56))
                    .foregroundStyle(pendingSetupTint)
                    .accessibilityHidden(true)
                Text(pendingSetupTitle)
                    .font(.title2.bold())
                Text(pendingSetupDescription)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 380)

                Picker("Finding action", selection: blockingBinding) {
                    Text("Monitor").tag(false)
                    Text("Block").tag(true)
                }
                .pickerStyle(.segmented)
                .frame(maxWidth: 280)
                .disabled(managedBlockingEnabled != nil)
                .help(managedBlockingEnabled != nil ? "This setting is managed by your organization" : "Choose whether suspicious requests are logged or refused")

                Text(blockingEnabled
                     ? "Block refuses detector findings. Within the hard 64 MiB transport cap, supported bodies are fully inspected up to 8 MiB; larger bodies receive a bounded 24-window sample, and a clean or inconclusive sample passes with a partial-coverage record. False positives can interrupt an agent session."
                     : "Monitor records suspicious findings without refusing them. Ordinary gateway errors and size limits still apply.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 360)

                if let error = proxyManager.errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 380)
                }
            }

            Spacer()

            if setupReady {
                Button("Done") {
                    hasCompletedOnboarding = true
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            } else {
                Button(action: {
                    isSettingUp = true
                    if !ShellEnvInjector.isEnabled,
                       !proxyManager.setCLICaptureEnabled(true)
                    {
                        isSettingUp = false
                        return
                    }
                    proxyManager.enableStandard()
                    // When the gateway is already live, CLI capture is applied
                    // synchronously and `isRunning` does not change to stop the
                    // spinner. Reflect the completed retry immediately.
                    if proxyManager.isRunning { isSettingUp = false }
                }) {
                    if isSettingUp {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Text(pendingSetupButtonTitle)
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(isSettingUp)

                Button("Set Up Later") {
                    hasCompletedOnboarding = true
                    dismiss()
                }
                .buttonStyle(.bordered)
                .foregroundStyle(.secondary)
            }
        }
        // Flip the setup spinner off when the proxy actually starts OR
        // when setup surfaces an error. Replaces a prior 2-second sleep
        // that could unblock the button before the proxy was ready.
        .onChange(of: proxyManager.isRunning) { _, running in
            if running { isSettingUp = false }
        }
        .onChange(of: proxyManager.errorMessage) { _, error in
            if error != nil { isSettingUp = false }
        }
        .onChange(of: proxyManager.cliCaptureHealthIssue) { _, issue in
            if issue != nil { isSettingUp = false }
        }
    }

    private var setupReady: Bool {
        Self.setupIsReady(
            isRunning: proxyManager.isRunning,
            protectionActive: proxyManager.protectionActive,
            cliCaptureHealthy: proxyManager.cliCaptureHealthy
        )
    }

    /// Pure readiness boundary used by the UI and focused journey tests.
    /// A bound gateway alone is insufficient: without verified CLI capture,
    /// newly launched compatible tools can still bypass it.
    static func setupIsReady(
        isRunning: Bool,
        protectionActive: Bool,
        cliCaptureHealthy: Bool
    ) -> Bool {
        isRunning && protectionActive && cliCaptureHealthy
    }

    private var managedBlockingEnabled: Bool? {
        FeatureFlags.managedInjectionBlock
    }

    private var protectionState: DesktopProtectionState {
        .resolve(
            protectionActive: proxyManager.protectionActive,
            gatewayRunning: proxyManager.isRunning,
            detectionEngineDegraded: proxyManager.detectionEngineDegraded
        )
    }

    private var pendingSetupIcon: String {
        switch protectionState {
        case .requested, .operational, .degraded:
            return "exclamationmark.shield.fill"
        case .off(let gatewayRunning):
            return gatewayRunning ? "shield.slash" : "lock.shield"
        }
    }

    private var pendingSetupTint: Color {
        switch protectionState {
        case .requested, .operational, .degraded:
            return .orange
        case .off(let gatewayRunning):
            return gatewayRunning ? .secondary : .accentColor
        }
    }

    private var pendingSetupTitle: String {
        switch protectionState {
        case .requested:
            return "Protection Requested"
        case .operational, .degraded:
            return "Setup Needs Attention"
        case .off:
            return "Enable Protection"
        }
    }

    private var pendingSetupDescription: String {
        switch protectionState {
        case .requested:
            return "The gateway is not listening yet. Traffic is not protected until startup completes. Retry if this state persists."
        case .operational, .degraded:
            return "The local gateway is running, but automatic CLI capture is incomplete. Until setup succeeds, some new AI tools may bypass Bouclier."
        case .off(let gatewayRunning):
            if gatewayRunning {
                return "The gateway is running in passthrough, so traffic flows uninspected. Enable protection to begin inspection."
            }
            return "Bouclier routes Claude Code and AI SDKs that honor base-URL settings through a local gateway — no certificate to install. It inspects requests for prompt injection hidden in untrusted tool output, on-device."
        }
    }

    private var pendingSetupButtonTitle: String {
        switch protectionState {
        case .requested:
            return "Retry Protection"
        case .operational, .degraded:
            return "Retry CLI Setup"
        case .off:
            return "Enable Protection"
        }
    }

    private var activeSetupDescription: String {
        if proxyManager.detectionEngineDegraded {
            if !proxyManager.detectorEnabled {
                return "The gateway and CLI capture are ready, but injection detection is disabled by managed policy. Routed traffic is relayed without injection inspection."
            }
            if !proxyManager.patternTierHealthy {
                return "The gateway and CLI capture are ready, but only emergency detection patterns loaded. Reinstall before relying on protection."
            }
            if proxyManager.mlTierUnavailable {
                return "The pattern tier is active, but on-device ML failed to load. Reinstall or review Logs before relying on protection."
            }
            return "The detection engine is degraded. Review Logs before relying on protection."
        }
        return blockingEnabled
            ? "Detector findings are refused before reaching the model. Within the hard 64 MiB transport cap, supported bodies are fully inspected up to 8 MiB; larger bodies receive a bounded 24-window sample, so a clean or inconclusive sample passes with a partial-coverage record. Open a new terminal (or restart your agent) so it picks up the gateway; existing sessions still talk directly to the provider. Bouclier preserves any custom provider base URL already in your environment."
            : "Suspicious untrusted tool output is logged, but model-visible request-body content is allowed through unchanged. You can turn on blocking anytime in Settings ▸ Protection. Open a new terminal (or restart your agent) so it picks up the gateway. Bouclier preserves any custom provider base URL already in your environment."
    }

    private var blockingEnabled: Bool {
        managedBlockingEnabled ?? userBlockingEnabled
    }

    private var blockingBinding: Binding<Bool> {
        Binding(
            get: { blockingEnabled },
            set: { value in
                guard managedBlockingEnabled == nil else { return }
                userBlockingEnabled = value
                if value { proxyManager.requestBlockNotificationAuthorizationIfNeeded() }
            }
        )
    }
}
