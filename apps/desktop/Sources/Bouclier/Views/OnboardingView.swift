import SwiftUI

struct OnboardingView: View {
    @ObservedObject var proxyManager: ProxyManager
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
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
        .frame(width: 480, height: 400)
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
            Text("A local prompt-injection firewall for your AI agent. Bouclier inspects the tool results your agent reads — web pages, files, MCP output — and refuses the request when something in there is trying to give your model orders. Your own prompts are never touched. It can also keep managed API keys out of the model. Nothing ever leaves your machine.")
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

            if proxyManager.isRunning {
                Image(systemName: "checkmark.shield.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(.green)
                    .accessibilityHidden(true)
                Text("You're Protected")
                    .font(.title2.bold())
                Text("One more step: open a new terminal (or restart your agent) so it picks up the gateway. Terminals and agents already running still talk to the provider directly until you do. Look for the shield icon in your menubar.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 380)
            } else {
                Image(systemName: "lock.shield")
                    .font(.system(size: 56))
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
                Text("Enable Protection")
                    .font(.title2.bold())
                Text("Bouclier routes your AI tools (Claude Code, Cursor, …) through a local gateway — no certificate to install. It refuses prompt injections hidden in tool output, and can keep your secrets out of the model.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 380)

                if let error = proxyManager.errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 380)
                }
            }

            Spacer()

            if proxyManager.isRunning {
                Button("Done") {
                    hasCompletedOnboarding = true
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            } else {
                Button(action: {
                    isSettingUp = true
                    proxyManager.enableStandard()
                }) {
                    if isSettingUp {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Text("Enable Protection")
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
    }
}
