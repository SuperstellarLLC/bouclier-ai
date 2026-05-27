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
            Text("A local firewall for AI traffic on your Mac. It scans every outbound request for prompt injections and inspects the attachments you send — images, PDFs, short audio clips — for PII before they reach the model. Your text prompts are forwarded byte-for-byte. Nothing ever leaves your machine.")
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
                Text("Bouclier.ai is scanning all AI traffic. Look for the shield icon in your menubar.")
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
                Text("Bouclier.ai will generate a local CA certificate (stored in your login Keychain, unique to this device, removable anytime) and install a System Extension to route AI traffic through the scanner.")
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
                    proxyManager.setup()
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
