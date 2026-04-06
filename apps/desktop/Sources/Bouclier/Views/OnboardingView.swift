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
                } else {
                    protectStep
                }
            }
            .padding(32)
        }
        .frame(width: 480, height: 400)
    }

    private var welcomeStep: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "shield.checkered")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            Text("Welcome to Bouclier.ai")
                .font(.title.bold())
            Text("A local prompt injection firewall for macOS. Scans every AI API request and streaming response — before they reach the model. Nothing ever leaves your machine.")
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
                    Task {
                        proxyManager.setup()
                        // setup() triggers async work internally;
                        // observe proxyManager.isRunning to know when it finishes
                        try? await Task.sleep(for: .seconds(2))
                        await MainActor.run { isSettingUp = false }
                    }
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
    }
}
