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
        .frame(width: 480, height: 380)
    }

    private var welcomeStep: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "shield.checkered")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
            Text("Welcome to Ilvarion")
                .font(.title.bold())
            Text("Ilvarion scans all AI API traffic on your Mac for prompt injections. Everything runs locally — no data ever leaves your machine.")
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
                Text("You're Protected")
                    .font(.title2.bold())
                Text("Ilvarion is now scanning all AI traffic. You'll see a shield icon in your menubar.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: 380)
            } else {
                Image(systemName: "lock.shield")
                    .font(.system(size: 56))
                    .foregroundStyle(.tint)
                Text("Enable Protection")
                    .font(.title2.bold())
                Text("Ilvarion will install a local security certificate and configure your network to route AI traffic through the scanner. You'll be prompted for your admin password.")
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
                    isSettingUp = false
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

                Button("Skip for Now") {
                    hasCompletedOnboarding = true
                    dismiss()
                }
                .buttonStyle(.bordered)
            }
        }
    }
}
