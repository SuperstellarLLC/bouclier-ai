import SwiftUI

struct OnboardingView: View {
    @ObservedObject var proxyManager: ProxyManager
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @State private var currentStep = 0
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            // Progress bar
            HStack(spacing: 4) {
                ForEach(0..<3, id: \.self) { step in
                    Capsule()
                        .fill(step <= currentStep ? Color.accentColor : Color.secondary.opacity(0.3))
                        .frame(height: 4)
                }
            }
            .padding(.horizontal)
            .padding(.top, 20)

            Group {
                switch currentStep {
                case 0:
                    welcomeStep
                case 1:
                    configureStep
                default:
                    startStep
                }
            }
            .padding(32)
        }
        .frame(width: 500, height: 400)
    }

    private var welcomeStep: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "shield.checkered")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
            Text("Welcome to Ilvarion")
                .font(.title.bold())
            Text("Ilvarion protects your AI interactions by scanning for prompt injections locally. No data ever leaves your machine.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 360)
            Spacer()
            Button("Get Started") { currentStep = 1 }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
    }

    private var configureStep: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "terminal")
                .font(.system(size: 48))
                .foregroundStyle(.tint)
            Text("Configure Your AI SDKs")
                .font(.title2.bold())
            Text("Point your AI SDK to the local proxy:")
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 12) {
                ConfigRow(
                    label: "OpenAI",
                    value: "OPENAI_BASE_URL=http://localhost:\(proxyManager.port)/openai/v1"
                )
                ConfigRow(
                    label: "Anthropic",
                    value: "ANTHROPIC_BASE_URL=http://localhost:\(proxyManager.port)/anthropic"
                )
            }
            .padding()
            .background(.quaternary.opacity(0.5))
            .clipShape(RoundedRectangle(cornerRadius: 8))

            Spacer()
            Button("Next") { currentStep = 2 }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
    }

    private var startStep: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: proxyManager.isRunning ? "checkmark.shield" : "play.circle")
                .font(.system(size: 48))
                .foregroundStyle(proxyManager.isRunning ? Color.green : Color.accentColor)
            Text(proxyManager.isRunning ? "You're Protected" : "Start the Proxy")
                .font(.title2.bold())
            Text(proxyManager.isRunning
                 ? "Ilvarion is now scanning all AI traffic for prompt injections."
                 : "Start the proxy to begin protecting your AI interactions.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 360)

            Spacer()
            if !proxyManager.isRunning {
                Button("Start Proxy") { proxyManager.start() }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
            }

            Button(proxyManager.isRunning ? "Done" : "Skip for Now") {
                hasCompletedOnboarding = true
                dismiss()
            }
            .buttonStyle(.bordered)
        }
    }
}

