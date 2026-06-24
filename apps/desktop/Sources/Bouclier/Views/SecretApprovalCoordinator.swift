import AppKit
import BouclierSecretsCore
import SwiftUI

/// Presents the just-in-time secret-request dialog and turns the user's
/// input into stored secrets — entirely inside the app, so values never
/// reach the agent, the MCP channel, or the IPC files.
///
/// Design (per research): own an `NSPanel` hosting an `NSHostingView`
/// rather than a SwiftUI scene (a menubar/`.accessory` app can't reliably
/// focus a scene on demand, and a scene can't return a value). Requests
/// are serialized through a FIFO queue so concurrent asks show one panel
/// at a time, each awaited via a continuation.
@MainActor
final class SecretApprovalCoordinator {
    static let shared = SecretApprovalCoordinator()

    /// Default for the "keep after this session" checkbox.
    var persistByDefault = true

    private var panel: NSPanel?
    private var queue: [(SecretRequestIPC, CheckedContinuation<SecretResponseIPC, Never>)] = []
    private var presenting = false

    /// Present a dialog for a (validated) request and return the names-only
    /// outcome. The values are stored here and never returned.
    func present(_ request: SecretRequestIPC, timeout: Duration = .seconds(120)) async -> SecretResponseIPC {
        await withCheckedContinuation { cont in
            queue.append((request, cont))
            scheduleTimeout(for: request.id, timeout: timeout)
            pump()
        }
    }

    // MARK: Queue

    private func pump() {
        guard !presenting, let (request, _) = queue.first else { return }
        presenting = true
        showPanel(for: request)
    }

    private func finishFront(_ make: (SecretRequestIPC) -> SecretResponseIPC) {
        guard let (request, cont) = queue.first else { return }
        let response = make(request)
        queue.removeFirst()
        cont.resume(returning: response)
        dismissPanel()
        presenting = false
        if queue.isEmpty { NSApp.setActivationPolicy(.accessory) }
        pump()
    }

    private func scheduleTimeout(for id: String, timeout: Duration) {
        Task { @MainActor in
            try? await Task.sleep(for: timeout)
            // Only fire if this request is still the one on screen.
            guard presenting, queue.first?.0.id == id else { return }
            finishFront { SecretResponseIPC(id: $0.id, status: .timeout, provided: [], skipped: $0.envVars) }
        }
    }

    // MARK: Storing (values live only here)

    /// Store each non-empty value as a managed secret + activate it for new
    /// shells. Returns (provided, skipped) env-var names — never values.
    private func store(_ request: SecretRequestIPC, values: [String: String], persist: Bool) -> (provided: [String], skipped: [String]) {
        var provided: [String] = []
        var skipped: [String] = []
        var activatedRuleNames: [String] = []
        for envVar in request.envVars {
            let value = values[envVar] ?? ""
            guard !value.isEmpty else { skipped.append(envVar); continue }
            let ruleName = envVar.lowercased()   // validator guarantees [A-Za-z_][A-Za-z0-9_]* → valid rule name
            if SecretStore.shared.addSecret(name: ruleName, value: value, allowedHosts: [], agentAccess: true, envVar: envVar) {
                provided.append(envVar)
                activatedRuleNames.append(ruleName)
                if !persist { SessionSecrets.add(ruleName) }
            } else {
                skipped.append(envVar)
            }
        }
        // Activate (merge into the active env manifest, names only).
        if !activatedRuleNames.isEmpty {
            let current = SecretEnvManifest.load()
            SecretEnvManifest.save(current + activatedRuleNames.filter { !current.contains($0) })
        }
        return (provided, skipped)
    }

    // MARK: Panel

    private func showPanel(for request: SecretRequestIPC) {
        // Flip to a regular app so macOS will let our window become key
        // (a Dock-less .accessory app can't focus a window on demand).
        NSApp.setActivationPolicy(.regular)

        let form = SecretApprovalForm(
            request: request,
            persistDefault: persistByDefault,
            onProvide: { [weak self] values, persist in
                self?.finishFront { req in
                    let (provided, skipped) = self?.store(req, values: values, persist: persist) ?? ([], req.envVars)
                    return SecretResponseIPC(id: req.id, status: provided.isEmpty ? .cancelled : .provided, provided: provided, skipped: skipped)
                }
            },
            onCancel: { [weak self] in
                self?.finishFront { SecretResponseIPC(id: $0.id, status: .cancelled, provided: [], skipped: $0.envVars) }
            }
        )

        let hosting = NSHostingView(rootView: form)
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 460, height: 200),
                            styleMask: [.titled, .closable],
                            backing: .buffered, defer: false)
        panel.title = "Bouclier — credential request"
        panel.isFloatingPanel = true
        panel.hidesOnDeactivate = false
        panel.level = .modalPanel
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.contentView = hosting
        panel.setContentSize(hosting.fittingSize)
        panel.center()
        panel.delegate = panelDelegate
        self.panel = panel

        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        panel.orderFrontRegardless()
        panel.makeKey()
    }

    private func dismissPanel() {
        panel?.orderOut(nil)
        panel?.contentView = nil   // releases the SwiftUI state → clears SecureFields
        panel = nil
    }

    /// Treat the red close button as Cancel.
    private lazy var panelDelegate: PanelCloseDelegate = PanelCloseDelegate { [weak self] in
        self?.finishFront { SecretResponseIPC(id: $0.id, status: .cancelled, provided: [], skipped: $0.envVars) }
    }
}

private final class PanelCloseDelegate: NSObject, NSWindowDelegate {
    let onClose: () -> Void
    init(onClose: @escaping () -> Void) { self.onClose = onClose }
    func windowShouldClose(_ sender: NSWindow) -> Bool { onClose(); return false }
}

// MARK: - The form

private struct SecretApprovalForm: View {
    let request: SecretRequestIPC
    let persistDefault: Bool
    let onProvide: ([String: String], Bool) -> Void
    let onCancel: () -> Void

    @State private var values: [String: String]
    @State private var persist: Bool
    @FocusState private var focused: String?

    init(request: SecretRequestIPC, persistDefault: Bool,
         onProvide: @escaping ([String: String], Bool) -> Void, onCancel: @escaping () -> Void) {
        self.request = request
        self.persistDefault = persistDefault
        self.onProvide = onProvide
        self.onCancel = onCancel
        _values = State(initialValue: Dictionary(uniqueKeysWithValues: request.envVars.map { ($0, "") }))
        _persist = State(initialValue: persistDefault)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Claude is requesting \(request.envVars.count == 1 ? "a credential" : "credentials")", systemImage: "key.horizontal.fill")
                .font(.headline)

            // The reason is supplied by the agent — quarantine it as untrusted.
            if !request.reason.isEmpty {
                GroupBox {
                    Text(request.reason)
                        .font(.callout)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                } label: {
                    Label("Reason (claimed by the agent — verify before pasting)", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }

            if request.generate {
                Text("Bouclier generated these — review and approve, or regenerate with ↻.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            ForEach(request.envVars, id: \.self) { name in
                VStack(alignment: .leading, spacing: 3) {
                    Text("$\(name)").font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                    HStack(spacing: 6) {
                        SecureField("Paste value for \(name)", text: Binding(
                            get: { values[name] ?? "" },
                            set: { values[name] = $0 }))
                            .textFieldStyle(.roundedBorder)
                            .focused($focused, equals: name)
                            .onSubmit { advance(after: name) }
                        Button {
                            if let v = SecretGenerator.generate() { values[name] = v }
                        } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .buttonStyle(.borderless)
                        .help("Generate a random value (\(SecretGenerator.command))")
                    }
                }
            }

            Toggle("Keep after this session", isOn: $persist)
                .toggleStyle(.checkbox)
                .font(.callout)

            Text("Values are stored in your Keychain and used directly by your tools. Claude never sees them.")
                .font(.caption2)
                .foregroundStyle(.secondary)

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Button("Provide") { onProvide(values, persist) }
                    .keyboardShortcut(.defaultAction)
                    .disabled(values.values.allSatisfy { $0.isEmpty })
            }
        }
        .padding(20)
        .frame(width: 460)
        .onAppear {
            // When the agent asked Bouclier to CREATE the secrets, pre-fill
            // each empty field with a freshly generated value the user just
            // reviews/approves.
            if request.generate {
                for name in request.envVars where (values[name] ?? "").isEmpty {
                    if let v = SecretGenerator.generate() { values[name] = v }
                }
            }
            focused = request.envVars.first
        }
    }

    private func advance(after name: String) {
        guard let i = request.envVars.firstIndex(of: name), i + 1 < request.envVars.count else { focused = nil; return }
        focused = request.envVars[i + 1]
    }
}

// MARK: - Session-only secrets (purged on relaunch / quit)

/// Tracks rule names of secrets the user chose NOT to keep, so they can be
/// purged when the app quits or next launches. Persisted (survives a crash)
/// in UserDefaults — names only, never values.
enum SessionSecrets {
    private static let key = "bouclier.sessionSecretNames"

    static func add(_ ruleName: String) {
        var s = Set(UserDefaults.standard.stringArray(forKey: key) ?? [])
        s.insert(ruleName)
        UserDefaults.standard.set(Array(s), forKey: key)
    }

    /// Delete every session-only secret from the store + active manifest.
    static func purge() {
        let names = UserDefaults.standard.stringArray(forKey: key) ?? []
        guard !names.isEmpty else { return }
        for n in names { SecretStore.shared.removeSecret(name: n) }
        let active = SecretEnvManifest.load().filter { !names.contains($0) }
        SecretEnvManifest.save(active)
        UserDefaults.standard.removeObject(forKey: key)
    }
}
