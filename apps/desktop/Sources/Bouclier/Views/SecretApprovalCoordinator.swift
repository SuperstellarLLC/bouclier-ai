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
    func present(_ request: SecretRequestIPC) async -> SecretResponseIPC {
        await withCheckedContinuation { cont in
            queue.append((request, cont))
            pump()
        }
    }

    // MARK: Queue

    private func pump() {
        guard !presenting, let (request, _) = queue.first else { return }
        presenting = true
        scheduleTimeout(for: request)   // start the clock when shown, not when queued
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

    private func scheduleTimeout(for request: SecretRequestIPC) {
        // Align the dialog's death with the agent's client-side deadline
        // (measured from when the request was created), so a request that
        // waited behind another doesn't outlive the agent's ~120s and let
        // the user provide a secret the agent already gave up on.
        let elapsed = max(0, Date().timeIntervalSince1970 - request.createdAt)
        let remaining = max(1, 120 - elapsed)
        let id = request.id
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(remaining))
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
        let existingByName = Dictionary(SecretStore.shared.rules().map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
        for envVar in request.envVars {
            let value = values[envVar] ?? ""
            guard !value.isEmpty else { skipped.append(envVar); continue }
            let ruleName = envVar.lowercased()   // validator guarantees [A-Za-z_][A-Za-z0-9_]* → valid rule name
            // Re-provisioning must NEVER widen a secret's policy. If a rule
            // already exists, preserve its agentAccess + allowedHosts; and a
            // LOCKED secret can't be re-provisioned to unlock itself (the
            // agent proposing the request must not be able to flip the gate).
            let existing = existingByName[ruleName]
            let policy = SecretReprovisionPolicy.decide(existingAgentAccess: existing?.agentAccess,
                                                        existingAllowedHosts: existing?.allowedHosts)
            guard policy.store else { skipped.append(envVar); continue }   // LOCKED → refuse
            if SecretStore.shared.addSecret(name: ruleName, value: value, allowedHosts: policy.allowedHosts, agentAccess: policy.agentAccess, envVar: envVar) {
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
    @State private var revealed: Set<String> = []
    @State private var genError: String?
    @FocusState private var focused: String?

    private func binding(_ name: String) -> Binding<String> {
        Binding(get: { values[name] ?? "" }, set: { values[name] = $0 })
    }

    private func generate(into name: String) {
        if let v = SecretGenerator.generate() {
            values[name] = v
            genError = nil
        } else {
            genError = "Couldn't generate a value — check the generator command in Settings → Secrets."
        }
    }

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
            Label("Your AI agent is requesting \(request.envVars.count == 1 ? "a credential" : "credentials")", systemImage: "key.horizontal.fill")
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
                Text("Bouclier generated these — tap the eye to review, ↻ to regenerate, then approve.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            // Many env vars (e.g. provisioning a whole project) must stay
            // usable: scroll the field list instead of letting the panel grow
            // taller than the screen.
            if request.envVars.count > 6 {
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) { fieldRows }
                        .padding(.trailing, 6)
                }
                .frame(maxHeight: 340)
            } else {
                fieldRows
            }

            if let genError {
                Text(genError).font(.caption).foregroundStyle(.red)
            }

            VStack(alignment: .leading, spacing: 2) {
                Toggle("Keep for future sessions", isOn: $persist)
                    .toggleStyle(.checkbox)
                    .font(.callout)
                if !persist {
                    Text("Removed when Bouclier next restarts.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }

            Text("Values are stored in your Keychain and used directly by your tools. The agent never sees them.")
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
                    generate(into: name)
                }
            }
            focused = request.envVars.first
        }
    }

    @ViewBuilder private var fieldRows: some View {
        ForEach(request.envVars, id: \.self) { name in
            VStack(alignment: .leading, spacing: 3) {
                Text("$\(name)").font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    Group {
                        if revealed.contains(name) {
                            TextField("Paste value for \(name)", text: binding(name))
                        } else {
                            SecureField("Paste value for \(name)", text: binding(name))
                        }
                    }
                    .textFieldStyle(.roundedBorder)
                    .focused($focused, equals: name)
                    .onSubmit { advance(after: name) }

                    Button {
                        if revealed.contains(name) { revealed.remove(name) } else { revealed.insert(name) }
                    } label: {
                        Image(systemName: revealed.contains(name) ? "eye.slash" : "eye")
                    }
                    .buttonStyle(.borderless)
                    .help(revealed.contains(name) ? "Hide" : "Show")

                    Button { generate(into: name) } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .buttonStyle(.borderless)
                    .help("Generate a random value")
                }
            }
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
