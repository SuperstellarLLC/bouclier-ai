import AppKit
import BouclierSecretsCore
import SwiftUI

/// Routes a generalized approval-action request to the right dialog. The
/// invariant: the agent *proposes* a state change; the human *approves* it
/// in Bouclier's own trusted UI; the app — never the agent — mutates state.
/// Security-WEAKENING actions (disable, install CA, uninstall) are NOT
/// routed here at all — they have no agent path by construction.
@MainActor
enum ActionApprovalRouter {
    static func present(_ req: ActionRequestIPC) async -> ActionResponseIPC {
        switch req.action {
        case "enable_protection":
            return await ProtectionApprovalCoordinator.shared.present(req)
        default:
            return ActionResponseIPC(id: req.id, action: req.action, status: .unsupported,
                                     message: "Bouclier doesn't support the action '\(req.action)'.")
        }
    }
}

/// Out-of-band approval for enabling protection. Mirrors
/// `SecretApprovalCoordinator`'s NSPanel + continuation + timeout design so
/// a menubar/.accessory app can reliably focus the dialog on demand.
@MainActor
final class ProtectionApprovalCoordinator {
    static let shared = ProtectionApprovalCoordinator()

    /// Wired by the app at startup. Performs the actual enable and returns a
    /// human-readable result. The agent can never call this directly — it
    /// only reaches it through an approved dialog.
    var onEnable: ((_ mode: String) -> (ok: Bool, message: String))?

    private var panel: NSPanel?
    private var queue: [(ActionRequestIPC, CheckedContinuation<ActionResponseIPC, Never>)] = []
    private var presenting = false

    func present(_ request: ActionRequestIPC) async -> ActionResponseIPC {
        await withCheckedContinuation { cont in
            queue.append((request, cont))
            pump()
        }
    }

    private func pump() {
        guard !presenting, let (request, _) = queue.first else { return }
        presenting = true
        scheduleTimeout(for: request)
        showPanel(for: request)
    }

    private func finishFront(_ make: (ActionRequestIPC) -> ActionResponseIPC) {
        guard let (request, cont) = queue.first else { return }
        let response = make(request)
        queue.removeFirst()
        cont.resume(returning: response)
        dismissPanel()
        presenting = false
        if queue.isEmpty { NSApp.setActivationPolicy(.accessory) }
        pump()
    }

    private func scheduleTimeout(for request: ActionRequestIPC) {
        let elapsed = max(0, Date().timeIntervalSince1970 - request.createdAt)
        let remaining = max(1, 120 - elapsed)
        let id = request.id
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(remaining))
            guard presenting, queue.first?.0.id == id else { return }
            finishFront { ActionResponseIPC(id: $0.id, action: $0.action, status: .timeout, message: "No response from the user.") }
        }
    }

    private func mode(for request: ActionRequestIPC) -> String {
        let m = request.params["mode"] ?? "standard"
        return m == "extreme" ? "standard" : m   // never let the agent steer into extreme/CA
    }

    private func approve(_ request: ActionRequestIPC) {
        finishFront { req in
            let m = self.mode(for: req)
            let result = self.onEnable?(m) ?? (ok: false, message: "Bouclier could not enable protection.")
            return ActionResponseIPC(
                id: req.id, action: req.action,
                status: result.ok ? .approved : .invalid,
                result: ["mode": m, "running": result.ok ? "true" : "false"],
                message: result.message)
        }
    }

    private func deny(_ request: ActionRequestIPC) {
        finishFront { ActionResponseIPC(id: $0.id, action: $0.action, status: .declined,
                                        message: "The user declined to enable protection.") }
    }

    private func showPanel(for request: ActionRequestIPC) {
        NSApp.setActivationPolicy(.regular)
        let form = ProtectionApprovalForm(
            mode: mode(for: request),
            reason: request.reason,
            onApprove: { [weak self] in self?.approve(request) },
            onDeny: { [weak self] in self?.deny(request) }
        )
        let hosting = NSHostingView(rootView: form)
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 460, height: 200),
                            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = "Bouclier — protection request"
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
        panel?.contentView = nil
        panel = nil
    }

    private lazy var panelDelegate: ActionPanelCloseDelegate = ActionPanelCloseDelegate { [weak self] in
        guard let (req, _) = self?.queue.first else { return }
        self?.deny(req)
    }
}

private final class ActionPanelCloseDelegate: NSObject, NSWindowDelegate {
    let onClose: () -> Void
    init(onClose: @escaping () -> Void) { self.onClose = onClose }
    func windowShouldClose(_ sender: NSWindow) -> Bool { onClose(); return false }
}

private struct ProtectionApprovalForm: View {
    let mode: String
    let reason: String
    let onApprove: () -> Void
    let onDeny: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Your AI agent wants to turn on Bouclier protection", systemImage: "lock.shield")
                .font(.headline)

            Text("This enables \(mode) protection and updates your shell environment so new terminals route AI traffic through Bouclier. You can turn it off anytime in Settings.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if !reason.isEmpty {
                GroupBox {
                    Text(reason)
                        .font(.callout)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                } label: {
                    Label("Reason (claimed by the agent)", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.orange)
                }
            }

            HStack {
                Spacer()
                Button("Don't enable", role: .cancel) { onDeny() }
                    .keyboardShortcut(.cancelAction)
                Button("Enable Protection") { onApprove() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
}
