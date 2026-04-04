import SwiftUI

struct ConfigRow: View {
    let label: String
    let value: String
    var copyPrefix: String = ""
    @State private var copied = false

    var body: some View {
        HStack {
            Text(label)
                .font(.caption.bold())
                .frame(width: 70, alignment: .trailing)
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
            Spacer()
            Button(action: {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(copyPrefix + value, forType: .string)
                copied = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
            }) {
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy to clipboard")
        }
    }
}
