import BouclierSecretsCore
import Foundation

/// bouclier-ai-env — outputs environment variables for shell eval.
///
/// Usage:
///   eval $(bouclier-ai-env)           # Configure current shell
///   eval $(bouclier-ai-env --unset)   # Remove configuration
///
/// Outputs:
///   export HTTPS_PROXY=http://127.0.0.1:8484
///   export HTTP_PROXY=http://127.0.0.1:8484
///   export NODE_EXTRA_CA_CERTS=/path/to/ca.pem
///   export SSL_CERT_FILE=/path/to/ca.pem
///   export REQUESTS_CA_BUNDLE=/path/to/ca.pem
///
/// Add to ~/.zshrc:
///   eval $(bouclier-ai-env 2>/dev/null)

let port = UserDefaults.standard.object(forKey: "proxyPort") as? Int ?? 8484

let appSupport = FileManager.default.urls(
    for: .applicationSupportDirectory,
    in: .userDomainMask
).first!.appendingPathComponent("ai.bouclier.app", isDirectory: true)

let caCertPath = appSupport.appendingPathComponent("ca.pem").path
let caExists = FileManager.default.fileExists(atPath: caCertPath)

let isUnset = CommandLine.arguments.contains("--unset")
let isHelp = CommandLine.arguments.contains("--help") || CommandLine.arguments.contains("-h")

// Secrets mode: emit `export NAME='value'` for every secret the agent has
// activated via the Bouclier MCP server (the active manifest), reading the
// real value from the Keychain. This is the ONLY place secret values are
// materialized — at shell-init, into the subprocess env. The values never
// pass through the MCP server or the model's context. Empty (no active
// secrets) ⇒ prints nothing.
if CommandLine.arguments.contains("--secrets") {
    let active = SecretEnvManifest.load()
    let metas = SecretRulesReader.load()
    let result = SecretEnvResolver.resolve(active: active, metas: metas) {
        KeychainSecretReader.value(forName: $0)
    }
    let fish = CommandLine.arguments.contains("--fish")
    let lines = fish
        ? SecretEnvResolver.exportLinesFish(result.exports)
        : SecretEnvResolver.exportLines(result.exports)
    if !lines.isEmpty { print(lines) }
    exit(0)
}

if isHelp {
    fputs("""
    bouclier-ai-env — Configure shell to route AI traffic through Bouclier

    Usage:
      eval $(bouclier-ai-env)           Configure current shell
      eval $(bouclier-ai-env --unset)   Remove configuration
      bouclier-ai-env --check           Check if Bouclier proxy is running
      bouclier-ai-env --help            Show this help

    Add to ~/.zshrc for automatic configuration:
      eval $(bouclier-ai-env 2>/dev/null)

    """, stderr)
    exit(0)
}

if CommandLine.arguments.contains("--check") {
    // Quick check if proxy is listening. The completion handler fires
    // on URLSession's delegate queue, so we publish the result through
    // a reference-typed box and synchronise via the semaphore — the
    // wait establishes happens-before for the post-semaphore read.
    final class ResultBox: @unchecked Sendable { var running = false }
    let url = URL(string: "http://127.0.0.1:\(port)/")!
    let semaphore = DispatchSemaphore(value: 0)
    let result = ResultBox()

    let task = URLSession.shared.dataTask(with: url) { _, response, _ in
        if let http = response as? HTTPURLResponse, http.statusCode == 200 {
            result.running = true
        }
        semaphore.signal()
    }
    task.resume()
    _ = semaphore.wait(timeout: .now() + 1)

    if result.running {
        fputs("[bouclier.ai] Proxy is running on port \(port)\n", stderr)
        exit(0)
    } else {
        fputs("[bouclier.ai] Proxy is not running\n", stderr)
        exit(1)
    }
}

if isUnset {
    print("unset HTTPS_PROXY;")
    print("unset HTTP_PROXY;")
    print("unset NODE_EXTRA_CA_CERTS;")
    print("unset SSL_CERT_FILE;")
    print("unset REQUESTS_CA_BUNDLE;")
} else {
    let proxy = "http://127.0.0.1:\(port)"
    print("export HTTPS_PROXY=\"\(proxy)\";")
    print("export HTTP_PROXY=\"\(proxy)\";")

    if caExists {
        print("export NODE_EXTRA_CA_CERTS=\"\(caCertPath)\";")
        print("export SSL_CERT_FILE=\"\(caCertPath)\";")
        print("export REQUESTS_CA_BUNDLE=\"\(caCertPath)\";")
    } else {
        fputs("[bouclier.ai] Warning: CA certificate not found. Run Bouclier.app and enable protection first.\n", stderr)
    }
}
