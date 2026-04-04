import Foundation

/// ilvarion-env — outputs environment variables for shell eval.
///
/// Usage:
///   eval $(ilvarion-env)           # Configure current shell
///   eval $(ilvarion-env --unset)   # Remove configuration
///
/// Outputs:
///   export HTTPS_PROXY=http://127.0.0.1:8484
///   export HTTP_PROXY=http://127.0.0.1:8484
///   export NODE_EXTRA_CA_CERTS=/path/to/ca.pem
///   export SSL_CERT_FILE=/path/to/ca.pem
///   export REQUESTS_CA_BUNDLE=/path/to/ca.pem
///
/// Add to ~/.zshrc:
///   eval $(ilvarion-env 2>/dev/null)

let port = UserDefaults.standard.object(forKey: "proxyPort") as? Int ?? 8484

let appSupport = FileManager.default.urls(
    for: .applicationSupportDirectory,
    in: .userDomainMask
).first!.appendingPathComponent("dev.ilvarion.Ilvarion", isDirectory: true)

let caCertPath = appSupport.appendingPathComponent("ca.pem").path
let caExists = FileManager.default.fileExists(atPath: caCertPath)

let isUnset = CommandLine.arguments.contains("--unset")
let isHelp = CommandLine.arguments.contains("--help") || CommandLine.arguments.contains("-h")

if isHelp {
    fputs("""
    ilvarion-env — Configure shell to route AI traffic through Ilvarion

    Usage:
      eval $(ilvarion-env)           Configure current shell
      eval $(ilvarion-env --unset)   Remove configuration
      ilvarion-env --check           Check if Ilvarion proxy is running
      ilvarion-env --help            Show this help

    Add to ~/.zshrc for automatic configuration:
      eval $(ilvarion-env 2>/dev/null)

    """, stderr)
    exit(0)
}

if CommandLine.arguments.contains("--check") {
    // Quick check if proxy is listening
    let url = URL(string: "http://127.0.0.1:\(port)/")!
    let semaphore = DispatchSemaphore(value: 0)
    var proxyRunning = false

    let task = URLSession.shared.dataTask(with: url) { data, response, _ in
        if let http = response as? HTTPURLResponse, http.statusCode == 200 {
            proxyRunning = true
        }
        semaphore.signal()
    }
    task.resume()
    _ = semaphore.wait(timeout: .now() + 1)

    if proxyRunning {
        fputs("[ilvarion] Proxy is running on port \(port)\n", stderr)
        exit(0)
    } else {
        fputs("[ilvarion] Proxy is not running\n", stderr)
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
        fputs("[ilvarion] Warning: CA certificate not found. Run Ilvarion.app and enable protection first.\n", stderr)
    }
}
