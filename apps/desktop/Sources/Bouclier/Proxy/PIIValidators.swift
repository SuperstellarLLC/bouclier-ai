import Foundation

/// Swift mirrors of the TypeScript PII validators. Kept in this file as
/// pure free functions so they can be unit-tested without spinning up
/// the scanner; semantics must stay in lockstep with
/// `packages/patterns/src/pii/validators.ts`.
enum PIIValidators {
    // MARK: - Shannon entropy

    /// Shannon entropy in bits-per-character. Used to distinguish
    /// high-entropy secret-like strings from low-entropy English-like
    /// strings of the same length. ~3.5–4.0 cleanly separates real
    /// tokens from repetitive or word-like material.
    @Sendable static func hasShannonEntropy(_ value: String, _ minBitsPerChar: Double) -> Bool {
        guard !value.isEmpty else { return false }
        var counts: [Character: Int] = [:]
        for ch in value { counts[ch, default: 0] += 1 }
        let n = Double(value.count)
        var entropy = 0.0
        for c in counts.values {
            let p = Double(c) / n
            entropy -= p * log2(p)
        }
        return entropy >= minBitsPerChar
    }

    // MARK: - Luhn

    /// Length-agnostic Luhn over a digit-only string.
    static func luhnCore(_ digits: String) -> Bool {
        var sum = 0
        var alt = false
        for char in digits.reversed() {
            guard let n = char.wholeNumberValue, n >= 0, n <= 9 else { return false }
            var v = n
            if alt {
                v *= 2
                if v > 9 { v -= 9 }
            }
            sum += v
            alt.toggle()
        }
        return sum % 10 == 0
    }

    /// Mathematical checksums accept placeholder identifiers such as all
    /// zeroes. Repeated single-digit runs are not plausible account or
    /// registry numbers and create noisy redactions in fixtures/docs.
    private static func hasVariedDigits(_ digits: String) -> Bool {
        guard let first = digits.first else { return false }
        return digits.dropFirst().contains { $0 != first }
    }

    /// Luhn for credit-card-shaped inputs (12–19 digits after separator strip).
    @Sendable static func luhn(_ value: String) -> Bool {
        let clean = stripSpaceDash(value)
        guard clean.count >= 12, clean.count <= 19 else { return false }
        guard clean.allSatisfy({ $0.isASCII && $0.isNumber }) else { return false }
        guard hasVariedDigits(clean) else { return false }
        return luhnCore(clean)
    }

    // MARK: - IBAN mod-97

    @Sendable static func ibanMod97(_ iban: String) -> Bool {
        let clean = iban.uppercased().filter { !$0.isWhitespace }
        guard clean.count >= 15, clean.count <= 34 else { return false }
        guard let countryStart = clean.first?.isLetter, countryStart,
              clean.dropFirst().first?.isLetter == true,
              clean.dropFirst(2).first?.isNumber == true,
              clean.dropFirst(3).first?.isNumber == true
        else { return false }
        let rearranged = String(clean.dropFirst(4)) + String(clean.prefix(4))
        var remainder = 0
        for ch in rearranged {
            let value: Int
            if let n = ch.wholeNumberValue, ch.isASCII, ch.isNumber {
                value = n
            } else if ch.isLetter, let scalar = ch.asciiValue, scalar >= 65, scalar <= 90 {
                value = Int(scalar) - 55
            } else {
                return false
            }
            remainder = (remainder * (value > 9 ? 100 : 10) + value) % 97
        }
        return remainder == 1
    }

    // MARK: - US SSN

    @Sendable static func isPlausibleSSN(_ ssn: String) -> Bool {
        let clean = ssn.replacingOccurrences(of: "-", with: "")
        guard clean.count == 9, clean.allSatisfy({ $0.isASCII && $0.isNumber }) else {
            return false
        }
        let area = String(clean.prefix(3))
        let group = String(clean.dropFirst(3).prefix(2))
        let serial = String(clean.suffix(4))
        if area == "000" || area == "666" || area.hasPrefix("9") { return false }
        if group == "00" { return false }
        if serial == "0000" { return false }
        return true
    }

    // MARK: - IPv4

    @Sendable static func isPlausibleIPv4(_ ip: String) -> Bool {
        let parts = ip.split(separator: ".")
        guard parts.count == 4 else { return false }
        var nums: [Int] = []
        for p in parts {
            guard p.count >= 1, p.count <= 3 else { return false }
            guard p.allSatisfy(\.isNumber) else { return false }
            guard let n = Int(p), n >= 0, n <= 255 else { return false }
            nums.append(n)
        }
        if nums.allSatisfy({ $0 == 0 }) { return false }
        if nums.allSatisfy({ $0 == 255 }) { return false }
        return true
    }

    // MARK: - IPv6

    @Sendable static func isPlausibleIPv6(_ ip: String) -> Bool {
        let doubleColons = ip.components(separatedBy: "::").count - 1
        if doubleColons > 1 { return false }

        let groups: [String]
        if doubleColons == 1 {
            let parts = ip.components(separatedBy: "::")
            let head = parts[0].isEmpty ? [] : parts[0].split(separator: ":").map(String.init)
            let tail = parts[1].isEmpty ? [] : parts[1].split(separator: ":").map(String.init)
            let fillCount = 8 - head.count - tail.count
            if fillCount < 1 { return false }
            groups = head + Array(repeating: "0", count: fillCount) + tail
        } else {
            groups = ip.split(separator: ":").map(String.init)
        }

        guard groups.count == 8 else { return false }

        var allZero = true
        var allFFFF = true
        var hasHexLetter = false
        for g in groups {
            guard g.count >= 1, g.count <= 4 else { return false }
            guard g.allSatisfy({ $0.isHexDigit }) else { return false }
            guard let n = UInt16(g, radix: 16) else { return false }
            if n != 0 { allZero = false }
            if n != 0xFFFF { allFFFF = false }
            if g.contains(where: { $0.isLetter }) { hasHexLetter = true }
        }
        if allZero || allFFFF { return false }
        // Disambiguate from decimal-only date shapes (see R4 in the review).
        if doubleColons == 0, !hasHexLetter { return false }
        return true
    }

    // MARK: - JWT

    @Sendable static func isPlausibleJWT(_ token: String) -> Bool {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, parts.allSatisfy({ !$0.isEmpty }) else { return false }
        var header = String(parts[0])
        header = header.replacingOccurrences(of: "-", with: "+")
        header = header.replacingOccurrences(of: "_", with: "/")
        let pad = (4 - header.count % 4) % 4
        header += String(repeating: "=", count: pad)
        guard let data = Data(base64Encoded: header),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let dict = obj as? [String: Any],
              dict["alg"] is String
        else { return false }
        return true
    }

    // MARK: - French SIREN / SIRET / NIR

    @Sendable static func isPlausibleSIREN(_ siren: String) -> Bool {
        let clean = stripSpace(siren)
        guard clean.count == 9, clean.allSatisfy(\.isNumber) else { return false }
        guard hasVariedDigits(clean) else { return false }
        return luhnCore(clean)
    }

    @Sendable static func isPlausibleSIRET(_ siret: String) -> Bool {
        let clean = stripSpace(siret)
        guard clean.count == 14, clean.allSatisfy(\.isNumber) else { return false }
        guard hasVariedDigits(clean) else { return false }
        if clean.hasPrefix("356000000") {
            var sum = 0
            for ch in clean { sum += ch.wholeNumberValue ?? 0 }
            return sum % 5 == 0
        }
        return luhnCore(clean)
    }

    private static let nirRegex = try! NSRegularExpression(
        pattern: #"^[12]\d{2}(0[1-9]|1[012]|20|[3-9]\d|[0-9][AB])\d[AB0-9]\d{6}\d{2}$"#
    )

    @Sendable static func isPlausibleNIR(_ nir: String) -> Bool {
        let clean = stripSpace(nir).uppercased()
        guard nirRegex.firstMatch(in: clean, range: NSRange(location: 0, length: (clean as NSString).length)) != nil
        else { return false }
        var body = String(clean.prefix(13))
        var adjust: Int64 = 0
        if body.contains("A") {
            body = body.replacingOccurrences(of: "A", with: "0")
            adjust = 1_000_000
        } else if body.contains("B") {
            body = body.replacingOccurrences(of: "B", with: "0")
            adjust = 2_000_000
        }
        guard let num = Int64(body),
              let key = Int64(clean.suffix(2))
        else { return false }
        return (97 - ((num - adjust) % 97)) == key
    }

    // MARK: - UK NHS / NINO / Postcode

    @Sendable static func isPlausibleNHS(_ nhs: String) -> Bool {
        let clean = nhs.replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: " ", with: "")
        guard clean.count == 10, clean.allSatisfy(\.isNumber) else { return false }
        guard hasVariedDigits(clean) else { return false }
        let digits = clean.map { $0.wholeNumberValue! }
        var sum = 0
        for i in 0..<9 { sum += digits[i] * (10 - i) }
        let remainder = sum % 11
        let check = (11 - remainder) % 11
        if check == 10 { return false }
        return check == digits[9]
    }

    private static let ninoRegex = try! NSRegularExpression(pattern: #"^[A-Z]{2}\d{6}[A-D]$"#)

    @Sendable static func isPlausibleNINO(_ nino: String) -> Bool {
        let clean = stripSpace(nino).uppercased()
        guard ninoRegex.firstMatch(in: clean, range: NSRange(location: 0, length: (clean as NSString).length)) != nil
        else { return false }
        let banned1: Set<Character> = ["D", "F", "I", "Q", "U", "V"]
        let banned2: Set<Character> = ["D", "F", "I", "O", "Q", "U", "V"]
        if banned1.contains(clean.first!) { return false }
        if banned2.contains(clean[clean.index(after: clean.startIndex)]) { return false }
        let pair = String(clean.prefix(2))
        let reserved: Set<String> = ["BG", "GB", "NK", "KN", "TN", "NT", "ZZ"]
        if reserved.contains(pair) { return false }
        return true
    }

    private static let ukPostcodeRegex = try! NSRegularExpression(
        pattern: #"^(GIR ?0AA|[A-PR-UWYZ](?:[0-9]{1,2}|[A-HK-Y][0-9]|[A-HK-Y][0-9](?:[0-9]|[ABEHMNPRV-Y])|[0-9][A-HJKPS-UW]) ?[0-9][ABD-HJLNP-UW-Z]{2})$"#,
        options: [.caseInsensitive]
    )

    @Sendable static func isPlausibleUKPostcode(_ pc: String) -> Bool {
        let trimmed = pc.trimmingCharacters(in: .whitespaces)
        let range = NSRange(location: 0, length: (trimmed as NSString).length)
        return ukPostcodeRegex.firstMatch(in: trimmed, range: range) != nil
    }

    // MARK: - US NPI

    @Sendable static func isPlausibleNPI(_ npi: String) -> Bool {
        let clean = stripSpace(npi)
        guard clean.count == 10, clean.allSatisfy(\.isNumber) else { return false }
        guard hasVariedDigits(clean) else { return false }
        return luhnCore("80840" + clean)
    }

    // MARK: - Context guard for credit-card matches

    /// Suppress Luhn-passing 16-digit shapes that are clearly not cards
    /// based on the preceding ~48 chars (sha256:, txn_id=, hash:, etc.).
    private static let creditCardContextRejectRegex = try! NSRegularExpression(
        pattern: #"(?:sha(?:1|256|512)?|md5|hash|nonce|txn[_-]?id|tx[_-]?id|correlation[_-]?id|trace[_-]?id|order[_-]?id|request[_-]?id|session[_-]?id|user[_-]?id)\s*[:=]?\s*$"#,
        options: [.caseInsensitive]
    )

    @Sendable static func creditCardContextOk(_ content: String, _ matchRange: NSRange) -> Bool {
        let lookbackLen = min(48, matchRange.location)
        let lookbackRange = NSRange(location: matchRange.location - lookbackLen, length: lookbackLen)
        let nsContent = content as NSString
        let lookback = nsContent.substring(with: lookbackRange)
        let range = NSRange(location: 0, length: (lookback as NSString).length)
        return creditCardContextRejectRegex.firstMatch(in: lookback, range: range) == nil
    }

    // MARK: - Secret-context guards

    /// Lookback regex matching key-naming words: api_key, apikey,
    /// secret, access_token, token, password, auth, bearer, etc.
    /// Combined with an entropy check, this is what gates GENERIC_API_KEY.
    static let keyContextLookback = try! NSRegularExpression(
        pattern: #"(?:api[_\-\s]?key|apikey|secret|access[_\-\s]?key|access[_\-\s]?token|token|password|passwd|pwd|auth|bearer|client[_\-\s]?secret)[\s:=]{1,4}["']?$"#,
        options: [.caseInsensitive]
    )

    /// AWS secret access key context.
    static let awsSecretLookback = try! NSRegularExpression(
        pattern: #"(?:aws[_\-]?secret(?:[_\-]?access)?[_\-]?key|aws_secret)[\s:=]{1,4}["']?$"#,
        options: [.caseInsensitive]
    )

    /// Datadog API key context.
    static let datadogLookback = try! NSRegularExpression(
        pattern: #"(?:dd[_\-]?api[_\-]?key|datadog[_\-]?api[_\-]?key)[\s:=]{1,4}["']?$"#,
        options: [.caseInsensitive]
    )

    /// Postmark server-token context.
    static let postmarkLookback = try! NSRegularExpression(
        pattern: #"(?:postmark|server[_\-]?token)[\s:=]{1,4}["']?$"#,
        options: [.caseInsensitive]
    )

    /// Returns a contextOk closure that requires `pattern` to match the
    /// ~48-char lookback preceding a candidate match.
    @Sendable static func requireContext(_ pattern: NSRegularExpression) -> @Sendable (String, NSRange) -> Bool {
        return { content, matchRange in
            let lookbackLen = min(48, matchRange.location)
            let lookbackRange = NSRange(location: matchRange.location - lookbackLen, length: lookbackLen)
            let nsContent = content as NSString
            let lookback = nsContent.substring(with: lookbackRange)
            let range = NSRange(location: 0, length: (lookback as NSString).length)
            return pattern.firstMatch(in: lookback, range: range) != nil
        }
    }

    /// Generic API-key validator: entropy + has letter + has digit.
    @Sendable static func genericKeyValueOk(_ value: String) -> Bool {
        guard value.count >= 32 else { return false }
        guard hasShannonEntropy(value, 4.0) else { return false }
        guard value.contains(where: { $0.isLetter }) else { return false }
        guard value.contains(where: { $0.isNumber }) else { return false }
        return true
    }

    /// Mistral 32-char alnum + entropy.
    @Sendable static func validateMistral(_ value: String) -> Bool {
        guard value.count == 32, value.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) else {
            return false
        }
        return hasShannonEntropy(value, 4.0)
    }

    /// Bearer / Token header generic — entropy 3.5.
    @Sendable static func validateBearerEntropy(_ value: String) -> Bool {
        hasShannonEntropy(value, 3.5)
    }

    /// AWS Secret Access Key — 40 base64-ish chars + entropy 4.0.
    @Sendable static func validateAWSSecretEntropy(_ value: String) -> Bool {
        hasShannonEntropy(value, 4.0)
    }

    // MARK: - Helpers

    private static func stripSpace(_ s: String) -> String {
        s.filter { !$0.isWhitespace }
    }

    private static func stripSpaceDash(_ s: String) -> String {
        s.filter { $0 != " " && $0 != "-" }
    }
}
