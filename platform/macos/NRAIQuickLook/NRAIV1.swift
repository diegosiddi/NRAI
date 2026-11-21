import CoreFoundation
import CryptoKit
import Foundation

enum NRAIError: Error {
    case badMagic
    case badHeader
    case oversizedManifest
    case truncatedManifest
    case invalidJSON
    case duplicateJSONKey
    case unsupportedVersion
    case invalidManifest(String)
    case payloadLength
    case payloadDigest
    case invalidSignature
    case screenshotDenied
}

struct NRAIV1 {
    static let magic = Data([0x4e, 0x52, 0x41, 0x49, 0x0d, 0x0a, 0x1a, 0x0a])
    static let maxManifestBytes = 4 * 1024 * 1024
    static let rightsKeys = ["ai_training", "ai_finetuning", "ai_inference", "ai_analysis", "screenshot", "redistribution"]
    static let rightsValues: Set<String> = ["allow", "deny", "ask", "unspecified"]

    static func verifiedPayload(from url: URL, forThumbnail: Bool = false) throws -> Data {
        try verifiedPayload(from: Data(contentsOf: url, options: [.mappedIfSafe]), forThumbnail: forThumbnail)
    }

    static func verifiedPayload(from data: Data, forThumbnail: Bool = false) throws -> Data {
        guard data.count >= 16 else { throw NRAIError.badHeader }
        guard data.prefix(8) == magic else { throw NRAIError.badMagic }

        var manifestLength: UInt64 = 0
        for byte in data[8..<16] { manifestLength = (manifestLength << 8) | UInt64(byte) }
        guard manifestLength <= UInt64(maxManifestBytes) else { throw NRAIError.oversizedManifest }
        let start = 16
        let end = start + Int(manifestLength)
        guard end <= data.count else { throw NRAIError.truncatedManifest }
        let manifestData = data.subdata(in: start..<end)
        guard !manifestData.starts(with: [0xef, 0xbb, 0xbf]) else { throw NRAIError.invalidJSON }
        guard !JSONDuplicateKeyScanner.containsDuplicateKeys(manifestData) else { throw NRAIError.duplicateJSONKey }
        guard let manifest = try JSONSerialization.jsonObject(with: manifestData) as? [String: Any] else {
            throw NRAIError.invalidJSON
        }

        guard manifest["format"] as? String == "NRAI",
              let version = manifest["version"] as? NSNumber,
              CFGetTypeID(version) != CFBooleanGetTypeID(), version.intValue == 1 else {
            throw NRAIError.unsupportedVersion
        }
        try validate(manifest)

        let payload = data.subdata(in: end..<data.count)
        guard let payloadInfo = manifest["payload"] as? [String: Any],
              let expectedLength = payloadInfo["length"] as? NSNumber,
              expectedLength.uint64Value == UInt64(payload.count) else { throw NRAIError.payloadLength }
        let digest = Data(SHA256.hash(data: payload))
        guard let digestText = payloadInfo["sha256"] as? String,
              digestText == digest.map({ String(format: "%02x", $0) }).joined() else { throw NRAIError.payloadDigest }

        guard let signatureInfo = manifest["signature"] as? [String: Any],
              let publicText = signatureInfo["public_key"] as? String,
              let signatureText = signatureInfo["value"] as? String,
              let rawKey = Data(base64Encoded: publicText), rawKey.count == 32,
              rawKey.base64EncodedString() == publicText,
              let signature = Data(base64Encoded: signatureText), signature.count == 64,
              signature.base64EncodedString() == signatureText,
              let keyID = signatureInfo["key_id"] as? String else { throw NRAIError.invalidSignature }
        let keyHash = Data(SHA256.hash(data: rawKey)).prefix(16)
        guard keyID == keyHash.map({ String(format: "%02x", $0) }).joined() else { throw NRAIError.invalidSignature }

        var unsigned = manifest
        unsigned.removeValue(forKey: "signature")
        let signedBytes = try canonicalJSON(unsigned)
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: rawKey)
        guard publicKey.isValidSignature(signature, for: signedBytes) else { throw NRAIError.invalidSignature }

        let rights = manifest["rights"] as! [String: String]
        if forThumbnail && rights["screenshot"] == "deny" { throw NRAIError.screenshotDenied }
        return payload
    }

    private static func validate(_ manifest: [String: Any]) throws {
        guard let assetID = manifest["asset_id"] as? String,
              UUID(uuidString: assetID)?.uuidString.lowercased() == assetID else {
            throw NRAIError.invalidManifest("asset_id")
        }
        guard validTimestamp(manifest["created_at"] as? String) else { throw NRAIError.invalidManifest("created_at") }
        guard let mediaType = manifest["media_type"] as? String, mediaType.contains("/"), !mediaType.hasPrefix("/"), !mediaType.hasSuffix("/") else {
            throw NRAIError.invalidManifest("media_type")
        }
        guard let payload = manifest["payload"] as? [String: Any],
              let length = payload["length"] as? NSNumber,
              CFGetTypeID(length) != CFBooleanGetTypeID(), !CFNumberIsFloatType(length),
              let sha = payload["sha256"] as? String, isLowerHex(sha, length: 64) else {
            throw NRAIError.invalidManifest("payload")
        }
        guard let rights = manifest["rights"] as? [String: String], Set(rights.keys) == Set(rightsKeys),
              rights.values.allSatisfy({ rightsValues.contains($0) }) else {
            throw NRAIError.invalidManifest("rights")
        }
        if let creator = manifest["creator"], !(creator is String) { throw NRAIError.invalidManifest("creator") }
        if let lineage = manifest["lineage"] {
            guard let value = lineage as? [String: Any],
                  Set(value.keys) == Set(["parent_asset_id", "parent_payload_sha256", "operation", "recorded_at"]),
                  let parentID = value["parent_asset_id"] as? String,
                  UUID(uuidString: parentID)?.uuidString.lowercased() == parentID,
                  let parentDigest = value["parent_payload_sha256"] as? String, isLowerHex(parentDigest, length: 64),
                  let operation = value["operation"] as? String, !operation.isEmpty,
                  validTimestamp(value["recorded_at"] as? String) else {
                throw NRAIError.invalidManifest("lineage")
            }
        }
        guard let signature = manifest["signature"] as? [String: Any],
              Set(signature.keys) == Set(["algorithm", "key_id", "public_key", "value"]),
              signature["algorithm"] as? String == "Ed25519",
              let keyID = signature["key_id"] as? String, isLowerHex(keyID, length: 32),
              signature["public_key"] is String, signature["value"] is String else {
            throw NRAIError.invalidManifest("signature")
        }
        _ = try canonicalJSON(manifest)
    }

    private static func validTimestamp(_ value: String?) -> Bool {
        guard let value = value, value.hasSuffix("Z") else { return false }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: value) != nil
    }

    private static func isLowerHex(_ value: String, length: Int) -> Bool {
        value.count == length && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private static func canonicalJSON(_ value: Any) throws -> Data {
        Data(try canonicalString(value).utf8)
    }

    private static func canonicalString(_ value: Any) throws -> String {
        if let object = value as? [String: Any] {
            let keys = object.keys.sorted { unicodeScalarLess($0, $1) }
            let fields = try keys.map { key in
                try canonicalString(key) + ":" + canonicalString(object[key]!)
            }
            return "{" + fields.joined(separator: ",") + "}"
        }
        if let array = value as? [Any] {
            return "[" + (try array.map { try canonicalString($0) }).joined(separator: ",") + "]"
        }
        if let string = value as? String { return quote(string) }
        if value is NSNull { return "null" }
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue ? "true" : "false" }
            guard !CFNumberIsFloatType(number) else { throw NRAIError.invalidManifest("floating-point value") }
            let text = number.stringValue
            guard text.range(of: "^-?(0|[1-9][0-9]*)$", options: .regularExpression) != nil else {
                throw NRAIError.invalidManifest("integer value")
            }
            guard Int64(text) != nil || UInt64(text) != nil else { throw NRAIError.invalidManifest("integer range") }
            return text
        }
        throw NRAIError.invalidManifest("unsupported JSON value")
    }

    private static func unicodeScalarLess(_ lhs: String, _ rhs: String) -> Bool {
        lhs.unicodeScalars.lexicographicallyPrecedes(rhs.unicodeScalars) { $0.value < $1.value }
    }

    private static func quote(_ value: String) -> String {
        var output = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x22: output += "\\\""
            case 0x5c: output += "\\\\"
            case 0x08: output += "\\b"
            case 0x09: output += "\\t"
            case 0x0a: output += "\\n"
            case 0x0c: output += "\\f"
            case 0x0d: output += "\\r"
            case 0x00...0x1f: output += String(format: "\\u%04x", scalar.value)
            default: output.unicodeScalars.append(scalar)
            }
        }
        output += "\""
        return output
    }
}

private struct JSONDuplicateKeyScanner {
    private let bytes: [UInt8]
    private var index = 0

    static func containsDuplicateKeys(_ data: Data) -> Bool {
        var scanner = JSONDuplicateKeyScanner(bytes: Array(data))
        do { try scanner.scanValue(depth: 0); scanner.skipWhitespace(); return scanner.index != scanner.bytes.count }
        catch { return true }
    }

    private mutating func scanValue(depth: Int) throws {
        guard depth <= 64 else { throw NRAIError.invalidJSON }
        skipWhitespace()
        guard index < bytes.count else { throw NRAIError.invalidJSON }
        switch bytes[index] {
        case 0x7b: try scanObject(depth: depth)
        case 0x5b: try scanArray(depth: depth)
        case 0x22: _ = try scanString()
        default:
            while index < bytes.count && ![0x2c, 0x5d, 0x7d, 0x20, 0x09, 0x0a, 0x0d].contains(bytes[index]) { index += 1 }
        }
    }

    private mutating func scanObject(depth: Int) throws {
        index += 1
        skipWhitespace()
        if take(0x7d) { return }
        var keys = Set<String>()
        while true {
            skipWhitespace()
            let key = try scanString()
            guard keys.insert(key).inserted else { throw NRAIError.duplicateJSONKey }
            skipWhitespace()
            guard take(0x3a) else { throw NRAIError.invalidJSON }
            try scanValue(depth: depth + 1)
            skipWhitespace()
            if take(0x7d) { return }
            guard take(0x2c) else { throw NRAIError.invalidJSON }
        }
    }

    private mutating func scanArray(depth: Int) throws {
        index += 1
        skipWhitespace()
        if take(0x5d) { return }
        while true {
            try scanValue(depth: depth + 1)
            skipWhitespace()
            if take(0x5d) { return }
            guard take(0x2c) else { throw NRAIError.invalidJSON }
        }
    }

    private mutating func scanString() throws -> String {
        let start = index
        guard take(0x22) else { throw NRAIError.invalidJSON }
        while index < bytes.count {
            if take(0x22) {
                let token = Data(bytes[start..<index])
                let wrapper = Data([0x5b]) + token + Data([0x5d])
                guard let strings = try JSONSerialization.jsonObject(with: wrapper) as? [String], let value = strings.first else {
                    throw NRAIError.invalidJSON
                }
                return value
            }
            if take(0x5c) {
                guard index < bytes.count else { throw NRAIError.invalidJSON }
                if bytes[index] == 0x75 { index += 1; index = min(index + 4, bytes.count) } else { index += 1 }
            } else { index += 1 }
        }
        throw NRAIError.invalidJSON
    }

    private mutating func skipWhitespace() {
        while index < bytes.count && [0x20, 0x09, 0x0a, 0x0d].contains(bytes[index]) { index += 1 }
    }

    private mutating func take(_ byte: UInt8) -> Bool {
        guard index < bytes.count && bytes[index] == byte else { return false }
        index += 1
        return true
    }
}
