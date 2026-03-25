import Foundation
import Crypto

private struct UnsignedRegistryManifest: Codable {
    let schemaVersion: String
    let registryId: String
    let generatedAt: String
    let expiresAt: String
    let entries: [IssuerEntry]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case registryId = "registry_id"
        case generatedAt = "generated_at"
        case expiresAt = "expires_at"
        case entries
    }
}

private struct UnsignedRevocationList: Codable {
    let schemaVersion: String
    let generatedAt: String
    let expiresAt: String
    let revokedKeys: [RevokedKey]
    let revokedIssuers: [RevokedIssuer]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case generatedAt = "generated_at"
        case expiresAt = "expires_at"
        case revokedKeys = "revoked_keys"
        case revokedIssuers = "revoked_issuers"
    }
}

public enum RegistryArtifactVerifier {
    private static let decoder = JSONDecoder()

    public static func loadBundledRootKeys() throws -> RootKeySet {
        guard let url = Bundle.module.url(forResource: "root-keys", withExtension: "json") else {
            throw OpenAgentTrustRegistryError.malformedRegistryState("Bundled root-keys.json is missing.")
        }

        let data = try Data(contentsOf: url)
        return try decoder.decode(RootKeySet.self, from: data)
    }

    public static func verifyArtifacts(
        manifestData: Data,
        revocationsData: Data,
        now: Date = Date()
    ) throws -> (manifest: RegistryManifest, revocations: RevocationList) {
        let manifest = try decodeManifest(manifestData)
        let revocations = try decodeRevocations(revocationsData)
        let manifestObject = try jsonObject(from: manifestData, label: "manifest")
        let revocationsObject = try jsonObject(from: revocationsData, label: "revocations")
        return try verifyArtifacts(
            manifest: manifest,
            revocations: revocations,
            manifestJSONObject: manifestObject,
            revocationsJSONObject: revocationsObject,
            now: now
        )
    }

    public static func verifyArtifacts(
        manifest: RegistryManifest,
        revocations: RevocationList,
        now: Date = Date()
    ) throws -> (manifest: RegistryManifest, revocations: RevocationList) {
        let manifestObject = try unsignedJSONObject(
            UnsignedRegistryManifest(
                schemaVersion: manifest.schemaVersion,
                registryId: manifest.registryId,
                generatedAt: manifest.generatedAt,
                expiresAt: manifest.expiresAt,
                entries: manifest.entries
            ),
            label: "manifest"
        )
        let revocationsObject = try unsignedJSONObject(
            UnsignedRevocationList(
                schemaVersion: revocations.schemaVersion,
                generatedAt: revocations.generatedAt,
                expiresAt: revocations.expiresAt,
                revokedKeys: revocations.revokedKeys,
                revokedIssuers: revocations.revokedIssuers
            ),
            label: "revocations"
        )

        return try verifyArtifacts(
            manifest: manifest,
            revocations: revocations,
            manifestJSONObject: manifestObject,
            revocationsJSONObject: revocationsObject,
            now: now
        )
    }

    private static func verifyArtifacts(
        manifest: RegistryManifest,
        revocations: RevocationList,
        manifestJSONObject: Any,
        revocationsJSONObject: Any,
        now: Date
    ) throws -> (manifest: RegistryManifest, revocations: RevocationList) {
        let rootKeys = try loadBundledRootKeys()
        try verifyManifest(manifest, unsignedJSONObject: manifestJSONObject, rootKeys: rootKeys, now: now)
        try verifyRevocations(revocations, unsignedJSONObject: revocationsJSONObject, rootKeys: rootKeys, now: now)
        return (manifest, revocations)
    }

    private static func decodeManifest(_ data: Data) throws -> RegistryManifest {
        do {
            return try decoder.decode(RegistryManifest.self, from: data)
        } catch {
            throw OpenAgentTrustRegistryError.malformedRegistryState("Manifest JSON does not match the signed registry schema.")
        }
    }

    private static func decodeRevocations(_ data: Data) throws -> RevocationList {
        do {
            return try decoder.decode(RevocationList.self, from: data)
        } catch {
            throw OpenAgentTrustRegistryError.malformedRegistryState("Revocation JSON does not match the signed registry schema.")
        }
    }

    private static func verifyManifest(
        _ manifest: RegistryManifest,
        unsignedJSONObject: Any,
        rootKeys: RootKeySet,
        now: Date
    ) throws {
        let encoded = try canonicalJSON(unsignedJSONObject)
        try verifySignature(encoded, signature: manifest.signature, rootKeys: rootKeys, now: now, label: "manifest")
        try ensureFresh(manifest.expiresAt, now: now, label: "manifest")
    }

    private static func verifyRevocations(
        _ revocations: RevocationList,
        unsignedJSONObject: Any,
        rootKeys: RootKeySet,
        now: Date
    ) throws {
        let encoded = try canonicalJSON(unsignedJSONObject)
        try verifySignature(encoded, signature: revocations.signature, rootKeys: rootKeys, now: now, label: "revocations")
        try ensureFresh(revocations.expiresAt, now: now, label: "revocations")
    }

    private static func ensureFresh(_ timestamp: String, now: Date, label: String) throws {
        let expiry = try parseDate(timestamp, label: "\(label).expires_at")
        if now > expiry {
            throw OpenAgentTrustRegistryError.staleRegistryState("\(label) is expired as of \(timestamp).")
        }
    }

    private static func verifySignature(
        _ payload: Data,
        signature: RegistrySignature,
        rootKeys: RootKeySet,
        now: Date,
        label: String
    ) throws {
        guard signature.algorithm == .ed25519 else {
            throw OpenAgentTrustRegistryError.invalidRegistrySignature("Unsupported \(label) signature algorithm \(signature.algorithm.rawValue).")
        }

        guard let rootKey = rootKeys.keys.first(where: { $0.kid == signature.kid }) else {
            throw OpenAgentTrustRegistryError.unknownRootKey("Unknown root key id \(signature.kid).")
        }

        guard rootKey.status == .active else {
            throw OpenAgentTrustRegistryError.invalidRegistrySignature("Root key \(signature.kid) is not active.")
        }

        let notBefore = try parseDate(rootKey.notBefore, label: "root key \(signature.kid).not_before")
        if now < notBefore {
            throw OpenAgentTrustRegistryError.invalidRegistrySignature("Root key \(signature.kid) is not valid yet.")
        }

        if let notAfter = rootKey.notAfter {
            let expiry = try parseDate(notAfter, label: "root key \(signature.kid).not_after")
            if now > expiry {
                throw OpenAgentTrustRegistryError.invalidRegistrySignature("Root key \(signature.kid) has expired.")
            }
        }

        guard let rawPublicKey = JWS.base64URLDecode(rootKey.publicKey) else {
            throw OpenAgentTrustRegistryError.malformedRegistryState("Root key \(signature.kid) is not valid base64url.")
        }
        guard let rawSignature = JWS.base64URLDecode(signature.value) else {
            throw OpenAgentTrustRegistryError.malformedRegistryState("\(label) signature is not valid base64url.")
        }

        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: rawPublicKey)
        if !publicKey.isValidSignature(rawSignature, for: payload) {
            throw OpenAgentTrustRegistryError.invalidRegistrySignature("\(label) signature verification failed.")
        }
    }

    private static func parseDate(_ timestamp: String, label: String) throws -> Date {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let fallbackFormatter = ISO8601DateFormatter()

        if let parsed = formatter.date(from: timestamp) ?? fallbackFormatter.date(from: timestamp) {
            return parsed
        }

        throw OpenAgentTrustRegistryError.malformedRegistryState("\(label) must be a valid ISO 8601 timestamp.")
    }

    private static func jsonObject(from data: Data, label: String) throws -> Any {
        do {
            let object = try JSONSerialization.jsonObject(with: data)
            return try removingSignature(from: object, label: label)
        } catch {
            throw OpenAgentTrustRegistryError.malformedRegistryState("Unable to parse \(label) JSON for signature verification.")
        }
    }

    private static func unsignedJSONObject<T: Encodable>(_ value: T, label: String) throws -> Any {
        let encoder = JSONEncoder()
        do {
            let data = try encoder.encode(value)
            return try JSONSerialization.jsonObject(with: data)
        } catch {
            throw OpenAgentTrustRegistryError.malformedRegistryState("Unable to canonicalize signed \(label) artifact.")
        }
    }

    private static func removingSignature(from object: Any, label: String) throws -> Any {
        guard var dictionary = object as? [String: Any] else {
            throw OpenAgentTrustRegistryError.malformedRegistryState("\(label) must be a JSON object.")
        }

        dictionary.removeValue(forKey: "signature")
        return dictionary
    }

    private static func canonicalJSON(_ value: Any) throws -> Data {
        let canonical = try canonicalize(value)
        return Data(canonical.utf8)
    }

    private static func canonicalize(_ value: Any) throws -> String {
        switch value {
        case is NSNull:
            return "null"
        case let array as [Any]:
            return "[\(try array.map { try canonicalize($0) }.joined(separator: ","))]"
        case let dictionary as [String: Any]:
            let pairs = try dictionary.keys.sorted().map { key in
                let canonicalValue = try canonicalize(dictionary[key] as Any)
                return "\(try canonicalizeString(key)):\(canonicalValue)"
            }
            return "{\(pairs.joined(separator: ","))}"
        case let string as String:
            return try canonicalizeString(string)
        case let number as NSNumber:
            return try canonicalizeNumber(number)
        default:
            throw OpenAgentTrustRegistryError.malformedRegistryState("Unsupported JSON value found during canonicalization.")
        }
    }

    private static func canonicalizeString(_ value: String) throws -> String {
        var escaped = "\""

        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x22:
                escaped += "\\\""
            case 0x5C:
                escaped += "\\\\"
            case 0x08:
                escaped += "\\b"
            case 0x09:
                escaped += "\\t"
            case 0x0A:
                escaped += "\\n"
            case 0x0C:
                escaped += "\\f"
            case 0x0D:
                escaped += "\\r"
            case 0x00...0x1F:
                escaped += String(format: "\\u%04x", scalar.value)
            default:
                escaped.unicodeScalars.append(scalar)
            }
        }

        escaped += "\""
        return escaped
    }

    private static func canonicalizeNumber(_ value: NSNumber) throws -> String {
        if CFGetTypeID(value) == CFBooleanGetTypeID() {
            return value.boolValue ? "true" : "false"
        }

        let wrapper = [value]
        let data = try JSONSerialization.data(withJSONObject: wrapper, options: [])
        guard let json = String(data: data, encoding: .utf8) else {
            throw OpenAgentTrustRegistryError.malformedRegistryState("Unable to canonicalize JSON number.")
        }
        return String(json.dropFirst().dropLast())
    }
}
