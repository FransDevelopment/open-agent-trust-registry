import Foundation

// MARK: - Registry Types

public enum KeyAlgorithm: String, Codable {
    case ed25519 = "Ed25519"
    case ecdsaP256 = "ECDSA-P256"
}

public enum KeyStatus: String, Codable {
    case active
    case deprecated
    case revoked
}

public enum IssuerStatus: String, Codable {
    case active
    case suspended
    case revoked
}

public struct PublicKeyEntry: Codable {
    public let kid: String
    public let algorithm: KeyAlgorithm
    public let publicKey: String
    public let status: KeyStatus
    public let issuedAt: String
    public let expiresAt: String
    public let deprecatedAt: String?
    public let revokedAt: String?

    enum CodingKeys: String, CodingKey {
        case kid, algorithm, status
        case publicKey = "public_key"
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
        case deprecatedAt = "deprecated_at"
        case revokedAt = "revoked_at"
    }
}

public struct IssuerCapabilities: Codable {
    public let supervisionModel: String
    public let auditLogging: Bool
    public let immutableAudit: Bool
    public let attestationFormat: String
    public let maxAttestationTtlSeconds: Int
    /// `false` for all new registrations (Tier 1 automated inclusion).
    /// Set to `true` by community auditors after independently verifying the
    /// capability claims above (Tier 2 review). Services may gate high-stakes
    /// operations on this flag. See GOVERNANCE.md for the review process.
    public let capabilitiesVerified: Bool

    enum CodingKeys: String, CodingKey {
        case supervisionModel = "supervision_model"
        case auditLogging = "audit_logging"
        case immutableAudit = "immutable_audit"
        case attestationFormat = "attestation_format"
        case maxAttestationTtlSeconds = "max_attestation_ttl_seconds"
        case capabilitiesVerified = "capabilities_verified"
    }
}

public struct IssuerEndpoints: Codable {
    public let attestationVerify: String?
    public let revocationList: String?

    enum CodingKeys: String, CodingKey {
        case attestationVerify = "attestation_verify"
        case revocationList = "revocation_list"
    }
}

public struct IssuerEntry: Codable {
    public let issuerId: String
    public let displayName: String
    public let website: URL
    public let securityContact: String
    public let status: IssuerStatus
    public let addedAt: String
    public let lastVerified: String
    public let publicKeys: [PublicKeyEntry]
    public let capabilities: IssuerCapabilities
    public let endpoints: IssuerEndpoints?

    enum CodingKeys: String, CodingKey {
        case issuerId = "issuer_id"
        case displayName = "display_name"
        case website
        case securityContact = "security_contact"
        case status
        case addedAt = "added_at"
        case lastVerified = "last_verified"
        case publicKeys = "public_keys"
        case capabilities
        case endpoints
    }
}

public struct RegistrySignature: Codable {
    public let algorithm: KeyAlgorithm
    public let kid: String
    public let value: String
}

public enum RootKeyStatus: String, Codable {
    case active
    case retired
}

public struct RootKeyEntry: Codable {
    public let kid: String
    public let algorithm: KeyAlgorithm
    public let publicKey: String
    public let status: RootKeyStatus
    public let notBefore: String
    public let notAfter: String?

    enum CodingKeys: String, CodingKey {
        case kid, algorithm, status
        case publicKey = "public_key"
        case notBefore = "not_before"
        case notAfter = "not_after"
    }
}

public struct RootKeySet: Codable {
    public let schemaVersion: String
    public let registryId: String
    public let generatedAt: String
    public let keys: [RootKeyEntry]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case registryId = "registry_id"
        case generatedAt = "generated_at"
        case keys
    }
}

public struct RegistryManifest: Codable {
    public let schemaVersion: String
    public let registryId: String
    public let generatedAt: String
    public let expiresAt: String
    public let entries: [IssuerEntry]
    public let signature: RegistrySignature

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case registryId = "registry_id"
        case generatedAt = "generated_at"
        case expiresAt = "expires_at"
        case entries
        case signature
    }
}

// MARK: - Revocations

public struct RevokedKey: Codable {
    public let issuerId: String
    public let kid: String
    public let revokedAt: String
    public let reason: String

    enum CodingKeys: String, CodingKey {
        case issuerId = "issuer_id"
        case kid
        case revokedAt = "revoked_at"
        case reason
    }
}

public struct RevokedIssuer: Codable {
    public let issuerId: String
    public let revokedAt: String
    public let reason: String

    enum CodingKeys: String, CodingKey {
        case issuerId = "issuer_id"
        case revokedAt = "revoked_at"
        case reason
    }
}

public struct RevocationList: Codable {
    public let schemaVersion: String
    public let generatedAt: String
    public let expiresAt: String
    public let revokedKeys: [RevokedKey]
    public let revokedIssuers: [RevokedIssuer]
    public let signature: RegistrySignature

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case generatedAt = "generated_at"
        case expiresAt = "expires_at"
        case revokedKeys = "revoked_keys"
        case revokedIssuers = "revoked_issuers"
        case signature
    }
}

// MARK: - Attestations

/// Utilizing AnyCodable conceptually - swift dictionaries for unknown generic JSON payloads.
public struct AttestationClaims: Codable {
    public let sub: String
    public let aud: String
    public let iat: Int
    public let exp: Int
    public let nonce: String?
    public let scope: [String]
    public let userPseudonym: String
    public let runtimeVersion: String

    // Keeping constraints as raw data to allow callers to decode into their domain models
    // or as a basic JSON string we can manually parse
    // A robust production library would use something like AnyCodable here 
    // but we can abstract it for the standard SDK.
    
    enum CodingKeys: String, CodingKey {
        case sub, aud, iat, exp, nonce, scope
        case userPseudonym = "user_pseudonym"
        case runtimeVersion = "runtime_version"
    }
}

public enum VerificationReason: String {
    case unknownIssuer = "unknown_issuer"
    case revokedIssuer = "revoked_issuer"
    case unknownKey = "unknown_key"
    case revokedKey = "revoked_key"
    case expiredAttestation = "expired_attestation"
    case invalidSignature = "invalid_signature"
    case audienceMismatch = "audience_mismatch"
    case nonceMismatch = "nonce_mismatch"
}

public struct VerificationResult {
    public let valid: Bool
    public let reason: VerificationReason?
    public let issuer: IssuerEntry?
    public let claims: AttestationClaims?
    
    public init(valid: Bool, reason: VerificationReason? = nil, issuer: IssuerEntry? = nil, claims: AttestationClaims? = nil) {
        self.valid = valid
        self.reason = reason
        self.issuer = issuer
        self.claims = claims
    }
}
