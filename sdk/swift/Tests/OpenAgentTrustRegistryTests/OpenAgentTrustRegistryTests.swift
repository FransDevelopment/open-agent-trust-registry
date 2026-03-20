import XCTest
import Crypto
@testable import AgentTrustRegistry

final class AgentTrustRegistryTests: XCTestCase {

    var validKeypair: Curve25519.Signing.PrivateKey!
    var revokedKeypair: Curve25519.Signing.PrivateKey!
    var expiredKeypair: Curve25519.Signing.PrivateKey!

    var manifest: RegistryManifest!
    var revocations: RevocationList!

    override func setUpWithError() throws {
        validKeypair = Curve25519.Signing.PrivateKey()
        revokedKeypair = Curve25519.Signing.PrivateKey()
        expiredKeypair = Curve25519.Signing.PrivateKey()

        let validPubKeyBase64 = validKeypair.publicKey.rawRepresentation.base64EncodedString()
        let revokedPubKeyBase64 = revokedKeypair.publicKey.rawRepresentation.base64EncodedString()
        let expiredPubKeyBase64 = expiredKeypair.publicKey.rawRepresentation.base64EncodedString()

        let isoFormatter = ISO8601DateFormatter()
        isoFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let now = Date()
        
        let validKey1 = PublicKeyEntry(
            kid: "valid-key-1",
            algorithm: .ed25519,
            publicKey: validPubKeyBase64,
            status: .active,
            issuedAt: isoFormatter.string(from: now),
            expiresAt: isoFormatter.string(from: now.addingTimeInterval(86400)),
            deprecatedAt: nil,
            revokedAt: nil
        )

        let expiredKey1 = PublicKeyEntry(
            kid: "expired-key-1",
            algorithm: .ed25519,
            publicKey: expiredPubKeyBase64,
            status: .active,
            issuedAt: isoFormatter.string(from: now.addingTimeInterval(-172800)),
            expiresAt: isoFormatter.string(from: now.addingTimeInterval(-86400)), // expired yesterday
            deprecatedAt: nil,
            revokedAt: nil
        )

        let revokedKey1 = PublicKeyEntry(
            kid: "revoked-key-1",
            algorithm: .ed25519,
            publicKey: revokedPubKeyBase64,
            status: .revoked,
            issuedAt: isoFormatter.string(from: now),
            expiresAt: isoFormatter.string(from: now.addingTimeInterval(86400)),
            deprecatedAt: nil,
            revokedAt: nil
        )

        let capabilities = IssuerCapabilities(
            supervisionModel: "none",
            auditLogging: false,
            immutableAudit: false,
            attestationFormat: "jwt",
            maxAttestationTtlSeconds: 3600,
            capabilitiesVerified: false
        )

        let validIssuer = IssuerEntry(
            issuerId: "valid-issuer",
            displayName: "Valid Issuer",
            website: URL(string: "https://example.com")!,
            securityContact: "sec@example.com",
            status: .active,
            addedAt: isoFormatter.string(from: now),
            lastVerified: isoFormatter.string(from: now),
            publicKeys: [validKey1, expiredKey1],
            capabilities: capabilities,
            endpoints: nil
        )
        
        let revokedIssuer = IssuerEntry(
            issuerId: "revoked-issuer",
            displayName: "Revoked Issuer",
            website: URL(string: "https://bad.com")!,
            securityContact: "sec@bad.com",
            status: .revoked, // Explicitly revoked
            addedAt: isoFormatter.string(from: now),
            lastVerified: isoFormatter.string(from: now),
            publicKeys: [revokedKey1],
            capabilities: capabilities,
            endpoints: nil
        )

        manifest = RegistryManifest(
            schemaVersion: "1.0.0",
            registryId: "open-trust-registry",
            generatedAt: isoFormatter.string(from: now),
            expiresAt: isoFormatter.string(from: now.addingTimeInterval(86400)),
            entries: [validIssuer, revokedIssuer],
            signature: RegistrySignature(algorithm: .ed25519, kid: "root", value: "placeholder")
        )

        revocations = RevocationList(
            schemaVersion: "1.0.0",
            generatedAt: isoFormatter.string(from: now),
            expiresAt: isoFormatter.string(from: now.addingTimeInterval(86400)),
            revokedKeys: [],
            revokedIssuers: [RevokedIssuer(issuerId: "revoked-issuer", revokedAt: isoFormatter.string(from: now), reason: "policy_violation")],
            signature: nil
        )
    }

    func signToken(
        keypair: Curve25519.Signing.PrivateKey,
        iss: String,
        kid: String,
        aud: String,
        expOffsetSeconds: TimeInterval = 3600,
        nonce: String? = nil
    ) throws -> String {
        let iat = Int(Date().timeIntervalSince1970)
        let exp = iat + Int(expOffsetSeconds)

        var payloadDict: [String: Any] = [
            "sub": "agent-123",
            "aud": aud,
            "iat": iat,
            "exp": exp,
            "scope": ["read"],
            "user_pseudonym": "user-xyz",
            "runtime_version": "1.0"
        ]
        if let n = nonce {
            payloadDict["nonce"] = n
        }

        let headerDict: [String: String] = [
            "alg": "EdDSA",
            "kid": kid,
            "iss": iss,
            "typ": "agent-attestation+jwt"
        ]

        let payloadData = try JSONSerialization.data(withJSONObject: payloadDict, options: [])
        let headerData = try JSONSerialization.data(withJSONObject: headerDict, options: [])

        let payloadString = JWS.base64URLEncode(payloadData)
        let headerString = JWS.base64URLEncode(headerData)

        let signingInput = "\(headerString).\(payloadString)"
        guard let signingInputData = signingInput.data(using: .ascii) else {
            throw JWSError.invalidFormat
        }

        let signatureData = try keypair.signature(for: signingInputData)
        let signatureString = JWS.base64URLEncode(signatureData)

        return "\(signingInput).\(signatureString)"
    }

    func testValidToken() throws {
        let token = try signToken(keypair: validKeypair, iss: "valid-issuer", kid: "valid-key-1", aud: "https://api.service.com")
        
        let result = Verification.verifyAttestation(
            attestationJws: token,
            manifest: manifest,
            revocations: revocations,
            expectedAudience: "https://api.service.com"
        )
        
        XCTAssertTrue(result.valid)
        XCTAssertEqual(result.issuer?.issuerId, "valid-issuer")
        XCTAssertEqual(result.claims?.sub, "agent-123")
    }

    func testUnknownIssuer() throws {
        let token = try signToken(keypair: validKeypair, iss: "fake-issuer", kid: "valid-key-1", aud: "https://api.service.com")
        let result = Verification.verifyAttestation(attestationJws: token, manifest: manifest, revocations: revocations, expectedAudience: "https://api.service.com")
        
        XCTAssertFalse(result.valid)
        XCTAssertEqual(result.reason, .unknownIssuer)
    }

    func testRevokedIssuer() throws {
        let token = try signToken(keypair: revokedKeypair, iss: "revoked-issuer", kid: "revoked-key-1", aud: "https://api.service.com")
        let result = Verification.verifyAttestation(attestationJws: token, manifest: manifest, revocations: revocations, expectedAudience: "https://api.service.com")
        
        XCTAssertFalse(result.valid)
        XCTAssertEqual(result.reason, .revokedIssuer)
    }

    func testUnknownKey() throws {
        let token = try signToken(keypair: validKeypair, iss: "valid-issuer", kid: "fake-key", aud: "https://api.service.com")
        let result = Verification.verifyAttestation(attestationJws: token, manifest: manifest, revocations: revocations, expectedAudience: "https://api.service.com")
        
        XCTAssertFalse(result.valid)
        XCTAssertEqual(result.reason, .unknownKey)
    }

    func testInvalidSignature() throws {
        // Sign with revoked key but claim it's the valid key
        let token = try signToken(keypair: revokedKeypair, iss: "valid-issuer", kid: "valid-key-1", aud: "https://api.service.com")
        let result = Verification.verifyAttestation(attestationJws: token, manifest: manifest, revocations: revocations, expectedAudience: "https://api.service.com")
        
        XCTAssertFalse(result.valid)
        XCTAssertEqual(result.reason, .invalidSignature)
    }

    func testExpiredRegistryPublicKey() throws {
        let token = try signToken(keypair: expiredKeypair, iss: "valid-issuer", kid: "expired-key-1", aud: "https://api.service.com")
        let result = Verification.verifyAttestation(attestationJws: token, manifest: manifest, revocations: revocations, expectedAudience: "https://api.service.com")
        
        XCTAssertFalse(result.valid)
        XCTAssertEqual(result.reason, .invalidSignature)
    }

    func testExpiredAttestationToken() throws {
        // -3600 seconds means it expired an hour ago
        let token = try signToken(keypair: validKeypair, iss: "valid-issuer", kid: "valid-key-1", aud: "https://api.service.com", expOffsetSeconds: -3600)
        let result = Verification.verifyAttestation(attestationJws: token, manifest: manifest, revocations: revocations, expectedAudience: "https://api.service.com")
        
        XCTAssertFalse(result.valid)
        XCTAssertEqual(result.reason, .expiredAttestation)
    }

    func testAudienceMismatch() throws {
        let token = try signToken(keypair: validKeypair, iss: "valid-issuer", kid: "valid-key-1", aud: "https://other.service.com")
        let result = Verification.verifyAttestation(attestationJws: token, manifest: manifest, revocations: revocations, expectedAudience: "https://api.service.com")
        
        XCTAssertFalse(result.valid)
        XCTAssertEqual(result.reason, .audienceMismatch)
    }

    func testNonceMismatch() throws {
        let token = try signToken(keypair: validKeypair, iss: "valid-issuer", kid: "valid-key-1", aud: "https://api.service.com", nonce: "expected-123")
        let result = Verification.verifyAttestation(attestationJws: token, manifest: manifest, revocations: revocations, expectedAudience: "https://api.service.com", expectedNonce: "wrong-456")
        
        XCTAssertFalse(result.valid)
        XCTAssertEqual(result.reason, .nonceMismatch)
    }
}
