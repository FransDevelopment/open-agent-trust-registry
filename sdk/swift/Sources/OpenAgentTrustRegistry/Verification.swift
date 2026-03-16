import Foundation

public struct Verification {
    
    /// Executes the identical 14-step Verification Protocol to assess an agent attestation natively in Swift.
    /// Operates purely locally in <1ms without any network calls.
    public static func verifyAttestation(
        attestationJws: String,
        manifest: RegistryManifest,
        revocations: RevocationList,
        expectedAudience: String,
        expectedNonce: String? = nil
    ) -> VerificationResult {
        
        do {
            // Step 1 & 2: Parse JWS and extract headers
            // We decode here merely to inspect the header securely
            let decoded = try JWS.decode(token: attestationJws)
            let header = decoded.header
            
            guard let issuerId = header.iss, let kid = header.kid, header.alg == "EdDSA" else {
                return VerificationResult(valid: false, reason: .invalidSignature)
            }
            
            // Fast reject if issuer or key is explicitly on the 5-min revocation list
            if revocations.revokedKeys.contains(where: { $0.kid == kid && $0.issuerId == issuerId }) {
                return VerificationResult(valid: false, reason: .revokedKey)
            }
            if revocations.revokedIssuers.contains(where: { $0.issuerId == issuerId }) {
                return VerificationResult(valid: false, reason: .revokedIssuer)
            }
            
            // Step 3: Look up issuer
            guard let issuer = manifest.entries.first(where: { $0.issuerId == issuerId }) else {
                return VerificationResult(valid: false, reason: .unknownIssuer) // Step 4
            }
            
            // Step 5: Active check
            if issuer.status != .active {
                return VerificationResult(valid: false, reason: .revokedIssuer, issuer: issuer)
            }
            
            // Step 6: Locate key
            guard let key = issuer.publicKeys.first(where: { $0.kid == kid }) else {
                return VerificationResult(valid: false, reason: .unknownKey, issuer: issuer) // Step 7
            }
            
            // Step 8: Revoked Key status check
            if key.status == .revoked {
                return VerificationResult(valid: false, reason: .revokedKey, issuer: issuer)
            }
            
            // Step 9: Deprecated logic gracefully handled (we just accept it, perhaps logging later)
            
            // Step 10: Check key expiration against current date
            let isoFormatter = ISO8601DateFormatter()
            isoFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            // Standard fallback if fractional seconds fail
            let fallbackFormatter = ISO8601DateFormatter()
            
            guard let keyExpiry = isoFormatter.date(from: key.expiresAt) ?? fallbackFormatter.date(from: key.expiresAt) else {
                return VerificationResult(valid: false, reason: .invalidSignature, issuer: issuer)
            }
            
            let now = Date()
            if now > keyExpiry {
                return VerificationResult(valid: false, reason: .invalidSignature, issuer: issuer)
            }
            
            // Step 11 & 12: Cryptographically verify the signature
            let verifiedPayloadData: Data
            do {
                let verification = try JWS.verifyEdDSA(token: attestationJws, publicKeyBase64URL: key.publicKey)
                verifiedPayloadData = verification.payload
            } catch {
                return VerificationResult(valid: false, reason: .invalidSignature, issuer: issuer)
            }
            
            // Decode the strongly typed agnostic Attestation Claims payload
            let claims = try JSONDecoder().decode(AttestationClaims.self, from: verifiedPayloadData)
            
            // Step 13: Additional manual specific checks
            
            // Check Attestation JWT Expiry (Unix timestamp in seconds)
            let expDate = Date(timeIntervalSince1970: TimeInterval(claims.exp))
            if now > expDate {
                return VerificationResult(valid: false, reason: .expiredAttestation, issuer: issuer)
            }
            
            // Expected Nonce mismatch
            if let expected = expectedNonce, claims.nonce != expected {
                return VerificationResult(valid: false, reason: .nonceMismatch, issuer: issuer)
            }
            
            // Intended Audience validation 
            if claims.aud != expectedAudience {
                return VerificationResult(valid: false, reason: .audienceMismatch, issuer: issuer)
            }
            
            // Step 14: All checks passed.
            return VerificationResult(valid: true, issuer: issuer, claims: claims)
            
        } catch {
            // General catch all for formatting failures representing an invalid token
            return VerificationResult(valid: false, reason: .invalidSignature)
        }
    }
}
