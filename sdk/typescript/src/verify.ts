// sdk/typescript/src/verify.ts

import * as jose from 'jose';
import type { RegistryManifest, RevocationList, VerificationResult, AttestationClaims } from './types';

/** Grace period for deprecated keys, per spec/04-key-rotation.md. */
const GRACE_PERIOD_MS = 90 * 24 * 60 * 60 * 1000;

/**
 * Executes the 14-step Verification Protocol to assess an agent attestation.
 * Operates purely locally in <1ms without any network calls.
 */
export async function verifyAttestation(
  attestationJws: string,
  manifest: RegistryManifest,
  revocations: RevocationList,
  expectedAudience: string,
  expectedNonce?: string,
  now?: Date
): Promise<VerificationResult> {

  try {
    // Step 1 & 2: Parse JWS and extract headers
    const protectedHeader = jose.decodeProtectedHeader(attestationJws);
    
    if (!protectedHeader.iss || !protectedHeader.kid || protectedHeader.alg !== 'EdDSA') {
        return { valid: false, reason: 'invalid_signature' };
    }

    const issuerId = protectedHeader.iss;
    const kid = protectedHeader.kid;

    // Fast reject if issuer or key is explicitly on the 5-min revocation list
    const isKeyRevoked = revocations.revoked_keys.some(k => k.kid === kid && k.issuer_id === issuerId);
    const isIssuerRevoked = revocations.revoked_issuers.some(i => i.issuer_id === issuerId);
    
    if (isKeyRevoked) return { valid: false, reason: 'revoked_key' };
    if (isIssuerRevoked) return { valid: false, reason: 'revoked_issuer' };

    // Step 3: Look up issuer
    const issuer = manifest.entries.find(e => e.issuer_id === issuerId);
    
    // Step 4: Unknown Issuer
    if (!issuer) return { valid: false, reason: 'unknown_issuer' };

    // Step 5: Issuer status check
    if (issuer.status === 'suspended') return { valid: false, reason: 'suspended_issuer', issuer };
    if (issuer.status === 'revoked') return { valid: false, reason: 'revoked_issuer', issuer };

    // Step 6: Locate key
    const key = issuer.public_keys.find(k => k.kid === kid);

    // Step 7: Unknown Key
    if (!key) return { valid: false, reason: 'unknown_key', issuer };

    // Step 8: Revoked Key status check
    if (key.status === 'revoked') return { valid: false, reason: 'revoked_key', issuer };

    // Step 9: Grace period enforcement for deprecated keys
    const currentTime = now ?? new Date();
    if (key.status === 'deprecated') {
      if (!key.deprecated_at) {
        return { valid: false, reason: 'grace_period_expired', issuer };
      }
      const deprecatedAt = new Date(key.deprecated_at);
      const elapsed = currentTime.getTime() - deprecatedAt.getTime();
      if (elapsed > GRACE_PERIOD_MS) {
        return { valid: false, reason: 'grace_period_expired', issuer };
      }
    }

    // Step 10: Check key expiration against current date
    const keyExpiry = new Date(key.expires_at);
    if (currentTime > keyExpiry) return { valid: false, reason: 'invalid_signature', issuer }; 

    // Step 11 & 12: Cryptographically verify the signature
    try {
        // Convert base64url Ed25519 key to Uint8Array for noble/ed25519 or jose
        // Jose handles the EdDSA verification inherently mapping base64 keys
        const jwkDecoded = {
            kty: 'OKP',
            crv: 'Ed25519',
            x: key.public_key // Base64url encoded
        };
        
        const importedKey = await jose.importJWK(jwkDecoded, 'EdDSA');
        
        // This validates the signature and standard JWT claims (exp, etc.) concurrently
        const { payload } = await jose.jwtVerify(attestationJws, importedKey, {
            audience: expectedAudience, 
            algorithms: ['EdDSA']
        });

        // The payload is strictly typed as an agnostic claim map
        const claims = payload as unknown as AttestationClaims;

        // Step 13: Additional manual specific checks
        if (expectedNonce && claims.nonce !== expectedNonce) {
            return { valid: false, reason: 'nonce_mismatch', issuer };
        }

        // Must explicitly check aud since jwtVerify might be lenient depending on config
        if (claims.aud !== expectedAudience) {
            return { valid: false, reason: 'audience_mismatch', issuer };
        }

        // Step 14: All checks passed.
        return {
            valid: true,
            issuer,
            claims
        };

    } catch (cryptoErr) {
        // Includes JWT expired, invalid signature mathematically, or audience mismatch thrown by jose
        if (cryptoErr instanceof jose.errors.JWTExpired) {
            return { valid: false, reason: 'expired_attestation', issuer };
        }
        if (cryptoErr instanceof jose.errors.JWTClaimValidationFailed && cryptoErr.claim === 'aud') {
             return { valid: false, reason: 'audience_mismatch', issuer };
        }
        
        return { valid: false, reason: 'invalid_signature', issuer };
    }

  } catch (globalErr) {
      // Catches malformed JWS tokens
      return { valid: false, reason: 'invalid_signature' };
  }
}
