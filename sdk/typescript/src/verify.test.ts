import { describe, it, expect, beforeAll } from 'vitest';
import * as jose from 'jose';
import { OpenAgentTrustRegistry, verifyAttestation } from './index';
import type { RegistryManifest, RevocationList, AttestationClaims } from './types';

describe('OpenAgentTrustRegistry (Client)', () => {
    
  let validKeypair: jose.GenerateKeyPairResult;
  let revokedKeypair: jose.GenerateKeyPairResult;
  let expiredKeypair: jose.GenerateKeyPairResult;
  
  let manifest: RegistryManifest;
  let revocations: RevocationList;
  let registry: OpenAgentTrustRegistry;

  beforeAll(async () => {
    // Generate fresh JS crypto keys for testing instead of hardcoded noble keys
    validKeypair = await jose.generateKeyPair('EdDSA', { crv: 'Ed25519' });
    revokedKeypair = await jose.generateKeyPair('EdDSA', { crv: 'Ed25519' });
    expiredKeypair = await jose.generateKeyPair('EdDSA', { crv: 'Ed25519' });

    const validJwk = await jose.exportJWK(validKeypair.publicKey);
    const revokedJwk = await jose.exportJWK(revokedKeypair.publicKey);
    const expiredJwk = await jose.exportJWK(expiredKeypair.publicKey);

    manifest = {
      schema_version: "1.0.0",
      registry_id: "open-trust-registry",
      generated_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 86400000).toISOString(),
      signature: { algorithm: 'Ed25519', kid: 'root', value: '...' },
      entries: [
        {
          issuer_id: "valid-issuer",
          display_name: "Valid Issuer",
          website: "https://example.com",
          security_contact: "sec@example.com",
          status: "active",
          added_at: new Date().toISOString(),
          last_verified: new Date().toISOString(),
          capabilities: { supervision_model: 'none', audit_logging: false, immutable_audit: false, attestation_format: 'jwt', max_attestation_ttl_seconds: 3600, capabilities_verified: false },
          public_keys: [
            {
              kid: "valid-key-1",
              algorithm: "Ed25519",
              public_key: validJwk.x!,
              status: "active",
              issued_at: new Date().toISOString(),
              expires_at: new Date(Date.now() + 86400000).toISOString(),
              deprecated_at: null,
              revoked_at: null
            },
            {
              kid: "expired-key-1",
              algorithm: "Ed25519",
              public_key: expiredJwk.x!,
              status: "active",
              issued_at: new Date(Date.now() - 86400000 * 2).toISOString(),
              expires_at: new Date(Date.now() - 86400000).toISOString(), // Expired yesterday
              deprecated_at: null,
              revoked_at: null
            }
          ]
        },
        {
           issuer_id: "revoked-issuer",
           display_name: "Revoked Issuer",
           website: "https://bad.com",
           security_contact: "sec@bad.com",
           status: "revoked",
           added_at: new Date().toISOString(),
           last_verified: new Date().toISOString(),
           capabilities: { supervision_model: 'none', audit_logging: false, immutable_audit: false, attestation_format: 'jwt', max_attestation_ttl_seconds: 3600, capabilities_verified: false },
           public_keys: [
             {
               kid: "revoked-key-1",
               algorithm: "Ed25519",
                 public_key: revokedJwk.x!,
                 status: "revoked",
                 issued_at: new Date().toISOString(),
                 expires_at: new Date(Date.now() + 86400000).toISOString(),
                 deprecated_at: null,
                 revoked_at: null
             }
           ]
        }
      ]
    };

    revocations = {
        schema_version: "1.0.0",
        generated_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 86400000).toISOString(),
        revoked_issuers: [{ issuer_id: 'revoked-issuer', reason: 'policy_violation', revoked_at: new Date().toISOString() }],
        revoked_keys: [],
        signature: { algorithm: 'Ed25519', kid: 'registry-root-2026-03', value: 'placeholder' }
    };
  });

  const signToken = async (
      keypair: jose.GenerateKeyPairResult, 
      iss: string, 
      kid: string, 
      aud: string, 
      expOffsetSeconds: number = 3600,
      nonce?: string
    ) => {
      
      const payload: Partial<AttestationClaims> = {
          sub: 'agent-123',
          aud,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + expOffsetSeconds,
          scope: ['read'],
          constraints: { max: 10 },
          user_pseudonym: 'user-xyz',
          runtime_version: '1.0'
      };
      if (nonce) {
          payload.nonce = nonce;
      }

      return new jose.SignJWT(payload)
          .setProtectedHeader({ alg: 'EdDSA', kid, iss, typ: 'agent-attestation+jwt' })
          .sign(keypair.privateKey);
  };

  it('verifies a completely valid token', async () => {
      const token = await signToken(validKeypair, 'valid-issuer', 'valid-key-1', 'https://api.service.com');
      const res = await verifyAttestation(token, manifest, revocations, 'https://api.service.com');
      
      expect(res.valid).toBe(true);
      expect(res.issuer?.issuer_id).toBe('valid-issuer');
      expect(res.claims?.sub).toBe('agent-123');
  });

  it('rejects an unknown issuer', async () => {
      const token = await signToken(validKeypair, 'fake-issuer', 'valid-key-1', 'https://api.service.com');
      const res = await verifyAttestation(token, manifest, revocations, 'https://api.service.com');
      
      expect(res.valid).toBe(false);
      expect(res.reason).toBe('unknown_issuer');
  });

  it('rejects a revoked issuer', async () => {
      const token = await signToken(revokedKeypair, 'revoked-issuer', 'revoked-key-1', 'https://api.service.com');
      const res = await verifyAttestation(token, manifest, revocations, 'https://api.service.com');
      
      expect(res.valid).toBe(false);
      expect(res.reason).toBe('revoked_issuer');
  });

  it('rejects an unknown key', async () => {
      const token = await signToken(validKeypair, 'valid-issuer', 'fake-key', 'https://api.service.com');
      const res = await verifyAttestation(token, manifest, revocations, 'https://api.service.com');
      
      expect(res.valid).toBe(false);
      expect(res.reason).toBe('unknown_key');
  });

  it('rejects a mathematically invalid signature', async () => {
      // Sign with the revoked key but claim it's the valid key
      const token = await signToken(revokedKeypair, 'valid-issuer', 'valid-key-1', 'https://api.service.com');
      const res = await verifyAttestation(token, manifest, revocations, 'https://api.service.com');
      
      expect(res.valid).toBe(false);
      expect(res.reason).toBe('invalid_signature');
  });

  it('rejects an expired registry public key (Step 10)', async () => {
      const token = await signToken(expiredKeypair, 'valid-issuer', 'expired-key-1', 'https://api.service.com');
      const res = await verifyAttestation(token, manifest, revocations, 'https://api.service.com');
      
      expect(res.valid).toBe(false);
      expect(res.reason).toBe('invalid_signature'); 
  });

  it('rejects an expired attestation token (JWT exp)', async () => {
      // Set expiration to 1 hour ago (-3600 seconds)
      const token = await signToken(validKeypair, 'valid-issuer', 'valid-key-1', 'https://api.service.com', -3600);
      const res = await verifyAttestation(token, manifest, revocations, 'https://api.service.com');
      
      expect(res.valid).toBe(false);
      expect(res.reason).toBe('expired_attestation');
  });

  it('rejects an audience mismatch', async () => {
      // Token minted for other-service.com but verified at api.service.com
      const token = await signToken(validKeypair, 'valid-issuer', 'valid-key-1', 'https://other-service.com');
      const res = await verifyAttestation(token, manifest, revocations, 'https://api.service.com');
      
      expect(res.valid).toBe(false);
      expect(res.reason).toBe('audience_mismatch');
  });

  it('rejects a nonce mismatch', async () => {
      const token = await signToken(validKeypair, 'valid-issuer', 'valid-key-1', 'https://api.service.com', 3600, 'nonce-123');
      // Verifying but expecting a completely different nonce
      const res = await verifyAttestation(token, manifest, revocations, 'https://api.service.com', 'nonce-999');
      
      expect(res.valid).toBe(false);
      expect(res.reason).toBe('nonce_mismatch');
  });

});
