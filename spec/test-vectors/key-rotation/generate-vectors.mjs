/**
 * Generates key rotation test vectors for the OATR spec.
 * Run: node generate-vectors.mjs > vectors.json
 *
 * Each vector contains real Ed25519 keys and signed JWTs
 * that can be verified independently.
 */

import * as jose from 'jose';

const GRACE_PERIOD_DAYS = 90;
const DAY_MS = 86400000;

function ts(offsetDays = 0) {
  return new Date(Date.now() + offsetDays * DAY_MS).toISOString();
}

function unixTs(offsetSeconds = 0) {
  return Math.floor(Date.now() / 1000) + offsetSeconds;
}

async function exportKey(keypair) {
  const jwk = await jose.exportJWK(keypair.publicKey);
  return jwk.x; // base64url-encoded Ed25519 public key
}

// Year 2099 exp so static test vectors remain usable long-term
const FAR_FUTURE_EXP = Math.floor(new Date('2099-12-31T23:59:59Z').getTime() / 1000);

async function signAttestation(keypair, iss, kid, aud) {
  return new jose.SignJWT({
    sub: 'agent-test-instance',
    aud,
    iat: unixTs(),
    exp: FAR_FUTURE_EXP,
    scope: ['read:data'],
    constraints: { max_cost_usd: 5.0 },
    user_pseudonym: 'test-pseudonym',
    runtime_version: '1.0.0'
  })
    .setProtectedHeader({ alg: 'EdDSA', kid, iss, typ: 'agent-attestation+jwt' })
    .sign(keypair.privateKey);
}

async function main() {
  // Generate keys for all scenarios
  const oldKey = await jose.generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const newKey = await jose.generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const revokedNewKey = await jose.generateKeyPair('EdDSA', { crv: 'Ed25519' });

  const oldPub = await exportKey(oldKey);
  const newPub = await exportKey(newKey);
  const revokedNewPub = await exportKey(revokedNewKey);

  const vectors = [];

  // Vector 1: Happy path — routine rotation, old key in grace period
  const v1Token = await signAttestation(oldKey, 'test-issuer', 'key-2025-12', 'https://api.example.com');
  const v1TokenNew = await signAttestation(newKey, 'test-issuer', 'key-2026-03', 'https://api.example.com');
  vectors.push({
    id: 'kr-01-happy-path',
    title: 'Routine key rotation — old key in grace period',
    description: 'Issuer rotates from key-2025-12 to key-2026-03. Old key deprecated but within 90-day grace period. Both keys should verify.',
    issuer: {
      issuer_id: 'test-issuer',
      display_name: 'Test Issuer',
      website: 'https://test.example.com',
      security_contact: 'security@test.example.com',
      status: 'active',
      added_at: '2025-12-01T00:00:00Z',
      last_verified: ts(),
      capabilities: { supervision_model: 'tiered', audit_logging: true, immutable_audit: true, attestation_format: 'jwt', max_attestation_ttl_seconds: 3600, capabilities_verified: false },
      public_keys: [
        {
          kid: 'key-2025-12',
          algorithm: 'Ed25519',
          public_key: oldPub,
          status: 'deprecated',
          issued_at: '2025-12-01T00:00:00Z',
          expires_at: '2027-12-01T00:00:00Z',
          deprecated_at: ts(-30), // deprecated 30 days ago (within 90-day grace)
          revoked_at: null
        },
        {
          kid: 'key-2026-03',
          algorithm: 'Ed25519',
          public_key: newPub,
          status: 'active',
          issued_at: ts(-30),
          expires_at: ts(700),
          deprecated_at: null,
          revoked_at: null
        }
      ]
    },
    attestations: [
      {
        description: 'Signed with deprecated key (within grace period)',
        token: v1Token,
        kid_used: 'key-2025-12',
        expected_result: 'pass',
        expected_reason: 'Key is deprecated but within the 90-day grace period. Signature is mathematically valid.'
      },
      {
        description: 'Signed with new active key',
        token: v1TokenNew,
        kid_used: 'key-2026-03',
        expected_result: 'pass',
        expected_reason: 'Key is active. Signature is mathematically valid.'
      }
    ]
  });

  // Vector 2: Expired grace period
  const v2Token = await signAttestation(oldKey, 'test-issuer', 'key-2025-06', 'https://api.example.com');
  vectors.push({
    id: 'kr-02-expired-grace-period',
    title: 'Deprecated key — grace period expired',
    description: 'Old key was deprecated 120 days ago, exceeding the 90-day grace period. Attestations signed with this key must fail.',
    issuer: {
      issuer_id: 'test-issuer',
      display_name: 'Test Issuer',
      website: 'https://test.example.com',
      security_contact: 'security@test.example.com',
      status: 'active',
      added_at: '2025-06-01T00:00:00Z',
      last_verified: ts(),
      capabilities: { supervision_model: 'tiered', audit_logging: true, immutable_audit: true, attestation_format: 'jwt', max_attestation_ttl_seconds: 3600, capabilities_verified: false },
      public_keys: [
        {
          kid: 'key-2025-06',
          algorithm: 'Ed25519',
          public_key: oldPub,
          status: 'deprecated',
          issued_at: '2025-06-01T00:00:00Z',
          expires_at: '2027-06-01T00:00:00Z',
          deprecated_at: ts(-120), // deprecated 120 days ago (exceeds 90-day grace)
          revoked_at: null
        },
        {
          kid: 'key-2025-12',
          algorithm: 'Ed25519',
          public_key: newPub,
          status: 'active',
          issued_at: ts(-120),
          expires_at: ts(600),
          deprecated_at: null,
          revoked_at: null
        }
      ]
    },
    attestations: [
      {
        description: 'Signed with deprecated key (grace period expired)',
        token: v2Token,
        kid_used: 'key-2025-06',
        expected_result: 'fail',
        expected_reason: 'Key was deprecated 120 days ago. The 90-day grace period has expired. Implementations MUST reject.'
      }
    ]
  });

  // Vector 3: Revoked key — immediate rejection
  const v3Token = await signAttestation(oldKey, 'test-issuer', 'key-compromised', 'https://api.example.com');
  vectors.push({
    id: 'kr-03-revoked-key',
    title: 'Revoked key — immediate rejection, no grace period',
    description: 'Key was emergency-revoked due to suspected compromise. Attestations signed with this key must fail immediately, regardless of when the key was issued.',
    issuer: {
      issuer_id: 'test-issuer',
      display_name: 'Test Issuer',
      website: 'https://test.example.com',
      security_contact: 'security@test.example.com',
      status: 'active',
      added_at: '2025-06-01T00:00:00Z',
      last_verified: ts(),
      capabilities: { supervision_model: 'tiered', audit_logging: true, immutable_audit: true, attestation_format: 'jwt', max_attestation_ttl_seconds: 3600, capabilities_verified: false },
      public_keys: [
        {
          kid: 'key-compromised',
          algorithm: 'Ed25519',
          public_key: oldPub,
          status: 'revoked',
          issued_at: '2025-06-01T00:00:00Z',
          expires_at: '2027-06-01T00:00:00Z',
          deprecated_at: null,
          revoked_at: ts(-1) // revoked yesterday
        },
        {
          kid: 'key-2026-03',
          algorithm: 'Ed25519',
          public_key: newPub,
          status: 'active',
          issued_at: ts(-1),
          expires_at: ts(700),
          deprecated_at: null,
          revoked_at: null
        }
      ]
    },
    attestations: [
      {
        description: 'Signed with revoked key',
        token: v3Token,
        kid_used: 'key-compromised',
        expected_result: 'fail',
        expected_reason: 'Key has revoked_at set. No grace period applies to revoked keys. Implementations MUST reject immediately.'
      }
    ]
  });

  // Vector 4: Multiple active keys
  const v4TokenA = await signAttestation(oldKey, 'test-issuer', 'key-primary', 'https://api.example.com');
  const v4TokenB = await signAttestation(newKey, 'test-issuer', 'key-secondary', 'https://api.example.com');
  vectors.push({
    id: 'kr-04-multiple-active-keys',
    title: 'Multiple active keys — both verify',
    description: 'Issuer maintains two active keys simultaneously (e.g., geographic redundancy or rolling deployment). Attestations signed with either key must verify.',
    issuer: {
      issuer_id: 'test-issuer',
      display_name: 'Test Issuer',
      website: 'https://test.example.com',
      security_contact: 'security@test.example.com',
      status: 'active',
      added_at: '2025-06-01T00:00:00Z',
      last_verified: ts(),
      capabilities: { supervision_model: 'tiered', audit_logging: true, immutable_audit: true, attestation_format: 'jwt', max_attestation_ttl_seconds: 3600, capabilities_verified: false },
      public_keys: [
        {
          kid: 'key-primary',
          algorithm: 'Ed25519',
          public_key: oldPub,
          status: 'active',
          issued_at: '2025-06-01T00:00:00Z',
          expires_at: ts(365),
          deprecated_at: null,
          revoked_at: null
        },
        {
          kid: 'key-secondary',
          algorithm: 'Ed25519',
          public_key: newPub,
          status: 'active',
          issued_at: ts(-90),
          expires_at: ts(365),
          deprecated_at: null,
          revoked_at: null
        }
      ]
    },
    attestations: [
      {
        description: 'Signed with primary active key',
        token: v4TokenA,
        kid_used: 'key-primary',
        expected_result: 'pass',
        expected_reason: 'Key is active. Signature is mathematically valid.'
      },
      {
        description: 'Signed with secondary active key',
        token: v4TokenB,
        kid_used: 'key-secondary',
        expected_result: 'pass',
        expected_reason: 'Key is active. Signature is mathematically valid.'
      }
    ]
  });

  // Vector 5: Rollback — new key revoked, old key reactivated
  const v5TokenRevoked = await signAttestation(revokedNewKey, 'test-issuer', 'key-2026-03-bad', 'https://api.example.com');
  const v5TokenOld = await signAttestation(oldKey, 'test-issuer', 'key-2025-12-restored', 'https://api.example.com');
  vectors.push({
    id: 'kr-05-rollback',
    title: 'Rollback — new key revoked, old key reactivated',
    description: 'The new key was compromised shortly after rotation. It has been revoked. The old key has been reactivated (deprecated_at cleared). Attestations signed with the revoked new key must fail. Attestations signed with the restored old key must pass.',
    issuer: {
      issuer_id: 'test-issuer',
      display_name: 'Test Issuer',
      website: 'https://test.example.com',
      security_contact: 'security@test.example.com',
      status: 'active',
      added_at: '2025-06-01T00:00:00Z',
      last_verified: ts(),
      capabilities: { supervision_model: 'tiered', audit_logging: true, immutable_audit: true, attestation_format: 'jwt', max_attestation_ttl_seconds: 3600, capabilities_verified: false },
      public_keys: [
        {
          kid: 'key-2025-12-restored',
          algorithm: 'Ed25519',
          public_key: oldPub,
          status: 'active',
          issued_at: '2025-12-01T00:00:00Z',
          expires_at: '2027-12-01T00:00:00Z',
          deprecated_at: null, // cleared — reactivated
          revoked_at: null
        },
        {
          kid: 'key-2026-03-bad',
          algorithm: 'Ed25519',
          public_key: revokedNewPub,
          status: 'revoked',
          issued_at: ts(-14),
          expires_at: ts(700),
          deprecated_at: null,
          revoked_at: ts(-7) // revoked 7 days after issuance
        }
      ]
    },
    attestations: [
      {
        description: 'Signed with revoked new key',
        token: v5TokenRevoked,
        kid_used: 'key-2026-03-bad',
        expected_result: 'fail',
        expected_reason: 'Key has revoked_at set. Revocation is immediate and permanent.'
      },
      {
        description: 'Signed with restored old key',
        token: v5TokenOld,
        kid_used: 'key-2025-12-restored',
        expected_result: 'pass',
        expected_reason: 'Key is active (reactivated after rollback). deprecated_at cleared. Signature is mathematically valid.'
      }
    ]
  });

  console.log(JSON.stringify({
    schema_version: '1.0.0',
    generated_at: new Date().toISOString(),
    description: 'Key rotation test vectors for the Open Agent Trust Registry spec. Each vector contains real Ed25519 keys and signed JWTs.',
    grace_period_days: GRACE_PERIOD_DAYS,
    vectors
  }, null, 2));
}

main().catch(console.error);
