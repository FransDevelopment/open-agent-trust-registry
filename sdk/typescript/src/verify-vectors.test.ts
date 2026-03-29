import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { verifyAttestation } from './index';
import type { RegistryManifest, RevocationList } from './types';

const vectorsPath = resolve(__dirname, '../../../spec/test-vectors/key-rotation/vectors.json');
const vectorsFile = JSON.parse(readFileSync(vectorsPath, 'utf-8'));

// Use the generation timestamp as our "now" so relative date offsets in vectors are correct
const verificationTime = new Date(vectorsFile.generated_at);

// Empty revocations — vectors test key status logic, not the revocations fast-path
const emptyRevocations: RevocationList = {
  schema_version: '1.0.0',
  generated_at: vectorsFile.generated_at,
  expires_at: new Date(verificationTime.getTime() + 86400000).toISOString(),
  revoked_keys: [],
  revoked_issuers: [],
  signature: { algorithm: 'Ed25519', kid: 'test', value: 'placeholder' }
};

describe('Key Rotation Test Vectors (spec/test-vectors)', () => {
  for (const vector of vectorsFile.vectors) {
    // Build a minimal manifest from the vector's issuer entry
    const manifest: RegistryManifest = {
      schema_version: '1.0.0',
      registry_id: 'test-vectors',
      generated_at: vectorsFile.generated_at,
      expires_at: new Date(verificationTime.getTime() + 86400000).toISOString(),
      entries: [vector.issuer],
      signature: { algorithm: 'Ed25519', kid: 'test', value: 'placeholder' }
    };

    for (const attestation of vector.attestations) {
      const label = `${vector.id}: ${attestation.description}`;
      const shouldPass = attestation.expected_result === 'pass';

      it(label, async () => {
        const result = await verifyAttestation(
          attestation.token,
          manifest,
          emptyRevocations,
          'https://api.example.com',
          undefined,
          verificationTime
        );

        expect(result.valid).toBe(shouldPass);
      });
    }
  }
});
