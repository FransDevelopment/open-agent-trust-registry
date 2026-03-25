import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import type { RegistryManifest, RevocationList } from './types';
import { OpenAgentTrustRegistryError, verifyRegistryArtifacts } from './registry-artifacts';

const loadJson = <T>(relativePath: string): T =>
  JSON.parse(readFileSync(resolve(process.cwd(), relativePath), 'utf8')) as T;

describe('registry artifact verification', () => {
  it('verifies the checked-in manifest and revocation list when they are fresh', () => {
    const manifest = loadJson<RegistryManifest>('../../registry/manifest.json');
    const revocations = loadJson<RevocationList>('../../registry/revocations.json');
    const now = new Date(manifest.generated_at);

    const verified = verifyRegistryArtifacts(manifest, revocations, { now });

    expect(verified.manifest.registry_id).toBe('open-trust-registry');
    expect(verified.manifest.entries.length).toBeGreaterThan(0);
    expect(verified.revocations.signature.kid).toBe('registry-root-2026-03');
  });

  it('rejects an expired manifest', () => {
    const manifest = loadJson<RegistryManifest>('../../registry/manifest.json');
    const revocations = loadJson<RevocationList>('../../registry/revocations.json');
    const now = new Date(new Date(manifest.expires_at).getTime() + 1000);

    expect(() => verifyRegistryArtifacts(manifest, revocations, { now })).toThrowError(OpenAgentTrustRegistryError);
    expect(() => verifyRegistryArtifacts(manifest, revocations, { now })).toThrow(/manifest is expired/);
  });

  it('rejects an expired revocation list', () => {
    const manifest = loadJson<RegistryManifest>('../../registry/manifest.json');
    const revocations = loadJson<RevocationList>('../../registry/revocations.json');
    // Use a revocation list with a short expiry so it expires before the manifest
    const expiredRevocations = structuredClone(revocations);
    expiredRevocations.expires_at = manifest.generated_at;
    const now = new Date(new Date(expiredRevocations.expires_at).getTime() + 1000);

    expect(() => verifyRegistryArtifacts(manifest, expiredRevocations, { now })).toThrowError(OpenAgentTrustRegistryError);
    expect(() => verifyRegistryArtifacts(manifest, expiredRevocations, { now })).toThrow(/revocations is expired/);
  });

  it('rejects a tampered manifest signature', () => {
    const manifest = loadJson<RegistryManifest>('../../registry/manifest.json');
    const revocations = loadJson<RevocationList>('../../registry/revocations.json');
    const tamperedManifest = structuredClone(manifest);
    tamperedManifest.entries[0].display_name = `${tamperedManifest.entries[0].display_name} tampered`;

    expect(() =>
      verifyRegistryArtifacts(tamperedManifest, revocations, { now: new Date(manifest.generated_at) })
    ).toThrow(/manifest signature verification failed/);
  });

  it('rejects a tampered revocation signature', () => {
    const manifest = loadJson<RegistryManifest>('../../registry/manifest.json');
    const revocations = loadJson<RevocationList>('../../registry/revocations.json');
    const tamperedRevocations = structuredClone(revocations);
    tamperedRevocations.revoked_keys.push({
      issuer_id: 'tampered-runtime',
      kid: 'tampered-key',
      revoked_at: revocations.generated_at,
      reason: 'key_compromise'
    });

    expect(() =>
      verifyRegistryArtifacts(manifest, tamperedRevocations, { now: new Date(manifest.generated_at) })
    ).toThrow(/revocations signature verification failed/);
  });

  it('rejects the legacy compiler manifest shape after cutover', () => {
    const revocations = loadJson<RevocationList>('../../registry/revocations.json');
    const legacyManifest = {
      version: '1.0',
      generated_at: revocations.generated_at,
      expires_at: revocations.expires_at,
      total_issuers: 0,
      issuers: {},
      signature: 'ed25519:legacy'
    };

    expect(() =>
      verifyRegistryArtifacts(legacyManifest, revocations, { now: new Date(revocations.generated_at) })
    ).toThrow(/manifest\.schema_version/);
  });
});
