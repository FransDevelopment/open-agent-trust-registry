import { readFileSync } from 'fs';
import { resolve } from 'path';
import { createPublicKey, verify as verifySignature } from 'crypto';
import type { RegistryManifest, RevocationList, RootKeyEntry, RootKeySet } from './types';
import type { RegistryStateErrorCode } from './types';

export class OpenAgentTrustRegistryError extends Error {
  public readonly code: RegistryStateErrorCode;

  constructor(code: RegistryStateErrorCode, message: string) {
    super(message);
    this.name = 'OpenAgentTrustRegistryError';
    this.code = code;
  }
}

export interface VerifyRegistryArtifactsOptions {
  now?: Date;
  rootKeys?: RootKeySet;
}

export interface VerifiedRegistryArtifacts {
  manifest: RegistryManifest;
  revocations: RevocationList;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new OpenAgentTrustRegistryError('malformed_registry_state', `${label} must be a non-empty string`);
  }
  return value;
}

function parseDate(value: string, label: string): Date {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new OpenAgentTrustRegistryError('malformed_registry_state', `${label} must be a valid ISO 8601 timestamp`);
  }
  return parsed;
}

function canonicalize(value: unknown): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new OpenAgentTrustRegistryError('malformed_registry_state', 'Canonical JSON does not support non-finite numbers');
      }
      return JSON.stringify(value);
    case 'string':
      return JSON.stringify(value);
    case 'object':
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalize(item)).join(',')}]`;
      }

      return `{${Object.keys(value)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalize((value as Record<string, unknown>)[key])}`)
        .join(',')}}`;
    default:
      throw new OpenAgentTrustRegistryError('malformed_registry_state', `Unsupported canonical JSON value type: ${typeof value}`);
  }
}

function loadBundledJson<T>(relativePath: string): T {
  const absolutePath = resolve(__dirname, '..', relativePath);
  return JSON.parse(readFileSync(absolutePath, 'utf8')) as T;
}

export function loadBundledRootKeys(): RootKeySet {
  const rootKeys = loadBundledJson<RootKeySet>('root-keys.json');

  if (!isRecord(rootKeys) || !Array.isArray(rootKeys.keys)) {
    throw new OpenAgentTrustRegistryError('malformed_registry_state', 'Bundled root-keys.json is malformed');
  }

  return rootKeys;
}

function assertRegistrySignature(signature: unknown): { algorithm: 'Ed25519'; kid: string; value: string } {
  if (!isRecord(signature)) {
    throw new OpenAgentTrustRegistryError('malformed_registry_state', 'signature must be an object');
  }

  const algorithm = assertString(signature.algorithm, 'signature.algorithm');
  if (algorithm !== 'Ed25519') {
    throw new OpenAgentTrustRegistryError('invalid_registry_signature', `Unsupported registry signature algorithm: ${algorithm}`);
  }

  return {
    algorithm: 'Ed25519',
    kid: assertString(signature.kid, 'signature.kid'),
    value: assertString(signature.value, 'signature.value')
  };
}

function assertManifestLike(manifest: unknown): asserts manifest is RegistryManifest {
  if (!isRecord(manifest)) {
    throw new OpenAgentTrustRegistryError('malformed_registry_state', 'manifest must be an object');
  }

  assertString(manifest.schema_version, 'manifest.schema_version');
  assertString(manifest.registry_id, 'manifest.registry_id');
  assertString(manifest.generated_at, 'manifest.generated_at');
  assertString(manifest.expires_at, 'manifest.expires_at');

  if (!Array.isArray(manifest.entries)) {
    throw new OpenAgentTrustRegistryError('malformed_registry_state', 'manifest.entries must be an array');
  }

  assertRegistrySignature(manifest.signature);
}

function assertRevocationListLike(revocations: unknown): asserts revocations is RevocationList {
  if (!isRecord(revocations)) {
    throw new OpenAgentTrustRegistryError('malformed_registry_state', 'revocations must be an object');
  }

  assertString(revocations.schema_version, 'revocations.schema_version');
  assertString(revocations.generated_at, 'revocations.generated_at');
  assertString(revocations.expires_at, 'revocations.expires_at');

  if (!Array.isArray(revocations.revoked_keys) || !Array.isArray(revocations.revoked_issuers)) {
    throw new OpenAgentTrustRegistryError('malformed_registry_state', 'revocation lists must be arrays');
  }

  assertRegistrySignature(revocations.signature);
}

function findTrustedRootKey(rootKeys: RootKeySet, signature: { algorithm: 'Ed25519'; kid: string; value: string }, now: Date): RootKeyEntry {
  const rootKey = rootKeys.keys.find((entry) => entry.kid === signature.kid);
  if (!rootKey) {
    throw new OpenAgentTrustRegistryError('unknown_root_key', `Unknown root key id: ${signature.kid}`);
  }

  if (rootKey.status !== 'active') {
    throw new OpenAgentTrustRegistryError('invalid_registry_signature', `Root key ${signature.kid} is not active`);
  }

  const notBefore = parseDate(rootKey.not_before, `root key ${signature.kid} not_before`);
  if (now < notBefore) {
    throw new OpenAgentTrustRegistryError('invalid_registry_signature', `Root key ${signature.kid} is not valid yet`);
  }

  if (rootKey.not_after) {
    const notAfter = parseDate(rootKey.not_after, `root key ${signature.kid} not_after`);
    if (now > notAfter) {
      throw new OpenAgentTrustRegistryError('invalid_registry_signature', `Root key ${signature.kid} has expired`);
    }
  }

  return rootKey;
}

function verifySignedArtifact(
  artifact: RegistryManifest | RevocationList,
  kind: 'manifest' | 'revocations',
  rootKeys: RootKeySet,
  now: Date
): void {
  const signature = assertRegistrySignature(artifact.signature);
  const trustedRootKey = findTrustedRootKey(rootKeys, signature, now);
  const expiresAt = parseDate(artifact.expires_at, `${kind}.expires_at`);

  if (now > expiresAt) {
    throw new OpenAgentTrustRegistryError('stale_registry_state', `${kind} is expired as of ${artifact.expires_at}`);
  }

  const unsignedArtifact = { ...artifact, signature: undefined } as Record<string, unknown>;
  delete unsignedArtifact.signature;

  const canonicalBytes = Buffer.from(canonicalize(unsignedArtifact), 'utf8');
  const signatureBytes = Buffer.from(signature.value, 'base64url');
  const publicKey = createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: trustedRootKey.public_key },
    format: 'jwk'
  });

  const isValid = verifySignature(null, canonicalBytes, publicKey, signatureBytes);
  if (!isValid) {
    throw new OpenAgentTrustRegistryError('invalid_registry_signature', `${kind} signature verification failed`);
  }
}

export function verifyRegistryArtifacts(
  manifest: unknown,
  revocations: unknown,
  options: VerifyRegistryArtifactsOptions = {}
): VerifiedRegistryArtifacts {
  const now = options.now ?? new Date();
  const rootKeys = options.rootKeys ?? loadBundledRootKeys();

  assertManifestLike(manifest);
  assertRevocationListLike(revocations);

  verifySignedArtifact(manifest, 'manifest', rootKeys, now);
  verifySignedArtifact(revocations, 'revocations', rootKeys, now);

  return { manifest, revocations };
}

export function canonicalizeRegistryArtifact(value: unknown): string {
  return canonicalize(value);
}
