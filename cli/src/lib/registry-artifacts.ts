import { readFile } from 'fs/promises';
import { createPrivateKey } from 'crypto';
import { join } from 'path';
import * as ed from '@noble/ed25519';

interface RootKeyEntry {
  kid: string;
  algorithm: 'Ed25519';
  public_key: string;
  status: 'active' | 'retired';
  not_before: string;
  not_after: string | null;
}

interface RootKeySet {
  schema_version: string;
  registry_id: string;
  generated_at: string;
  keys: RootKeyEntry[];
}

export interface RegistrySignature {
  algorithm: 'Ed25519';
  kid: string;
  value: string;
}

export function canonicalizeJson(value: unknown): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('Canonical JSON does not support non-finite numbers.');
      }
      return JSON.stringify(value);
    case 'string':
      return JSON.stringify(value);
    case 'object':
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalizeJson(item)).join(',')}]`;
      }

      return `{${Object.keys(value as Record<string, unknown>)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalizeJson((value as Record<string, unknown>)[key])}`)
        .join(',')}}`;
    default:
      throw new Error(`Unsupported value type for canonical JSON: ${typeof value}`);
  }
}

export function createPrivateKeyFromSeed(seedBase64Url: string) {
  const privateKeyBytes = Buffer.from(seedBase64Url.trim(), 'base64url');
  if (privateKeyBytes.length !== 32) {
    throw new Error(`Invalid private key length (${privateKeyBytes.length} bytes). Must be 32 bytes.`);
  }

  const seedHex = privateKeyBytes.toString('hex');
  const pkcs8Der = Buffer.from(`302e020100300506032b657004220420${seedHex}`, 'hex');

  return createPrivateKey({
    key: pkcs8Der,
    format: 'der',
    type: 'pkcs8'
  });
}

export async function loadRootKeySet(registryDir: string): Promise<RootKeySet> {
  const raw = await readFile(join(registryDir, 'root-keys.json'), 'utf8');
  return JSON.parse(raw) as RootKeySet;
}

export async function resolveActiveRootKey(registryDir: string, privateSeed: string): Promise<RootKeyEntry> {
  const publicKey = Buffer.from(await ed.getPublicKeyAsync(Buffer.from(privateSeed.trim(), 'base64url'))).toString('base64url');
  const rootKeys = await loadRootKeySet(registryDir);
  const rootKey = rootKeys.keys.find((entry) => entry.public_key === publicKey && entry.status === 'active');

  if (!rootKey) {
    throw new Error('The supplied root private key does not match any active key in registry/root-keys.json.');
  }

  return rootKey;
}

export async function signRegistryArtifact(
  unsignedArtifact: Record<string, unknown>,
  privateSeed: string,
  signatureKid: string
): Promise<RegistrySignature> {
  const canonicalPayload = canonicalizeJson(unsignedArtifact);
  const signatureBytes = await ed.signAsync(Buffer.from(canonicalPayload, 'utf8'), Buffer.from(privateSeed.trim(), 'base64url'));

  return {
    algorithm: 'Ed25519',
    kid: signatureKid,
    value: Buffer.from(signatureBytes).toString('base64url')
  };
}
