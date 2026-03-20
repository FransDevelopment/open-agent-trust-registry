// sdk/typescript/src/types/registry.ts

export type KeyAlgorithm = 'Ed25519' | 'ECDSA-P256';
export type KeyStatus = 'active' | 'deprecated' | 'revoked';
export type IssuerStatus = 'active' | 'suspended' | 'revoked';

export interface PublicKey {
  kid: string;
  algorithm: KeyAlgorithm;
  public_key: string;
  status: KeyStatus;
  issued_at: string;
  expires_at: string;
  deprecated_at: string | null;
  revoked_at: string | null;
}

export interface IssuerCapabilities {
  supervision_model: string;
  audit_logging: boolean;
  immutable_audit: boolean;
  attestation_format: string;
  max_attestation_ttl_seconds: number;
  /**
   * Whether community auditors have independently verified this issuer's
   * capability claims. New issuers are automatically included with
   * `capabilities_verified: false` (Tier 1 registration). Community
   * reviewers may upgrade to `true` via a separate PR (Tier 2).
   *
   * Services may use this field to apply differentiated policies, e.g.
   * requiring `capabilities_verified: true` for high-stakes operations.
   *
   * @see https://github.com/FransDevelopment/open-agent-trust-registry/blob/main/GOVERNANCE.md#tier-2-capability-verification-community-review
   */
  capabilities_verified: boolean;
}

export interface IssuerEndpoints {
  attestation_verify?: string;
  revocation_list?: string;
}

export interface IssuerEntry {
  issuer_id: string;
  display_name: string;
  website: string;
  security_contact: string;
  status: IssuerStatus;
  added_at: string;
  last_verified: string;
  public_keys: PublicKey[];
  capabilities: IssuerCapabilities;
  endpoints?: IssuerEndpoints;
}

export interface RegistrySignature {
  algorithm: KeyAlgorithm;
  kid: string;
  value: string;
}

export interface RegistryManifest {
  schema_version: string;
  registry_id: string;
  generated_at: string;
  expires_at: string;
  entries: IssuerEntry[];
  signature: RegistrySignature;
}

// Revocations
export interface RevokedKey {
  issuer_id: string;
  kid: string;
  revoked_at: string;
  reason: string;
}

export interface RevokedIssuer {
  issuer_id: string;
  revoked_at: string;
  reason: string;
}

export interface RevocationList {
  schema_version: string;
  generated_at: string;
  expires_at: string;
  revoked_keys: RevokedKey[];
  revoked_issuers: RevokedIssuer[];
  signature?: RegistrySignature;
}
