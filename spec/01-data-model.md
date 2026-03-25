# 01 - Data Model Specification

This document details the JSON schema formats that define the Open Agent Trust Registry. The registry represents a single signed document containing a dictionary of trusted attestation issuers.

## 1. Registry Manifest (`manifest.json`)

The single signed document containing all trusted issuers.

```json
{
  "schema_version": "1.0.0",
  "registry_id": "open-trust-registry",
  "generated_at": "2026-03-15T12:00:00Z",
  "expires_at": "2026-03-16T12:00:00Z",
  "entries": [ ... ],
  "signature": {
    "algorithm": "Ed25519",
    "kid": "registry-root-2026-03",
    "value": "base64-encoded-signature"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | semver | Schema version for backward compatibility |
| `registry_id` | string | Canonical identifier for this registry |
| `generated_at` | ISO 8601 | When this snapshot was produced |
| `expires_at` | ISO 8601 | Mirrors must not serve this snapshot after this time (max 24h window) |
| `entries` | array | Array of `IssuerEntry` objects |
| `signature` | object | Registry maintainer signature over the canonical JSON of all other fields |

### Signature Canonicalization

The signed bytes for both `manifest.json` and `revocations.json` are produced as follows:

1. Remove the top-level `signature` field entirely.
2. Canonicalize the remaining JSON using RFC 8785 JSON Canonicalization Scheme (JCS).
3. UTF-8 encode the canonical JSON bytes.
4. Sign those bytes with the active Ed25519 root key referenced by `signature.kid`.

Clients MUST reconstruct the same canonical byte stream before verifying the signature.

## 1.1 Root Trust Anchor (`root-keys.json`)

Clients bootstrap trust from a checked-in root key set:

```json
{
  "schema_version": "1.0.0",
  "registry_id": "open-trust-registry",
  "generated_at": "2026-03-24T00:00:00Z",
  "keys": [
    {
      "kid": "registry-root-2026-03",
      "algorithm": "Ed25519",
      "public_key": "base64url-ed25519-public-key",
      "status": "active",
      "not_before": "2026-03-24T00:00:00Z",
      "not_after": null
    }
  ]
}
```

Clients MUST reject signed artifacts whose `signature.kid` is missing from `root-keys.json`, not yet valid, expired, or retired.

## 2. Issuer Entry

Each entry models one trusted attestation issuer.

```json
{
  "issuer_id": "acme-agent-runtime",
  "display_name": "Acme Agent Runtime",
  "website": "https://acme.example.com",
  "security_contact": "security@acme.example.com",
  "status": "active",
  "added_at": "2026-03-15T00:00:00Z",
  "last_verified": "2026-03-15T00:00:00Z",
  "public_keys": [ ... ],
  "capabilities": {
    "supervision_model": "tiered",
    "audit_logging": true,
    "immutable_audit": true,
    "attestation_format": "jwt",
    "max_attestation_ttl_seconds": 3600,
    "capabilities_verified": false
  },
  "endpoints": {
    "attestation_verify": "https://api.acme.example.com/v1/identity/verify",
    "revocation_list": "https://api.acme.example.com/v1/identity/revocations"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `issuer_id` | string | yes | Globally unique identifier. Lowercase alphanumeric + hyphens. |
| `display_name` | string | yes | Human-readable name |
| `website` | URL | yes | Issuer's public website |
| `security_contact` | email | yes | Security disclosure contact |
| `status` | enum | yes | `active`, `suspended`, `revoked` |
| `added_at` | ISO 8601 | yes | When issuer was added to registry |
| `last_verified` | ISO 8601 | yes | Last time issuer passed verification check |
| `public_keys` | array | yes | Array of `PublicKey` objects (at least one active) |
| `capabilities` | object | yes | Self-declared capabilities of the runtime (see Capabilities sub-fields below) |
| `endpoints` | object | no | Optional verification/revocation endpoints |

### 2.1 Capabilities Sub-fields

| Field | Type | Description |
|-------|------|-------------|
| `supervision_model` | string | Human oversight model (e.g. `"tiered"`, `"full"`, `"autonomous"`) |
| `audit_logging` | boolean | Whether the runtime maintains audit logs of agent actions |
| `immutable_audit` | boolean | Whether the audit log is write-once / tamper-evident |
| `attestation_format` | string | Token format produced by the runtime (e.g. `"jwt"`) |
| `max_attestation_ttl_seconds` | integer | Maximum lifetime of any issued attestation, in seconds |
| `capabilities_verified` | boolean | `false` for all new registrations (automated Tier 1). Community auditors may open a PR setting this to `true` (Tier 2 review) after independently verifying the above claims. Services may use this flag to apply differentiated trust policies (see [Governance Tier 2](../GOVERNANCE.md)). |

## 3. Public Key Entry

```json
{
  "kid": "acme-2026-03",
  "algorithm": "Ed25519",
  "public_key": "base64url-encoded-32-bytes",
  "status": "active",
  "issued_at": "2026-03-15T00:00:00Z",
  "expires_at": "2027-03-15T00:00:00Z",
  "deprecated_at": null,
  "revoked_at": null
}
```

| Field | Type | Description |
|-------|------|-------------|
| `kid` | string | Key identifier, unique within issuer. Referenced in attestation headers. |
| `algorithm` | enum | `Ed25519` (required support), `ECDSA-P256` (optional support) |
| `public_key` | string | Base64url-encoded public key bytes |
| `status` | enum | `active`, `deprecated`, `revoked` |
| `issued_at` | ISO 8601 | Key creation time |
| `expires_at` | ISO 8601 | Key expiry (max 2 years from issuance) |
| `deprecated_at` | ISO 8601 | When key was deprecated (still valid for verification during grace period) |
| `revoked_at` | ISO 8601 | When key was revoked (no longer valid for any verification) |
