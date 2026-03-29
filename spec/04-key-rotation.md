# 04 - Key Rotation Protocol

Issuers are strongly encouraged to rotate their signing keys proactively to minimize the impact of long-term key exhaustion and potential compromise.

## Routine Key Rotation

Issuers routinely rotate their active signing keys using a two-step Git Pull Request process:

**1. Deprecation Phase:**
The active issuer submits a pull request against their file in `registry/issuers/` that:
1. Adds a newly generated key entry to their `public_keys` array, setting the new key `status` to `active`.
2. Downgrades the older key's `status` to `deprecated`, and populates the `deprecated_at` timestamp.

> *Grace Period:* A deprecated key remains explicitly valid for 90 days. This "grace period" allows services relying on slightly stale, cached versions of the registry manifest to continue serving their users without interruption while they pull the latest manifest update.

**2. Revocation Phase:**
Once the 90-day grace period concludes, the issuer submits a final, subsequent pull request setting the older key's status strictly to `revoked` and migrating the `revoked_at` timestamp.

## Emergency Key Rotation

In the critical event a signing key is potentially compromised, the issuer submits a pull request immediately setting the key to `revoked` (entirely skipping the graceful deprecation phase).

- Emergency PRs are fast-tracked for immediate manual merge by the registry governance council.
- Changes to `registry/revocations.json` trigger an immediate manifest recompilation on merge. Services polling the revocation list will reject subsequent attestations from the compromised key within their cache refresh interval (SDK default: 15 minutes).

## Key Reactivation (Rollback)

A deprecated key MAY be reactivated by the issuer submitting a pull request that:
1. Sets the key `status` back to `active`.
2. Clears the `deprecated_at` timestamp (sets to `null`).

This is permitted when the issuer determines the deprecation was premature or the replacement key has issues.

A revoked key MUST NOT be reactivated under any circumstances. Revocation indicates potential compromise, and reactivation would undermine the security guarantees of the revocation protocol. If an issuer needs the same key material after revocation, they MUST register it as a new key entry with a new `kid`.
