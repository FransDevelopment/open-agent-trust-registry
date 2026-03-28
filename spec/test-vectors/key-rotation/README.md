# Key Rotation Test Vectors

Test vectors for verifying that implementations handle the key rotation protocol defined in [04-key-rotation.md](../../04-key-rotation.md) correctly.

## Overview

| ID | Scenario | Attestations | Expected |
|----|----------|-------------|----------|
| `kr-01` | Routine rotation — old key in grace period | 2 | Both pass |
| `kr-02` | Deprecated key — grace period expired | 1 | Fail |
| `kr-03` | Revoked key — immediate rejection | 1 | Fail |
| `kr-04` | Multiple active keys | 2 | Both pass |
| `kr-05` | Rollback — new key revoked, old key reactivated | 2 | Revoked fails, restored passes |

## How to use

Each vector in `vectors.json` contains:

- **`issuer`** — A complete issuer entry with `public_keys` in the rotation state being tested
- **`attestations[]`** — One or more JWTs signed with real Ed25519 keys, each with:
  - `token` — The compact JWS to verify
  - `kid_used` — Which key signed it
  - `expected_result` — `pass` or `fail`
  - `expected_reason` — Why

To run against your implementation:

1. Load the issuer entry into your registry/manifest
2. For each attestation, call your verification function with the token and audience `https://api.example.com`
3. Assert the result matches `expected_result`

## Vector details

### kr-01: Routine key rotation — old key in grace period

The issuer has rotated from `key-2025-12` to `key-2026-03`. The old key was deprecated 30 days ago — well within the 90-day grace period.

**Key states:**
| kid | status | deprecated_at | revoked_at |
|-----|--------|--------------|------------|
| `key-2025-12` | `deprecated` | 30 days ago | — |
| `key-2026-03` | `active` | — | — |

**Expected behavior:**
- Attestation signed with `key-2025-12`: **PASS** — deprecated but within grace period
- Attestation signed with `key-2026-03`: **PASS** — active key

### kr-02: Deprecated key — grace period expired

The old key was deprecated 120 days ago, exceeding the 90-day grace period.

**Key states:**
| kid | status | deprecated_at | revoked_at |
|-----|--------|--------------|------------|
| `key-2025-06` | `deprecated` | 120 days ago | — |
| `key-2025-12` | `active` | — | — |

**Expected behavior:**
- Attestation signed with `key-2025-06`: **FAIL** — grace period expired

**Implementation note:** The grace period is calculated as `deprecated_at + 90 days`. If the current time exceeds this, the key MUST be treated as invalid for verification purposes, even though its status is `deprecated` (not `revoked`).

### kr-03: Revoked key — immediate rejection

The key was emergency-revoked due to suspected compromise. Per [04-key-rotation.md](../../04-key-rotation.md), revocation skips the deprecation phase entirely.

**Key states:**
| kid | status | deprecated_at | revoked_at |
|-----|--------|--------------|------------|
| `key-compromised` | `revoked` | — | 1 day ago |
| `key-2026-03` | `active` | — | — |

**Expected behavior:**
- Attestation signed with `key-compromised`: **FAIL** — revoked keys have no grace period

**Implementation note:** A key with `revoked_at` set MUST be rejected immediately regardless of any other field values. Revocation is permanent and not subject to the grace period logic.

### kr-04: Multiple active keys

The issuer maintains two active keys simultaneously. This is valid — the spec does not require exactly one active key.

**Key states:**
| kid | status | deprecated_at | revoked_at |
|-----|--------|--------------|------------|
| `key-primary` | `active` | — | — |
| `key-secondary` | `active` | — | — |

**Expected behavior:**
- Attestation signed with `key-primary`: **PASS**
- Attestation signed with `key-secondary`: **PASS**

### kr-05: Rollback — new key revoked, old key reactivated

The new key (`key-2026-03-bad`) was compromised shortly after rotation. It has been revoked. The old key (`key-2025-12-restored`) has been reactivated by clearing its `deprecated_at` field and resetting its status to `active`.

**Key states:**
| kid | status | deprecated_at | revoked_at |
|-----|--------|--------------|------------|
| `key-2025-12-restored` | `active` | — (cleared) | — |
| `key-2026-03-bad` | `revoked` | — | 7 days ago |

**Expected behavior:**
- Attestation signed with `key-2026-03-bad`: **FAIL** — revoked
- Attestation signed with `key-2025-12-restored`: **PASS** — reactivated

**Implementation note:** Rollback is a valid operational scenario. Implementations MUST NOT assume that key lifecycle is monotonically forward (active → deprecated → revoked). A key can return to `active` from `deprecated` if the successor key is compromised.

## Regenerating vectors

The vectors contain real Ed25519 keypairs and signed JWTs. To regenerate with fresh keys:

```bash
cd sdk/typescript
npm install
node ../../spec/test-vectors/key-rotation/generate-vectors.mjs > ../../spec/test-vectors/key-rotation/vectors.json
```

The generator script is at `spec/test-vectors/key-rotation/generate-vectors.mjs`.

## References

- [04-key-rotation.md](../../04-key-rotation.md) — Key rotation protocol
- [07-attestation-format.md](../../07-attestation-format.md) — JWT format specification
- [01-data-model.md](../../01-data-model.md) — Public key entry schema
