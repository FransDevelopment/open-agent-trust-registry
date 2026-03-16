# 09 — Service Integration Guidance

This document provides non-prescriptive guidance for services consuming agent attestations verified against the Open Agent Trust Registry.

> **Note on language:** This document uses [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) terminology. "SHOULD" indicates a recommendation. "MAY" indicates an option. This document contains no "MUST" requirements — services retain full autonomy over their trust policies.

---

## 1. Layered Trust Architecture

The registry provides a single primitive: **identity verification** (is this attestation from a known, non-revoked issuer?). 

Services SHOULD layer additional trust decisions on top of this primitive rather than treating registry inclusion as a binary trust signal.

```
┌─────────────────────────────────────┐
│  Service-Specific Authorization     │  ← Your policies
├─────────────────────────────────────┤
│  Risk Tiering & Allowlists          │  ← Your risk tolerance
├─────────────────────────────────────┤
│  Registry Identity Verification     │  ← The open standard
└─────────────────────────────────────┘
```

---

## 2. Risk Tiering (Suggested, Not Required)

Services MAY assign risk tiers to registered issuers based on observable signals:

| Signal | What It Tells You | Example Policy |
|--------|------------------|----------------|
| `capabilities_verified` | Whether community auditors have validated the issuer's capability claims | "Only allow `verified: true` issuers for financial operations" |
| Registration age (`added_at`) | How long the issuer has been in the registry | "Require > 30 days of registration for high-value actions" |
| Key age (`issued_at`) | How long the specific signing key has been active | "Flag attestations from keys issued < 24 hours ago" |
| Historical behavior | Your own logs of past interactions with this issuer | "Blocklist issuers who have previously caused incidents" |

---

## 3. Allowlists and Blocklists

Services SHOULD maintain their own local allowlists and/or blocklists alongside the registry.

- **Allowlist approach:** "We only accept attestations from these specific issuers." The registry is used to verify the identity, but the service decides who is allowed.
- **Blocklist approach:** "We accept any registered issuer except these." The registry provides the universe; the service applies exclusions.
- **Open approach:** "We accept any registered, non-revoked issuer." Relies entirely on the registry plus the service's own authorization layer.

No approach is inherently better. The choice depends on the service's risk tolerance and domain.

---

## 4. Nonce Usage

Services MAY require attestation nonces for replay protection.

- For **high-value or state-changing operations** (payments, data modifications), services SHOULD issue a unique nonce per request and verify it in the attestation.
- For **read-only or low-risk operations**, services MAY skip nonce verification to reduce latency.

---

## 5. Scope and Constraint Enforcement

Attestations include `scope` and `constraints` fields. These are domain-agnostic — the registry does not define what valid scopes or constraints look like.

Services SHOULD:
- Define their own scope vocabulary and reject attestations with unrecognized scopes.
- Enforce constraint values according to their own domain logic.
- Treat the absence of a constraint as "no restriction granted" rather than "all restrictions lifted."

---

## 6. Example Integration Patterns

These examples are illustrative only. They represent possible approaches, not recommendations.

### Financial Service
```
Accept if:
  ✓ Issuer is registered and not revoked
  ✓ capabilities_verified == true
  ✓ immutable_audit == true
  ✓ Nonce matches
  ✓ Scope includes required financial permissions
  ✓ constraints.max_cost_usd within service limits
```

### Communication Service
```
Accept if:
  ✓ Issuer is registered and not revoked
  ✓ Registration age > 7 days
  ✓ Scope includes messaging permissions

Rate limit if:
  ⚠ capabilities_verified == false → limit to 10 messages/hour
```

### Public API
```
Accept if:
  ✓ Issuer is registered and not revoked
  ✓ Attestation not expired

No additional requirements.
```

---

## 7. Handling Unknown Fields

As the attestation format evolves, services SHOULD follow the **"ignore unknown"** principle: unknown fields in the attestation payload should be silently ignored, not rejected. This allows the standard to evolve without breaking existing integrations.

---

## 8. Offline Verification

Services SHOULD verify attestations locally using a cached copy of the registry (see [06-mirroring.md](06-mirroring.md)). Calling a central server per-request creates a single point of failure and adds unnecessary latency.

The target verification performance is **<1ms on commodity hardware** with no network calls.
