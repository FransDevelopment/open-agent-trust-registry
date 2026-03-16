# 07 - Expected Attestation Format

While the Open Agent Trust Registry defines *who* is trusted to attest, the attestations themselves are explicitly issued by the individual runtimes — not the central registry. 

However, the registry rigidly enforces the expected JWT format so disparate downstream digital services know exactly what structured claims to inherently verify.

## 1. Minimal Compact JWS Token

The expected state of an agent attestation is a compact JSON Web Signature (JWS).

**Header:**
```json
{
  "alg": "EdDSA",
  "kid": "acme-2026-03",
  "iss": "acme-agent-runtime",
  "typ": "agent-attestation+jwt"
}
```

**Payload:**
```json
{
  "sub": "agent-instance-uuid",
  "aud": "target-service-origin",
  "iat": 1742025600,
  "exp": 1742029200,
  "nonce": "service-provided-nonce",
  "scope": ["read:email", "send:email"],
  "constraints": {
    "max_cost_usd": 10.00,
    "allowed_actions": ["read", "send"],
    "time_bound": true
  },
  "user_pseudonym": "pairwise-pseudonymous-id-for-this-service",
  "runtime_version": "1.0.0"
}
```

### Claim Definitions

| Claim | Description |
|-------|-------------|
| `iss` | The `issuer_id` corresponding to the trusted runtime registered in the `manifest.json`. |
| `kid` | Key identifier corresponding to the actively rotated `public_key` registered to the issuer. |
| `sub` | Opaque agent instance identifier (not fundamentally user-identifying). |
| `aud` | Target service origin constraint. The attestation is *only valid* mathematically if presented to this service. Intelligently prevents mass-replay attacks across services. |
| `iat` / `exp` | Issued-at and expiry unix timestamps. |
| `nonce` | Optional downstream service-provided nonce mathematically bound deep into the signed payload. Prevents simple replay within the identical service session. |
| `scope` | Array of authorized semantic action scopes defining precisely what the attestation grants. |
| `constraints` | Highly structured nested object defining hard bounds (spending limits, specific action types, hard time bounds). |
| `user_pseudonym` | A pairwise pseudonymous identifier — fundamentally different for each integrated service, permanently preventing cross-service correlation or invasive tracking architectures. |
