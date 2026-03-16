# 08 — Security Model

This document defines what the Open Agent Trust Registry guarantees, what it explicitly does not guarantee, and the threat model under which it operates.

---

## 1. What the Registry Provides

### 1.1 Identity Verification
The registry provides cryptographic proof that an attestation was issued by a specific, registered runtime. Given a valid JWS token, a verifier can confirm:
- The issuer is a known, registered entity.
- The signing key is active and not revoked.
- The signature is mathematically valid.

### 1.2 Public Accountability
Every registered issuer is tied to:
- A verifiable domain (via `/.well-known/agent-trust.json`).
- A cryptographic public key on a permanent, auditable, Git-backed ledger.
- A timestamped registration record.

Registration creates an irrevocable accountability chain. The issuer cannot later deny their participation — their public key and domain binding are part of the signed registry history.

### 1.3 Rapid Revocation
Compromised or malicious issuers can be revoked through the governance process. The revocation list is updated on a 5-minute cycle, allowing services polling the list to reject compromised issuers within minutes.

### 1.4 Tamper Evidence
The registry manifest is cryptographically signed. Any modification to the manifest (adding, removing, or altering an issuer entry) invalidates the signature. Mirrors cannot serve tampered data without detection.

---

## 2. What the Registry Does NOT Provide

### 2.1 Authorization
The registry answers **"who is this?"** — not **"what are they allowed to do?"**

A registered issuer is not inherently authorized to perform any action on any service. Authorization decisions remain entirely with the consuming service. The registry provides the identity primitive; the service applies its own policies on top.

### 2.2 Behavioral Guarantees
Registration does not certify that an issuer will act honestly, securely, or in good faith. The `capabilities` block represents self-declared claims. Until community-audited (Tier 2), these claims are unverified.

### 2.3 Fraud Prevention
The registry does not prevent malicious actors from registering. It provides **accountability, not prevention**. The design philosophy is:

> A malicious actor who registers is in a *worse* position than one who does not, because they have voluntarily tied their operations to a verifiable, permanent identity.

---

## 3. Threat Model

| Threat | Impact | Mitigation |
|--------|--------|------------|
| **Compromised mirror** | Attacker serves a modified registry with a rogue issuer | All registry data is signed. Clients verify the signature before trusting any data. A compromised mirror cannot forge a valid signature. |
| **Compromised root key** | Attacker can sign arbitrary registry content | Threshold signing (3-of-5). Compromising a single key is insufficient. Keys held offline on secure hardware. |
| **Malicious issuer registration** | A bad actor registers and issues harmful attestations | Registration creates a permanent audit trail. Services apply their own trust policies. Revocation available within minutes via governance. |
| **Stale registry at service** | Service has an old copy missing a recent revocation | `expires_at` fields on both manifest and revocation list. Clients MUST reject expired data and fetch fresh copies. Revocation list has a 5-minute expiry. |
| **Attestation replay (same service)** | Attacker captures a valid attestation and replays it | Attestations include a service-provided nonce and short TTL. Replays fail the nonce or expiry check. |
| **Cross-service attestation replay** | Attacker uses an attestation issued for Service A at Service B | The `aud` claim binds the attestation to a specific service origin. Service B rejects attestations where `aud` does not match. |
| **Key compromise at issuer** | Attacker obtains an issuer's private key and forges attestations | Issuer submits an emergency revocation PR. Key is revoked (skipping deprecation). Revocation list updated within 5 minutes. |

---

## 4. Design Philosophy

The registry is intentionally a **thin identity layer**. It does not attempt to solve authorization, fraud detection, rate limiting, or behavioral monitoring. These are responsibilities of consuming services, not the trust infrastructure.

This separation follows the principle of **minimal authority**: the registry knows the least it needs to know to provide cryptographic identity verification, and nothing more.

Services are expected to layer their own policies on top. See [09-service-integration.md](09-service-integration.md) for guidance.
