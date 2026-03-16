# Governance Charter: Open Agent Trust Registry

The Open Agent Trust Registry is public infrastructure. As such, it must be governed transparently, predictably, and with clear mechanisms to prevent capture by any single entity — including its founders.

This Charter defines the structural governance for the registry, codifying the rules for onboarding, maintaining, and revoking trust on the agent internet.

---

## 1. Core Principles

1. **Agnostic by Design:** The registry exists solely to provide cryptographic assurance of an agent runtime's identity. It categorically refuses to dictate specific domain payloads, authorization schemas, or payment models.
2. **Open Access:** Any runtime operator matching the objective technical bar is included automatically. There is no commercial tollbooth and no human gatekeeper for registration.
3. **No Founder's Veto:** Initial founding maintainers possess no permanent privileges. They can be removed by the same process as any other maintainer.
4. **Registration is Permissionless; Revocation is Governed:** Anyone who proves key ownership and domain control gets included. The only governed action is removal.

---

## 2. Registration Model: Three Tiers

### Tier 1: Automated Inclusion (No Human Gate)

If you can cryptographically prove the following, you are **automatically included** via CI pipeline. No human reviewer can block your registration.

1. **Valid Ed25519 Key** — machine-verifiable.
2. **Cryptographic Proof-of-Ownership** — a signed statement proving control of the key, machine-verifiable.
3. **Domain Verification** — your claimed website must host a `/.well-known/agent-trust.json` file containing your `issuer_id` and public key fingerprint. This is the same model used by Let's Encrypt, Keybase, and DNS-based domain verification. Machine-verifiable.

**If all three are satisfied, the CI pipeline merges the registration automatically.** No maintainer approval is required or solicited.

### Tier 2: Capability Verification (Community Review)

The `capabilities` block in each issuer entry contains claims about the runtime's behavior (supervision model, audit logging, immutable audit). These claims **cannot** be machine-verified.

Rather than making these claims a gate on registration:
- New issuers are included with `"capabilities_verified": false`.
- Community members and independent auditors can review the claims and submit PRs upgrading them to `"capabilities_verified": true`.
- Services can choose whether to accept issuers with unverified capabilities.

**Your inclusion in the registry never depends on human review of your capabilities.**

### Tier 3: Removal (The Only Governed Action)

Revoking an issuer is the only action that requires human consensus. Revocation requires:
- A public GitHub Issue documenting the justification.
- Approval from **at least 3-of-5 threshold key holders** during a signing ceremony.
- No single maintainer can unilaterally revoke any issuer.

Revocation reasons: `key_compromise`, `issuer_compromise`, `policy_violation`, `voluntary_withdrawal`, `governance_decision`.

---

## 3. Reviewer Pool & Maintainer Structure

### 3.1 Reviewer Make-Up
The registry is maintained by the **Reviewer Pool**. The pool is designed to consist of:
- The initial contributing engineering maintainers.
- 2-4 identified independent cross-industry operators (e.g., maintainers of other major agentic frameworks, cybersecurity researchers).

### 3.2 Reviewer Responsibilities
Reviewers participate in:
- **Tier 2 capability audits** (optional, community-driven).
- **Tier 3 revocation votes** (required for removal).
- **Spec and governance amendments** (standard PR review).

Reviewers do **not** approve or reject Tier 1 registrations. The CI pipeline handles those autonomously.

---

## 4. Distributed Root of Trust (Threshold Signing)

A single root signing key creates an unacceptable systemic vulnerability.

**Mandate:** By Month 6 of operation, the registry manifest `signature` infrastructure will transition to a **3-of-5 Threshold Signature scheme** (FROST over Ed25519).

### 4.1 Key Allocation
The 5 master keys will be distributed among:
- 1 Founding Maintainer
- 4 Independent Ecosystem Reviewers

### 4.2 Signing Ceremony
Every registry state change (addition or revocation) triggers a signing ceremony. See `docs/multi-sig-ceremony.md` for the full protocol.

---

## 5. Dispute Resolution & Maintainer Removal

### 5.1 Dispute Escalation
If an issuer believes they have been wrongfully revoked, they may open a public GitHub Issue tagged `Appeal`. The Reviewer Pool must collectively document the justification. If the justification is found insufficient by a 2/3 supermajority, the revocation is reversed.

### 5.2 Removing a Maintainer
Any Maintainer (including founding members) can be forcibly removed and replaced if they:
1. Cease active participation for >60 days.
2. Attempt to block or modify automated Tier 1 registrations.
3. Approve revocations maliciously or without documented justification.
4. Attempt to monetize or restrict the baseline registry infrastructure.

**Replacement Process:** A public GitHub Issue is opened. If a 2/3 supermajority of the remaining Reviewer Pool votes to remove the maintainer, their commit access is revoked and their threshold key shard is cycled out.

---

## 6. Why This Model

| Concern | How It's Addressed |
|---------|-------------------|
| "Can a maintainer block my registration?" | No. Tier 1 is fully automated. |
| "Can a maintainer revoke me unilaterally?" | No. Revocation requires 3-of-5 threshold. |
| "Can the founders capture the registry?" | No. Founders can be forcibly removed by 2/3 vote. |
| "What if I disagree with my revocation?" | Public appeal process with documented justification. |
| "Is registration free?" | Yes. Forever. (The Let's Encrypt model.) |
