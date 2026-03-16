# Multi-Signature Ceremony (Draft Specification)

Per the **Phase 5 Governance Expansion Mandate**, the Open Agent Trust Registry transitions to a **3-of-5 Threshold Signature** scheme by Month 6, distributing the root of trust among the independent Reviewer Pool.

This document outlines the hypothetical ceremony operators will use to sign the `manifest.json`.

---

## 1. Technical Primitives
Instead of uploading a single `Ed25519` private key to a server (a central point of failure), the Registry will utilize **FROST (Flexible Round-Optimized Schnorr Threshold)** signatures over the `Ed25519` curve.

This allows 5 distinct Reviewers to hold mathematically secure "Shards" of a master private key.

## 2. The Ceremony Flow

Whenever a new Issuer PR is approved and merged into `main`, the `manifest.json` becomes structurally out of date (its hash no longer perfectly matches the underlying directory state).

**A Signing Ceremony is declared representing a "Registry Epoch Update":**

1. A GitHub Action automatically compiles the new canonical `manifest.json` payload (sans signature).
2. The Action publishes the `SHA-256` hash of this payload to the PR thread.
3. Reviewers independently run the specialized `agent-trust sign-shard <hash>` CLI tool locally on their secure hardware.
4. Each Reviewer pastes their generated "Signature Shard" back into the PR thread as a comment.
5. Once 3 valid Shards are mathematically aggregated by the CI pipeline, the singular valid `Ed25519` signature is generated and appended to the `manifest.json`.
6. The updated Master Registry is pushed to production mirrors instantly.

---

## 3. Why this Matters
With a 3-of-5 threshold:
- No single Reviewer (not even the creator) can unilaterally add or revoke an Issuer.
- If a Reviewer is compromised or goes offline, the remaining 4 can still safely produce the 3 required signatures, maintaining uptime.
- If a Reviewer needs to be cycled out per the *Governance Charter*, the FROST protocol allows the remaining participants to mathematically generate a new Epoch Keypair without disrupting the base public key services rely on.
