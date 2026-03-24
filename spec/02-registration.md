# 02 - Registration Protocol

This protocol defines how a new runtime registers as a trusted issuer within the Open Agent Trust Registry. Registration is **automated and permissionless** — no human reviewer can block a legitimate registration.

## Registration Flow

**Step 1 — Prepare Your Keypair**
The runtime must generate a cryptographic keypair locally. We strongly recommend `Ed25519` for performance, though `ECDSA P-256` is also accepted.

Use the CLI tool to generate a compliant key:
```bash
$ npx @open-agent-trust/cli keygen --issuer-id my-runtime
```

**Step 2 — Prepare the Issuer Entry**
Use the CLI to scaffold a compliant `issuer_entry` JSON file conforming to the [Data Model Spec](01-data-model.md):
```bash
$ npx @open-agent-trust/cli register --issuer-id my-runtime --display-name "My Runtime" \
    --website https://my-runtime.com --contact security@my-runtime.com --public-key <KEY>
```

**Step 3 — Domain Verification**
Prove you control the domain you declared. The CI pipeline checks two locations in order:

**Option A (recommended):** If your domain hosts an [`agent.json`](https://github.com/FransDevelopment/agent-json) manifest (v1.4+), add `oatr_issuer_id` to the identity block:
```json
{
  "identity": {
    "did": "did:web:my-runtime.com",
    "public_key": "<PUBLIC_KEY>",
    "oatr_issuer_id": "my-runtime"
  }
}
```

**Option B:** Host a standalone `/.well-known/agent-trust.json` file containing your `issuer_id` and public key fingerprint.

Both are verified automatically by the CI pipeline. The CI checks `agent.json` first, then falls back to `agent-trust.json`. This is the same domain ownership model used by Let's Encrypt.

**Step 4 — Generate Proof of Key Ownership**
Generate a cryptographic proof that you control the private key corresponding to the public key in your registration. See [spec 11 — Proof of Key Ownership](11-proof-of-key-ownership.md) for the full format specification.

```bash
$ npx @open-agent-trust/cli prove --issuer-id my-runtime --private-key my-runtime.private.pem
```

This creates `registry/proofs/my-runtime.proof` — a detached Ed25519 signature over a versioned canonical message. The private key is used for signing but never appears in the proof file.

**Step 5 — Submit a Pull Request**
The runtime opens a pull request against the registry repository. The PR **must** include exactly two files:
- `registry/issuers/{issuer_id}.json` — the issuer entry from Step 2
- `registry/proofs/{issuer_id}.proof` — the proof of key ownership from Step 4

**Step 6 — Automated Verification (Tier 1)**
The CI pipeline automatically verifies:
1. **Valid Ed25519 key** — machine-verifiable.
2. **Proof-of-key-ownership signature** — machine-verifiable.
3. **Domain verification** — `agent.json` with `identity.oatr_issuer_id` or `/.well-known/agent-trust.json` resolves and matches.

If all three checks pass, the PR is **automatically merged**. No human approval is required or solicited. See `GOVERNANCE.md` for the full tiered registration model.

**Step 7 — Capability Review (Tier 2 — Optional)**
New issuers are included with `capabilities_verified: false`. Community auditors may independently review and verify capability claims in a separate PR. Inclusion in the registry never depends on this step.

**Step 8 — Resign & Distribute**
Once merged, the `registry/manifest.json` is recompiled and cryptographically signed during the next scheduled signing ceremony. Mirrors will pick up the new verified version within their standard synchronization interval.

**Step 9 — Announce**
New issuers are automatically appended to the `CHANGELOG.md` and officially announced via standard repository release mechanics.
