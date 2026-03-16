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
Host a `/.well-known/agent-trust.json` file at your declared website containing your `issuer_id` and public key fingerprint. This is verified automatically by the CI pipeline — identical to how Let's Encrypt verifies domain ownership.

**Step 4 — Submit a Pull Request**
The runtime opens a pull request against the registry repository, adding their entry to `registry/issuers/{issuer_id}.json`.

The PR **must** include:
- The `issuer_entry` JSON content.
- A cryptographic Proof-of-Key-Ownership: a signed statement (e.g., "I control this key and am registering it for {issuer_id}") signed with the private key corresponding to the submitted public key.

**Step 5 — Automated Verification (Tier 1)**
The CI pipeline automatically verifies:
1. **Valid Ed25519 key** — machine-verifiable.
2. **Proof-of-key-ownership signature** — machine-verifiable.
3. **Domain verification** — `/.well-known/agent-trust.json` resolves and matches.

If all three checks pass, the PR is **automatically merged**. No human approval is required or solicited. See `GOVERNANCE.md` for the full tiered registration model.

**Step 6 — Capability Review (Tier 2 — Optional)**
New issuers are included with `capabilities_verified: false`. Community auditors may independently review and verify capability claims in a separate PR. Inclusion in the registry never depends on this step.

**Step 7 — Resign & Distribute**
Once merged, the `registry/manifest.json` is recompiled and cryptographically signed during the next scheduled signing ceremony. Mirrors will pick up the new verified version within their standard synchronization interval.

**Step 8 — Announce**
New issuers are automatically appended to the `CHANGELOG.md` and officially announced via standard repository release mechanics.
