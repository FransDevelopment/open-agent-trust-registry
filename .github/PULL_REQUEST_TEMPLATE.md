## Issuer Registration

Thank you for contributing to the open agent internet!

### How Registration Works

Registration is **automated and permissionless**. To ensure the integrity of the Open Trust Registry, please ensure your PR meets the following acceptance criteria:

### Automated Verification Checklist (Tier 1)

- [ ] **Valid Ed25519 Key:** I have generated my keypair using `agent-trust keygen --issuer-id <MY_ID>`.
- [ ] **Proof-of-Key-Ownership:** I have included a signed proof in this PR (see below).
- [ ] **Domain Verification:** My website hosts `/.well-known/agent-trust.json` containing my `issuer_id` and public key fingerprint.

If all three checks pass, the CI pipeline will merge this PR automatically.

### Proof of Key Ownership

Include a file `proof.txt` in your PR containing:
```
I control the Ed25519 key registered for issuer_id: <YOUR_ISSUER_ID>
```
Signed with your private key. The CI pipeline will verify this signature against the public key in your `issuer_entry` JSON.

### Capability Verification (Tier 2 — Optional)

Your `capabilities` block (supervision model, audit logging, etc.) will initially be marked as `"capabilities_verified": false`. Community auditors may review and verify your claims in a separate PR.

**Your inclusion in the registry does not depend on this step.**

### What Happens Next

Once merged, your issuer entry will be included in the next signed `manifest.json` during the scheduled signing ceremony. See `GOVERNANCE.md` for details on the governance model.
