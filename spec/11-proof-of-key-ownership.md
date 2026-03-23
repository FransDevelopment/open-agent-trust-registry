# 11 — Proof of Key Ownership

This document defines the canonical format for cryptographic proof-of-key-ownership used during issuer registration in the Open Agent Trust Registry. The proof demonstrates that the submitter controls the Ed25519 private key corresponding to the public key in their registration, without revealing the private key.

---

### 1. Overview

When a new issuer submits a registration Pull Request (see [spec 02 — Registration](02-registration.md)), the PR must include a cryptographic proof that the submitter controls the private key. This prevents an attacker from registering someone else's public key under a domain they control.

The proof is a **detached Ed25519 signature** over a versioned canonical message. It is:
- Human-readable in a GitHub PR diff
- Machine-verifiable by the CI pipeline
- Permanently stored in the registry as an audit trail

---

### 2. Canonical Message

The signed message is a UTF-8 string with the following structure:

```
oatr-proof-v1:{issuer_id}
```

Where `{issuer_id}` is the exact value from the `issuer_id` field in the registration JSON.

**Encoding rules:**
- UTF-8, no BOM (byte order mark)
- No trailing newline
- No padding or whitespace
- The signed bytes are exactly `Buffer.from('oatr-proof-v1:' + issuerId, 'utf8')` in Node.js, or the equivalent `b'oatr-proof-v1:' + issuer_id.encode('utf-8')` in Python

**Version prefix:** The `oatr-proof-v1:` prefix allows future versions to change the message format without invalidating existing proofs. Verifiers MUST check that the canonical message starts with a recognized version prefix before verifying the signature.

**issuer_id constraints:** The `issuer_id` MUST match the pattern `^[a-z0-9][a-z0-9-]*[a-z0-9]$` (lowercase alphanumeric and hyphens, no leading/trailing hyphens). This is enforced by both the CLI and the CI pipeline. The constraint prevents injection of control characters that could break proof parsing.

---

### 3. Proof File Format

The proof is stored as a structured text file with PEM-style delimiters:

```
-----BEGIN OATR KEY OWNERSHIP PROOF-----
Canonical-Message: oatr-proof-v1:{issuer_id}
Signature: {base64url_encoded_ed25519_signature}
-----END OATR KEY OWNERSHIP PROOF-----
```

| Field | Value |
|-------|-------|
| `Canonical-Message` | The exact UTF-8 string that was signed. Included for auditability — verifiers reconstruct the message independently and compare. |
| `Signature` | The Ed25519 signature over the canonical message bytes, encoded as base64url (RFC 4648 §5) without padding. This is consistent with the `ed25519:{sig}` format used in `manifest.json` and with JWT conventions. |

**File location:** `registry/proofs/{issuer_id}.proof`

**Parsing rules for verifiers:**
- Extract content between `-----BEGIN OATR KEY OWNERSHIP PROOF-----` and `-----END OATR KEY OWNERSHIP PROOF-----`
- Parse `Canonical-Message:` and `Signature:` lines using the pattern `/^(Canonical-Message|Signature):\s*(.+?)\s*$/m`
- Handle both `\n` and `\r\n` line endings
- Ignore blank lines within the delimiters
- Reject the proof if either field is missing

---

### 4. Generating a Proof

Use the CLI:

```bash
npx @open-agent-trust/cli prove \
  --issuer-id my-runtime \
  --private-key my-runtime.private.pem
```

This command:
1. Reads the Ed25519 private seed from the `.private.pem` file (base64url-encoded, 32 bytes)
2. Constructs the canonical message: `oatr-proof-v1:{issuer_id}`
3. Signs the UTF-8 bytes of the message with Ed25519
4. Writes the proof file to `registry/proofs/{issuer_id}.proof`

The private key is read from disk, used in memory for signing, and never written to the proof file.

---

### 5. Verification Protocol

The CI pipeline (`.github/workflows/verify-registration.yml`) verifies proofs as follows:

1. **Extract issuer_id** from the registration JSON filename (`registry/issuers/{issuer_id}.json`)
2. **Locate proof file** at `registry/proofs/{issuer_id}.proof`. If missing, reject.
3. **Parse proof file** — extract the `Signature` field (base64url-encoded)
4. **Reconstruct canonical message** — `oatr-proof-v1:{issuer_id}` encoded as UTF-8. Do NOT use the `Canonical-Message` field from the proof file for verification. Reconstruct it independently from the issuer_id in the registration JSON.
5. **Extract public key** from the registration JSON — use the `public_key` field (base64url-encoded, 32 bytes) from the first entry in `public_keys` with `status: "active"` and `algorithm: "Ed25519"`
6. **Verify signature** — `Ed25519.verify(signature_bytes, message_bytes, public_key_bytes)`. The signature is valid if and only if this returns true.
7. **Cross-check canonical message** — verify that the `Canonical-Message` field in the proof file matches the independently reconstructed message. This is a consistency check, not a security check (the signature binds the message cryptographically).

**Critical constraints:**
- The public key used for verification MUST come from the registration JSON within the same PR. Never fetch keys from external sources, the registry manifest, or any network endpoint.
- If the issuer has multiple active keys, verify the signature against each active key. Accept if any match.
- If no active Ed25519 key exists in the registration JSON, reject.

---

### 6. Security Analysis

#### 6.1 What the proof demonstrates

The proof demonstrates that at the time of PR submission, the submitter had access to the Ed25519 private key corresponding to the public key in their registration. Combined with domain verification (`/.well-known/agent-trust.json`), this establishes that:
- The submitter controls the claimed domain (domain verification)
- The submitter controls the claimed key (proof-of-key-ownership)
- The key is bound to the issuer identity (issuer_id in canonical message)

#### 6.2 Replay protection

The `issuer_id` is bound into the canonical message, preventing a proof generated for issuer A from being used to register issuer B. Since each `issuer_id` is unique in the registry, each proof is unique.

#### 6.3 No timestamp by design

The proof does not include a timestamp. This is intentional:
- If an attacker possesses the private key, they can generate a fresh proof with any timestamp — timestamps do not prevent key compromise scenarios
- The Git commit timestamp on the PR provides a sufficient temporal anchor for audit purposes
- Omitting timestamps simplifies the format and eliminates clock-skew edge cases

#### 6.4 Key rotation

When an issuer rotates their key, the old proof (signed with the old key) remains in `registry/proofs/`. This is correct:
- Proofs are point-in-time artifacts, not ongoing assertions
- The old proof was valid at registration time and the Git history timestamps it
- Key rotation PRs that add a new public key MUST include a new proof signed with the new key

#### 6.5 Private key protection

The proof file contains:
- The canonical message (public, deterministic from the issuer_id)
- The Ed25519 signature (public — this is the mathematical proof)

The private key is never serialized into the proof. An Ed25519 signature cannot be used to recover the private key — this is the fundamental hardness assumption of elliptic curve cryptography (the discrete logarithm problem over the Edwards curve).

#### 6.6 CI pipeline security

The verification workflow MUST enforce file-scope restrictions: auto-merge is only permitted when the PR exclusively modifies files in `registry/issuers/` and `registry/proofs/`. If the PR touches any other path (`.github/workflows/`, `cli/`, `spec/`, etc.), auto-merge MUST be blocked. This prevents an attacker from submitting a "registration" PR that also modifies the verification workflow to skip checks.

---

### 7. Reference

- **Ed25519**: [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) — Edwards-Curve Digital Signature Algorithm
- **base64url**: [RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5) — Base 64 Encoding with URL and Filename Safe Alphabet
- **Registration spec**: [spec 02 — Registration](02-registration.md)
- **Data model**: [spec 01 — Data Model](01-data-model.md) — issuer_id format constraints
- **Security model**: [spec 08 — Security Model](08-security-model.md) — threat model and mitigations
