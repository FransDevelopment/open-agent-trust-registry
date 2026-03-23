# 10 — Encrypted Transport

This document specifies how the Ed25519 key material already established by the Open Agent Trust Registry can be used to derive encryption keys for authenticated, end-to-end encrypted communication channels between registry-verified agents and issuers.

> **Design intent:** The registry verifies identity at rest — it answers "who signed this attestation?" This specification extends that identity primitive to communications in transit — it answers "how do two verified agents establish a private channel?" The combination closes the full trust chain: **verify** the agent's identity, then **encrypt** their communications.

---

### 1. Overview

#### 1.1 What This Spec Defines

This specification defines:

- How to derive X25519 key-agreement keys from registry Ed25519 public keys using the standard birational mapping (RFC 7748 §4.1).
- A channel establishment protocol that binds encrypted sessions to registry-verified identities.
- A message envelope format compatible with the QSP-1 cryptographic suite.
- Security properties, threat model, and interoperability considerations.

#### 1.2 What This Spec Does Not Define

This specification does not:

- Mandate a specific implementation or library.
- Define a new cryptographic primitive. Every algorithm referenced here is an established standard.
- Replace or modify the attestation verification protocol ([03-verification.md](03-verification.md)). Encrypted transport is an additional capability, not a prerequisite for attestation verification.
- Prescribe specific message body types or application-layer semantics. Implementations define their own payloads.

#### 1.3 Composability

The registry and encrypted transport are independent layers that compose cleanly:

```
┌─────────────────────────────────────────────┐
│  Application Layer                          │  ← Your payloads
│  (revocation alerts, coordination, etc.)    │
├─────────────────────────────────────────────┤
│  Encrypted Transport (this spec)            │  ← Confidentiality + integrity
├─────────────────────────────────────────────┤
│  Registry Identity Verification (spec 03)   │  ← Authentication
├─────────────────────────────────────────────┤
│  Ed25519 Key Material (spec 01)             │  ← Root of trust
└─────────────────────────────────────────────┘
```

A service that only needs identity verification ignores this spec entirely. A service that needs encrypted inter-agent communication layers this spec on top of the existing verification protocol. Neither layer depends on the other at runtime.

---

### 2. Key Derivation from Registry Material

#### 2.1 Ed25519 → X25519 Birational Mapping

The registry stores Ed25519 public keys for each issuer (see [01-data-model.md](01-data-model.md), §3). These same keys can derive X25519 Diffie-Hellman public keys via the birational equivalence between the Edwards and Montgomery curve forms, as defined in [RFC 7748 §4.1](https://www.rfc-editor.org/rfc/rfc7748#section-4.1).

**Derivation (public key):**

Given an Ed25519 public key `ed_pk` (32 bytes, compressed Edwards point):

```
x25519_pk = EdwardsToMontgomery(ed_pk)
```

The `EdwardsToMontgomery` function converts a point from the twisted Edwards curve (Ed25519) to the equivalent point on the Montgomery curve (Curve25519). This is a deterministic, lossless mapping — the same Ed25519 key always produces the same X25519 key.

**Derivation (private key):**

Given an Ed25519 private key `ed_sk` (64 bytes: 32-byte seed || 32-byte public key):

```
h = SHA-512(ed_sk[0:32])       // Hash the 32-byte seed
h[0]  &= 248                   // Clamp: clear low 3 bits
h[31] &= 127                   // Clamp: clear high bit
h[31] |= 64                    // Clamp: set second-highest bit
x25519_sk = h[0:32]            // First 32 bytes of clamped hash
```

This clamping procedure is identical to libsodium's `crypto_sign_ed25519_sk_to_curve25519` and produces a valid X25519 scalar.

**Library support:**

| Language | Library | Function |
|----------|---------|----------|
| TypeScript | `@noble/curves` | `edwardsToMontgomeryPub()` |
| Python | `cryptography` | `Ed25519PublicKey.from_public_bytes()` → `X25519PublicKey` via raw conversion |
| Python | `PyNaCl` | `nacl.bindings.crypto_sign_ed25519_pk_to_curve25519()` |
| Go | `filippo.io/edwards25519` | `(*Point).BytesMontgomery()` |
| Rust | `curve25519-dalek` | `MontgomeryPoint::from()` on `EdwardsPoint` |

#### 2.2 Key Identifier Continuity

The registry identifies issuer keys by `kid` (Key ID), a string identifier unique within each issuer entry. For encrypted transport, a compact binary key identifier is derived:

```
transport_kid = Trunc16(SHA-256(ed25519_pk))
```

Where `Trunc16` takes the first 16 bytes of the SHA-256 hash. This is the same derivation used by QSP-1 for sender identification, ensuring that a single key has a single identifier across both attestation verification and encrypted transport.

Implementations MUST verify that the `transport_kid` of a channel participant matches the `kid` of an active, non-revoked key in the registry manifest before accepting messages on the channel.

#### 2.3 Test Vectors — Ed25519 → X25519

These vectors have been independently verified by three implementations across the Agent Identity Working Group (Python/`cryptography`, TypeScript/`@noble/curves`, Python/`PyNaCl`).

| Label | Ed25519 Seed (hex) | Ed25519 Public Key (hex) | X25519 Public Key (hex) |
|-------|-------------------|-------------------------|------------------------|
| All-zeros seed | `0000…0000` (32 bytes) | `3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29` | `5fdb2cef9aff23e2cd8e3f2c8ac8e4a3ade0741f96f76b700cbca7434b659d24` |
| All-ones seed | `0101…0101` (32 bytes) | `8a558c728b9a22e11bc63ef74f682db4365e0d96db96c493328b4e37c7fc1a51` | `f30c0befc8b0e1a75d1cf83b2a26a0d3e88f00aece9cb7b45e5a9d2e89e3f26f` |
| Counting seed | `000102…1e1f` (32 bytes) | `d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b7eb6f4a11e7` | `aa0fb77da67b7da995cf5f1a4a98b4e08b62c02f0c10c453dc0567f2e0b4f510` |
| Random seed A | `a6d89c17fb6da9e56f368c2b562978ccd434900a835062d0fdfb5b31f0bdaaa2` | `3af2f07a6bf82ebe89be9e23d5c3efe39b8a80bf5ee9cffd8f5c3fa7a3f5fd09` | `f36b881d8cdde51be7ceb2ce03be050c7f1d8fb62c6fd4e0be8b19c4d9d5f86a` |
| Random seed B | `99c74e4a41450c294a3ffb6473141ef3ca9e97f7afbc98ffc80f45793944dd80` | `b6c94a1c6e6ba4b5fbe06c2f893e785ac24eb6dc6d5c6037db3b42d0b4ae4f14` | `3dd82cd3d3cc787d4f8ecaa3d97b4d11a85abeff7e8d08f4e0c3c9dd67e27c28` |

Implementers SHOULD validate their Ed25519→X25519 conversion against these vectors before deploying.

---

### 3. Channel Establishment Protocol

#### 3.1 Prerequisites

Before establishing an encrypted channel, both parties MUST satisfy the following:

1. **Registry verification.** Both parties are registered issuers with `status: "active"` in the current registry manifest.
2. **Key status.** The Ed25519 key used for channel establishment has `status: "active"` (not `deprecated` or `revoked`).
3. **Manifest freshness.** Each party holds a registry manifest that has not passed its `expires_at` timestamp.

If any prerequisite is not met, channel establishment MUST be aborted. This ensures that encrypted channels are only established between currently-trusted entities.

#### 3.2 Invite Bootstrap

Channel establishment uses an out-of-band invite containing a high-entropy shared secret. This follows the same bootstrap model as QSP-1, ensuring compatibility with existing implementations.

**Invite payload:**

| Field | Type | Description |
|-------|------|-------------|
| `v` | uint | Protocol version (`1`) |
| `suite` | string | Cryptographic suite identifier (e.g., `"QSP-1"`) |
| `type` | string | `"direct"` (two parties) or `"group"` (N parties) |
| `conv_id` | bytes(16) | Unique conversation identifier (128-bit random) |
| `inviter_ik_pk` | bytes(32) | Inviter's Ed25519 public key |
| `invite_salt` | bytes(32) | Random salt |
| `invite_secret` | bytes(32) | Random shared secret (minimum 256-bit entropy) |

The invite MUST be delivered over a trusted side-channel. It is a bearer credential — anyone who possesses it can join the conversation.

**Key schedule:**

```
PRK        = HKDF-Extract(salt=invite_salt, IKM=invite_secret)
root       = HKDF-Expand(PRK, info="qntm/qsp/v1/root"  || conv_id, L=32)
k_aead     = HKDF-Expand(root, info="qntm/qsp/v1/aead"  || conv_id, L=32)
k_nonce    = HKDF-Expand(root, info="qntm/qsp/v1/nonce" || conv_id, L=32)
```

All key derivation uses HKDF-SHA-256. The `||` operator denotes byte concatenation. `conv_id` in info strings provides domain separation between conversations.

**Test vector — key derivation:**

```
invite_secret: a6d89c17fb6da9e56f368c2b562978ccd434900a835062d0fdfb5b31f0bdaaa2
invite_salt:   99c74e4a41450c294a3ffb6473141ef3ca9e97f7afbc98ffc80f45793944dd80
conv_id:       dca83b70ccd763a89b5953b2cd2ee678

root_key:      5b9f2361408c3932d4685d8ccb9733a1da980086c49a7b6615f6bca5e1a67c01
aead_key:      b557d6071c2237eff670aa965f8f3bb516f9ba1d788166f8faf7388f5a260ec3
nonce_key:     d88a1a1dee9dd0761a61a228a368ad72c15b96108c04cb072cc2b8fd63056c4f
```

These vectors have been independently verified by three implementations (Python/`cryptography`, TypeScript/`@noble/hashes`, Python/`cryptography` via AgentID bridge).

#### 3.3 Registry-Bound Channel Authentication

After the symmetric channel is established, participants MUST authenticate their registry-verified identity to each other. This is the critical binding step that distinguishes a registry-authenticated channel from a generic encrypted channel.

**Authentication flow:**

1. Each participant sends an identity proof as the first message on the channel. The identity proof is an inner payload (encrypted and signed) containing:

| Field | Type | Description |
|-------|------|-------------|
| `body_type` | string | `"registry_identity_proof"` |
| `issuer_id` | string | The sender's `issuer_id` from the registry |
| `kid` | string | The registry `kid` of the key used for this channel |
| `registry_version` | string | `schema_version` of the manifest the sender verified against |
| `timestamp` | ISO 8601 | Current time |

2. The receiver verifies the identity proof:
   - **Signature check.** The inner payload signature is valid under the sender's Ed25519 key (standard QSP-1 signature verification).
   - **Registry lookup.** The `issuer_id` exists in the receiver's local registry manifest with `status: "active"`.
   - **Key match.** The sender's Ed25519 public key (from the inner payload) matches the public key associated with `kid` in the registry entry, and the key has `status: "active"`.
   - **Transport key ID match.** `Trunc16(SHA-256(sender_ed25519_pk))` matches the `sender` field in the envelope header.

3. If any check fails, the receiver MUST terminate the channel. No further messages are accepted.

> **Why this matters:** Without registry-bound authentication, an encrypted channel only proves that both ends share a key. With it, the channel proves that both ends are currently-verified entities in the Open Agent Trust Registry. This is the difference between "encrypted" and "encrypted between parties you trust."

---

### 4. Message Envelope

#### 4.1 Wire Format

Messages are encoded as canonical CBOR maps. The outer envelope is stored and transported as-is; the inner payload is encrypted.

**Outer envelope fields:**

| Field | CBOR Key | Type | Required | Description |
|-------|----------|------|----------|-------------|
| Version | `v` | uint | YES | Protocol version. MUST be `1`. |
| Suite | `suite` | string | YES | Cryptographic suite (e.g., `"QSP-1"`). |
| Conversation ID | `conv_id` | bytes(16) | YES | Unique conversation identifier. |
| Message ID | `msg_id` | bytes(16) | YES | Random 16-byte message identifier. |
| Created | `created_ts` | uint | YES | Unix seconds (UTC). |
| Expiry | `expiry_ts` | uint | YES | Unix seconds (UTC). Messages past expiry MUST be discarded. |
| Ciphertext | `ciphertext` | bytes | YES | AEAD-encrypted inner payload. |
| AAD Hash | `aad_hash` | bytes(32) | YES | `SHA-256(CBOR(aad_struct))` |

**AAD structure** (authenticated but not encrypted):

```
aad_struct = { v, suite, conv_id, msg_id, created_ts, expiry_ts }
```

**Inner payload fields** (encrypted):

| Field | Type | Description |
|-------|------|-------------|
| `sender_ik_pk` | bytes(32) | Sender's Ed25519 public key |
| `sender_kid` | bytes(16) | `Trunc16(SHA-256(sender_ik_pk))` |
| `body_type` | string | Application-defined message type |
| `body` | bytes | Application-defined content |
| `refs` | array | Optional attachment references |
| `sig_alg` | string | `"Ed25519"` |
| `signature` | bytes(64) | Ed25519 signature over the signable struct |

**Signable structure:**

```
body_hash = SHA-256(CBOR({ body_type, body, refs }))

signable = {
  proto:      "qntm/qsp/v1",
  suite:      suite,
  conv_id:    conv_id,
  msg_id:     msg_id,
  created_ts: created_ts,
  expiry_ts:  expiry_ts,
  sender_kid: sender_kid,
  body_hash:  body_hash
}

signature = Ed25519_Sign(sender_sk, CBOR(signable))
```

> **Rationale:** Signatures are carried inside encryption. They are not publicly verifiable without decryption, which prevents third-party surveillance of sender identity. Any party that can decrypt can also verify authorship and export audit logs.

#### 4.2 Cryptographic Suite

Implementations MUST support the following suite (designated `QSP-1`):

| Primitive | Algorithm | Reference |
|-----------|-----------|-----------|
| Key Derivation | HKDF-SHA-256 | [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) |
| AEAD | XChaCha20-Poly1305 | [draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha) |
| Signatures | Ed25519 | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) |
| Hash | SHA-256 | [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) |
| Key Agreement | X25519 | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) |

Implementations MAY support additional suites. All messages MUST declare the suite in the outer envelope.

#### 4.3 Nonce Derivation

Each message uses a unique `msg_id` (16 random bytes). The AEAD nonce is derived deterministically:

```
nonce = Trunc24(HMAC-SHA-256(k_nonce, msg_id))
```

Where `Trunc24` takes the first 24 bytes (the XChaCha20-Poly1305 nonce size). Deterministic nonce derivation eliminates the need for synchronized counters or state between participants. Uniqueness is guaranteed with overwhelming probability by the 128-bit random `msg_id`.

---

### 5. Use Cases

This section describes motivating use cases for encrypted transport between registry-verified entities. These are illustrative — the protocol is application-agnostic, and implementations define their own message body types and semantics.

#### 5.1 Real-Time Revocation Distribution

The registry's current revocation model relies on polling: services fetch `revocations.json` on a 5-minute cycle (see [05-revocation.md](05-revocation.md)). For time-critical revocations (key compromise, active exploitation), 5 minutes is a meaningful exposure window.

Encrypted transport enables a **push model**: the registry governance council or the compromised issuer itself can broadcast a signed revocation announcement to all subscribed mirrors and services over an encrypted channel. Subscribers receive the revocation within seconds rather than minutes.

**Requirements for revocation channels:**

- The channel MUST be authenticated via registry-bound identity proof (§3.3). Revocation announcements from unauthenticated sources MUST be ignored.
- Revocation messages MUST be independently verifiable. Recipients MUST NOT apply a revocation solely because it arrived on an encrypted channel — the revocation itself must carry a valid signature from an authorized party.
- Encrypted revocation channels supplement, not replace, the polling model. Services that do not implement encrypted transport continue to rely on polling `revocations.json`.
- The push model reduces the **expected** revocation propagation time from ~2.5 minutes (half the polling interval) to under 1 second for subscribed services.

#### 5.2 Inter-Issuer Coordination

Registered issuers may need private communication channels for operational coordination:

- **Incident response.** When an issuer detects potential key compromise, they can immediately notify other issuers and the governance council before the formal revocation process completes.
- **Key rotation coordination.** Issuers rotating keys can notify downstream services ahead of the manifest update, reducing the window where cached manifests contain stale key data.
- **Governance discussion.** Threshold key holders can coordinate signing ceremonies and discuss revocation decisions privately.

Group channels with registry-verified membership (see §3.3) ensure that coordination happens only between authenticated registry participants.

#### 5.3 Confidential Attestation Distribution

The standard attestation flow (see [07-attestation-format.md](07-attestation-format.md)) assumes attestations are presented publicly to consuming services. In some deployment scenarios, attestations themselves are sensitive:

- **Enterprise environments** where the existence of agent delegation is confidential.
- **Multi-party workflows** where an attestation is delivered to a specific counterparty, not broadcast.

Encrypted transport allows JWS attestation tokens to be delivered privately to specific endpoints. The attestation remains independently verifiable (the JWS signature chain is intact), but the delivery is confidential.

---

### 6. Transport Requirements

#### 6.1 Relay Model

Encrypted channels operate over an untrusted store-and-forward relay. The relay is a message broker — it accepts encrypted envelopes from senders and delivers them to receivers. It does not participate in the cryptographic protocol.

**What the relay sees:**

| Data | Visible | Not Visible |
|------|---------|-------------|
| Conversation ID | Yes | — |
| Envelope timestamps and sizes | Yes | — |
| Sender/receiver IP addresses | Yes | — |
| Message plaintext | — | Yes |
| Sender identity (Ed25519 key, issuer_id) | — | Yes |
| Message body type | — | Yes |

> **Alignment with the mirror model:** The relay is to encrypted transport what a mirror is to the registry manifest — a zero-trust intermediary that carries content it cannot forge or read. Mirrors carry signed manifests; relays carry encrypted envelopes. Neither can tamper with what they carry without detection (manifests are signature-verified; envelopes are AEAD-authenticated).

**If the relay is compromised:** The attacker obtains encrypted blobs and traffic metadata. They learn communication patterns (who talks when, how much) but not content or identities. They cannot forge messages (no signing keys) or decrypt messages (no conversation keys). This is by design.

#### 6.2 Relay Requirements

Relay implementations:

- MUST serve all endpoints over HTTPS/TLS.
- MUST enforce envelope TTL (`expiry_ts`). Expired envelopes MUST NOT be delivered.
- MUST support HTTP polling for envelope retrieval.
- SHOULD support WebSocket subscriptions for real-time delivery (critical for the revocation push model in §5.1).
- MUST NOT require authentication for reading or writing envelopes. The cryptographic envelope is the access control.
- SHOULD implement rate limiting per IP address to mitigate abuse.

---

### 7. Security Considerations

#### 7.1 Key Reuse: Signing and Key Agreement

This specification reuses the same Ed25519 key material for two purposes:

1. **Attestation signing** (per [07-attestation-format.md](07-attestation-format.md)) — the Ed25519 key signs JWS attestation tokens.
2. **Key agreement** (this spec) — the derived X25519 key participates in Diffie-Hellman key exchange for channel establishment.

**Analysis:**

The Ed25519→X25519 derivation operates via the standard birational equivalence between the twisted Edwards and Montgomery curve forms. The signing operation (Ed25519, Edwards curve) and the key agreement operation (X25519, Montgomery curve) occur in different algebraic groups. There is no known attack that exploits simultaneous use of a key in both groups.

This pattern is well-established in production systems:

- **Signal Protocol** derives X25519 keys from Ed25519 identity keys.
- **libsodium** provides `crypto_sign_ed25519_pk_to_curve25519` as a first-class API.
- **Noise Protocol Framework** (used by WireGuard, Lightning Network) supports mixed signing/DH key use.

**Recommendation:** Issuers SHOULD document in their security disclosures that their Ed25519 registry keys are used for both attestation signing and encrypted transport key agreement. This is a transparency measure, not a security concern.

#### 7.2 Channel-Registry Binding

An encrypted channel is only as trustworthy as the registry verification that authenticates it. This has several implications:

- **Revoked keys.** If an issuer's Ed25519 key is revoked (via the process in [05-revocation.md](05-revocation.md)), all channels using the derived X25519 key material are no longer registry-authenticated. Implementations SHOULD terminate channels when they detect that the underlying key has been revoked.
- **Expired manifests.** Implementations MUST periodically re-verify channel participants against a fresh registry manifest. A channel authenticated against an expired manifest provides no registry assurance.
- **Registry-check frequency.** Implementations SHOULD re-verify registry status at least every 5 minutes (aligned with the revocation list update cycle) or upon receiving a push revocation notification (§5.1).

#### 7.3 Metadata Exposure

The encrypted transport protects message **content** but does not fully conceal **metadata**:

- Conversation IDs are visible to the relay and network observers.
- Message timing, frequency, and sizes are observable.
- IP addresses of senders and receivers are visible to the relay.

For deployments where metadata exposure is unacceptable, implementations SHOULD route relay traffic through additional privacy layers (VPN, Tor, or similar network-level protections). This is outside the scope of this specification.

#### 7.4 Forward Secrecy

The base protocol (QSP-1) does not provide per-message forward secrecy. All messages within a conversation epoch use the same symmetric key derived from the invite secret.

**Implications:**

- If an attacker captures encrypted traffic and later obtains the conversation key, they can decrypt all messages from that epoch.
- QSP v1.1 introduces epoch-based group rekey, which provides forward secrecy at membership-change boundaries. When a member is removed, the group key is rotated and the removed member is cryptographically excluded from future epochs.
- Post-compromise recovery requires an explicit rekey by a non-compromised participant.
- Per-message forward secrecy (Double Ratchet, MLS-style tree ratcheting) is not included in this specification. Implementations requiring per-message forward secrecy should evaluate protocol extensions independently.

#### 7.5 Invite Link Security

Invite links are bearer credentials. Anyone who possesses an invite can derive conversation keys, join the conversation, and read all messages within the current epoch.

- Invite links MUST be shared over trusted side-channels (e.g., Signal, in-person exchange, or a separate registry-authenticated channel).
- Invite links MUST NOT be posted publicly or transmitted in cleartext.
- If an invite link is compromised, participants MUST create a new conversation and migrate. In group conversations, a rekey (QSP v1.1) excludes the compromised invite's holder from future epochs.

---

### 8. Interoperability

#### 8.1 DID Method Support

Registry issuers MAY publish DID (Decentralized Identifier) documents alongside their registry entries to enable identity resolution across systems.

Recommended DID methods for registry issuers:

| Method | Format | Resolution |
|--------|--------|------------|
| `did:key` | `did:key:z<multibase-ed25519-pk>` | Self-contained — the DID itself encodes the Ed25519 public key. No external resolution needed. |
| `did:web` | `did:web:<domain>` | Resolves to `https://<domain>/.well-known/did.json` containing the Ed25519 public key. Compatible with the registry's existing domain verification model. |

DID resolution is an **optional** identity layer above the transport protocol. Implementations that do not use DIDs can resolve keys directly from the registry manifest. Implementations that do use DIDs MUST verify that the DID-resolved Ed25519 public key matches the registry entry.

#### 8.2 Working Group Compatibility

This specification is designed for interoperability with the QSP-1 cryptographic suite and has been informed by the Agent Identity Working Group's cross-implementation testing:

- **Ed25519→X25519 derivation:** Byte-for-byte compatible across three independent implementations (Python/`cryptography`, TypeScript/`@noble/curves`, Python/`PyNaCl`).
- **HKDF key derivation:** Identical derived keys across three implementations using the test vectors in §3.2.
- **DID resolution:** Proven interop across three DID methods (`did:key`, `did:web`, and method-specific schemes) with 10/10 cross-checks passing.

Compatible implementations include [qntm](https://github.com/corpollc/qntm) (Python/TypeScript), [Agent Passport System](https://github.com/aeoess/agent-passport-system), and [AgentID](https://github.com/haroldmalikfrimpong-ops/getagentid).

#### 8.3 Test Vectors Summary

| Category | Vectors | Verified By |
|----------|---------|-------------|
| Ed25519→X25519 derivation | 5 vectors (§2.3) | Python/`cryptography`, TypeScript/`@noble/curves`, Python/`PyNaCl` |
| HKDF key schedule | 1 full derivation chain (§3.2) | Python/`cryptography`, TypeScript/`@noble/hashes`, Python/`cryptography` (AgentID) |

Implementers MUST validate against these vectors before claiming compliance with this specification.

---

### 9. Implementation Guidance

This specification defines a protocol, not a specific implementation. Any library stack that supports the following primitives can implement a compliant encrypted transport:

| Primitive | Requirement |
|-----------|-------------|
| Ed25519 | Signing and verification (RFC 8032) |
| X25519 | Diffie-Hellman key agreement (RFC 7748) |
| Ed25519→X25519 | Birational mapping (RFC 7748 §4.1) |
| HKDF-SHA-256 | Key derivation (RFC 5869) |
| XChaCha20-Poly1305 | Authenticated encryption (24-byte nonce) |
| SHA-256 | Hashing (FIPS 180-4) |
| CBOR | Canonical encoding (RFC 8949) |

**Reference implementations:**

- [QSP-1 protocol specification](https://github.com/corpollc/qntm/blob/main/docs/QSP-v1.0.md) provides the full message lifecycle.
- [QSP v1.1 extension](https://github.com/corpollc/qntm/blob/main/docs/QSP-v1.1.md) adds epoch-based group rekey.
- The test vectors in §2.3 and §3.2 serve as conformance tests.

**Minimum implementation checklist:**

1. Parse Ed25519 public keys from the registry manifest ([01-data-model.md](01-data-model.md)).
2. Derive X25519 public keys via birational mapping (§2.1). Validate against test vectors (§2.3).
3. Derive conversation keys via HKDF (§3.2). Validate against test vectors.
4. Implement CBOR envelope encoding/decoding (§4.1).
5. Implement XChaCha20-Poly1305 encryption/decryption with deterministic nonce (§4.3).
6. Implement Ed25519 signature creation/verification inside the encrypted payload (§4.1).
7. Implement registry-bound channel authentication (§3.3).
8. Implement periodic registry re-verification (§7.2).
