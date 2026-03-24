# Contributing to the Open Agent Trust Registry

Thank you for your interest in contributing. This is public infrastructure for the agent internet — a trust layer that lets services verify whether an AI agent is who it says it is.

## Quick orientation

```
spec/                  11 specifications (data model → encrypted transport)
registry/issuers/      Issuer JSON files (one per registered runtime)
registry/proofs/       Proof-of-key-ownership files
registry/manifest.json Signed manifest (auto-compiled on merge + every 50 min)
cli/                   CLI tool (@open-agent-trust/cli on npm)
sdk/typescript/        TypeScript SDK for attestation verification
sdk/swift/             Swift SDK
```

**7 registered issuers.** 11 specs. CI auto-verifies and auto-merges registrations. The [Agent Identity Working Group](https://github.com/corpollc/qntm/issues/5) has 4 founding members and multiple conformant implementations.

## Ways to contribute

### 1. Register as an issuer (no code required)

If you run an agent platform or runtime, register in 4 steps:

```bash
# 1. Generate an Ed25519 keypair
npx @open-agent-trust/cli keygen --issuer-id your-runtime

# 2. Create your registration file
npx @open-agent-trust/cli register \
  --issuer-id your-runtime \
  --display-name "Your Runtime" \
  --website https://yourdomain.com \
  --contact security@yourdomain.com \
  --public-key <PUBLIC_KEY_FROM_STEP_1>

# 3. Generate proof-of-key-ownership
npx @open-agent-trust/cli prove \
  --issuer-id your-runtime \
  --private-key your-runtime.private.pem

# 4. Host domain verification at https://yourdomain.com/.well-known/agent-trust.json
#    { "issuer_id": "your-runtime", "public_key_fingerprint": "<KID>" }
```

Then submit a PR with `registry/issuers/your-runtime.json` and `registry/proofs/your-runtime.proof`. The CI pipeline verifies all three checks (schema, proof signature, domain verification) and auto-merges. No human approval needed. See [GOVERNANCE.md](GOVERNANCE.md) for the full model.

### 2. Pick up a good first issue

We maintain [`good first issue`](https://github.com/FransDevelopment/open-agent-trust-registry/labels/good%20first%20issue) labels for scoped, achievable tasks. Current examples:

- **[Port the SDK to Python](https://github.com/FransDevelopment/open-agent-trust-registry/issues/15)** — the WG has multiple Python implementations that need native verification
- **[Build a mirror health checker](https://github.com/FransDevelopment/open-agent-trust-registry/issues/16)** — monitor whether registry mirrors are valid and up-to-date
- **[Add key rotation test vectors](https://github.com/FransDevelopment/open-agent-trust-registry/issues/17)** — enable interop testing for key lifecycle management
- **[Improve repo discoverability](https://github.com/FransDevelopment/open-agent-trust-registry/issues/18)** — badges, topic tags, integration links
- **[Add --verify flag to the prove CLI](https://github.com/FransDevelopment/open-agent-trust-registry/issues/19)** — let contributors check proofs locally before submitting

### 3. Develop specs and tooling

For changes to specifications, SDKs, CLI, or infrastructure:

1. Fork the repo and create your branch from `main`
2. If changing a spec (`spec/`), explain the cryptographic or architectural rationale in your PR
3. Ensure new code has tests
4. Run tests before submitting:

```bash
# TypeScript SDK
cd sdk/typescript && npm ci && npx vitest run

# CLI
cd cli && npm ci && npx tsx src/index.ts --help
```

**Requirements:** Node.js 22+

### 4. Join the Working Group

The [Agent Identity Working Group](https://github.com/corpollc/qntm/issues/5) coordinates across multiple projects building agent identity, transport, and trust infrastructure. Current participants:

| Project | What it does |
|---------|-------------|
| [OATR](https://github.com/FransDevelopment/open-agent-trust-registry) | Trust registry — identity verification |
| [qntm](https://github.com/corpollc/qntm) | Encrypted transport between verified agents |
| [ArkForge](https://github.com/ark-forge/trust-layer) | Execution attestation — proof of what agents did |
| [APS](https://github.com/aeoess/agent-passport-system) | Delegation chains, economic authorization |
| [AgentID](https://github.com/haroldmalikfrimpong-ops/getagentid) | CA-issued identity, trust scoring |
| [Agent Agora](https://github.com/archedark-publishing/agora) | Agent and service discovery |

All projects use Ed25519 keys and DID resolution. The WG has ratified DID Resolution v1.0 and is working on Trust Enrichment next.

## Architecture

The registry is a signed list of trusted attestation issuers — the "Certificate Authority trust store" for the agent internet.

```
Agent Runtime                  Service (API)
     │                              │
     │  1. Signs attestation        │
     │     (Ed25519 JWT)            │
     │                              │
     │  2. Agent presents           │
     │     attestation ──────────►  │
     │                              │  3. Service fetches manifest.json
     │                              │     (from registry or mirror)
     │                              │
     │                              │  4. Verifies signature
     │                              │     (Ed25519, local verification)
     │                              │
     │                              │  5. Checks issuer status
     │                              │     (active? key valid? not revoked?)
     │                              │
     │                   ◄──────────│  6. Accept or reject
```

**Key design properties:**
- **Verify locally** — services download the manifest and verify offline. No per-request calls to a central server.
- **Zero-trust mirrors** — anyone can host a mirror. Tampered manifests are detected by signature verification.
- **Permissionless registration** — automated CI verification, no human gatekeepers.
- **Threshold governance** — 3-of-5 keys required to sign the manifest. No single point of control.

## Code of Conduct

This project adheres to the Contributor Covenant [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.
