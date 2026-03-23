# Open Agent Trust Registry

> The open root-of-trust for agent identity on the internet.

A public, federated registry of trusted attestation issuers — the agent runtimes authorized to vouch for agents acting on behalf of humans. Services verify agent attestations against this registry to determine if the issuing runtime is legitimate.

This acts as the Certificate Authority trust store for the agent internet.

> **Read More:** To learn more about the broader vision, architecture, and principles of the Agent Internet, visit [arcede.com/papers](https://arcede.com/papers).

## The Problem

How can a website know if an AI agent is actually allowed to do something on your behalf? 

Right now, if you log into a website like your bank, you use a password or FaceID. The bank knows it’s *you*. But if you tell an AI agent, "Go pay my internet bill," the agent needs a way to prove to the bank, "I am an authorized agent acting for my user."

To do this, the agent presents a digital "ID badge" (called an *Attestation*). But anyone can fake a digital ID badge. The bank needs a way to verify that the ID badge was issued by a trustworthy organization (like a reputable developer, platform, or runtime) and not by a hacker.

**This registry is the master list of trustworthy badge issuers.** It acts just like the systems that power the padlock icon in your web browser (Certificate Authorities). When a website sees an agent's badge, it checks the Open Agent Trust Registry to see if the issuer of that badge is on the approved list.

## How It Works (In Simple Terms)

1. **The Wax Seal (Ed25519 Cryptography):** An organization creates a Private Key (a secret, like a signet ring) and publishes their Public Key to our registry (the imprint the ring leaves in wax). When they issue an ID badge to an agent, they stamp it with their Private Key. When a website gets the badge, they look at the stamp, check our registry for the public imprint, and if they match, the badge is authentic.
2. **Permissionless Registration:** Organizations register by cryptographically proving they own their website domain (like `my-company.com`). Our automated CI pipeline instantly adds them to the registry. No human gatekeepers, no bias.
3. **Threshold Governance:** To prevent any single person (even the founders) from maliciously altering the registry, the master list is secured by a cryptographic lock requiring 3 out of 5 keys to open. We distribute these 5 keys to independent ecosystem leaders. Every revocation requires mathematically provable consensus.

### Zero-Trust Mirror Servers
A core feature of the registry is that the `manifest.json` is cryptographically signed. Because of this, **anyone can host a registry mirror server without compromising security.** 

If a malicious actor hosts a mirror server and tries to secretly add a hacker to the list, the cryptographic signature of the file breaks. When a website downloads that list, the SDK will instantly detect the invalid signature and reject the entire file. Mirror servers are "zero-trust messengers"—they can distribute the data, but they cannot fake it.

## Design Principles

1. **Open from day one.** MIT or Apache 2.0 licensed. No proprietary extensions, no dual licensing, no "open core."
2. **No single point of control.** Multiple mirrors, multi-party signing, governance designed to scale beyond founding maintainers.
3. **Verify locally.** Services should never need to call a central server per-request. Download the registry, verify locally.
4. **Small and auditable.** Hundreds to low thousands of entries. Any human can read the full registry in minutes.
5. **Cryptographically verifiable.** Every registry state is signed. Every change is attributable. Tamper-evident by construction.

## Quickstart

**Requirements:** Node.js 18+

### 1. Generate a keypair

```bash
npx @open-agent-trust/cli keygen --issuer-id my-runtime
```

This creates:
- A **private key** file (`my-runtime.private.pem`) — keep this secret, never commit it
- A **public key** printed to your terminal — used for registration and verification

To read your private key later: `cat my-runtime.private.pem`

> **macOS users:** Do not double-click `.private.pem` files. macOS will try to import them into Keychain Access, which is not what you want. Always use `cat` in the terminal.

### 2. Create your registration file

```bash
npx @open-agent-trust/cli register \
  --issuer-id my-runtime \
  --display-name "My Agent Runtime" \
  --website https://my-runtime.com \
  --contact security@my-runtime.com \
  --public-key <PUBLIC_KEY_FROM_STEP_1>
```

This generates a `my-runtime.json` file. Review the `capabilities` block to match your runtime's actual profile before submitting.

### 3. Host your domain verification file

Host a `/.well-known/agent-trust.json` file at the website you declared in Step 2. This proves you control the domain — the same model used by Let's Encrypt and DNS-based domain verification.

**At `https://my-runtime.com/.well-known/agent-trust.json`:**

```json
{
  "issuer_id": "my-runtime",
  "public_key_fingerprint": "my-runtime-2026-03"
}
```

The `public_key_fingerprint` is the `kid` value printed during Step 1 (format: `{issuer-id}-{YYYY-MM}`). The CI pipeline will fetch this file and verify it matches your registration.

### 4. Submit your Pull Request

Open a PR against this repository adding your file to `registry/issuers/my-runtime.json`.

Your PR **must** include a cryptographic **proof-of-key-ownership**: a file called `proof.txt` containing a signed statement. This proves you control the private key corresponding to the public key in your registration.

```
I control the Ed25519 key registered for issuer_id: my-runtime
```

Sign this statement with your private key. The CI pipeline verifies the signature against the public key in your registration file. See the [PR template](.github/PULL_REQUEST_TEMPLATE.md) for the full checklist.

**Automated verification (Tier 1):** The CI pipeline checks three things — valid Ed25519 key, proof-of-key-ownership signature, and domain verification. If all three pass, the PR is auto-merged. No human approval required. See [GOVERNANCE.md](GOVERNANCE.md) for the full tiered model.

### 5. Issue and verify attestations

Once registered, your runtime can sign attestations (JWTs) to vouch for agents it runs:

```bash
# Issue a test attestation
npx @open-agent-trust/cli issue \
  --issuer-id my-runtime \
  --kid <KID_FROM_STEP_1> \
  --private-key my-runtime.private.pem \
  --audience https://target-api.com

# Verify an attestation against the registry
npx @open-agent-trust/cli verify <JWT_STRING> --audience https://target-api.com
```

### 6. Integrate into your application

```bash
npm install @open-agent-trust/registry
```

```typescript
import { OpenAgentTrustRegistry } from '@open-agent-trust/registry';

const registry = new OpenAgentTrustRegistry();
const result = await registry.verifyAttestation(jwt, {
  audience: 'https://your-api.com'
});
```

### Understanding the roles

| Role | What it means | Example |
|------|--------------|---------|
| **Runtime Operator** | Runs agents on behalf of users. Registers in the Trust Registry so APIs can verify its agents are legitimate. | Agent Internet Runtime, LangChain Cloud |
| **API Provider** | Accepts requests from agents. Verifies attestations to ensure the requesting agent is authorized. | Stripe, OpenAI, any paid API |
| **Agent** | Acts on behalf of a user. Carries an attestation signed by its runtime to prove its identity. | A shopping assistant, a code reviewer |

### How signing works

When your runtime sends an agent to call a third-party API:

1. Your backend signs a JWT using the private key from Step 1
2. The JWT says: "I am [your runtime], and this agent is authorized to act for user X"
3. The target API receives the JWT, looks up your public key in the Trust Registry, and verifies the signature
4. If valid, the API trusts the request

This happens automatically in your server code. The private key never leaves your infrastructure.

## Relationship to `agent.json`

This registry is highly complementary to the [agent.json](https://github.com/FransDevelopment/agent-json) standard. They serve different but mutually reinforcing purposes:

- **`agent.json`**: Hosted by the *Agent owner* on their domain. Declares exactly what the agent is capable of doing, its API integrations, and its operator. 
- **The Registry Manifest (`manifest.json`)**: Hosted centrally by *this Open Agent Trust Registry*. This is the curated list of *Trusted Runtimes* (Issuers) authorized to execute and attest to those agents.

By combining the two, a service can guarantee both *what* the agent intent is (via `agent.json`) and *who* is securely authorizing the execution (via the Open Agent Trust Registry).

## The two trust problems

When AI agents act on behalf of people, paying for things, calling APIs, and making decisions, everyone needs to know who they're dealing with. Just like you wouldn't hand your credit card to a stranger on the street, an API shouldn't blindly trust an agent that shows up claiming to represent someone. This registry exists so that trust between agents and APIs can be verified cryptographically, without relying on any single company to be the gatekeeper.

There are two distinct trust problems. They look similar but they're solved differently:

### Problem 1: "Is this API real?" (API provider identity)

When an agent discovers an API in the [Open 402 Directory](https://github.com/ArcedeDev/open-402), how does it know the API is legitimate?

**Solved by: agent.json Tier 3.** The API provider adds a DID (Decentralized Identifier) and public key to their `agent.json`. This is like a notarized business license. It cryptographically proves the provider owns the domain, without needing a central authority.

```json
{
  "identity": {
    "did": "did:web:example.com",
    "public_key": "base64url-encoded-ed25519-public-key"
  }
}
```

### Problem 2: "Is this agent authorized?" (Agent runtime trust)

When an AI agent shows up at an API and says "I'm acting on behalf of a user," how does the API know the agent is legitimate? Anyone can write a bot that claims to represent someone.

**Solved by: this registry.** It works like the Certificate Authority system that powers the padlock in your browser:

1. Agent runtimes register their public keys in this registry
2. When a runtime sends an agent to call an API, the agent carries a signed attestation (a digital ID badge)
3. The API checks the attestation against this registry: "Is this runtime on the approved list?"
4. If the signature matches a registered runtime, the agent is trusted

### How it all connects

| Layer | Answers | Who maintains it |
|-------|---------|-----------------|
| **[Open 402 Directory](https://github.com/ArcedeDev/open-402)** | "What paid APIs exist?" | Community (open registry) |
| **agent.json** (on each domain) | "What can this API do?" + "Can it prove it owns this domain?" | Each API provider |
| **This Trust Registry** | "Is the agent calling me authorized by a legitimate platform?" | Threshold governance (3-of-5 keys) |
| **On-chain data** (Base) | "Has real money actually flowed through this API?" | The blockchain (immutable) |

Each layer answers a different trust question. Together they form a complete trust infrastructure for the agent economy, with no central authority and every layer independently verifiable. This is what makes it possible for agents to transact with APIs they've never seen before and still know they're safe.

## Specifications

The architecture and protocols are defined in the `spec/` directory:
- [01: Data Model](spec/01-data-model.md)
- [02: Registration Protocol](spec/02-registration.md)
- [03: Verification Protocol](spec/03-verification.md)
- [04: Key Rotation Protocol](spec/04-key-rotation.md)
- [05: Revocation Protocol](spec/05-revocation.md)
- [06: Mirroring Protocol](spec/06-mirroring.md)
- [07: Attestation Format](spec/07-attestation-format.md)
- [08: Security Model](spec/08-security-model.md)
- [09: Service Integration Guidance](spec/09-service-integration.md)

## Governance & Contributions

This project is community-owned. Please see [GOVERNANCE.md](GOVERNANCE.md) to understand how decisions are made, how keys are managed, and how you can join as a maintainer.
