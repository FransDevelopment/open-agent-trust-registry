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

**Requirements**
- Node.js installed

You can run the global CLI directly via `npx` without installing it:

```bash
# 1. Generate an Ed25519 keypair for your runtime
$ npx @open-agent-trust/cli keygen --issuer-id my-runtime
```

**For Runtime Operators (Registering)**
1. Generate your keypair using the CLI command above.
2. Scaffold your registration JSON file:
   `$ npx @open-agent-trust/cli register --issuer-id my-runtime --display-name "My Agent" --website https://my.com --contact sec@my.com --public-key <KEY>`
3. Submit a Pull Request adding your generated `my-runtime.json` file to the `registry/issuers/` directory.

**For Services (Verifying)**
1. You can easily test your integration by issuing a test attestation:
   `$ npx @open-agent-trust/cli issue --issuer-id my-runtime --kid <KID> --private-key private.key --audience https://my.service.com`
2. You can then test verifying that attestation against the registry:
   `$ npx @open-agent-trust/cli verify <JWT_STRING> --audience https://my.service.com`
3. Integrating directly into your TypeScript application:
   `$ npm install @open-agent-trust/registry`

## Relationship to `agent.json`

This registry is highly complementary to the [agent.json](https://github.com/FransDevelopment/agent-json) standard. They serve different but mutually reinforcing purposes:

- **`agent.json`**: Hosted by the *Agent owner* on their domain. Declares exactly what the agent is capable of doing, its API integrations, and its operator. 
- **The Registry Manifest (`manifest.json`)**: Hosted centrally by *this Open Agent Trust Registry*. This is the curated list of *Trusted Runtimes* (Issuers) authorized to execute and attest to those agents.

By combining the two, a service can guarantee both *what* the agent intent is (via `agent.json`) and *who* is securely authorizing the execution (via the Open Agent Trust Registry).

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
