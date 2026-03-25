# Changelog

All notable changes to the Open Agent Trust Registry, including issuer registrations and protocol updates, will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.1.0] - 2026-03-25

### Added
- `submit` CLI command (`npx @open-agent-trust/cli submit`) for automated, secure Pull Request submission of registry entries and proofs directly to the global registry.

### Security
- Fixed a critical JavaScript Injection Remote Code Execution (RCE) vulnerability in the GitHub Action verification pipeline.
- Hardened the auto-merge CI pipeline against Issuer Identity Hijacking (Account Takeover) by enforcing precise dual-anchor modification constraints: preventing `website` and `issuer_id` changes from being auto-merged, while seamlessly preserving self-serve key rotations and revocations.

## [1.0.1] - 2026-03-25

### Fixed
- Resolved merge conflict in registry/manifest.json (invalid JSON from stash conflict markers)
- Corrected root signing key in root-keys.json to match arcede's actual key pair
- Fixed GitHub Actions compiler workflow to commit both manifest.json and revocations.json
- Fixed revocation expiry test that failed when manifest TTL < revocations TTL
- Corrected repository URLs in all package.json files (SDK, CLI, server) to FransDevelopment org
- Aligned CLI version with published NPM version

## [1.0.0] - 2026-03-23

### Added
- Initial repository setup and specifications
- Defined Data Model and Protocol specifications
- Established initial Governance model
- TypeScript SDK (`@open-agent-trust/registry`) for verifying agent identity attestations
- CLI (`@open-agent-trust/cli`) for generating proof-of-key-ownership
- Swift SDK for iOS/macOS verification
- Registry compiler with Ed25519 signing for manifest and revocations
- Trust-anchor verification for manifest and revocation list signatures
- GitHub Actions workflow for automated manifest compilation (every 50 minutes)
- GitHub Actions workflow for issuer registration verification
