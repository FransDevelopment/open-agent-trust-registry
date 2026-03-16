# Contributing to the Open Trust Registry

Thank you for your interest in contributing to the Open Trust Registry! This project is public infrastructure, and we welcome contributions from everyone.

There are two main ways to contribute to this repository:
1. **Registering an Issuer** (Adding your runtime to the registry)
2. **Developing the Standard** (Improving the SDKs, specs, or tooling)

---

## 1. Registering an Issuer

If you want to register an AI agent runtime in the registry, you do **not** need to modify source code.

Registration is **automated and permissionless**. Please follow these steps:
1. Read the `GOVERNANCE.md` charter to understand the hybrid registration model.
2. Use the CLI tool (`agent-trust register`) to generate your compliant `issuer_entry` JSON payload.
3. Open a Pull Request and complete the checklist in `.github/PULL_REQUEST_TEMPLATE.md`.
4. The CI pipeline will verify your key ownership and domain automatically. If successful, your PR will be automatically merged.

---

## 2. Developing the Standard

If you want to contribute to the core specifications, SDKs, server reference implementation, or CLI tooling, please follow standard open-source workflows.

### 2.1 Local Setup

The repository is a monorepo containing multiple components. You will need:
- **Node.js 20+** (for the TypeScript SDK, Server, and CLI)
- **Swift 5.9+** (for the Swift SDK)

### 2.2 Running Tests

Before submitting a PR for code changes, you must ensure all tests pass.

**TypeScript SDK:**
```bash
cd sdk/typescript
npm install
npx vitest run
```

**Swift SDK:**
```bash
cd sdk/swift
swift test
```

### 2.3 Pull Request Process for Code/Specs

1. Fork the repo and create your branch from `main`.
2. Ensure any new code is fully covered by tests.
3. If changing the specification (`spec/`), clearly explain the cryptographic or architectural rationale in your PR description.
4. Update the `README.md` and `CHANGELOG.md` if applicable.
5. Your PR requires approval from the Reviewer Pool before merging.

---

## 3. Code of Conduct

This project adheres to the Contributor Covenant [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.
