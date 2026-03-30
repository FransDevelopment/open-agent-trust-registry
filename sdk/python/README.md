# Open Agent Trust Registry — Python SDK

Python port of the TypeScript SDK (`sdk/typescript/`). Verifies agent
attestation tokens locally against the registry manifest — no network calls
per request, pure local computation, target `<1ms`.

## Installation

```bash
pip install open-agent-trust
```

## Quick Start

```python
import json
from open_agent_trust import verify_attestation, RegistryManifest, RevocationList

# Load the manifest and revocations you fetched and cached locally
with open("manifest.json") as f:
    manifest = RegistryManifest.from_dict(json.load(f))

with open("revocations.json") as f:
    revocations = RevocationList.from_dict(json.load(f))

# Verify an incoming attestation token
result = verify_attestation(
    attestation_jws=token,
    manifest=manifest,
    revocations=revocations,
    expected_audience="https://your-api.com",
)

if result.valid:
    # Safe to use result.claims.scope / result.claims.constraints
    print("Agent verified:", result.issuer.issuer_id)
    print("Scopes:", result.claims.scope)
else:
    print("Rejected:", result.reason)
```

## Verification Protocol

Implements the 14-step protocol from `spec/03-verification.md`:

1. Parse JWS and extract `iss` / `kid` from protected header
2. Fast-reject against the revocation list (O(n) scan, expected empty)
3. Look up the issuer in the manifest
4. Reject unknown issuer
5. Reject suspended / revoked issuer
6. Locate key by `kid` in the issuer's `public_keys` array
7. Reject unknown key
8. Reject revoked key
9. Enforce 90-day grace period for deprecated keys
10. Reject expired registry public key
11–12. Verify Ed25519 signature cryptographically
13. Check `aud`, `exp`, and optional `nonce` claims
14. Return `VerificationResult(valid=True, issuer=..., claims=...)`

## Requirements

- Python 3.10+
- `cryptography >= 41` (Ed25519 support)
- `PyJWT >= 2.8` (EdDSA algorithm)

## Running Tests

```bash
cd sdk/python
pip install -e ".[dev]"
pytest -v
```
