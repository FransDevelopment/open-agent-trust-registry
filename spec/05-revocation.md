# 05 - Revocation Protocol

The Open Agent Trust Registry operates two separate revocation tracks:

1. **Key Revocation:** A specific issuer key is lost or compromised. The key is explicitly marked revoked. All agent attestations currently utilizing that signature become immediately invalid.
2. **Issuer Revocation:** A runtime is fundamentally removed from the registry (e.g., due to a major security breach, severe policy violation, or infrastructure abandonment). All of their keys are summarily revoked.

## The Revocation List

While the main registry manifest (`registry.json`) is recompiled on every issuer or revocation change (and on a 50-minute cron as a safety net), the `revocations.json` file is the fast-path for emergency revocations. Changes to `revocations.json` trigger an immediate manifest recompilation on merge to main.

```json
{
  "schema_version": "1.0.0",
  "generated_at": "2026-03-15T12:05:00Z",
  "expires_at": "2026-03-15T12:10:00Z",
  "revoked_keys": [
    {
      "issuer_id": "compromised-runtime",
      "kid": "their-key-2026-01",
      "revoked_at": "2026-03-15T11:30:00Z",
      "reason": "key_compromise"
    }
  ],
  "revoked_issuers": [
    {
      "issuer_id": "bad-actor-runtime",
      "revoked_at": "2026-03-14T00:00:00Z",
      "reason": "policy_violation"
    }
  ],
  "signature": { 
     "algorithm": "Ed25519",
     "kid": "registry-root-2026-03",
     "value": "base64-encoded-signature"
  }
}
```

### Supported Revocation Reasons
Both `revoked_keys` and `revoked_issuers` must denote a specific, accepted enumeration describing the rationale for the removal:
- `key_compromise`
- `issuer_compromise`
- `policy_violation`
- `voluntary_withdrawal`
- `governance_decision`
