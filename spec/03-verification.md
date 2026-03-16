# 03 - Verification Protocol

This protocol defines how digital services can locally verify agent identity attestations against the current state of the Open Agent Trust Registry. 

## Protocol

Target performance: Steps 1-14 must be optimized to complete in `<1ms` on commodity hardware. 

The primary advantage of this architecture is **No network calls per request. Pure local computation.**

```
Step 1: Parse the incoming JWS attestation token.
Step 2: Extract the `iss` (issuer_id) and `kid` (Key ID) from the JWS header.

Step 3: Look up the `issuer_id` within the local copy of the registry manifest.
Step 4: If the issuer is not found → REJECT (Unknown Issuer).
Step 5: If the issuer `status` is not "active" → REJECT (Issuer Suspended/Revoked).

Step 6: Locate the public key in the `public_keys` array matching the extracted `kid`.
Step 7: If the key is not found → REJECT (Unknown Key).
Step 8: If the key `status` is "revoked" → REJECT.
Step 9: If the key `status` is "deprecated" → ACCEPT but log a warning that rotation is imminent.
Step 10: If the key is expired (current time > `expires_at`) → REJECT.

Step 11: Verify the JWS signature using the located public key.
Step 12: If the signature is mathematically invalid → REJECT.

Step 13: Check the attestation claims:
         - `aud` (Audience): Matches this specific service's origin.
         - `exp` (Expiry): > current time (The token itself is not expired).
         - `nonce` (If applicable): Matches the specific nonce the service previously issued (to prevent replay within the same session).

Step 14: If all checks pass → ACCEPT 
         The service may safely extract the `scope` and `constraints` arrays to authorize the agent's actions on behalf of the pseudonymized user.
```

## Attestation Replay Protections
- Cross-Service Replay: The `aud` claim unequivocally binds the attestation to a specific service origin. Service B rejects attestations where `aud` doesn't match its own domain, mitigating stolen tokens.
- Intra-Service Replay: Services can enforce a `nonce` check, ensuring an intercepted token cannot be re-presented to the same service at a later date. Validated attestations should explicitly include their short TTL.
