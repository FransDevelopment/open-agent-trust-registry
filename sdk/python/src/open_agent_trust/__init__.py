"""
Open Agent Trust Registry — Python SDK

Verify agent attestation tokens locally against the registry manifest.
No network calls required per verification (pure local computation, <1ms).

Usage::

    from open_agent_trust import verify_attestation, RegistryManifest, RevocationList

    manifest = RegistryManifest.from_dict(manifest_json)
    revocations = RevocationList.from_dict(revocations_json)

    result = verify_attestation(token, manifest, revocations, audience="https://your-api.com")
    if result.valid:
        scopes = result.claims.scope
"""

from .types import (
    AttestationClaims,
    IssuerCapabilities,
    IssuerEndpoints,
    IssuerEntry,
    PublicKey,
    RegistryManifest,
    RegistrySignature,
    RevocationList,
    RevokedIssuer,
    RevokedKey,
    VerificationResult,
)
from .verify import verify_attestation

__all__ = [
    "verify_attestation",
    "VerificationResult",
    "AttestationClaims",
    "RegistryManifest",
    "RevocationList",
    "IssuerEntry",
    "PublicKey",
    "IssuerCapabilities",
    "IssuerEndpoints",
    "RegistrySignature",
    "RevokedKey",
    "RevokedIssuer",
]

__version__ = "0.1.0"
