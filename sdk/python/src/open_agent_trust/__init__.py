"""Open Agent Trust Registry SDK for Python.

Verify agent identity attestations against the Open Agent Trust Registry.

Usage::

    from open_agent_trust import OpenAgentTrustRegistry

    registry = await OpenAgentTrustRegistry.load(
        "https://trust-registry-mirror.example.com"
    )
    result = await registry.verify_token(jws_token, "https://my-api.example.com")
    if result.valid:
        print(f"Verified: issuer={result.issuer.display_name}")

For lower-level use (when you manage manifest fetching yourself)::

    from open_agent_trust import verify_attestation

    result = verify_attestation(jws_token, manifest, revocations, audience)
"""
from __future__ import annotations

from .registry import OpenAgentTrustRegistry, OpenAgentTrustRegistryError
from .types import (
    AttestationClaims,
    IssuerCapabilities,
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
    "OpenAgentTrustRegistry",
    "OpenAgentTrustRegistryError",
    "verify_attestation",
    "AttestationClaims",
    "IssuerCapabilities",
    "IssuerEntry",
    "PublicKey",
    "RegistryManifest",
    "RegistrySignature",
    "RevocationList",
    "RevokedIssuer",
    "RevokedKey",
    "VerificationResult",
]
