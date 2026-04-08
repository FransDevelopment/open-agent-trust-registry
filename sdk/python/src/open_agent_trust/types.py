"""Type definitions for the Open Agent Trust Registry SDK."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

# --- Key & Issuer Status Literals ---

KeyAlgorithm = Literal["Ed25519", "ECDSA-P256"]
KeyStatus = Literal["active", "deprecated", "revoked"]
IssuerStatus = Literal["active", "suspended", "revoked"]

VerificationReason = Literal[
    "unknown_issuer",
    "revoked_issuer",
    "suspended_issuer",
    "unknown_key",
    "revoked_key",
    "grace_period_expired",
    "expired_attestation",
    "invalid_signature",
    "audience_mismatch",
    "nonce_mismatch",
]

RegistryStateErrorCode = Literal[
    "invalid_registry_signature",
    "stale_registry_state",
    "malformed_registry_state",
    "unknown_root_key",
    "fetch_failed",
    "registry_not_loaded",
]


# --- Registry Types ---


@dataclass
class PublicKey:
    """A public key entry in the registry."""

    kid: str
    algorithm: str
    public_key: str
    status: str
    issued_at: str
    expires_at: str
    deprecated_at: Optional[str] = None
    revoked_at: Optional[str] = None


@dataclass
class IssuerCapabilities:
    """Capabilities declared by a registry issuer."""

    supervision_model: str
    audit_logging: bool
    immutable_audit: bool
    attestation_format: str
    max_attestation_ttl_seconds: int
    capabilities_verified: bool = False


@dataclass
class IssuerEntry:
    """A registered issuer in the trust registry."""

    issuer_id: str
    display_name: str
    website: str
    security_contact: str
    status: str
    added_at: str
    last_verified: str
    public_keys: List[PublicKey]
    capabilities: IssuerCapabilities


@dataclass
class RegistrySignature:
    """Ed25519 signature over the registry artifact."""

    algorithm: str
    kid: str
    value: str


@dataclass
class RegistryManifest:
    """The full registry manifest containing all issuer entries."""

    schema_version: str
    registry_id: str
    generated_at: str
    expires_at: str
    entries: List[IssuerEntry]
    signature: RegistrySignature


@dataclass
class RevokedKey:
    """A key that has been revoked via the fast-path revocation list."""

    issuer_id: str
    kid: str
    revoked_at: str
    reason: str


@dataclass
class RevokedIssuer:
    """An issuer that has been revoked via the fast-path revocation list."""

    issuer_id: str
    revoked_at: str
    reason: str


@dataclass
class RevocationList:
    """The revocation list for fast-path rejection of compromised keys/issuers."""

    schema_version: str
    generated_at: str
    expires_at: str
    revoked_keys: List[RevokedKey]
    revoked_issuers: List[RevokedIssuer]
    signature: RegistrySignature


# --- Attestation Types ---


@dataclass
class AttestationClaims:
    """Claims extracted from a verified attestation JWT."""

    sub: str
    aud: str
    iat: int
    exp: int
    scope: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    user_pseudonym: str = ""
    runtime_version: str = ""
    nonce: Optional[str] = None


@dataclass
class VerificationResult:
    """The result of verifying an attestation token."""

    valid: bool
    reason: Optional[str] = None
    issuer: Optional[IssuerEntry] = None
    claims: Optional[AttestationClaims] = None
