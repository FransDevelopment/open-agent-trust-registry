"""
Type definitions for the Open Agent Trust Registry Python SDK.

Mirrors sdk/typescript/src/types/ for API parity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional


# --- Registry types ---

KeyAlgorithm = Literal["Ed25519", "ECDSA-P256"]
KeyStatus = Literal["active", "deprecated", "revoked"]
IssuerStatus = Literal["active", "suspended", "revoked"]

VerificationReasonCode = Literal[
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


@dataclass
class PublicKey:
    kid: str
    algorithm: KeyAlgorithm
    public_key: str  # Base64url-encoded Ed25519 x coordinate
    status: KeyStatus
    issued_at: str
    expires_at: str
    deprecated_at: Optional[str]
    revoked_at: Optional[str]

    @classmethod
    def from_dict(cls, d: dict) -> "PublicKey":
        return cls(
            kid=d["kid"],
            algorithm=d["algorithm"],
            public_key=d["public_key"],
            status=d["status"],
            issued_at=d["issued_at"],
            expires_at=d["expires_at"],
            deprecated_at=d.get("deprecated_at"),
            revoked_at=d.get("revoked_at"),
        )


@dataclass
class IssuerCapabilities:
    supervision_model: str
    audit_logging: bool
    immutable_audit: bool
    attestation_format: str
    max_attestation_ttl_seconds: int
    capabilities_verified: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "IssuerCapabilities":
        return cls(
            supervision_model=d["supervision_model"],
            audit_logging=d["audit_logging"],
            immutable_audit=d["immutable_audit"],
            attestation_format=d["attestation_format"],
            max_attestation_ttl_seconds=d["max_attestation_ttl_seconds"],
            capabilities_verified=d.get("capabilities_verified", False),
        )


@dataclass
class IssuerEndpoints:
    attestation_verify: Optional[str] = None
    revocation_list: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "IssuerEndpoints":
        return cls(
            attestation_verify=d.get("attestation_verify"),
            revocation_list=d.get("revocation_list"),
        )


@dataclass
class IssuerEntry:
    issuer_id: str
    display_name: str
    website: str
    security_contact: str
    status: IssuerStatus
    added_at: str
    last_verified: str
    public_keys: list[PublicKey]
    capabilities: IssuerCapabilities
    endpoints: Optional[IssuerEndpoints] = None

    @classmethod
    def from_dict(cls, d: dict) -> "IssuerEntry":
        return cls(
            issuer_id=d["issuer_id"],
            display_name=d["display_name"],
            website=d["website"],
            security_contact=d["security_contact"],
            status=d["status"],
            added_at=d["added_at"],
            last_verified=d["last_verified"],
            public_keys=[PublicKey.from_dict(k) for k in d["public_keys"]],
            capabilities=IssuerCapabilities.from_dict(d["capabilities"]),
            endpoints=IssuerEndpoints.from_dict(d["endpoints"]) if d.get("endpoints") else None,
        )


@dataclass
class RegistrySignature:
    algorithm: KeyAlgorithm
    kid: str
    value: str

    @classmethod
    def from_dict(cls, d: dict) -> "RegistrySignature":
        return cls(algorithm=d["algorithm"], kid=d["kid"], value=d["value"])


@dataclass
class RegistryManifest:
    schema_version: str
    registry_id: str
    generated_at: str
    expires_at: str
    entries: list[IssuerEntry]
    signature: RegistrySignature

    @classmethod
    def from_dict(cls, d: dict) -> "RegistryManifest":
        return cls(
            schema_version=d["schema_version"],
            registry_id=d["registry_id"],
            generated_at=d["generated_at"],
            expires_at=d["expires_at"],
            entries=[IssuerEntry.from_dict(e) for e in d["entries"]],
            signature=RegistrySignature.from_dict(d["signature"]),
        )


@dataclass
class RevokedKey:
    issuer_id: str
    kid: str
    revoked_at: str
    reason: str

    @classmethod
    def from_dict(cls, d: dict) -> "RevokedKey":
        return cls(
            issuer_id=d["issuer_id"],
            kid=d["kid"],
            revoked_at=d["revoked_at"],
            reason=d["reason"],
        )


@dataclass
class RevokedIssuer:
    issuer_id: str
    revoked_at: str
    reason: str

    @classmethod
    def from_dict(cls, d: dict) -> "RevokedIssuer":
        return cls(
            issuer_id=d["issuer_id"],
            revoked_at=d["revoked_at"],
            reason=d["reason"],
        )


@dataclass
class RevocationList:
    schema_version: str
    generated_at: str
    expires_at: str
    revoked_keys: list[RevokedKey]
    revoked_issuers: list[RevokedIssuer]
    signature: RegistrySignature

    @classmethod
    def from_dict(cls, d: dict) -> "RevocationList":
        return cls(
            schema_version=d["schema_version"],
            generated_at=d["generated_at"],
            expires_at=d["expires_at"],
            revoked_keys=[RevokedKey.from_dict(k) for k in d["revoked_keys"]],
            revoked_issuers=[RevokedIssuer.from_dict(i) for i in d["revoked_issuers"]],
            signature=RegistrySignature.from_dict(d["signature"]),
        )


# --- Attestation types ---

AgnosticConstraints = dict[str, Any]


@dataclass
class AttestationClaims:
    sub: str
    aud: str
    iat: int
    exp: int
    scope: list[str]
    constraints: AgnosticConstraints
    user_pseudonym: str
    runtime_version: str
    nonce: Optional[str] = None


@dataclass
class VerificationResult:
    valid: bool
    reason: Optional[VerificationReasonCode] = None
    issuer: Optional[IssuerEntry] = None
    claims: Optional[AttestationClaims] = None
