"""Attestation verification implementing the 14-step Verification Protocol.

Operates purely locally against a pre-loaded registry manifest and revocation
list.  No network calls are made during verification.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .types import (
    AttestationClaims,
    IssuerEntry,
    RegistryManifest,
    RevocationList,
    VerificationResult,
)

# Grace period for deprecated keys, per spec/04-key-rotation.md (90 days).
GRACE_PERIOD_SECONDS = 90 * 24 * 60 * 60


def _b64url_decode(data: str) -> bytes:
    """Decode a base64url string, adding padding as needed."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _parse_iso(iso_str: str) -> datetime:
    """Parse an ISO 8601 timestamp to a timezone-aware datetime."""
    # Handle trailing Z
    if iso_str.endswith("Z"):
        iso_str = iso_str[:-1] + "+00:00"
    return datetime.fromisoformat(iso_str)


def _decode_jws_header(token: str) -> dict:
    """Decode the protected header from a compact JWS token."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWS: expected 3 dot-separated parts")
    header_bytes = _b64url_decode(parts[0])
    return json.loads(header_bytes)


def _decode_jws_payload(token: str) -> dict:
    """Decode the payload from a compact JWS token."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWS: expected 3 dot-separated parts")
    payload_bytes = _b64url_decode(parts[1])
    return json.loads(payload_bytes)


def _verify_ed25519_signature(
    public_key_b64url: str,
    token: str,
) -> bool:
    """Verify an Ed25519 signature over header.payload of a compact JWS.

    Returns True if the signature is valid, False otherwise.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return False

    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    signature_bytes = _b64url_decode(parts[2])
    key_bytes = _b64url_decode(public_key_b64url)

    try:
        public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
        public_key.verify(signature_bytes, signing_input)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_attestation(
    attestation_jws: str,
    manifest: RegistryManifest,
    revocations: RevocationList,
    expected_audience: str,
    expected_nonce: Optional[str] = None,
    now: Optional[datetime] = None,
) -> VerificationResult:
    """Execute the 14-step Verification Protocol on an agent attestation.

    This function operates purely locally -- no network calls.

    Args:
        attestation_jws: The raw compact JWS token string.
        manifest: The loaded registry manifest.
        revocations: The loaded revocation list.
        expected_audience: The ``aud`` claim this service expects.
        expected_nonce: Optional nonce for intra-service replay protection.
        now: Override for the current time (for testing).

    Returns:
        A :class:`VerificationResult` with ``valid=True`` on success, or
        ``valid=False`` with a ``reason`` code on failure.
    """
    current_time = now or datetime.now(timezone.utc)

    try:
        # Steps 1 & 2: Parse JWS and extract protected header
        header = _decode_jws_header(attestation_jws)
    except Exception:
        return VerificationResult(valid=False, reason="invalid_signature")

    iss = header.get("iss")
    kid = header.get("kid")
    alg = header.get("alg")

    if not iss or not kid or alg != "EdDSA":
        return VerificationResult(valid=False, reason="invalid_signature")

    # Fast-path: check revocation list before touching the manifest
    for rk in revocations.revoked_keys:
        if rk.kid == kid and rk.issuer_id == iss:
            return VerificationResult(valid=False, reason="revoked_key")

    for ri in revocations.revoked_issuers:
        if ri.issuer_id == iss:
            return VerificationResult(valid=False, reason="revoked_issuer")

    # Step 3: Look up issuer in manifest
    issuer: Optional[IssuerEntry] = None
    for entry in manifest.entries:
        if entry.issuer_id == iss:
            issuer = entry
            break

    # Step 4: Unknown issuer
    if issuer is None:
        return VerificationResult(valid=False, reason="unknown_issuer")

    # Step 5: Issuer status check
    if issuer.status == "suspended":
        return VerificationResult(valid=False, reason="suspended_issuer", issuer=issuer)
    if issuer.status == "revoked":
        return VerificationResult(valid=False, reason="revoked_issuer", issuer=issuer)

    # Step 6: Locate key by kid
    key = None
    for k in issuer.public_keys:
        if k.kid == kid:
            key = k
            break

    # Step 7: Unknown key
    if key is None:
        return VerificationResult(valid=False, reason="unknown_key", issuer=issuer)

    # Step 8: Revoked key status in manifest
    if key.status == "revoked":
        return VerificationResult(valid=False, reason="revoked_key", issuer=issuer)

    # Step 9: Grace period enforcement for deprecated keys
    if key.status == "deprecated":
        if not key.deprecated_at:
            return VerificationResult(
                valid=False, reason="grace_period_expired", issuer=issuer
            )
        deprecated_at = _parse_iso(key.deprecated_at)
        elapsed = (current_time - deprecated_at).total_seconds()
        if elapsed > GRACE_PERIOD_SECONDS:
            return VerificationResult(
                valid=False, reason="grace_period_expired", issuer=issuer
            )

    # Step 10: Check key expiration
    key_expiry = _parse_iso(key.expires_at)
    if current_time > key_expiry:
        return VerificationResult(
            valid=False, reason="invalid_signature", issuer=issuer
        )

    # Steps 11 & 12: Cryptographic signature verification
    if not _verify_ed25519_signature(key.public_key, attestation_jws):
        return VerificationResult(
            valid=False, reason="invalid_signature", issuer=issuer
        )

    # Decode payload for claim checks
    try:
        payload = _decode_jws_payload(attestation_jws)
    except Exception:
        return VerificationResult(
            valid=False, reason="invalid_signature", issuer=issuer
        )

    # Check JWT expiration (exp claim)
    exp = payload.get("exp")
    if exp is not None:
        now_epoch = int(current_time.timestamp())
        if now_epoch > exp:
            return VerificationResult(
                valid=False, reason="expired_attestation", issuer=issuer
            )

    # Step 13: Audience check
    token_aud = payload.get("aud")
    if token_aud != expected_audience:
        return VerificationResult(
            valid=False, reason="audience_mismatch", issuer=issuer
        )

    # Nonce check
    if expected_nonce is not None:
        token_nonce = payload.get("nonce")
        if token_nonce != expected_nonce:
            return VerificationResult(
                valid=False, reason="nonce_mismatch", issuer=issuer
            )

    # Build claims dataclass
    claims = AttestationClaims(
        sub=payload.get("sub", ""),
        aud=payload.get("aud", ""),
        iat=payload.get("iat", 0),
        exp=payload.get("exp", 0),
        scope=payload.get("scope", []),
        constraints=payload.get("constraints", {}),
        user_pseudonym=payload.get("user_pseudonym", ""),
        runtime_version=payload.get("runtime_version", ""),
        nonce=payload.get("nonce"),
    )

    # Step 14: All checks passed
    return VerificationResult(valid=True, issuer=issuer, claims=claims)
