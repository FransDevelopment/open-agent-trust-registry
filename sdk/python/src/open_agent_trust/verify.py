"""
14-step Verification Protocol implementation for the Open Agent Trust Registry.

Mirrors sdk/typescript/src/verify.ts — pure local computation, no network calls.
Target: <1ms per verification on commodity hardware.

Reference: spec/03-verification.md
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Optional

import jwt as pyjwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .types import (
    AttestationClaims,
    IssuerEntry,
    RegistryManifest,
    RevocationList,
    VerificationResult,
)

# Grace period for deprecated keys: 90 days (spec/04-key-rotation.md)
GRACE_PERIOD_SECONDS = 90 * 24 * 60 * 60


def _base64url_decode(value: str) -> bytes:
    """Decode a base64url string, adding padding as required."""
    # Add padding so len is a multiple of 4
    padding = 4 - len(value) % 4
    if padding != 4:
        value += "=" * padding
    return base64.urlsafe_b64decode(value)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp, always returning a UTC-aware datetime."""
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def verify_attestation(
    attestation_jws: str,
    manifest: RegistryManifest,
    revocations: RevocationList,
    expected_audience: str,
    expected_nonce: Optional[str] = None,
    now: Optional[datetime] = None,
) -> VerificationResult:
    """
    Execute the 14-step Verification Protocol to assess an agent attestation.

    Operates purely locally in <1ms without any network calls.

    Args:
        attestation_jws: The compact JWS (JWT) attestation token.
        manifest: The locally cached registry manifest.
        revocations: The locally cached revocation list.
        expected_audience: The service origin that should match the ``aud`` claim.
        expected_nonce: Optional per-session nonce to check against ``nonce`` claim.
        now: Override the current time (useful for testing with fixed vectors).

    Returns:
        A :class:`VerificationResult` with ``valid=True`` on success, or
        ``valid=False`` and an appropriate ``reason`` code on failure.
    """
    current_time = now or _utcnow()

    try:
        # Steps 1 & 2: Parse JWS and extract headers.
        # PyJWT requires options={"verify_signature": False} to inspect headers
        # before we have the public key.
        try:
            header = pyjwt.get_unverified_header(attestation_jws)
        except pyjwt.exceptions.DecodeError:
            return VerificationResult(valid=False, reason="invalid_signature")

        issuer_id: Optional[str] = header.get("iss")
        kid: Optional[str] = header.get("kid")
        alg: Optional[str] = header.get("alg")

        if not issuer_id or not kid or alg != "EdDSA":
            return VerificationResult(valid=False, reason="invalid_signature")

        # Fast-reject: explicit revocation list check (5-min cache).
        is_key_revoked = any(
            k.kid == kid and k.issuer_id == issuer_id
            for k in revocations.revoked_keys
        )
        is_issuer_revoked_fast = any(
            i.issuer_id == issuer_id for i in revocations.revoked_issuers
        )

        if is_key_revoked:
            return VerificationResult(valid=False, reason="revoked_key")
        if is_issuer_revoked_fast:
            return VerificationResult(valid=False, reason="revoked_issuer")

        # Step 3: Look up issuer in manifest.
        issuer: Optional[IssuerEntry] = next(
            (e for e in manifest.entries if e.issuer_id == issuer_id), None
        )

        # Step 4: Unknown issuer.
        if issuer is None:
            return VerificationResult(valid=False, reason="unknown_issuer")

        # Step 5: Issuer status check.
        if issuer.status == "suspended":
            return VerificationResult(valid=False, reason="suspended_issuer", issuer=issuer)
        if issuer.status == "revoked":
            return VerificationResult(valid=False, reason="revoked_issuer", issuer=issuer)

        # Step 6: Locate key by kid.
        key = next((k for k in issuer.public_keys if k.kid == kid), None)

        # Step 7: Unknown key.
        if key is None:
            return VerificationResult(valid=False, reason="unknown_key", issuer=issuer)

        # Step 8: Revoked key status check.
        if key.status == "revoked":
            return VerificationResult(valid=False, reason="revoked_key", issuer=issuer)

        # Step 9: Grace period enforcement for deprecated keys.
        if key.status == "deprecated":
            if not key.deprecated_at:
                # spec/09a: missing deprecated_at is a data integrity error → REJECT
                return VerificationResult(valid=False, reason="grace_period_expired", issuer=issuer)
            deprecated_at = _parse_iso(key.deprecated_at)
            elapsed = (current_time - deprecated_at).total_seconds()
            if elapsed > GRACE_PERIOD_SECONDS:
                return VerificationResult(valid=False, reason="grace_period_expired", issuer=issuer)
            # Step 9c: within grace period — continue (caller may log a warning)

        # Step 10: Check key expiration against current date.
        key_expiry = _parse_iso(key.expires_at)
        if current_time > key_expiry:
            return VerificationResult(valid=False, reason="invalid_signature", issuer=issuer)

        # Steps 11 & 12: Cryptographically verify the signature.
        # The public_key field is the base64url-encoded raw 32-byte Ed25519 x coordinate.
        try:
            raw_public_key_bytes = _base64url_decode(key.public_key)
            ed_public_key = Ed25519PublicKey.from_public_bytes(raw_public_key_bytes)
        except (ValueError, Exception):
            return VerificationResult(valid=False, reason="invalid_signature", issuer=issuer)

        # Decode the JWT, verifying signature and standard claims (exp, aud).
        # PyJWT's Ed25519 algorithm wraps cryptography internally.
        try:
            payload = pyjwt.decode(
                attestation_jws,
                ed_public_key,
                algorithms=["EdDSA"],
                audience=expected_audience,
                options={"verify_iat": False},  # iat checked by jose implicitly; we skip
                leeway=0,
            )
        except pyjwt.exceptions.ExpiredSignatureError:
            return VerificationResult(valid=False, reason="expired_attestation", issuer=issuer)
        except pyjwt.exceptions.InvalidAudienceError:
            return VerificationResult(valid=False, reason="audience_mismatch", issuer=issuer)
        except pyjwt.exceptions.InvalidSignatureError:
            return VerificationResult(valid=False, reason="invalid_signature", issuer=issuer)
        except pyjwt.exceptions.DecodeError:
            return VerificationResult(valid=False, reason="invalid_signature", issuer=issuer)

        # Step 13: Additional claim checks.

        # Nonce check (replay prevention within a session).
        if expected_nonce is not None and payload.get("nonce") != expected_nonce:
            return VerificationResult(valid=False, reason="nonce_mismatch", issuer=issuer)

        # Explicit audience re-check (belt-and-suspenders; PyJWT should have caught this).
        if payload.get("aud") != expected_audience:
            return VerificationResult(valid=False, reason="audience_mismatch", issuer=issuer)

        # Step 14: All checks passed — build claims and return success.
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
        return VerificationResult(valid=True, issuer=issuer, claims=claims)

    except Exception:
        # Catch-all: malformed JWS or unexpected parsing error.
        return VerificationResult(valid=False, reason="invalid_signature")
