"""Tests for the Open Agent Trust Registry Python SDK verification logic.

Covers the 14-step Verification Protocol:
  - Valid attestation verification
  - Expired attestation rejection
  - Unknown issuer handling
  - Signature tampering detection
  - Key rotation / grace period enforcement
  - Revocation fast-path
  - Audience and nonce mismatch
"""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from open_agent_trust.types import (
    IssuerCapabilities,
    IssuerEntry,
    PublicKey,
    RegistryManifest,
    RegistrySignature,
    RevocationList,
    RevokedIssuer,
    RevokedKey,
)
from open_agent_trust.verify import verify_attestation

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _public_key_b64url(private_key: Ed25519PrivateKey) -> str:
    """Extract the raw 32-byte public key as a base64url string."""
    pub = private_key.public_key()
    raw = pub.public_bytes_raw()
    return _b64url_encode(raw)


def _sign_token(
    private_key: Ed25519PrivateKey,
    iss: str,
    kid: str,
    aud: str,
    exp_offset_seconds: int = 3600,
    nonce: Optional[str] = None,
    sub: str = "agent-123",
) -> str:
    """Create a compact JWS (EdDSA / Ed25519) attestation token."""
    header = {
        "alg": "EdDSA",
        "kid": kid,
        "iss": iss,
        "typ": "agent-attestation+jwt",
    }
    now_epoch = int(time.time())
    payload = {
        "sub": sub,
        "aud": aud,
        "iat": now_epoch,
        "exp": now_epoch + exp_offset_seconds,
        "scope": ["read"],
        "constraints": {"max": 10},
        "user_pseudonym": "user-xyz",
        "runtime_version": "1.0",
    }
    if nonce is not None:
        payload["nonce"] = nonce

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")

    signature = private_key.sign(signing_input)
    sig_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

DEFAULT_CAPS = IssuerCapabilities(
    supervision_model="none",
    audit_logging=False,
    immutable_audit=False,
    attestation_format="jwt",
    max_attestation_ttl_seconds=3600,
    capabilities_verified=False,
)

PLACEHOLDER_SIG = RegistrySignature(algorithm="Ed25519", kid="root", value="...")


@pytest.fixture()
def keys():
    """Generate fresh Ed25519 keypairs for each test run."""

    class _Keys:
        valid = Ed25519PrivateKey.generate()
        revoked = Ed25519PrivateKey.generate()
        expired = Ed25519PrivateKey.generate()
        deprecated = Ed25519PrivateKey.generate()
        second_active = Ed25519PrivateKey.generate()
        fastpath = Ed25519PrivateKey.generate()

    return _Keys()


@pytest.fixture()
def manifest(keys):
    """Build a test manifest with multiple issuers and key states."""
    now_iso = datetime.now(timezone.utc).isoformat()
    tomorrow_iso = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    yesterday_iso = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    two_days_ago_iso = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    thirty_days_ago_iso = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    one_twenty_days_ago_iso = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
    sixty_days_ago_iso = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    far_future_iso = (datetime.now(timezone.utc) + timedelta(days=300)).isoformat()

    return RegistryManifest(
        schema_version="1.0.0",
        registry_id="open-trust-registry",
        generated_at=now_iso,
        expires_at=tomorrow_iso,
        signature=PLACEHOLDER_SIG,
        entries=[
            IssuerEntry(
                issuer_id="valid-issuer",
                display_name="Valid Issuer",
                website="https://example.com",
                security_contact="sec@example.com",
                status="active",
                added_at=now_iso,
                last_verified=now_iso,
                capabilities=DEFAULT_CAPS,
                public_keys=[
                    PublicKey(
                        kid="valid-key-1",
                        algorithm="Ed25519",
                        public_key=_public_key_b64url(keys.valid),
                        status="active",
                        issued_at=now_iso,
                        expires_at=tomorrow_iso,
                    ),
                    PublicKey(
                        kid="expired-key-1",
                        algorithm="Ed25519",
                        public_key=_public_key_b64url(keys.expired),
                        status="active",
                        issued_at=two_days_ago_iso,
                        expires_at=yesterday_iso,
                    ),
                    PublicKey(
                        kid="deprecated-within-grace",
                        algorithm="Ed25519",
                        public_key=_public_key_b64url(keys.deprecated),
                        status="deprecated",
                        issued_at=sixty_days_ago_iso,
                        expires_at=far_future_iso,
                        deprecated_at=thirty_days_ago_iso,
                    ),
                    PublicKey(
                        kid="deprecated-past-grace",
                        algorithm="Ed25519",
                        public_key=_public_key_b64url(keys.deprecated),
                        status="deprecated",
                        issued_at=(
                            datetime.now(timezone.utc) - timedelta(days=200)
                        ).isoformat(),
                        expires_at=far_future_iso,
                        deprecated_at=one_twenty_days_ago_iso,
                    ),
                    PublicKey(
                        kid="deprecated-no-timestamp",
                        algorithm="Ed25519",
                        public_key=_public_key_b64url(keys.deprecated),
                        status="deprecated",
                        issued_at=sixty_days_ago_iso,
                        expires_at=far_future_iso,
                        deprecated_at=None,
                    ),
                    PublicKey(
                        kid="second-active-key",
                        algorithm="Ed25519",
                        public_key=_public_key_b64url(keys.second_active),
                        status="active",
                        issued_at=now_iso,
                        expires_at=tomorrow_iso,
                    ),
                    PublicKey(
                        kid="fastpath-key",
                        algorithm="Ed25519",
                        public_key=_public_key_b64url(keys.fastpath),
                        status="active",
                        issued_at=now_iso,
                        expires_at=tomorrow_iso,
                    ),
                ],
            ),
            IssuerEntry(
                issuer_id="suspended-issuer",
                display_name="Suspended Issuer",
                website="https://suspended.com",
                security_contact="sec@suspended.com",
                status="suspended",
                added_at=now_iso,
                last_verified=now_iso,
                capabilities=DEFAULT_CAPS,
                public_keys=[
                    PublicKey(
                        kid="suspended-key-1",
                        algorithm="Ed25519",
                        public_key=_public_key_b64url(keys.valid),
                        status="active",
                        issued_at=now_iso,
                        expires_at=tomorrow_iso,
                    ),
                ],
            ),
            IssuerEntry(
                issuer_id="revoked-issuer",
                display_name="Revoked Issuer",
                website="https://bad.com",
                security_contact="sec@bad.com",
                status="revoked",
                added_at=now_iso,
                last_verified=now_iso,
                capabilities=DEFAULT_CAPS,
                public_keys=[
                    PublicKey(
                        kid="revoked-key-1",
                        algorithm="Ed25519",
                        public_key=_public_key_b64url(keys.revoked),
                        status="revoked",
                        issued_at=now_iso,
                        expires_at=tomorrow_iso,
                    ),
                ],
            ),
        ],
    )


@pytest.fixture()
def revocations():
    """Build a test revocation list."""
    now_iso = datetime.now(timezone.utc).isoformat()
    tomorrow_iso = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

    return RevocationList(
        schema_version="1.0.0",
        generated_at=now_iso,
        expires_at=tomorrow_iso,
        revoked_issuers=[
            RevokedIssuer(
                issuer_id="revoked-issuer",
                reason="policy_violation",
                revoked_at=now_iso,
            ),
        ],
        revoked_keys=[
            RevokedKey(
                issuer_id="valid-issuer",
                kid="fastpath-key",
                reason="key_compromise",
                revoked_at=now_iso,
            ),
        ],
        signature=PLACEHOLDER_SIG,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

AUD = "https://api.service.com"


class TestValidAttestation:
    """Tests for successfully verified attestations."""

    def test_valid_token(self, keys, manifest, revocations):
        token = _sign_token(keys.valid, "valid-issuer", "valid-key-1", AUD)
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is True
        assert result.issuer is not None
        assert result.issuer.issuer_id == "valid-issuer"
        assert result.claims is not None
        assert result.claims.sub == "agent-123"

    def test_second_active_key(self, keys, manifest, revocations):
        token = _sign_token(keys.second_active, "valid-issuer", "second-active-key", AUD)
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is True
        assert result.issuer.issuer_id == "valid-issuer"

    def test_deprecated_key_within_grace_period(self, keys, manifest, revocations):
        token = _sign_token(
            keys.deprecated, "valid-issuer", "deprecated-within-grace", AUD
        )
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is True
        assert result.issuer.issuer_id == "valid-issuer"


class TestIssuerRejection:
    """Tests for issuer-level rejection."""

    def test_unknown_issuer(self, keys, manifest, revocations):
        token = _sign_token(keys.valid, "fake-issuer", "valid-key-1", AUD)
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "unknown_issuer"

    def test_revoked_issuer(self, keys, manifest, revocations):
        token = _sign_token(keys.revoked, "revoked-issuer", "revoked-key-1", AUD)
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "revoked_issuer"

    def test_suspended_issuer(self, keys, manifest, revocations):
        token = _sign_token(keys.valid, "suspended-issuer", "suspended-key-1", AUD)
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "suspended_issuer"


class TestKeyRejection:
    """Tests for key-level rejection."""

    def test_unknown_key(self, keys, manifest, revocations):
        token = _sign_token(keys.valid, "valid-issuer", "fake-key", AUD)
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "unknown_key"

    def test_expired_registry_key(self, keys, manifest, revocations):
        token = _sign_token(keys.expired, "valid-issuer", "expired-key-1", AUD)
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "invalid_signature"

    def test_revocation_fastpath(self, keys, manifest, revocations):
        """Key revoked in revocation list overrides active status in manifest."""
        token = _sign_token(keys.fastpath, "valid-issuer", "fastpath-key", AUD)
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "revoked_key"


class TestGracePeriod:
    """Tests for deprecated key grace period enforcement."""

    def test_deprecated_past_grace_period(self, keys, manifest, revocations):
        token = _sign_token(
            keys.deprecated, "valid-issuer", "deprecated-past-grace", AUD
        )
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "grace_period_expired"

    def test_deprecated_missing_timestamp(self, keys, manifest, revocations):
        token = _sign_token(
            keys.deprecated, "valid-issuer", "deprecated-no-timestamp", AUD
        )
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "grace_period_expired"


class TestSignatureAndClaims:
    """Tests for cryptographic and claim-level checks."""

    def test_tampered_signature(self, keys, manifest, revocations):
        """Signing with the wrong key should fail signature verification."""
        token = _sign_token(keys.revoked, "valid-issuer", "valid-key-1", AUD)
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "invalid_signature"

    def test_expired_attestation(self, keys, manifest, revocations):
        """Token with exp in the past should be rejected."""
        token = _sign_token(
            keys.valid, "valid-issuer", "valid-key-1", AUD, exp_offset_seconds=-3600
        )
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "expired_attestation"

    def test_audience_mismatch(self, keys, manifest, revocations):
        token = _sign_token(
            keys.valid, "valid-issuer", "valid-key-1", "https://other-service.com"
        )
        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "audience_mismatch"

    def test_nonce_mismatch(self, keys, manifest, revocations):
        token = _sign_token(
            keys.valid,
            "valid-issuer",
            "valid-key-1",
            AUD,
            nonce="nonce-123",
        )
        result = verify_attestation(token, manifest, revocations, AUD, expected_nonce="nonce-999")

        assert result.valid is False
        assert result.reason == "nonce_mismatch"

    def test_malformed_jws(self, keys, manifest, revocations):
        result = verify_attestation("not.a.valid.jws.token", manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "invalid_signature"

    def test_completely_garbage_input(self, keys, manifest, revocations):
        result = verify_attestation("garbage", manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "invalid_signature"

    def test_missing_alg_header(self, keys, manifest, revocations):
        """A token without alg=EdDSA should be rejected."""
        header = {"kid": "valid-key-1", "iss": "valid-issuer"}
        payload = {"sub": "agent-123", "aud": AUD, "exp": int(time.time()) + 3600}
        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = (header_b64 + "." + payload_b64).encode("ascii")
        sig = keys.valid.sign(signing_input)
        sig_b64 = _b64url_encode(sig)
        token = f"{header_b64}.{payload_b64}.{sig_b64}"

        result = verify_attestation(token, manifest, revocations, AUD)

        assert result.valid is False
        assert result.reason == "invalid_signature"
