"""
Tests for the Open Agent Trust Registry Python SDK — verify_attestation().

Mirrors sdk/typescript/src/verify.test.ts for API parity.
Covers all acceptance criteria from Issue #15:
  - valid attestation
  - expired attestation
  - unknown issuer
  - tampered manifest / invalid signature
"""

from __future__ import annotations

import base64
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from open_agent_trust import (
    RegistryManifest,
    RevocationList,
    verify_attestation,
)
from open_agent_trust.types import (
    IssuerCapabilities,
    IssuerEntry,
    PublicKey,
    RegistrySignature,
    RevokedIssuer,
    RevokedKey,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64url(raw: bytes) -> str:
    """Encode raw bytes as base64url *without* padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Generate an Ed25519 keypair, return (private_key, base64url_x)."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw_bytes = public_key.public_bytes_raw()  # 32 bytes
    return private_key, _b64url(raw_bytes)


def _sign_token(
    private_key: Ed25519PrivateKey,
    iss: str,
    kid: str,
    aud: str,
    exp_offset_seconds: int = 3600,
    nonce: Optional[str] = None,
) -> str:
    """Create a signed EdDSA JWT matching the expected attestation format."""
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": "agent-123",
        "aud": aud,
        "iat": now,
        "exp": now + exp_offset_seconds,
        "scope": ["read"],
        "constraints": {"max": 10},
        "user_pseudonym": "user-xyz",
        "runtime_version": "1.0",
    }
    if nonce is not None:
        payload["nonce"] = nonce

    return pyjwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers={"kid": kid, "iss": iss, "typ": "agent-attestation+jwt"},
    )


def _make_public_key_entry(
    kid: str,
    x: str,
    status: str = "active",
    expires_delta_days: int = 1,
    deprecated_at: Optional[str] = None,
    issued_delta_days: int = -1,
) -> PublicKey:
    now = datetime.now(timezone.utc)
    return PublicKey(
        kid=kid,
        algorithm="Ed25519",
        public_key=x,
        status=status,  # type: ignore[arg-type]
        issued_at=(now + timedelta(days=issued_delta_days)).isoformat(),
        expires_at=(now + timedelta(days=expires_delta_days)).isoformat(),
        deprecated_at=deprecated_at,
        revoked_at=None,
    )


def _base_capabilities() -> IssuerCapabilities:
    return IssuerCapabilities(
        supervision_model="none",
        audit_logging=False,
        immutable_audit=False,
        attestation_format="jwt",
        max_attestation_ttl_seconds=3600,
        capabilities_verified=False,
    )


def _make_issuer(
    issuer_id: str,
    status: str,
    public_keys: list[PublicKey],
) -> IssuerEntry:
    now = datetime.now(timezone.utc).isoformat()
    return IssuerEntry(
        issuer_id=issuer_id,
        display_name=f"{issuer_id} Display",
        website="https://example.com",
        security_contact="sec@example.com",
        status=status,  # type: ignore[arg-type]
        added_at=now,
        last_verified=now,
        public_keys=public_keys,
        capabilities=_base_capabilities(),
    )


def _empty_revocations() -> RevocationList:
    now = datetime.now(timezone.utc)
    sig = RegistrySignature(algorithm="Ed25519", kid="root", value="placeholder")
    return RevocationList(
        schema_version="1.0.0",
        generated_at=now.isoformat(),
        expires_at=(now + timedelta(days=1)).isoformat(),
        revoked_keys=[],
        revoked_issuers=[],
        signature=sig,
    )


def _make_manifest(entries: list[IssuerEntry]) -> RegistryManifest:
    now = datetime.now(timezone.utc)
    sig = RegistrySignature(algorithm="Ed25519", kid="root", value="placeholder")
    return RegistryManifest(
        schema_version="1.0.0",
        registry_id="open-trust-registry",
        generated_at=now.isoformat(),
        expires_at=(now + timedelta(days=1)).isoformat(),
        entries=entries,
        signature=sig,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keypairs():
    """Generate three Ed25519 keypairs: valid, revoked, expired."""
    valid_priv, valid_x = _make_keypair()
    revoked_priv, revoked_x = _make_keypair()
    expired_priv, expired_x = _make_keypair()
    return {
        "valid": (valid_priv, valid_x),
        "revoked": (revoked_priv, revoked_x),
        "expired": (expired_priv, expired_x),
    }


@pytest.fixture(scope="module")
def manifest(keypairs):
    valid_priv, valid_x = keypairs["valid"]
    revoked_priv, revoked_x = keypairs["revoked"]
    expired_priv, expired_x = keypairs["expired"]

    now = datetime.now(timezone.utc)

    valid_issuer = _make_issuer(
        "valid-issuer",
        "active",
        [
            _make_public_key_entry("valid-key-1", valid_x),
            # expired registry key (expires_at yesterday)
            PublicKey(
                kid="expired-registry-key-1",
                algorithm="Ed25519",
                public_key=expired_x,
                status="active",
                issued_at=(now - timedelta(days=2)).isoformat(),
                expires_at=(now - timedelta(days=1)).isoformat(),  # expired
                deprecated_at=None,
                revoked_at=None,
            ),
        ],
    )

    revoked_issuer = _make_issuer(
        "revoked-issuer",
        "revoked",
        [
            _make_public_key_entry("revoked-key-1", revoked_x, status="revoked"),
        ],
    )

    return _make_manifest([valid_issuer, revoked_issuer])


@pytest.fixture(scope="module")
def revocations():
    now = datetime.now(timezone.utc)
    sig = RegistrySignature(algorithm="Ed25519", kid="root", value="placeholder")
    return RevocationList(
        schema_version="1.0.0",
        generated_at=now.isoformat(),
        expires_at=(now + timedelta(days=1)).isoformat(),
        revoked_keys=[],
        revoked_issuers=[
            RevokedIssuer(
                issuer_id="revoked-issuer",
                revoked_at=now.isoformat(),
                reason="policy_violation",
            )
        ],
        signature=sig,
    )


# ---------------------------------------------------------------------------
# Tests — happy path
# ---------------------------------------------------------------------------

def test_verifies_valid_token(keypairs, manifest, revocations):
    priv, _ = keypairs["valid"]
    token = _sign_token(priv, "valid-issuer", "valid-key-1", "https://api.service.com")
    result = verify_attestation(token, manifest, revocations, "https://api.service.com")

    assert result.valid is True
    assert result.issuer is not None
    assert result.issuer.issuer_id == "valid-issuer"
    assert result.claims is not None
    assert result.claims.sub == "agent-123"


def test_verifies_valid_token_with_nonce(keypairs, manifest, revocations):
    priv, _ = keypairs["valid"]
    token = _sign_token(
        priv, "valid-issuer", "valid-key-1", "https://api.service.com", nonce="nonce-abc"
    )
    result = verify_attestation(
        token, manifest, revocations, "https://api.service.com", expected_nonce="nonce-abc"
    )

    assert result.valid is True


# ---------------------------------------------------------------------------
# Tests — issuer rejection
# ---------------------------------------------------------------------------

def test_rejects_unknown_issuer(keypairs, manifest, revocations):
    priv, _ = keypairs["valid"]
    token = _sign_token(priv, "fake-issuer", "valid-key-1", "https://api.service.com")
    result = verify_attestation(token, manifest, revocations, "https://api.service.com")

    assert result.valid is False
    assert result.reason == "unknown_issuer"


def test_rejects_revoked_issuer(keypairs, manifest, revocations):
    priv, _ = keypairs["revoked"]
    token = _sign_token(priv, "revoked-issuer", "revoked-key-1", "https://api.service.com")
    result = verify_attestation(token, manifest, revocations, "https://api.service.com")

    assert result.valid is False
    assert result.reason == "revoked_issuer"


def test_rejects_suspended_issuer(keypairs, revocations):
    priv, x = _make_keypair()
    suspended_issuer = _make_issuer(
        "suspended-issuer",
        "suspended",
        [_make_public_key_entry("key-1", x)],
    )
    manifest = _make_manifest([suspended_issuer])
    token = _sign_token(priv, "suspended-issuer", "key-1", "https://api.service.com")
    result = verify_attestation(token, manifest, _empty_revocations(), "https://api.service.com")

    assert result.valid is False
    assert result.reason == "suspended_issuer"


# ---------------------------------------------------------------------------
# Tests — key rejection
# ---------------------------------------------------------------------------

def test_rejects_unknown_key(keypairs, manifest, revocations):
    priv, _ = keypairs["valid"]
    token = _sign_token(priv, "valid-issuer", "fake-key", "https://api.service.com")
    result = verify_attestation(token, manifest, revocations, "https://api.service.com")

    assert result.valid is False
    assert result.reason == "unknown_key"


def test_rejects_revoked_key_via_manifest(keypairs, revocations):
    """Key with status='revoked' in the manifest entry itself (Step 8)."""
    priv, x = _make_keypair()
    issuer = _make_issuer(
        "issuer-with-revoked-key",
        "active",
        [_make_public_key_entry("revoked-k", x, status="revoked")],
    )
    manifest = _make_manifest([issuer])
    token = _sign_token(priv, "issuer-with-revoked-key", "revoked-k", "https://api.service.com")
    result = verify_attestation(token, manifest, _empty_revocations(), "https://api.service.com")

    assert result.valid is False
    assert result.reason == "revoked_key"


def test_rejects_revoked_key_via_revocations_list(keypairs):
    """Key on the fast-path revocations list (Step 2 fast reject)."""
    priv, x = _make_keypair()
    issuer = _make_issuer(
        "valid-issuer-2",
        "active",
        [_make_public_key_entry("my-key", x)],
    )
    manifest = _make_manifest([issuer])

    now = datetime.now(timezone.utc)
    sig = RegistrySignature(algorithm="Ed25519", kid="root", value="placeholder")
    revocations = RevocationList(
        schema_version="1.0.0",
        generated_at=now.isoformat(),
        expires_at=(now + timedelta(days=1)).isoformat(),
        revoked_keys=[
            RevokedKey(
                issuer_id="valid-issuer-2",
                kid="my-key",
                revoked_at=now.isoformat(),
                reason="compromise",
            )
        ],
        revoked_issuers=[],
        signature=sig,
    )

    token = _sign_token(priv, "valid-issuer-2", "my-key", "https://api.service.com")
    result = verify_attestation(token, manifest, revocations, "https://api.service.com")

    assert result.valid is False
    assert result.reason == "revoked_key"


# ---------------------------------------------------------------------------
# Tests — signature & crypto
# ---------------------------------------------------------------------------

def test_rejects_invalid_signature(keypairs, manifest, revocations):
    """Sign with the revoked keypair but claim the valid-issuer/valid-key identity."""
    wrong_priv, _ = keypairs["revoked"]
    token = _sign_token(wrong_priv, "valid-issuer", "valid-key-1", "https://api.service.com")
    result = verify_attestation(token, manifest, revocations, "https://api.service.com")

    assert result.valid is False
    assert result.reason == "invalid_signature"


def test_rejects_tampered_token(keypairs, manifest, revocations):
    """Mutate one character in the payload segment — signature must fail."""
    priv, _ = keypairs["valid"]
    token = _sign_token(priv, "valid-issuer", "valid-key-1", "https://api.service.com")
    parts = token.split(".")
    # Flip one char in the payload
    flipped = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
    tampered = ".".join([parts[0], flipped, parts[2]])

    result = verify_attestation(tampered, manifest, revocations, "https://api.service.com")

    assert result.valid is False
    assert result.reason == "invalid_signature"


def test_rejects_malformed_jws(manifest, revocations):
    result = verify_attestation("not.a.jwt", manifest, revocations, "https://api.service.com")
    assert result.valid is False
    assert result.reason == "invalid_signature"


# ---------------------------------------------------------------------------
# Tests — time-based rejections
# ---------------------------------------------------------------------------

def test_rejects_expired_attestation_token(keypairs, manifest, revocations):
    """JWT exp is 1 hour in the past."""
    priv, _ = keypairs["valid"]
    token = _sign_token(
        priv, "valid-issuer", "valid-key-1", "https://api.service.com", exp_offset_seconds=-3600
    )
    result = verify_attestation(token, manifest, revocations, "https://api.service.com")

    assert result.valid is False
    assert result.reason == "expired_attestation"


def test_rejects_expired_registry_key(keypairs, manifest, revocations):
    """Registry public key has expires_at in the past (Step 10)."""
    priv, _ = keypairs["expired"]
    # The manifest fixture includes "expired-registry-key-1" which expired yesterday
    token = _sign_token(
        priv, "valid-issuer", "expired-registry-key-1", "https://api.service.com"
    )
    result = verify_attestation(token, manifest, revocations, "https://api.service.com")

    assert result.valid is False
    assert result.reason == "invalid_signature"


def test_rejects_deprecated_key_past_grace_period():
    """deprecated_at 91 days ago — beyond 90-day grace period."""
    priv, x = _make_keypair()
    now = datetime.now(timezone.utc)
    deprecated_at = (now - timedelta(days=91)).isoformat()

    issuer = _make_issuer(
        "issuer-deprecated",
        "active",
        [
            PublicKey(
                kid="deprecated-k",
                algorithm="Ed25519",
                public_key=x,
                status="deprecated",
                issued_at=(now - timedelta(days=180)).isoformat(),
                expires_at=(now + timedelta(days=1)).isoformat(),
                deprecated_at=deprecated_at,
                revoked_at=None,
            )
        ],
    )
    manifest = _make_manifest([issuer])
    token = _sign_token(priv, "issuer-deprecated", "deprecated-k", "https://api.service.com")
    result = verify_attestation(token, manifest, _empty_revocations(), "https://api.service.com")

    assert result.valid is False
    assert result.reason == "grace_period_expired"


def test_accepts_deprecated_key_within_grace_period():
    """deprecated_at 30 days ago — still within 90-day grace period."""
    priv, x = _make_keypair()
    now = datetime.now(timezone.utc)
    deprecated_at = (now - timedelta(days=30)).isoformat()

    issuer = _make_issuer(
        "issuer-deprecated-ok",
        "active",
        [
            PublicKey(
                kid="deprecated-grace-k",
                algorithm="Ed25519",
                public_key=x,
                status="deprecated",
                issued_at=(now - timedelta(days=60)).isoformat(),
                expires_at=(now + timedelta(days=1)).isoformat(),
                deprecated_at=deprecated_at,
                revoked_at=None,
            )
        ],
    )
    manifest = _make_manifest([issuer])
    token = _sign_token(
        priv, "issuer-deprecated-ok", "deprecated-grace-k", "https://api.service.com"
    )
    result = verify_attestation(token, manifest, _empty_revocations(), "https://api.service.com")

    assert result.valid is True


# ---------------------------------------------------------------------------
# Tests — claim validation
# ---------------------------------------------------------------------------

def test_rejects_audience_mismatch(keypairs, manifest, revocations):
    priv, _ = keypairs["valid"]
    token = _sign_token(priv, "valid-issuer", "valid-key-1", "https://other-service.com")
    result = verify_attestation(token, manifest, revocations, "https://api.service.com")

    assert result.valid is False
    assert result.reason == "audience_mismatch"


def test_rejects_nonce_mismatch(keypairs, manifest, revocations):
    priv, _ = keypairs["valid"]
    token = _sign_token(
        priv, "valid-issuer", "valid-key-1", "https://api.service.com", nonce="nonce-123"
    )
    result = verify_attestation(
        token, manifest, revocations, "https://api.service.com", expected_nonce="nonce-999"
    )

    assert result.valid is False
    assert result.reason == "nonce_mismatch"


def test_no_nonce_check_when_not_expected(keypairs, manifest, revocations):
    """Token carries a nonce but service doesn't require one — should still pass."""
    priv, _ = keypairs["valid"]
    token = _sign_token(
        priv, "valid-issuer", "valid-key-1", "https://api.service.com", nonce="nonce-xyz"
    )
    result = verify_attestation(token, manifest, revocations, "https://api.service.com")

    assert result.valid is True


# ---------------------------------------------------------------------------
# Tests — claims extraction
# ---------------------------------------------------------------------------

def test_claims_are_populated_on_success(keypairs, manifest, revocations):
    priv, _ = keypairs["valid"]
    token = _sign_token(priv, "valid-issuer", "valid-key-1", "https://api.service.com")
    result = verify_attestation(token, manifest, revocations, "https://api.service.com")

    assert result.valid is True
    assert result.claims is not None
    assert result.claims.sub == "agent-123"
    assert result.claims.aud == "https://api.service.com"
    assert result.claims.scope == ["read"]
    assert result.claims.constraints == {"max": 10}
    assert result.claims.user_pseudonym == "user-xyz"
    assert result.claims.runtime_version == "1.0"


# ---------------------------------------------------------------------------
# Tests — RegistryManifest.from_dict round-trip
# ---------------------------------------------------------------------------

def test_manifest_from_dict():
    """RegistryManifest.from_dict parses a raw JSON-like dict correctly."""
    now = datetime.now(timezone.utc)
    raw = {
        "schema_version": "1.0.0",
        "registry_id": "test",
        "generated_at": now.isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "signature": {"algorithm": "Ed25519", "kid": "root", "value": "sig"},
        "entries": [
            {
                "issuer_id": "test-issuer",
                "display_name": "Test",
                "website": "https://test.com",
                "security_contact": "sec@test.com",
                "status": "active",
                "added_at": now.isoformat(),
                "last_verified": now.isoformat(),
                "capabilities": {
                    "supervision_model": "none",
                    "audit_logging": False,
                    "immutable_audit": False,
                    "attestation_format": "jwt",
                    "max_attestation_ttl_seconds": 3600,
                    "capabilities_verified": True,
                },
                "public_keys": [
                    {
                        "kid": "k1",
                        "algorithm": "Ed25519",
                        "public_key": "abc123",
                        "status": "active",
                        "issued_at": now.isoformat(),
                        "expires_at": (now + timedelta(days=1)).isoformat(),
                        "deprecated_at": None,
                        "revoked_at": None,
                    }
                ],
            }
        ],
    }
    m = RegistryManifest.from_dict(raw)
    assert m.registry_id == "test"
    assert len(m.entries) == 1
    assert m.entries[0].issuer_id == "test-issuer"
    assert m.entries[0].capabilities.capabilities_verified is True
    assert m.entries[0].public_keys[0].kid == "k1"
