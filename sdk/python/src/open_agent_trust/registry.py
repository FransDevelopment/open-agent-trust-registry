"""High-level registry client that fetches, caches, and verifies attestations."""
from __future__ import annotations

import time
from typing import Optional

import httpx

from .types import (
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

# Default cache TTL: 15 minutes (in seconds).
DEFAULT_CACHE_TTL = 15 * 60


class OpenAgentTrustRegistryError(Exception):
    """Error raised by registry operations."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _parse_manifest(data: dict) -> RegistryManifest:
    """Parse a raw JSON dict into a :class:`RegistryManifest`."""
    entries = []
    for e in data.get("entries", []):
        keys = [
            PublicKey(
                kid=k["kid"],
                algorithm=k["algorithm"],
                public_key=k["public_key"],
                status=k["status"],
                issued_at=k["issued_at"],
                expires_at=k["expires_at"],
                deprecated_at=k.get("deprecated_at"),
                revoked_at=k.get("revoked_at"),
            )
            for k in e.get("public_keys", [])
        ]
        caps_data = e.get("capabilities", {})
        caps = IssuerCapabilities(
            supervision_model=caps_data.get("supervision_model", "none"),
            audit_logging=caps_data.get("audit_logging", False),
            immutable_audit=caps_data.get("immutable_audit", False),
            attestation_format=caps_data.get("attestation_format", "jwt"),
            max_attestation_ttl_seconds=caps_data.get(
                "max_attestation_ttl_seconds", 3600
            ),
            capabilities_verified=caps_data.get("capabilities_verified", False),
        )
        entries.append(
            IssuerEntry(
                issuer_id=e["issuer_id"],
                display_name=e["display_name"],
                website=e["website"],
                security_contact=e["security_contact"],
                status=e["status"],
                added_at=e["added_at"],
                last_verified=e["last_verified"],
                public_keys=keys,
                capabilities=caps,
            )
        )

    sig = data.get("signature", {})
    signature = RegistrySignature(
        algorithm=sig.get("algorithm", "Ed25519"),
        kid=sig.get("kid", ""),
        value=sig.get("value", ""),
    )

    return RegistryManifest(
        schema_version=data.get("schema_version", ""),
        registry_id=data.get("registry_id", ""),
        generated_at=data.get("generated_at", ""),
        expires_at=data.get("expires_at", ""),
        entries=entries,
        signature=signature,
    )


def _parse_revocations(data: dict) -> RevocationList:
    """Parse a raw JSON dict into a :class:`RevocationList`."""
    revoked_keys = [
        RevokedKey(
            issuer_id=k["issuer_id"],
            kid=k["kid"],
            revoked_at=k["revoked_at"],
            reason=k["reason"],
        )
        for k in data.get("revoked_keys", [])
    ]
    revoked_issuers = [
        RevokedIssuer(
            issuer_id=i["issuer_id"],
            revoked_at=i["revoked_at"],
            reason=i["reason"],
        )
        for i in data.get("revoked_issuers", [])
    ]
    sig = data.get("signature", {})
    signature = RegistrySignature(
        algorithm=sig.get("algorithm", "Ed25519"),
        kid=sig.get("kid", ""),
        value=sig.get("value", ""),
    )

    return RevocationList(
        schema_version=data.get("schema_version", ""),
        generated_at=data.get("generated_at", ""),
        expires_at=data.get("expires_at", ""),
        revoked_keys=revoked_keys,
        revoked_issuers=revoked_issuers,
        signature=signature,
    )


class OpenAgentTrustRegistry:
    """Client for the Open Agent Trust Registry.

    Fetches and caches the registry manifest and revocation list, then
    verifies attestation tokens locally against the cached state.

    Usage::

        registry = await OpenAgentTrustRegistry.load(
            "https://trust-registry-mirror.example.com"
        )
        result = await registry.verify_token(jws_token, "https://my-api.example.com")
        if result.valid:
            print(f"Verified agent from {result.issuer.display_name}")

    """

    def __init__(self, mirror_url: str, cache_ttl: int = DEFAULT_CACHE_TTL) -> None:
        self._mirror_url = mirror_url.rstrip("/")
        self._cache_ttl = cache_ttl
        self._manifest: Optional[RegistryManifest] = None
        self._revocations: Optional[RevocationList] = None
        self._last_fetch_time: float = 0

    @classmethod
    async def load(
        cls,
        mirror_url: str,
        cache_ttl: int = DEFAULT_CACHE_TTL,
    ) -> OpenAgentTrustRegistry:
        """Create a registry client and fetch the initial state.

        Args:
            mirror_url: Base URL of the registry mirror server.
            cache_ttl: Cache time-to-live in seconds (default 900 = 15 min).

        Returns:
            An initialised :class:`OpenAgentTrustRegistry` instance.
        """
        registry = cls(mirror_url, cache_ttl)
        await registry.refresh()
        return registry

    async def refresh(self) -> None:
        """Fetch the latest manifest and revocation list from the mirror."""
        async with httpx.AsyncClient() as client:
            try:
                manifest_resp, revocations_resp = await _parallel_fetch(
                    client,
                    f"{self._mirror_url}/v1/registry",
                    f"{self._mirror_url}/v1/revocations",
                )
            except httpx.HTTPError as exc:
                raise OpenAgentTrustRegistryError(
                    "fetch_failed",
                    f"Failed to fetch registry state: {exc}",
                ) from exc

        if manifest_resp.status_code != 200 or revocations_resp.status_code != 200:
            raise OpenAgentTrustRegistryError(
                "fetch_failed",
                f"Failed to fetch registry state: "
                f"{manifest_resp.status_code} / {revocations_resp.status_code}",
            )

        self._manifest = _parse_manifest(manifest_resp.json())
        self._revocations = _parse_revocations(revocations_resp.json())
        self._last_fetch_time = time.monotonic()

    async def verify_token(
        self,
        attestation_jws: str,
        expected_audience: str,
        expected_nonce: Optional[str] = None,
    ) -> VerificationResult:
        """Verify an incoming agent attestation JWS token.

        Automatically refreshes the cached registry state if the cache TTL
        has elapsed.

        Args:
            attestation_jws: The raw compact JWS token.
            expected_audience: The ``aud`` claim this service expects.
            expected_nonce: Optional nonce for replay protection.

        Returns:
            A :class:`VerificationResult`.
        """
        # Auto-refresh if stale
        if time.monotonic() - self._last_fetch_time > self._cache_ttl:
            await self.refresh()

        if self._manifest is None or self._revocations is None:
            raise OpenAgentTrustRegistryError(
                "registry_not_loaded", "Registry state not loaded"
            )

        return verify_attestation(
            attestation_jws,
            self._manifest,
            self._revocations,
            expected_audience,
            expected_nonce,
        )

    @property
    def manifest(self) -> Optional[RegistryManifest]:
        """The currently cached manifest, or ``None`` if not loaded."""
        return self._manifest

    @property
    def revocations(self) -> Optional[RevocationList]:
        """The currently cached revocation list, or ``None`` if not loaded."""
        return self._revocations


async def _parallel_fetch(
    client: httpx.AsyncClient,
    url_a: str,
    url_b: str,
) -> tuple:
    """Fetch two URLs concurrently and return both responses."""
    import asyncio

    resp_a, resp_b = await asyncio.gather(
        client.get(url_a),
        client.get(url_b),
    )
    return resp_a, resp_b
