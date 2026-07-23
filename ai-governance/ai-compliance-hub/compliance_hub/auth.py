"""Shared OIDC-style JWT (HS256) helpers for open-security-platform (Phase 1).

Stdlib-only sign/verify for tokens minted by the platform IdP (Keycloak in
production, the mock IdP offline). Mirrors ``platform/auth`` (Go) and
``src/auth.ts`` (Node) so a token issued for one component is accepted by any
other. HS256 keeps this dependency-free; production Keycloak can use RS256, in
which case components verify against its JWKS (a thin, optional upgrade).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Optional


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign(claims: dict[str, Any], secret: str) -> str:
    """Encode claims as an HS256 JWT."""
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url_encode(sig)}"


def issue_token(
    subject: str, scopes: list[str], ttl: int, secret: str, issuer: str = "osp-mock-idp"
) -> str:
    """Mint a token (mock IdP / tests). A real deployment uses Keycloak."""
    now = int(time.time())
    return sign(
        {"sub": subject, "iss": issuer, "scopes": scopes, "iat": now, "exp": now + ttl}, secret
    )


def verify(token: str, secret: str) -> dict[str, Any]:
    """Verify signature + expiry and return the claims (raises ValueError otherwise)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64url_decode(parts[2])):
        raise ValueError("invalid signature")
    claims = json.loads(_b64url_decode(parts[1]))
    if claims.get("exp") and time.time() > claims["exp"]:
        raise ValueError("token expired")
    return claims


def has_scope(claims: dict[str, Any], scope: str) -> bool:
    """An empty required scope always matches (authentication only)."""
    if not scope:
        return True
    return scope in (claims.get("scopes") or [])


def bearer_token(headers: Any) -> Optional[str]:
    """Extract a Bearer token from a headers mapping (http.server style)."""
    header = headers.get("Authorization", "")
    if header[:7].lower() == "bearer ":
        return header[7:].strip()
    return None


def authorized(headers: Any, secret: str, scope: str = "") -> bool:
    """True if the headers carry a valid token with the required scope.

    An empty secret disables auth (returns True) so components stay open offline.
    """
    if not secret:
        return True
    token = bearer_token(headers)
    if not token:
        return False
    try:
        claims = verify(token, secret)
    except ValueError:
        return False
    return has_scope(claims, scope)
