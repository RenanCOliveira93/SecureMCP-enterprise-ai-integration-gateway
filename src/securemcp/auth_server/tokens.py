"""Signing keys, password hashing and access-token issuance for the local authorization server."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

log = logging.getLogger(__name__)

PBKDF2_ITERATIONS = 600_000  # OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _int_b64(value: int) -> str:
    return _b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


# ----------------------------------------------------------------------------- passwords
def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64url(salt)}${_b64url(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_b64 + "=" * (-len(salt_b64) % 4))
        expected = base64.urlsafe_b64decode(digest_b64 + "=" * (-len(digest_b64) % 4))
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
    return hmac.compare_digest(actual, expected)


# ---------------------------------------------------------------------------------- PKCE
def pkce_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode()).digest())


# --------------------------------------------------------------------------- signing key
@dataclass(frozen=True)
class SigningKey:
    private_key: rsa.RSAPrivateKey
    kid: str

    @classmethod
    def from_pem(cls, pem: str) -> SigningKey:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("auth_signing_key must be an RSA private key")
        return cls(key, cls._thumbprint(key))

    @classmethod
    def generate(cls) -> SigningKey:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return cls(key, cls._thumbprint(key))

    @staticmethod
    def _thumbprint(key: rsa.RSAPrivateKey) -> str:
        numbers = key.public_key().public_numbers()
        canonical = f'{{"e":"{_int_b64(numbers.e)}","kty":"RSA","n":"{_int_b64(numbers.n)}"}}'  # RFC 7638
        return _b64url(hashlib.sha256(canonical.encode()).digest())[:16]

    def to_pem(self) -> str:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()

    def jwk(self) -> dict[str, str]:
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": _int_b64(numbers.n),
            "e": _int_b64(numbers.e),
        }


class TokenIssuer:
    def __init__(self, key: SigningKey, issuer: str, ttl_seconds: int) -> None:
        self.key = key
        self.issuer = issuer
        self.ttl = ttl_seconds

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.key.jwk()]}

    def issue(
        self,
        *,
        subject: str,
        tenant_id: str,
        roles: list[str],
        scopes: list[str],
        client_id: str,
        audience: str,
        ttl_seconds: int | None = None,
        extra: dict[str, Any] | None = None,
        now: int | None = None,
    ) -> str:
        now = now or int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + (ttl_seconds or self.ttl),
            "jti": secrets.token_urlsafe(12),
            "client_id": client_id,
            "scope": " ".join(sorted(scopes)),
            "tenant_id": tenant_id,
            "roles": roles,
            **(extra or {}),
        }
        return jwt.encode(claims, self.key.private_key, algorithm="RS256", headers={"kid": self.key.kid})
