"""Resource-server token checks (threat model: forged, replayed-elsewhere and malformed tokens)."""

import hashlib
import hmac
import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from securemcp.auth_server.tokens import SigningKey, TokenIssuer
from securemcp.security.jwt_verifier import JwksCache, JwtTokenVerifier

pytestmark = pytest.mark.anyio

ISS = "http://auth.test"
AUD = "http://gateway.test/mcp"


@pytest.fixture(scope="module")
def key():
    return SigningKey.generate()


@pytest.fixture(scope="module")
def other_key():
    return SigningKey.generate()


@pytest.fixture
def issuer(key):
    return TokenIssuer(key, ISS, 900)


@pytest.fixture
def verifier(issuer):
    return JwtTokenVerifier(issuer=ISS, audience=AUD, jwks=JwksCache(static_jwks=issuer.jwks()), leeway_seconds=30)


def issue(issuer, **overrides):
    kwargs = dict(
        subject="usr_aur_bruno",
        tenant_id="tnt_aurora",
        roles=["support_agent"],
        scopes=["clients:read", "tickets:read"],
        client_id="securemcp-host",
        audience=AUD,
    )
    kwargs.update(overrides)
    return issuer.issue(**kwargs)


def raw(key, claims, *, alg="RS256", kid=None, secret=None):
    base = {
        "iss": ISS,
        "aud": AUD,
        "sub": "usr_aur_bruno",
        "tenant_id": "tnt_aurora",
        "roles": ["viewer"],
        "scope": "clients:read",
        "client_id": "securemcp-host",
        "jti": "j1",
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "exp": int(time.time()) + 300,
    }
    base.update(claims)
    base = {k: v for k, v in base.items() if v is not None}
    return jwt.encode(
        base, secret if secret is not None else key.private_key, algorithm=alg, headers={"kid": kid or key.kid}
    )


async def test_valid_token(verifier, issuer):
    token = await verifier.verify_token(issue(issuer))
    assert token is not None
    assert token.subject == "usr_aur_bruno" and token.client_id == "securemcp-host"
    assert token.scopes == ["clients:read", "tickets:read"]
    assert token.resource == AUD
    assert token.claims["tenant_id"] == "tnt_aurora" and token.claims["roles"] == ["support_agent"]


async def test_wrong_audience_rejected(verifier, issuer):
    """A token minted for another resource must not be replayable here (RFC 8707 / confused deputy)."""
    assert await verifier.verify_token(issue(issuer, audience="http://other-service.test/mcp")) is None


async def test_wrong_issuer_rejected(verifier, key):
    assert (
        await verifier.verify_token(
            TokenIssuer(key, "http://evil.test", 900).issue(
                subject="usr_aur_bruno", tenant_id="tnt_aurora", roles=[], scopes=[], client_id="c", audience=AUD
            )
        )
        is None
    )


async def test_expired_rejected(verifier, issuer):
    past = int(time.time()) - 3600
    assert await verifier.verify_token(issue(issuer, now=past, ttl_seconds=600)) is None


async def test_clock_skew_tolerated(verifier, key):
    now = int(time.time())
    assert await verifier.verify_token(raw(key, {"exp": now - 10})) is not None  # inside the 30 s leeway
    assert await verifier.verify_token(raw(key, {"nbf": now + 600})) is None  # far in the future


async def test_unsigned_token_rejected(verifier, key):
    token = jwt.encode({"iss": ISS, "aud": AUD, "sub": "usr_aur_bruno"}, None, algorithm="none")
    assert await verifier.verify_token(token) is None


async def test_hs256_key_confusion_rejected(verifier, key):
    """HMAC-signed with the public key as the secret must not pass (algorithm pinned to RS256).

    PyJWT refuses to produce such a token, so it is assembled by hand like an attacker would."""
    public_pem = key.private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    b64 = lambda data: jwt.utils.base64url_encode(data).decode()  # noqa: E731
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": key.kid}).encode())
    now = int(time.time())
    payload = b64(
        json.dumps(
            {
                "iss": ISS,
                "aud": AUD,
                "sub": "usr_aur_diego",
                "tenant_id": "tnt_aurora",
                "roles": ["tenant_admin"],
                "scope": "clients:read",
                "client_id": "x",
                "jti": "j",
                "iat": now,
                "nbf": now,
                "exp": now + 300,
            }
        ).encode()
    )
    signature = b64(hmac.new(public_pem, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    assert await verifier.verify_token(f"{header}.{payload}.{signature}") is None


async def test_unknown_signing_key_rejected(verifier, other_key):
    assert await verifier.verify_token(raw(other_key, {})) is None  # unknown kid
    assert await verifier.verify_token(raw(other_key, {}, kid=None)) is None


async def test_signature_from_other_key_with_known_kid_rejected(verifier, key, other_key):
    assert await verifier.verify_token(raw(other_key, {}, kid=key.kid)) is None


async def test_tampered_payload_rejected(verifier, issuer):
    header, payload, sig = issue(issuer).split(".")
    claims = jwt.utils.base64url_decode(payload).replace(b"tnt_aurora", b"tnt_boreal")
    assert await verifier.verify_token(f"{header}.{jwt.utils.base64url_encode(claims).decode()}.{sig}") is None


@pytest.mark.parametrize(
    "claims",
    [
        {"tenant_id": None},
        {"tenant_id": "tnt_x' OR 1=1"},
        {"sub": "admin"},
        {"roles": "tenant_admin"},
        {"client_id": None},
        {"jti": None},
        {"exp": None},
    ],
)
async def test_missing_or_malformed_claims_rejected(verifier, key, claims):
    assert await verifier.verify_token(raw(key, claims)) is None


async def test_garbage_rejected(verifier):
    for token in ["", "abc", "a.b.c", "Bearer x"]:
        assert await verifier.verify_token(token) is None


async def test_jwks_refetched_for_rotated_key(key, other_key):
    served = {"jwks": {"keys": [key.jwk()]}, "calls": 0}

    def handler(request):
        served["calls"] += 1
        return httpx.Response(200, json=served["jwks"])

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    cache = JwksCache("http://auth.test/jwks.json", http=http, min_refresh_seconds=0)
    verifier = JwtTokenVerifier(issuer=ISS, audience=AUD, jwks=cache)
    assert await verifier.verify_token(raw(key, {})) is not None
    served["jwks"] = {"keys": [key.jwk(), other_key.jwk()]}  # the issuer rotated keys
    assert await verifier.verify_token(raw(other_key, {})) is not None
    assert served["calls"] == 2
    await http.aclose()


async def test_unknown_kid_does_not_hammer_jwks(key, other_key):
    calls = []
    http = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: calls.append(1) or httpx.Response(200, json={"keys": [key.jwk()]}))
    )
    verifier = JwtTokenVerifier(
        issuer=ISS, audience=AUD, jwks=JwksCache("http://auth.test/jwks.json", http=http, min_refresh_seconds=60)
    )
    for _ in range(5):
        assert await verifier.verify_token(raw(other_key, {})) is None
    assert len(calls) == 1
    await http.aclose()


async def test_jwks_outage_fails_closed(key):
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    verifier = JwtTokenVerifier(
        issuer=ISS, audience=AUD, jwks=JwksCache("http://auth.test/jwks.json", http=http, min_refresh_seconds=0)
    )
    assert await verifier.verify_token(raw(key, {})) is None
    await http.aclose()
