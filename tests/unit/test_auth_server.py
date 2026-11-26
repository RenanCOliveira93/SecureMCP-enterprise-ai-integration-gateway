"""Local authorization server: PKCE, single-use codes, exact redirects, resource binding, scope down-scoping."""

import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest

from securemcp.auth_server.app import Directory, create_auth_app
from securemcp.auth_server.tokens import SigningKey, TokenIssuer, hash_password, pkce_challenge, verify_password
from securemcp.security.policy import PolicyEngine
from tests.helpers import ROOT

pytestmark = pytest.mark.anyio

ISS = "http://auth.test"
RESOURCE = "http://gateway.test/mcp"
HOST_REDIRECT = "http://127.0.0.1:8976/callback"
APPROVALS_REDIRECT = "http://127.0.0.1:8977/callback"
PASSWORD = "correct horse battery"
VERIFIER = "v" * 64


@pytest.fixture(scope="module")
def key():
    return SigningKey.generate()


@pytest.fixture(scope="module")
def directory():
    """Same shape as config/auth-users.yaml, with a cheap hash so the suite stays fast."""
    real = Directory.from_file(ROOT / "config/auth-users.yaml")
    fast = hash_password(PASSWORD, iterations=1_000)
    return real.model_copy(update={"users": [u.model_copy(update={"password_hash": fast}) for u in real.users]})


@pytest.fixture
async def http(key, directory):
    app = create_auth_app(
        issuer=TokenIssuer(key, ISS, 900),
        directory=directory,
        policy=PolicyEngine.from_file(ROOT / "config/policy.yaml"),
        allowed_resources=[RESOURCE],
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ISS) as client:
        yield client


def params(**overrides):
    base = {
        "response_type": "code",
        "client_id": "securemcp-host",
        "redirect_uri": HOST_REDIRECT,
        "code_challenge": pkce_challenge(VERIFIER),
        "code_challenge_method": "S256",
        "resource": RESOURCE,
        "scope": "",
        "state": "st-123",
    }
    base.update(overrides)
    return base


async def authorize(http, user="bruno", password=PASSWORD, **overrides):
    return await http.post("/authorize", data={**params(**overrides), "username": user, "password": password})


def redirect_query(response):
    assert response.status_code == 302, response.text
    return {k: v[0] for k, v in parse_qs(urlparse(response.headers["location"]).query).items()}


async def exchange(http, code, **overrides):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": HOST_REDIRECT,
        "client_id": "securemcp-host",
        "code_verifier": VERIFIER,
        "resource": RESOURCE,
    }
    data.update(overrides)
    return await http.post("/token", data=data)


async def login(http, user="bruno", **overrides):
    query = redirect_query(await authorize(http, user, **overrides))
    redirect = overrides.get("redirect_uri", HOST_REDIRECT)
    client_id = overrides.get("client_id", "securemcp-host")
    response = await exchange(http, query["code"], redirect_uri=redirect, client_id=client_id)
    assert response.status_code == 200, response.text
    return response.json()


def claims(token, key):
    return jwt.decode(token, key.private_key.public_key(), algorithms=["RS256"], audience=RESOURCE, issuer=ISS)


def test_password_hashing():
    encoded = hash_password("s3cret", iterations=1_000)
    assert encoded.startswith("pbkdf2_sha256$1000$") and "s3cret" not in encoded
    assert verify_password("s3cret", encoded) and not verify_password("S3cret", encoded)
    assert not verify_password("s3cret", "md5$1$abc$def") and not verify_password("s3cret", "garbage")


async def test_metadata_and_jwks(http, key):
    meta = (await http.get("/.well-known/oauth-authorization-server")).json()
    assert meta["issuer"] == ISS and meta["code_challenge_methods_supported"] == ["S256"]
    assert meta["grant_types_supported"] == ["authorization_code"]
    assert meta["authorization_response_iss_parameter_supported"] is True
    jwks = (await http.get("/jwks.json")).json()
    assert jwks["keys"][0]["kid"] == key.kid and "d" not in jwks["keys"][0]  # never the private part


async def test_full_flow_issues_bound_token(http, key):
    query = redirect_query(await authorize(http))
    assert query["state"] == "st-123" and query["iss"] == ISS
    response = await exchange(http, query["code"])
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["token_type"] == "Bearer" and body["expires_in"] == 900
    c = claims(body["access_token"], key)
    assert c["sub"] == "usr_aur_bruno" and c["tenant_id"] == "tnt_aurora" and c["aud"] == RESOURCE
    assert c["roles"] == ["support_agent"] and c["client_id"] == "securemcp-host"
    assert c["exp"] - c["iat"] == 900


async def test_scopes_are_intersection_of_request_client_and_roles(http, key):
    viewer = claims((await login(http, "ana"))["access_token"], key)["scope"].split()
    assert "tickets:write" not in viewer and "clients:read" in viewer
    narrowed = await login(http, "carla", scope="clients:read maintenance:write approvals:decide")
    assert narrowed["scope"] == "clients:read maintenance:write"  # host client may never hold approvals:decide


async def test_host_client_never_gets_approval_rights(http):
    assert "approvals:decide" not in (await login(http, "diego"))["scope"].split()


async def test_approvals_client_only_gets_approval_rights(http):
    body = await login(http, "carla", client_id="securemcp-approvals", redirect_uri=APPROVALS_REDIRECT)
    assert body["scope"] == "approvals:decide"


async def test_no_grantable_scope_is_an_error_redirect(http):
    query = redirect_query(
        await authorize(http, "bruno", client_id="securemcp-approvals", redirect_uri=APPROVALS_REDIRECT)
    )
    assert query["error"] == "invalid_scope" and "code" not in query


async def test_bad_credentials(http):
    assert (await authorize(http, password="wrong")).status_code == 401
    assert (await authorize(http, user="mallory")).status_code == 401


@pytest.mark.parametrize(
    "overrides",
    [
        {"redirect_uri": "http://evil.test/callback"},
        {"redirect_uri": HOST_REDIRECT + "/../steal"},
        {"client_id": "unknown"},
        {"response_type": "token"},
        {"code_challenge_method": "plain"},
        {"code_challenge": ""},
        {"resource": "http://other-service.test/mcp"},
    ],
)
async def test_invalid_authorization_requests_never_redirect(http, overrides):
    for response in (await http.get("/authorize", params=params(**overrides)), await authorize(http, **overrides)):
        assert response.status_code == 400 and "location" not in response.headers


async def test_sign_in_page_escapes_input(http):
    page = await http.get("/authorize", params=params(state='"><script>alert(1)</script>'))
    assert page.status_code == 200 and "<script>alert(1)" not in page.text
    assert page.headers["x-frame-options"] == "DENY"


async def test_wrong_pkce_verifier(http):
    code = redirect_query(await authorize(http))["code"]
    response = await exchange(http, code, code_verifier="w" * 64)
    assert response.status_code == 400 and response.json()["error"] == "invalid_grant"


async def test_code_is_single_use(http):
    code = redirect_query(await authorize(http))["code"]
    assert (await exchange(http, code)).status_code == 200
    assert (await exchange(http, code)).json()["error"] == "invalid_grant"


async def test_failed_exchange_burns_the_code(http):
    code = redirect_query(await authorize(http))["code"]
    assert (await exchange(http, code, code_verifier="w" * 64)).status_code == 400
    assert (await exchange(http, code)).status_code == 400


async def test_code_bound_to_client_redirect_and_resource(http):
    for overrides, error in [
        ({"redirect_uri": "http://127.0.0.1:8976/other"}, "invalid_grant"),
        ({"client_id": "securemcp-approvals"}, "invalid_grant"),
        ({"resource": "http://other-service.test/mcp"}, "invalid_target"),
    ]:
        code = redirect_query(await authorize(http))["code"]
        assert (await exchange(http, code, **overrides)).json()["error"] == error


async def test_expired_code(http, monkeypatch):
    code = redirect_query(await authorize(http))["code"]
    real = time.time
    monkeypatch.setattr("securemcp.auth_server.app.time.time", lambda: real() + 120)
    assert (await exchange(http, code)).json()["error"] == "invalid_grant"


async def test_only_authorization_code_grant(http):
    for grant in ["password", "client_credentials", "refresh_token", "implicit"]:
        response = await http.post("/token", data={"grant_type": grant})
        assert response.json()["error"] == "unsupported_grant_type"
