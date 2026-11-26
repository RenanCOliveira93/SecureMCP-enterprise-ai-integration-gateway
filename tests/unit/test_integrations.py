import httpx
import pytest

from securemcp.config import Settings
from securemcp.integrations.clients import CrmClient, NotificationClient
from securemcp.integrations.http import ResilientHttp, RetryPolicy
from securemcp.security.secrets import build_secret_provider
from tests.helpers import principal

pytestmark = pytest.mark.anyio


def capture():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"message_id": "m1", "status": "queued", "account_manager": "x"})

    return seen, httpx.MockTransport(handler)


async def test_caller_token_not_forwarded():
    seen, transport = capture()
    secrets = build_secret_provider(Settings(env="test", _env_file=None))
    http = ResilientHttp(
        service="n", base_url="http://n", connect_timeout=1, read_timeout=1, retry=RetryPolicy(), transport=transport
    )
    p = principal("carla")
    await NotificationClient(http, secrets).send(p, {"channel": "email"}, "client-key-123456789")
    await CrmClient(http, secrets).get_account(p, "cli_aur001")
    for request in seen:
        assert "authorization" not in {k.lower() for k in request.headers}
        assert request.headers["x-tenant-id"] == "tnt_aurora"
        assert request.headers["x-on-behalf-of"] == "usr_aur_carla"
        assert (
            request.headers["x-api-key"]
            == secrets.get("notifications_api_key" if request.method == "POST" else "crm_api_key").get_secret_value()
        )


def test_downstream_idempotency_key_is_namespaced():
    a = NotificationClient.downstream_key(principal("carla"), "same-key-1234567890")
    b = NotificationClient.downstream_key(principal("fabio"), "same-key-1234567890")
    assert a != b and len(a) == 64
