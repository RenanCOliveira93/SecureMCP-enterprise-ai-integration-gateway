from datetime import UTC, datetime, timedelta

import pytest

from tests.helpers import As, error_of

pytestmark = pytest.mark.anyio


def future(days=10, hour=2):
    return (datetime.now(UTC) + timedelta(days=days)).replace(hour=hour, minute=0, second=0, microsecond=0).isoformat()


def maintenance(**overrides):
    args = {
        "client_id": "cli_aur001",
        "camera_ids": ["cam_aur00104", "cam_aur00105"],
        "starts_at": future(),
        "duration_minutes": 60,
        "reason": "Firmware upgrade",
        "idempotency_key": "mnt-key-000000000001",
    }
    return {**args, **overrides}


async def test_schedule_maintenance(mcp):
    with As("carla"):
        r = await mcp.call_tool("schedule_maintenance", maintenance())
    data = r.structured_content
    assert data["status"] == "completed" and data["camera_count"] == 2 and data["maintenance_id"].startswith("mnt_")


async def test_overlapping_window_conflicts(mcp):
    seeded_start = (datetime.now(UTC) + timedelta(days=5)).replace(hour=2, minute=30, second=0, microsecond=0)
    with As("carla"):
        r = await mcp.call_tool(
            "schedule_maintenance", maintenance(camera_ids=["cam_aur00101"], starts_at=seeded_start.isoformat())
        )
    err = error_of(r)
    assert err["code"] == "CONFLICT" and "mnt_aur00101" in err["message"]


async def test_maintenance_business_validation(mcp):
    with As("carla"):
        past = await mcp.call_tool(
            "schedule_maintenance",
            maintenance(
                starts_at=(datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
                idempotency_key="mnt-key-past-0000001",
            ),
        )
        naive = await mcp.call_tool(
            "schedule_maintenance", maintenance(starts_at="2030-01-01T02:00:00", idempotency_key="mnt-key-naive-000001")
        )
        outside = await mcp.call_tool(
            "schedule_maintenance", maintenance(starts_at=future(days=900), idempotency_key="mnt-key-outside-0001")
        )
        foreign = await mcp.call_tool(
            "schedule_maintenance", maintenance(camera_ids=["cam_aur00201"], idempotency_key="mnt-key-foreign-0001")
        )
    assert error_of(past)["fields"] == ["starts_at"]
    assert error_of(naive)["code"] == "INVALID_ARGUMENT"
    assert error_of(outside)["code"] == "CONFLICT"
    assert error_of(foreign)["code"] == "NOT_FOUND"  # camera of another client


async def test_long_window_requires_approval(mcp):
    with As("carla"):
        r = await mcp.call_tool("schedule_maintenance", maintenance(duration_minutes=180))
    data = r.structured_content
    assert data["status"] == "approval_required" and data["maintenance_id"] is None
    assert data["approval"]["policy_id"] == "approval.schedule_maintenance.long_window"


async def test_send_notification_to_primary_contact(mcp, mock_state):
    with As("carla"):
        r = await mcp.call_tool(
            "send_notification",
            {
                "client_id": "cli_aur001",
                "template": "maintenance_notice",
                "reference_id": "mnt_aur00101",
                "audience": "primary_contact",
                "channel": "email",
                "idempotency_key": "notify-key-000000001",
            },
        )
    assert r.structured_content["status"] == "completed" and r.structured_content["recipients_count"] == 1
    assert mock_state.deliveries == [
        {"tenant_id": "tnt_aurora", "channel": "email", "template": "maintenance_notice", "recipients": 1}
    ]


async def test_notification_reference_must_match_template_and_client(mcp):
    with As("carla"):
        wrong_kind = await mcp.call_tool(
            "send_notification",
            {
                "client_id": "cli_aur001",
                "template": "maintenance_notice",
                "reference_id": "tkt_aur00001",
                "audience": "primary_contact",
                "channel": "email",
                "idempotency_key": "notify-key-000000002",
            },
        )
        other_client = await mcp.call_tool(
            "send_notification",
            {
                "client_id": "cli_aur002",
                "template": "ticket_update",
                "reference_id": "tkt_aur00001",
                "audience": "primary_contact",
                "channel": "email",
                "idempotency_key": "notify-key-000000003",
            },
        )
    assert error_of(wrong_kind)["fields"] == ["reference_id"]
    assert error_of(other_client)["code"] == "NOT_FOUND"


async def test_broadcast_and_sms_require_approval(mcp, mock_state):
    base = {"client_id": "cli_aur001", "template": "ticket_update", "reference_id": "tkt_aur00001"}
    with As("carla"):
        broadcast = await mcp.call_tool(
            "send_notification",
            {**base, "audience": "all_contacts", "channel": "email", "idempotency_key": "notify-key-000000004"},
        )
        sms = await mcp.call_tool(
            "send_notification",
            {**base, "audience": "primary_contact", "channel": "sms", "idempotency_key": "notify-key-000000005"},
        )
    assert broadcast.structured_content["status"] == "approval_required"
    assert sms.structured_content["status"] == "approval_required"
    assert mock_state.deliveries == []
