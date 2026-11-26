import pytest
import yaml
from pydantic import ValidationError

from securemcp.security.policy import Effect, PolicyDocument, PolicyEngine
from tests.helpers import POLICY, ROOT, principal

engine = PolicyEngine.from_file(ROOT / "config/policy.yaml")


def test_unknown_operation_denied_by_default():
    d = engine.evaluate(principal("diego"), "execute_sql", {})
    assert d.effect is Effect.DENY and d.policy_id == "allowlist"


@pytest.mark.parametrize(
    ("user", "operation", "effect"),
    [
        ("ana", "get_client", Effect.ALLOW),
        ("ana", "create_support_ticket", Effect.DENY),
        ("bruno", "create_support_ticket", Effect.ALLOW),
        ("bruno", "schedule_maintenance", Effect.DENY),
        ("bruno", "send_notification", Effect.DENY),
        ("carla", "send_notification", Effect.ALLOW),
        ("carla", "schedule_maintenance", Effect.ALLOW),
    ],
)
def test_rbac_matrix(user, operation, effect):
    args = {
        "priority": "low",
        "audience": "primary_contact",
        "channel": "email",
        "duration_minutes": 60,
        "camera_ids": ["cam_aur00101"],
    }
    assert engine.evaluate(principal(user), operation, args).effect is effect


def test_effective_permissions_are_role_and_scope_intersection():
    narrow = principal("diego", scopes={"clients:read"})  # admin who delegated only one scope
    assert engine.evaluate(narrow, "get_client", {}).effect is Effect.ALLOW
    assert engine.evaluate(narrow, "search_tickets", {}).effect is Effect.DENY
    # a scope the role does not grant is useless
    forged = principal("ana", scopes={"clients:read", "notifications:send"})
    assert engine.evaluate(forged, "send_notification", {"audience": "primary_contact"}).effect is Effect.DENY


def test_unknown_roles_grant_nothing():
    p = principal("ana")
    p2 = type(p)(
        subject=p.subject, tenant_id=p.tenant_id, roles=frozenset({"superuser"}), scopes=p.scopes, client_id=p.client_id
    )
    assert engine.evaluate(p2, "get_client", {}).effect is Effect.DENY


@pytest.mark.parametrize(
    ("operation", "args", "policy_id"),
    [
        ("create_support_ticket", {"priority": "critical"}, "approval.create_support_ticket.critical_priority"),
        (
            "schedule_maintenance",
            {"duration_minutes": 121, "camera_ids": ["a"]},
            "approval.schedule_maintenance.long_window",
        ),
        (
            "schedule_maintenance",
            {"duration_minutes": 60, "camera_ids": list("abcdefghijk")},
            "approval.schedule_maintenance.many_cameras",
        ),
        ("send_notification", {"audience": "all_contacts", "channel": "email"}, "approval.send_notification.broadcast"),
        (
            "send_notification",
            {"audience": "primary_contact", "channel": "sms"},
            "approval.send_notification.sms_channel",
        ),
    ],
)
def test_approval_conditions(operation, args, policy_id):
    d = engine.evaluate(principal("diego"), operation, args)
    assert d.effect is Effect.APPROVAL_REQUIRED and d.policy_id == policy_id


def test_boundaries_do_not_require_approval():
    assert (
        engine.evaluate(
            principal("carla"), "schedule_maintenance", {"duration_minutes": 120, "camera_ids": list("abcdefghij")}
        ).effect
        is Effect.ALLOW
    )


def _mutated(**changes):
    doc = yaml.safe_load((ROOT / "config/policy.yaml").read_text())
    for path, value in changes.items():
        target = doc
        *parents, leaf = path.split(".")
        for key in parents:
            target = target[key]
        target[leaf] = value
    return doc


@pytest.mark.parametrize(
    "doc",
    [
        _mutated(**{"roles.viewer": ["clients:read", "clients:delete"]}),
        _mutated(**{"operations.get_client.permission": "everything"}),
        _mutated(**{"operations.get_client.surprise": True}),
        _mutated(
            **{
                "operations.send_notification.approval_when": [
                    {"id": "x", "field": "audience", "op": "regex", "value": ".*", "reason": "r"}
                ]
            }
        ),
        _mutated(**{"operations.send_notification.idempotent": False}),
    ],
)
def test_invalid_policy_fails_to_load(doc):
    with pytest.raises(ValidationError):
        PolicyDocument.model_validate(doc)


def test_policy_file_covers_every_permission_used():
    used = {op["permission"] for op in POLICY["operations"].values()}
    assert used <= set(POLICY["permissions"])
