"""Traces, logs and audit carry the fields operators need (request id, trace id, caller, tenant, tool, duration,
status, policy, error code) and nothing they must not (tokens, API keys, contact details)."""

import json
import logging

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from sqlalchemy import select

from securemcp.config import Settings
from securemcp.db.models import AuditEvent
from securemcp.security.sanitize import RedactingFilter
from securemcp.telemetry import JsonFormatter, request_id_var
from tests.helpers import As, error_of

pytestmark = pytest.mark.anyio

_EXPORTER = InMemorySpanExporter()
_provider = TracerProvider()
_provider.add_span_processor(SimpleSpanProcessor(_EXPORTER))
trace.set_tracer_provider(_provider)  # module tracers are proxies: they start recording from here on


@pytest.fixture
def spans():
    _EXPORTER.clear()
    yield _EXPORTER
    _EXPORTER.clear()


def by_name(exporter, name):
    return [s for s in exporter.get_finished_spans() if s.name == name]


async def test_operation_span_has_operational_fields(mcp, spans):
    with As("bruno"):
        await mcp.call_tool("get_client", {"client_id": "cli_aur001"})
    (op,) = by_name(spans, "securemcp.operation")
    attrs = dict(op.attributes)
    assert attrs["securemcp.operation"] == "get_client" and attrs["securemcp.status"] == "ok"
    assert attrs["securemcp.tenant_id"] == "tnt_aurora" and attrs["securemcp.subject"] == "usr_aur_bruno"
    assert attrs["securemcp.client_id"] == "securemcp-host" and attrs["securemcp.policy_id"] == "rbac.get_client"
    assert attrs["securemcp.request_id"].startswith("req_") and attrs["securemcp.duration_ms"] >= 0


async def test_downstream_call_is_a_child_span_with_propagated_context(mcp, spans, mock_state):
    with As("bruno"):
        await mcp.call_tool("get_client", {"client_id": "cli_aur001"})
    (op,) = by_name(spans, "securemcp.operation")
    (crm,) = by_name(spans, "crm GET")
    assert crm.parent.span_id == op.context.span_id and crm.context.trace_id == op.context.trace_id
    assert crm.attributes["securemcp.upstream"] == "crm" and crm.attributes["http.response.status_code"] == 200


async def test_retries_are_visible_as_attempt_spans(mcp, spans, mock_state):
    mock_state.faults["crm"] = mock_state.faults["crm"].model_copy(update={"mode": "flaky", "failures_remaining": 1})
    with As("bruno"):
        await mcp.call_tool("get_client", {"client_id": "cli_aur001"})
    attempts = sorted(s.attributes["securemcp.attempt"] for s in by_name(spans, "crm GET"))
    assert attempts == [1, 2]
    assert by_name(spans, "crm GET")[0].attributes.get("securemcp.transient_error") == "HTTP 503"


async def test_denied_call_span_and_audit_share_trace_id(mcp, container, spans):
    with As("ana"):
        result = await mcp.call_tool(
            "create_support_ticket",
            {
                "client_id": "cli_aur001",
                "subject": "Camera offline",
                "description": "No image since 6am.",
                "priority": "high",
                "category": "camera_offline",
                "idempotency_key": "obs-denied-000001",
            },
        )
    assert error_of(result)["code"] == "FORBIDDEN"
    (op,) = by_name(spans, "securemcp.operation")
    assert op.status.status_code == trace.StatusCode.ERROR
    assert op.attributes["securemcp.error_code"] == "FORBIDDEN" and op.attributes["securemcp.status"] == "denied"
    async with container.db.tenant_session("tnt_aurora") as s:
        event = (await s.execute(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1))).scalar_one()
    assert event.trace_id == f"{op.context.trace_id:032x}" and event.request_id == op.attributes["securemcp.request_id"]


async def test_no_secrets_or_contact_details_in_telemetry(mcp, spans, mock_state, caplog):
    caplog.set_level(logging.DEBUG)
    caplog.handler.addFilter(RedactingFilter())
    with As("carla"):
        await mcp.call_tool("get_client", {"client_id": "cli_aur001"})
        await mcp.call_tool(
            "send_notification",
            {
                "client_id": "cli_aur001",
                "template": "ticket_update",
                "reference_id": "tkt_aur00001",
                "audience": "primary_contact",
                "channel": "email",
                "idempotency_key": "obs-notify-0000001",
            },
        )
    exported = json.dumps([dict(s.attributes) for s in spans.get_finished_spans()], default=str)
    logs = "\n".join(r.getMessage() for r in caplog.records)
    for text in (exported, logs):
        assert "@" not in text.replace("[EMAIL]", "")  # no e-mail addresses
        assert "dev-insecure" not in text and "Bearer ey" not in text
        assert "95555" not in text  # seeded phone numbers


def test_json_log_line_has_correlation_fields():
    formatter = JsonFormatter()
    token = request_id_var.set("req_0123456789ab")
    try:
        record = logging.LogRecord(
            "securemcp.test",
            logging.INFO,
            __file__,
            1,
            "calling with Authorization: Bearer eyJabc.def.ghi to ana.souza@client.example",
            None,
            None,
        )
        RedactingFilter().filter(record)
        line = json.loads(formatter.format(record))
    finally:
        request_id_var.reset(token)
    assert line["request_id"] == "req_0123456789ab" and "trace_id" in line
    assert "eyJ" not in line["message"] and "ana.souza" not in line["message"]


def test_tracing_disabled_by_default():
    assert Settings(_env_file=None).otel_enabled is False
