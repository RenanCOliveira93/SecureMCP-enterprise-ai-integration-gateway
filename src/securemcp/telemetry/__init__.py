"""OpenTelemetry tracing and sanitized structured logging (ADR-0014)."""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter

from securemcp.config import Settings
from securemcp.security.sanitize import RedactingFilter

request_id_var: ContextVar[str | None] = ContextVar("securemcp_request_id", default=None)

_configured = False


def current_trace_id() -> str | None:
    ctx = trace.get_current_span().get_span_context()
    return f"{ctx.trace_id:032x}" if ctx.is_valid else None


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get(),
            "trace_id": current_trace_id(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        rid = request_id_var.get()
        prefix = f"[{rid}] " if rid else ""
        record.message = record.getMessage()
        base = f"{self.formatTime(record, '%H:%M:%S')} {record.levelname:<7} {record.name}: {prefix}{record.message}"
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


def configure_logging(settings: Settings) -> None:
    handler = logging.StreamHandler(sys.stderr)  # stderr: stdout is the MCP channel under stdio
    handler.setFormatter(JsonFormatter() if settings.log_format == "json" else ConsoleFormatter())
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(settings.log_level)
    for noisy in ("httpx", "httpcore", "mcp.server.streamable_http_manager", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def configure_tracing(
    settings: Settings, service_name: str | None = None, exporter: SpanExporter | None = None
) -> None:
    """Install a tracer provider once. OTLP endpoint comes from the standard OTEL_EXPORTER_OTLP_* variables."""
    global _configured
    if _configured or not (settings.otel_enabled or exporter is not None):
        return
    provider = TracerProvider(resource=Resource.create({"service.name": service_name or settings.otel_service_name}))
    if exporter is None:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        exporter = OTLPSpanExporter()
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    _configured = True
