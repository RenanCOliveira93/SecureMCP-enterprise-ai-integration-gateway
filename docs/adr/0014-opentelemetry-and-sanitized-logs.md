# ADR-0014: OpenTelemetry tracing and sanitized structured logs

## Context
Operators need per-call visibility (latency, outcome, policy) correlated across the agent, the gateway and
downstream APIs, without leaking tokens or PII into telemetry backends.

## Decision
- OpenTelemetry SDK with OTLP/HTTP export (`OTEL_EXPORTER_OTLP_ENDPOINT`), enabled by `SECUREMCP_OTEL_ENABLED`.
  Compose runs an OpenTelemetry Collector forwarding to Jaeger.
- One span per operation (`securemcp.operation`) with attributes `securemcp.operation`, `.kind`, `.tenant_id`,
  `.subject`, `.status`, `.error_code`, `.policy_id`, `.risk`, `.replayed`; child spans for downstream HTTP calls,
  which propagate W3C `traceparent`.
- JSON logs with `request_id` and `trace_id`; a `logging.Filter` redacts bearer tokens, JWTs, API keys, e-mails and
  phone numbers from every message and argument.
- Argument values are never put in spans or logs.

## Alternatives considered
- **Prometheus metrics only**: no per-request causality.
- **Vendor APM agent**: lock-in.

## Consequences
- Telemetry is off by default in tests; the span attributes are tested with an in-memory exporter.
