from securemcp.errors import RETRYABLE, ErrorCode, GatewayError, internal_error, not_found


def test_error_body_is_closed_and_minimal():
    body = GatewayError(ErrorCode.RATE_LIMITED, "slow down", retry_after_seconds=1.234).to_dict("req_1")["error"]
    assert body == {
        "code": "RATE_LIMITED",
        "message": "slow down",
        "retryable": True,
        "request_id": "req_1",
        "retry_after_seconds": 1.23,
    }


def test_internal_error_leaks_nothing():
    body = internal_error().to_dict("req_2")["error"]
    assert set(body) == {"code", "message", "retryable", "request_id"}
    assert "Traceback" not in body["message"]


def test_not_found_message_does_not_reveal_tenant():
    assert not_found("client").message == "client not found"


def test_retryable_set():
    assert {
        ErrorCode.RATE_LIMITED,
        ErrorCode.TIMEOUT,
        ErrorCode.UPSTREAM_UNAVAILABLE,
        ErrorCode.IDEMPOTENCY_IN_PROGRESS,
    } == RETRYABLE
