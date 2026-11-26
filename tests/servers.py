"""Run real ASGI apps on localhost ports in background threads (for end-to-end HTTP tests)."""

from __future__ import annotations

import socket
import threading
import time

import uvicorn


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerThread:
    def __init__(self, app, port: int) -> None:
        self.port = port
        self.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_config=None, lifespan="on", access_log=False)
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> ServerThread:
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started:
            if time.monotonic() > deadline or not self.thread.is_alive():
                raise RuntimeError(f"server on port {self.port} did not start")
            time.sleep(0.02)
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)
