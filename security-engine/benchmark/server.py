"""
Mock Application Server Management for Benchmark Execution.

Starts the mock vulnerable FastAPI app in a background daemon thread on
a free 127.0.0.1 port and exposes start, stop, and counter-reset handles.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Callable, Tuple

import uvicorn

from tests.mock_vuln_app import app as _mock_app, reset_counters as _reset_counters


def _find_free_port() -> int:
    """Bind to port 0 on loopback to find an OS-assigned available port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_mock_server(timeout: float = 5.0) -> Tuple[str, Callable[[], None], Callable[[], None]]:
    """
    Start the mock vulnerable FastAPI application on 127.0.0.1.

    Returns:
        (base_url, stop_fn, reset_fn)
    """
    port = _find_free_port()
    config = uvicorn.Config(
        app=_mock_app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        loop="asyncio",
    )
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + timeout
    while not server.started:
        if time.time() > deadline:
            server.should_exit = True
            thread.join(timeout=1.0)
            raise RuntimeError(f"Mock server on port {port} failed to start within {timeout}s")
        time.sleep(0.05)

    base_url = f"http://127.0.0.1:{port}"

    def stop_fn() -> None:
        server.should_exit = True
        thread.join(timeout=5.0)

    def reset_fn() -> None:
        _reset_counters()

    return base_url, stop_fn, reset_fn

