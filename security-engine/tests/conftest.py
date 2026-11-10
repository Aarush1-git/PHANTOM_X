"""
pytest fixtures shared across all PHANTOM-X security-engine tests.

The key fixture is `live_server`, which starts the mock vulnerable FastAPI
application in a background thread on 127.0.0.1 at a free port and tears it
down after the test session ends.

Usage in tests:
    def test_something(live_server):
        base_url = live_server  # e.g. "http://127.0.0.1:52341"
"""

import socket
import threading
import time

import pytest
import uvicorn

from tests.mock_vuln_app import app as _mock_app


def _find_free_port() -> int:
    """Bind a socket to port 0 and return the OS-assigned free port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def live_server():
    """
    Start the mock vulnerable FastAPI app on 127.0.0.1 in a background thread.

    Yields the base URL string, e.g. "http://127.0.0.1:PORT".
    Shuts down the server after the full test session completes.
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

    # Wait until the server is ready to accept connections (max 5 s)
    deadline = time.time() + 5.0
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("Mock server did not start within 5 seconds")
        time.sleep(0.05)

    base_url = f"http://127.0.0.1:{port}"
    yield base_url

    server.should_exit = True
    thread.join(timeout=5)

