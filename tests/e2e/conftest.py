"""End-to-end fixtures: the real server on a free loopback port, driven by Playwright Chromium."""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

REPO = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def server_url(tmp_path_factory):
    log_path = tmp_path_factory.mktemp("server") / "server.log"
    log = log_path.open("wb")
    port = _free_port()
    env = {**os.environ, "ESIGN_PORT": str(port)}
    process = subprocess.Popen(
        [sys.executable, "-c", "import server; server.main()"],
        cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                if httpx.get(url, timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"server did not start: {log_path.read_text()}")
            time.sleep(0.1)
        yield url
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        log.close()


@pytest.fixture(scope="session")
def base_url(server_url):
    return server_url


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    return {**browser_context_args, "viewport": {"width": 1280, "height": 900}, "accept_downloads": True}
