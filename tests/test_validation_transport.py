"""Real local HTTPS verifies redirects, response bounds and slow-drip cancellation."""

import asyncio
import ssl
import time

import aiohttp
import pytest
from aiohttp import web
from cryptography.hazmat.primitives import serialization

import certificate_validation as cv
from tests.test_certificate_validation import issue


@pytest.fixture(scope="module")
def tls_files(tmp_path_factory):
    directory = tmp_path_factory.mktemp("generated-tls")
    authority = issue("Local HTTPS fixture", ca=True)
    cert, key = directory / "cert.pem", directory / "key.pem"
    cert.write_bytes(authority.cert.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(
        authority.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return cert, key


@pytest.mark.parametrize(
    "case",
    [
        "success",
        "redirect",
        "compressed",
        "declared-size",
        "streamed-size",
        "slow",
        "timestamp-content-type",
    ],
)
def test_bounded_https_transport(tls_files, monkeypatch, case):
    cert, key = tls_files
    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl.load_cert_chain(cert, key)
    client_ssl = ssl.create_default_context(cafile=str(cert))
    # The generated fixture cert has no DNS SAN; this override exists only in this test connector.
    client_ssl.check_hostname = False
    original_session = aiohttp.ClientSession
    contacts, settings = [], []

    def session(**kwargs):
        settings.append(kwargs)
        return original_session(connector=aiohttp.TCPConnector(ssl=client_ssl), **kwargs)

    monkeypatch.setattr(cv.aiohttp, "ClientSession", session)
    monkeypatch.setattr(cv, "MAX_RESPONSE_BYTES", 256)
    monkeypatch.setattr(cv, "REQUEST_TIMEOUT_SECONDS", 0.2)

    async def handler(request):
        contacts.append(request.path)
        if case == "success":
            assert request.headers["Authorization"] == aiohttp.BasicAuth("test", "secret").encode()
        if case == "redirect":
            return web.Response(status=302, headers={"Location": "https://attacker.invalid/redirect"})
        if case == "compressed":
            return web.Response(body=b"compressed-data", headers={"Content-Encoding": "gzip"})
        if case == "declared-size":
            return web.Response(body=b"x" * 257)
        if case in ("streamed-size", "slow"):
            response = web.StreamResponse()
            response.enable_chunked_encoding()
            await response.prepare(request)
            for _ in range(8):
                if case == "slow":
                    await asyncio.sleep(0.06)
                try:
                    await response.write(b"x" * (1 if case == "slow" else 64))
                except ConnectionError:
                    break
            return response
        return web.Response(body=b"bounded-response")

    async def run():
        app = web.Application()
        app.router.add_route("*", "/configured", handler)
        runner = web.AppRunner(app, shutdown_timeout=1)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=server_ssl)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            started = time.monotonic()
            if case == "success":
                assert (
                    await cv.fetch_service(
                        f"https://127.0.0.1:{port}/configured",
                        username="test",
                        password="secret",
                    )
                    == b"bounded-response"
                )
            else:
                with pytest.raises(cv.NetworkPolicyError):
                    await cv.fetch_service(
                        f"https://127.0.0.1:{port}/configured",
                        data=b"query" if case == "timestamp-content-type" else None,
                        timestamp=case == "timestamp-content-type",
                    )
            assert time.monotonic() - started < 0.8
        finally:
            await runner.cleanup()

    asyncio.run(run())
    assert contacts == ["/configured"]
    assert len(settings) == 1
    assert settings[0]["trust_env"] is False and settings[0]["auto_decompress"] is False
    assert settings[0]["timeout"].total == 0.2


def test_crl_batch_has_an_overall_deadline(monkeypatch):
    monkeypatch.setattr(cv, "CRL_BATCH_TIMEOUT_SECONDS", 0.05)
    calls = []

    async def slow(url):
        calls.append(url)
        await asyncio.sleep(10)
        return b"never returned"

    monkeypatch.setattr(cv, "fetch_service", slow)
    policy = cv.ValidationPolicy(crl_urls=("https://pki.test/a", "https://pki.test/b"))
    started = time.monotonic()
    assert asyncio.run(cv.fetch_crls(policy)) == ()
    assert time.monotonic() - started < 0.5
    assert calls == ["https://pki.test/a"]
