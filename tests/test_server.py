"""HTTP API: security boundary, limits, admission and signing through the real endpoints."""

import asyncio
import contextlib
import json
import os
import re
import tempfile
import threading
import time
from dataclasses import replace

import httpx
import pymupdf
import pytest
from fastapi.testclient import TestClient
from starlette.formparsers import MultiPartParser

import server
from config import Settings
from tests.conftest import assert_all_signatures_ok, make_identity, make_pdf

BASE = "http://127.0.0.1:8501"
ORIGIN = BASE
SECRET = "Sup3r-Secret-P@ss"
SETTINGS = Settings(max_pdf_bytes=5 * 1024 * 1024, max_p12_bytes=64 * 1024, max_placements=5)
SIGNATURE = {"page": 0, "type": "signature", "x": 100, "y": 100}


@pytest.fixture(scope="module")
def secret_identity():
    return make_identity(common_name="Petra Svobodová", password=SECRET)


def make_app(settings: Settings = SETTINGS):
    return server.create_app(settings)


def token_of(client) -> str:
    html = client.get("/").text
    return re.search(r'<meta name="esign-token" content="([^"]+)"', html).group(1)


@pytest.fixture
def client():
    with TestClient(make_app(), base_url=BASE) as test_client:
        yield test_client


def auth(client, token=None, origin=ORIGIN):
    headers = {"X-ESign-Token": token if token is not None else token_of(client)}
    if origin is not None:
        headers["Origin"] = origin
    return headers


def sign_form(identity, pdf=None, placements=(SIGNATURE,), password=None, **fields):
    files = {
        "pdf": ("doc.pdf", pdf if pdf is not None else make_pdf(), "application/pdf"),
        "p12": ("cert.p12", identity.p12, "application/x-pkcs12"),
    }
    data = {
        "password": identity.password if password is None else password,
        "placements": placements if isinstance(placements, str) else json.dumps(list(placements)),
        **fields,
    }
    return {"files": files, "data": data}


# --- Static frontend and headers --------------------------------------------------------------

def test_index_embeds_a_per_launch_token_and_security_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert token_of(client) == client.app.state.token
    assert make_app().state.token != client.app.state.token
    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_vendored_pdfjs_is_served_as_javascript(client):
    response = client.get("/static/vendor/pdfjs/pdf.mjs")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/javascript")
    assert client.get("/static/vendor/pdfjs/wasm/openjpeg.wasm").headers["content-type"] == "application/wasm"


# --- R13: Host, Origin, token, no CORS ---------------------------------------------------------

@pytest.mark.parametrize("host", ["evil.example", "127.0.0.1.nip.io", "192.168.0.10:8501"])
def test_r13_foreign_host_header_is_rejected_on_every_route(host):
    with TestClient(make_app(), base_url=f"http://{host}") as foreign:
        assert foreign.get("/").status_code == 400
        assert foreign.get("/static/vendor/pdfjs/pdf.mjs").status_code == 400
        assert foreign.post("/api/sign").status_code == 400


@pytest.mark.parametrize("origin", [None, "null", "http://evil.example", "http://127.0.0.1:9999",
                                    "https://127.0.0.1:8501", "http://localhost.evil.example:8501"])
def test_r13_post_without_matching_origin_is_forbidden(client, identity, origin):
    response = client.post("/api/sign", headers=auth(client, origin=origin), **sign_form(identity))
    assert response.status_code == 403
    assert "error" in response.json()


@pytest.mark.parametrize("token", ["", "wrong", "x" * 43])
def test_r13_post_without_the_launch_token_is_forbidden(client, identity, token):
    response = client.post("/api/sign", headers=auth(client, token=token), **sign_form(identity))
    assert response.status_code == 403


def test_r13_missing_token_header_is_forbidden(client, identity):
    response = client.post("/api/certificate", headers={"Origin": ORIGIN},
                           files={"p12": ("c.p12", identity.p12)}, data={"password": identity.password})
    assert response.status_code == 403


def test_r13_localhost_origin_is_accepted(identity):
    with TestClient(make_app(), base_url="http://localhost:8501") as local:
        response = local.post("/api/sign", headers=auth(local, origin="http://localhost:8501"),
                              **sign_form(identity))
    assert response.status_code == 200


def test_r13_no_cors_headers(client):
    response = client.options("/api/sign", headers={
        "Origin": "http://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in response.headers


# --- Certificate endpoint ----------------------------------------------------------------------

def test_certificate_info(client, identity):
    response = client.post("/api/certificate", headers=auth(client),
                           files={"p12": ("c.p12", identity.p12)}, data={"password": identity.password})
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "Jan Novák"
    assert body["initials"] == "JN"
    assert body["valid_to"] and body["valid_from"] and body["issuer"] == "Jan Novák"
    assert response.headers["cache-control"] == "no-store"


def test_explicit_empty_password_is_allowed(client):
    no_password = make_identity(password="")
    response = client.post("/api/certificate", headers=auth(client),
                           files={"p12": ("c.p12", no_password.p12)}, data={"password": ""})
    assert response.status_code == 200
    signed = client.post("/api/sign", headers=auth(client), **sign_form(no_password, password=""))
    assert signed.status_code == 200
    assert_all_signatures_ok(signed.content, no_password, expected=1)


def test_missing_password_field_is_422_not_an_empty_password(client):
    no_password = make_identity(password="")
    response = client.post("/api/certificate", headers=auth(client),
                           files={"p12": ("c.p12", no_password.p12)})
    assert response.status_code == 422
    form = sign_form(no_password, password="")
    del form["data"]["password"]
    assert client.post("/api/sign", headers=auth(client), **form).status_code == 422


def test_expired_certificate_is_reported(client):
    expired = make_identity(valid_from_days=-30, valid_to_days=-1)
    response = client.post("/api/certificate", headers=auth(client),
                           files={"p12": ("c.p12", expired.p12)}, data={"password": expired.password})
    assert response.status_code == 400
    assert "expired" in response.json()["error"]


# --- Signing -----------------------------------------------------------------------------------

def test_sign_returns_a_valid_pdf_with_no_store(client, identity):
    pdf = make_pdf(pages=2)
    placements = [SIGNATURE, {"page": 1, "type": "initials", "x": 500, "y": 780}]
    response = client.post("/api/sign", headers=auth(client),
                           **sign_form(identity, pdf=pdf, placements=placements,
                                       lock="true", protocol="true"))
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["cache-control"] == "no-store"
    assert_all_signatures_ok(response.content, identity, expected=1)
    with pymupdf.open(stream=response.content, filetype="pdf") as doc:
        assert doc.page_count == 3  # protocol page appended


def test_retry_after_success_gives_two_independent_valid_pdfs(client, identity):
    form = sign_form(identity, placements=[SIGNATURE, {**SIGNATURE, "y": 300}])
    first = client.post("/api/sign", headers=auth(client), **form)
    second = client.post("/api/sign", headers=auth(client), **form)
    assert first.status_code == second.status_code == 200
    for out in (first.content, second.content):
        assert_all_signatures_ok(out, identity, expected=2)


def test_placement_limit_comes_from_config_not_the_client(client, identity):
    placements = [{**SIGNATURE, "y": 50 + 60 * i} for i in range(6)]
    response = client.post("/api/sign", headers=auth(client),
                           **sign_form(identity, placements=placements, max_placements="100"))
    assert response.status_code == 400  # unknown field rejected
    response = client.post("/api/sign", headers=auth(client),
                           **sign_form(identity, placements=placements))
    assert response.status_code == 400
    assert "maximum is 5" in response.json()["error"]


def test_signer_name_comes_from_the_certificate(client, identity):
    response = client.post("/api/sign", headers=auth(client),
                           **sign_form(identity, name="Somebody Else"))
    assert response.status_code == 400


# --- R14: body limits while streaming ----------------------------------------------------------

def test_r14_declared_oversized_body_is_413_before_reading(client):
    response = client.post("/api/sign", headers={**auth(client), "Content-Length": str(10 ** 9),
                                                 "Content-Type": "multipart/form-data; boundary=x"},
                           content=b"--x--")
    assert response.status_code == 413


def test_r14_chunked_oversized_body_without_content_length_is_413():
    app = make_app()
    consumed = []

    async def body():
        yield (b'--x\r\nContent-Disposition: form-data; name="pdf"; filename="a.pdf"\r\n'
               b"Content-Type: application/pdf\r\n\r\n")
        chunk = b"0" * 64 * 1024
        for _ in range(200):  # 12.5 MB, above the 6 MB request cap
            consumed.append(len(chunk))
            yield chunk

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url=BASE) as http:
            html = (await http.get("/")).text
            token = re.search(r'name="esign-token" content="([^"]+)"', html).group(1)
            request = http.build_request(
                "POST", "/api/sign", content=body(),
                headers={"Origin": ORIGIN, "X-ESign-Token": token,
                         "Content-Type": "multipart/form-data; boundary=x"})
            assert "content-length" not in request.headers
            return await http.send(request)

    response = asyncio.run(scenario())
    assert response.status_code == 413
    assert sum(consumed) <= SETTINGS.max_request_bytes + 2 * 64 * 1024
    assert app.state.gate.in_flight == 0


def test_r14_pdf_over_its_own_limit_is_413(identity):
    small = replace(SETTINGS, max_pdf_bytes=100)
    with TestClient(make_app(small), base_url=BASE) as small_client:
        response = small_client.post("/api/sign", headers=auth(small_client), **sign_form(identity))
    assert response.status_code == 413
    assert "PDF" in response.json()["error"]


# --- R15: malformed input ----------------------------------------------------------------------

def test_r15_malformed_multipart_is_400(client):
    response = client.post("/api/sign", headers={
        **auth(client), "Content-Type": "multipart/form-data; boundary=abc"},
        content=b"--abc\r\nContent-Disposition: form-data\r\n\r\nvalue\r\n--abc--\r\n")
    assert response.status_code == 400
    assert "error" in response.json()


def test_r15_non_multipart_body_is_400(client):
    response = client.post("/api/sign", headers=auth(client), json={"pdf": "x"})
    assert response.status_code == 400


@pytest.mark.parametrize("placements", ["not json", "{\"page\": 0}", "[1, 2]", "[{\"page\": 0}]",
                                        "[{\"page\": 0, \"type\": \"signature\", \"x\": NaN, \"y\": 1}]",
                                        "[]"])
def test_r15_malformed_placements_are_400(client, identity, placements):
    response = client.post("/api/sign", headers=auth(client), **sign_form(identity, placements=placements))
    assert response.status_code == 400
    assert response.json()["error"]


@pytest.mark.parametrize("field, value", [("lock", "yes"), ("protocol", "1")])
def test_r15_bad_option_values_are_400(client, identity, field, value):
    response = client.post("/api/sign", headers=auth(client), **sign_form(identity, **{field: value}))
    assert response.status_code == 400


def test_r15_missing_pdf_is_422(client, identity):
    form = sign_form(identity)
    del form["files"]["pdf"]
    assert client.post("/api/sign", headers=auth(client), **form).status_code == 422


def test_r15_duplicate_field_is_400(client, identity):
    form = sign_form(identity)
    response = client.post("/api/sign", headers=auth(client), files=[
        ("pdf", form["files"]["pdf"]), ("p12", form["files"]["p12"]),
        ("password", (None, identity.password)), ("password", (None, "other")),
        ("placements", (None, form["data"]["placements"]))])
    assert response.status_code == 400


def test_r15_placement_outside_the_page_is_400(client, identity):
    response = client.post("/api/sign", headers=auth(client),
                           **sign_form(identity, placements=[{**SIGNATURE, "x": 500}]))
    assert response.status_code == 400
    assert "does not fit" in response.json()["error"]


def test_r15_not_a_pdf_is_400(client, identity):
    response = client.post("/api/sign", headers=auth(client), **sign_form(identity, pdf=b"hello"))
    assert response.status_code == 400


# --- R17: the password never appears in responses or logs --------------------------------------

def test_r17_password_never_in_error_bodies_or_logs(client, secret_identity, caplog):
    caplog.set_level("DEBUG")
    bad_cases = [
        sign_form(secret_identity, pdf=b"%PDF-1.4 broken"),
        sign_form(secret_identity, placements=[{"page": 99, "type": "signature", "x": 1, "y": 1}]),
        sign_form(secret_identity, placements="garbage " + SECRET),
        sign_form(secret_identity, password=SECRET + "x"),
        sign_form(secret_identity, lock=SECRET),
    ]
    for form in bad_cases:
        response = client.post("/api/sign", headers=auth(client), **form)
        assert response.status_code >= 400
        assert SECRET not in response.text
    response = client.post("/api/certificate", headers=auth(client),
                           files={"p12": ("c.p12", b"not a p12")}, data={"password": SECRET})
    assert response.status_code == 400 and SECRET not in response.text
    assert SECRET not in caplog.text


def test_r17_unexpected_error_is_generic_and_does_not_log_the_password(client, identity, caplog,
                                                                       monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("boom with " + args[2])

    monkeypatch.setattr(server, "sign_pdf_multiple", explode)
    response = client.post("/api/sign", headers=auth(client), **sign_form(identity))
    assert response.status_code == 500
    assert identity.password not in response.text
    assert identity.password not in caplog.text


# --- R18 / R30 / R31: concurrency, memory-only uploads, admission ------------------------------

def _async_client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE)


async def _token(http) -> str:
    html = (await http.get("/")).text
    return re.search(r'name="esign-token" content="([^"]+)"', html).group(1)


def test_r18_concurrent_sign_requests_both_succeed_one_at_a_time(identity, monkeypatch):
    app = make_app()
    real = server.sign_pdf_multiple
    active, peak, lock = [0], [0], threading.Lock()

    def tracked(*args, **kwargs):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        try:
            time.sleep(0.2)
            return real(*args, **kwargs)
        finally:
            with lock:
                active[0] -= 1

    monkeypatch.setattr(server, "sign_pdf_multiple", tracked)

    async def scenario():
        async with _async_client(app) as http:
            headers = {"Origin": ORIGIN, "X-ESign-Token": await _token(http)}
            form = sign_form(identity)
            return await asyncio.gather(*(http.post("/api/sign", headers=headers, **form)
                                          for _ in range(2)))

    responses = asyncio.run(scenario())
    assert [r.status_code for r in responses] == [200, 200]
    assert peak[0] == 1
    for response in responses:
        assert_all_signatures_ok(response.content, identity, expected=1)


def test_r30_accepted_large_upload_never_touches_disk(identity, monkeypatch):
    doc = pymupdf.open()
    doc.new_page()
    doc.embfile_add("blob.bin", os.urandom(1_600_000))
    pdf = doc.tobytes()
    doc.close()
    assert len(pdf) > MultiPartParser.spool_max_size  # Starlette would spool this to a temp file

    def forbidden(*args, **kwargs):
        raise AssertionError("temporary file created")

    with TestClient(make_app(), base_url=BASE) as http:
        headers = auth(http)
        for name in ("TemporaryFile", "NamedTemporaryFile", "mkstemp", "mkdtemp"):
            monkeypatch.setattr(tempfile, name, forbidden)
        response = http.post("/api/sign", headers=headers, **sign_form(identity, pdf=pdf))
    assert response.status_code == 200, response.text
    assert_all_signatures_ok(response.content, identity, expected=1)


def test_r31_over_capacity_is_503_without_reading_the_body(identity, monkeypatch):
    app = make_app(replace(SETTINGS, max_in_flight=1))
    started, release = threading.Event(), threading.Event()

    def blocking(*args, **kwargs):
        started.set()
        release.wait(10)
        return b"%PDF-1.7 fake"

    monkeypatch.setattr(server, "sign_pdf_multiple", blocking)
    read = []

    async def body():
        read.append(True)
        yield b"--x--"

    async def scenario():
        async with _async_client(app) as http:
            headers = {"Origin": ORIGIN, "X-ESign-Token": await _token(http)}
            first = asyncio.create_task(http.post("/api/sign", headers=headers, **sign_form(identity)))
            await asyncio.to_thread(started.wait, 10)
            second = await http.post("/api/sign", content=body(), headers={
                **headers, "Content-Type": "multipart/form-data; boundary=x"})
            release.set()
            return second, await first

    second, first = asyncio.run(scenario())
    assert second.status_code == 503
    assert read == []
    assert first.status_code == 200


def test_r31_client_cancellation_keeps_the_slot_until_the_worker_finishes(identity, monkeypatch):
    app = make_app(replace(SETTINGS, max_in_flight=1))
    started, release, finished = threading.Event(), threading.Event(), threading.Event()

    def blocking(*args, **kwargs):
        started.set()
        release.wait(10)
        finished.set()
        return b"%PDF-1.7 fake"

    monkeypatch.setattr(server, "sign_pdf_multiple", blocking)

    async def scenario():
        async with _async_client(app) as http:
            headers = {"Origin": ORIGIN, "X-ESign-Token": await _token(http)}
            task = asyncio.create_task(http.post("/api/sign", headers=headers, **sign_form(identity)))
            await asyncio.to_thread(started.wait, 10)
            task.cancel()  # the client goes away while the worker is signing
            with contextlib.suppress(asyncio.CancelledError):
                await task
            assert not finished.is_set()
            busy = await http.post("/api/certificate", headers=headers,
                                   files={"p12": ("c.p12", identity.p12)},
                                   data={"password": identity.password})
            assert busy.status_code == 503
            release.set()
            await asyncio.to_thread(finished.wait, 10)
            for _ in range(100):
                if app.state.gate.in_flight == 0:
                    break
                await asyncio.sleep(0.02)
            return await http.post("/api/certificate", headers=headers,
                                   files={"p12": ("c.p12", identity.p12)},
                                   data={"password": identity.password})

    after = asyncio.run(scenario())
    assert after.status_code == 200
    assert app.state.gate.in_flight == 0


def test_failed_parse_releases_the_slot(client):
    for _ in range(3):  # more than max_in_flight
        response = client.post("/api/sign", headers={
            **auth(client), "Content-Type": "multipart/form-data; boundary=abc"}, content=b"junk")
        assert response.status_code == 400
    assert client.app.state.gate.in_flight == 0


def test_r30_control_default_starlette_parser_would_spool_to_disk(monkeypatch):
    """Proves the R30 test is meaningful: the stock parser creates a temp file for the same size."""
    from starlette.datastructures import Headers

    body = (b'--x\r\nContent-Disposition: form-data; name="pdf"; filename="a.pdf"\r\n\r\n'
            + b"0" * (MultiPartParser.spool_max_size + 1) + b"\r\n--x--\r\n")

    async def stream():
        yield body

    def forbidden(*args, **kwargs):
        raise AssertionError("temporary file created")

    monkeypatch.setattr(tempfile, "TemporaryFile", forbidden)
    headers = Headers({"content-type": "multipart/form-data; boundary=x"})
    with pytest.raises(AssertionError, match="temporary file"):
        asyncio.run(MultiPartParser(headers, stream()).parse())
    form = asyncio.run(server.InMemoryMultiPartParser(
        headers, stream(), spool_max_size=len(body) + 1).parse())
    assert form["pdf"].size == MultiPartParser.spool_max_size + 1


def test_port_80_page_origin_is_accepted(identity):
    with TestClient(make_app(replace(SETTINGS, port=80)), base_url="http://127.0.0.1") as http:
        response = http.post("/api/sign", headers=auth(http, origin="http://127.0.0.1"),
                             **sign_form(identity))
    assert response.status_code == 200


def test_deeply_nested_placements_json_is_400_not_500(identity):
    # json raises RecursionError somewhere past ~100k levels depending on the Python build; a
    # larger ESIGN_MAX_PLACEMENTS raises the field cap enough to get there.
    settings = Settings(max_placements=10_000)
    depth = 600_000
    assert 2 * depth <= settings.max_field_bytes
    with TestClient(make_app(settings), base_url=BASE) as http:
        response = http.post("/api/sign", headers=auth(http),
                             **sign_form(identity, placements="[" * depth + "]" * depth))
        assert http.app.state.gate.in_flight == 0
    assert response.status_code == 400
    assert response.json()["error"] == "Placements are not valid JSON."


def test_stalled_upload_times_out_with_408_and_frees_the_slot(identity):
    app = make_app(replace(SETTINGS, max_in_flight=1, body_timeout_s=0.3))

    async def stalled():
        yield (b'--x\r\nContent-Disposition: form-data; name="pdf"; filename="a.pdf"\r\n'
               b"Content-Type: application/pdf\r\n\r\n%PDF-1.7")
        await asyncio.sleep(30)  # the client stops sending

    async def scenario():
        async with _async_client(app) as http:
            headers = {"Origin": ORIGIN, "X-ESign-Token": await _token(http)}
            started = time.monotonic()
            stuck = await http.post("/api/sign", content=stalled(), headers={
                **headers, "Content-Type": "multipart/form-data; boundary=x"})
            elapsed = time.monotonic() - started
            after = await http.post("/api/certificate", headers=headers,
                                    files={"p12": ("c.p12", identity.p12)},
                                    data={"password": identity.password})
            return stuck, elapsed, after

    stuck, elapsed, after = asyncio.run(scenario())
    assert stuck.status_code == 408
    assert elapsed < 5
    assert after.status_code == 200
    assert app.state.gate.in_flight == 0
