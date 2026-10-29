"""Local web app: serves the editor frontend and the signing API on loopback.

Security boundary (one origin, one user, one machine):
- binds to loopback only (config), and rejects any other Host header (DNS rebinding);
- every non-GET request needs the exact page Origin and the per-launch ``X-ESign-Token`` that is
  embedded in the served index.html; no CORS;
- request bodies are capped while they stream in (413 even without Content-Length), multipart
  parts stay in memory, and at most ``max_in_flight`` requests are admitted before parsing;
- all PyMuPDF/pyHanko work runs on one dedicated worker thread; an admission slot is released
  only when that worker finishes, even if the client went away;
- responses carry ``Cache-Control: no-store`` and a restrictive CSP; nothing is logged about
  request contents and error bodies never echo the password.
"""

import asyncio
import hmac
import json
import logging
import mimetypes
import secrets
import sys
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.formparsers import MultiPartException, MultiPartParser
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import ClientDisconnect
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from config import LOOPBACK_HOSTS, ConfigError, Settings, load_settings
from geometry import PlacementError
from signer import (
    CertificateValidationError,
    PdfInputError,
    SigningError,
    get_certificate_info,
    get_initials,
    get_signer_name_from_signer,
    load_signer_from_p12,
    sanitize_signer_name,
    sign_pdf_multiple,
    validate_certificate,
)

logger = logging.getLogger("esignature")

ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
FONTS_DIR = ROOT / "fonts"
TOKEN_PLACEHOLDER = "__ESIGN_TOKEN__"

mimetypes.add_type("text/javascript", ".mjs")
mimetypes.add_type("application/wasm", ".wasm")

# PDF.js needs a module worker from 'self' and compiles its own WASM decoders.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; "
    "style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

SAFE_METHODS = {"GET", "HEAD"}


# --- Errors ------------------------------------------------------------------------------------

class ApiError(Exception):
    """An error with an HTTP status and a message that is safe to show to the user."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def error_response(status: int, message: str, code: Optional[str] = None) -> JSONResponse:
    """JSON error body {error, code?}; ``code`` is a machine-readable reason for the frontend."""
    body = {"error": message}
    if code:
        body["code"] = code
    return JSONResponse(body, status_code=status)


async def _send_error(send: Send, status: int, message: str) -> None:
    body = json.dumps({"error": message}).encode()
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


# --- ASGI middleware ---------------------------------------------------------------------------

class SecurityHeadersMiddleware:
    """Adds no-store caching, CSP and related headers to every response."""

    HEADERS = [
        (b"cache-control", b"no-store"),
        (b"content-security-policy", CONTENT_SECURITY_POLICY.encode()),
        (b"x-content-type-options", b"nosniff"),
        (b"referrer-policy", b"no-referrer"),
        (b"cross-origin-opener-policy", b"same-origin"),
        (b"cross-origin-resource-policy", b"same-origin"),
    ]

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                names = {name for name, _ in self.HEADERS}
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in names]
                message = {**message, "headers": headers + self.HEADERS}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestGuardMiddleware:
    """Non-GET requests need the exact page Origin and the per-launch token, checked before the body."""

    def __init__(self, app: ASGIApp, allowed_origins: frozenset, token: str) -> None:
        self.app = app
        self.allowed_origins = allowed_origins
        self.token = token.encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] not in SAFE_METHODS:
            headers = dict(scope["headers"])
            origin = headers.get(b"origin", b"").decode("latin-1")
            token = headers.get(b"x-esign-token", b"")
            if origin not in self.allowed_origins:
                await _send_error(send, 403, "Requests must come from the eSignature page.")
                return
            if not hmac.compare_digest(token, self.token):
                await _send_error(send, 403, "This page is out of date. Reload it and try again.")
                return
        await self.app(scope, receive, send)


class BodyTooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """Caps the request body while it streams in, with or without Content-Length."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    def _message(self) -> str:
        return f"The upload is too large (limit {self.max_bytes // (1024 * 1024)} MB in total)."

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                await _send_error(send, 400, "Invalid Content-Length.")
                return
            if length > self.max_bytes:
                await _send_error(send, 413, self._message())
                return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise BodyTooLarge()
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except BodyTooLarge:
            if not response_started:
                await _send_error(send, 413, self._message())


# --- Admission and the worker thread -----------------------------------------------------------

class SigningGate:
    """Bounded admission plus one dedicated worker thread for all PDF/crypto work.

    PyMuPDF must not be used from several threads at once, so the executor has one worker.
    A slot taken by :meth:`try_acquire` is released either by the caller (if no job was submitted)
    or by the job's completion callback, never by the awaiting coroutine being cancelled.
    """

    def __init__(self, max_in_flight: int) -> None:
        self._lock = threading.Lock()
        self._max = max_in_flight
        self._in_flight = 0
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="esign-worker")

    @property
    def in_flight(self) -> int:
        with self._lock:
            return self._in_flight

    def try_acquire(self) -> bool:
        with self._lock:
            if self._in_flight >= self._max:
                return False
            self._in_flight += 1
            return True

    def release(self) -> None:
        with self._lock:
            self._in_flight -= 1

    def submit(self, job: Callable[[], Any]) -> Future:
        """Run ``job`` on the worker; its slot is released when it finishes or is cancelled unstarted."""
        future = self._executor.submit(job)
        future.add_done_callback(lambda _: self.release())
        return future

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


class InMemoryMultiPartParser(MultiPartParser):
    """Starlette's parser with a spool threshold above the request cap, so files never hit disk."""

    def __init__(self, *args: Any, spool_max_size: int, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.spool_max_size = spool_max_size


async def read_form(
    request: Request, settings: Settings, files: Set[str], fields: Set[str]
) -> Dict[str, Any]:
    """Parse the multipart body into {name: bytes | str}; every name at most once, none unknown."""
    content_type = request.headers.get("content-type", "")
    if not content_type.lower().startswith("multipart/form-data"):
        raise ApiError(400, "Expected a multipart form upload.")
    parser = InMemoryMultiPartParser(
        request.headers, request.stream(),
        max_files=len(files), max_fields=len(fields),
        max_part_size=settings.max_field_bytes,
        spool_max_size=settings.max_request_bytes + 1,
    )
    try:
        # A client that stops sending must not hold an admission slot forever.
        form = await asyncio.wait_for(parser.parse(), timeout=settings.body_timeout_s)
    except TimeoutError:
        raise ApiError(408, "The upload took too long. Try again.") from None
    except MultiPartException:
        raise ApiError(400, "The upload could not be read.") from None
    except BodyTooLarge:
        raise ApiError(413, f"The upload is too large "
                            f"(limit {settings.max_request_bytes // (1024 * 1024)} MB in total).") from None

    result: Dict[str, Any] = {}
    try:
        for name, value in form.multi_items():
            if name not in files and name not in fields:
                raise ApiError(400, f"Unexpected field: {name[:40]}")
            if name in result:
                raise ApiError(400, f"Field sent more than once: {name}")
            if name in files:
                if isinstance(value, str):
                    raise ApiError(400, f"Field {name} must be a file.")
                result[name] = await value.read()
            else:
                if not isinstance(value, str):
                    raise ApiError(400, f"Field {name} must not be a file.")
                result[name] = value
    finally:
        await form.close()
    return result


def require(form: Dict[str, Any], name: str) -> Any:
    if name not in form:
        raise ApiError(422, f"Missing field: {name}")
    return form[name]


def parse_flag(form: Dict[str, Any], name: str) -> bool:
    value = form.get(name, "false")
    if value not in ("true", "false"):
        raise ApiError(400, f"Field {name} must be 'true' or 'false'.")
    return value == "true"


def parse_placements(raw: str) -> Any:
    def reject_constant(_: str) -> None:
        raise ValueError("non-finite number")

    try:
        return json.loads(raw, parse_constant=reject_constant)
    except (ValueError, RecursionError):  # RecursionError: absurdly deep nesting
        raise ApiError(400, "Placements are not valid JSON.") from None


def check_size(data: bytes, limit: int, what: str) -> None:
    if len(data) > limit:
        if limit >= 1024 * 1024:
            pretty = f"{limit // (1024 * 1024)} MB"
        else:
            pretty = f"{limit // 1024} KB"
        raise ApiError(413, f"The {what} is larger than the {pretty} limit.")


async def run_admitted(
    request: Request,
    files: Set[str],
    fields: Set[str],
    prepare: Callable[[Dict[str, Any]], Callable[[], Response]],
) -> Response:
    """Admit, parse, validate (``prepare``), then run the returned job on the worker thread."""
    app_state = request.app.state
    gate: SigningGate = app_state.gate
    if not gate.try_acquire():
        return error_response(503, "The signer is busy with another request. Try again in a moment.")
    handed_off = False
    try:
        form = await read_form(request, app_state.settings, files, fields)
        job = prepare(form)
        future = gate.submit(job)
        handed_off = True
        return await asyncio.wrap_future(future)
    except ApiError as e:
        return error_response(e.status, e.message)
    except PdfInputError as e:
        return error_response(400, str(e), e.code)
    except (CertificateValidationError, PlacementError) as e:
        return error_response(400, str(e))
    except SigningError as e:
        return error_response(500, str(e))
    except ClientDisconnect:
        return error_response(400, "The upload was interrupted.")
    except Exception as e:  # noqa: BLE001 - boundary: never leak internals or inputs
        logger.error("Unexpected error in %s: %s", request.url.path, type(e).__name__)
        return error_response(500, "Something went wrong. Please try again.")
    finally:
        if not handed_off:
            gate.release()


# --- Jobs (run on the worker thread) -----------------------------------------------------------

def certificate_job(p12: bytes, password: str) -> Callable[[], Response]:
    def job() -> Response:
        try:
            signer = load_signer_from_p12(p12, password)
            validate_certificate(signer)
            info = get_certificate_info(signer)
            name = sanitize_signer_name(get_signer_name_from_signer(signer))
        except SigningError:
            raise
        except Exception as e:  # noqa: BLE001 - unreadable certificate details
            logger.warning("Certificate could not be read: %s", type(e).__name__)
            raise CertificateValidationError("The certificate could not be read.") from None
        return JSONResponse({
            "name": name,
            "initials": get_initials(name),
            "organization": info["subject_org"],
            "issuer": info["issuer_cn"],
            "valid_from": info["valid_from"],
            "valid_to": info["valid_to"],
        })

    return job


def sign_job(
    pdf: bytes, p12: bytes, password: str, placements: Any, lock: bool, protocol: bool,
    settings: Settings,
) -> Callable[[], Response]:
    def job() -> Response:
        signed = sign_pdf_multiple(
            pdf, p12, password, placements,
            lock_after_signing=lock, add_protocol_page=protocol,
            max_placements=settings.max_placements,
            max_existing_signatures=settings.max_existing_signatures,
        )
        return Response(signed, media_type="application/pdf",
                        headers={"Content-Disposition": 'attachment; filename="signed.pdf"'})

    return job


# --- App ---------------------------------------------------------------------------------------

def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or Settings()
    gate = SigningGate(settings.max_in_flight)
    token = secrets.token_urlsafe(32)
    index_html = (STATIC_DIR / "index.html").read_text(encoding="utf-8").replace(TOKEN_PLACEHOLDER, token)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        gate.shutdown()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.gate = gate
    app.state.token = token

    @app.get("/", include_in_schema=False)
    async def index() -> HTMLResponse:
        return HTMLResponse(index_html)

    @app.post("/api/certificate")
    async def certificate(request: Request) -> Response:
        def prepare(form: Dict[str, Any]) -> Callable[[], Response]:
            p12 = require(form, "p12")
            password = require(form, "password")
            check_size(p12, settings.max_p12_bytes, "certificate file")
            return certificate_job(p12, password)

        return await run_admitted(request, {"p12"}, {"password"}, prepare)

    @app.post("/api/sign")
    async def sign(request: Request) -> Response:
        def prepare(form: Dict[str, Any]) -> Callable[[], Response]:
            pdf = require(form, "pdf")
            p12 = require(form, "p12")
            password = require(form, "password")
            placements = parse_placements(require(form, "placements"))
            lock = parse_flag(form, "lock")
            protocol = parse_flag(form, "protocol")
            check_size(pdf, settings.max_pdf_bytes, "PDF")
            check_size(p12, settings.max_p12_bytes, "certificate file")
            return sign_job(pdf, p12, password, placements, lock, protocol, settings)

        return await run_admitted(
            request, {"pdf", "p12"}, {"password", "placements", "lock", "protocol"}, prepare)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.mount("/fonts", StaticFiles(directory=FONTS_DIR), name="fonts")

    # Outermost last: headers on every response, then Host, then Origin/token, then body cap.
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(RequestGuardMiddleware, allowed_origins=settings.allowed_origins, token=token)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(LOOPBACK_HOSTS))
    app.add_middleware(SecurityHeadersMiddleware)
    return app


def main() -> None:
    """Entry point for ``uv run esignature``."""
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    # Validating existing signatures without trusting their certificates makes pyHanko log every
    # untrusted chain with the signers' names; that is document content, which is not logged.
    for name in ("pyhanko", "pyhanko_certvalidator"):
        logging.getLogger(name).setLevel(logging.ERROR)
    try:
        settings = load_settings()
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(2)
    print(f"Keboola eSignature is running at http://{settings.host}:{settings.port}", flush=True)
    uvicorn.run(
        create_app(settings), host=settings.host, port=settings.port,
        access_log=False, server_header=False, log_level="warning", workers=1,
    )


if __name__ == "__main__":
    main()
