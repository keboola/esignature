"""Explicit certificate trust, opt-in CRL checks and bounded configured RFC3161 requests.

No certificate, signature or PDF can nominate a network endpoint. Validation contexts never
fetch AIA/CDP/OCSP URLs; only the operator's configured HTTPS CRL/TSA URLs are contacted.
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlsplit

import aiohttp
from asn1crypto import crl, pem, tsp, x509
from pyhanko.sign.general import extract_certificate_info
from pyhanko.sign.timestamps.api import TimeStamper
from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp
from pyhanko.sign.validation.generic_cms import extract_tst_data_iter
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import (
    InvalidCertificateError,
    PathBuildingError,
    PathValidationError,
    RevokedError,
)
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)

REQUEST_TIMEOUT_SECONDS = 10
CRL_BATCH_TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_CRL_URLS = 8
TIMESTAMP_JOB_TIMEOUT_SECONDS = 60


class NetworkPolicyError(ValueError):
    """Safe error for a configured service which did not return a bounded valid response."""


def validate_service_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
            and parsed.port != 0
        )
    except (TypeError, ValueError):
        valid = False
    if not valid or any(c.isspace() or ord(c) < 32 for c in url):
        raise ValueError("Service URLs must be HTTPS URLs without embedded credentials or fragments.")
    return url


@dataclass(frozen=True)
class ValidationPolicy:
    trust_roots: Tuple[x509.Certificate, ...] = ()
    intermediates: Tuple[x509.Certificate, ...] = ()
    crl_urls: Tuple[str, ...] = ()
    tsa_trust_roots: Tuple[x509.Certificate, ...] = ()

    def __post_init__(self):
        if len(self.crl_urls) > MAX_CRL_URLS:
            raise ValueError(f"At most {MAX_CRL_URLS} CRL service URLs may be configured.")
        for url in self.crl_urls:
            validate_service_url(url)

    @property
    def timestamp_roots(self):
        return self.tsa_trust_roots or self.trust_roots


@dataclass(frozen=True)
class TimestampConfig:
    url: str
    validation_policy: ValidationPolicy
    username: Optional[str] = field(default=None, repr=False)
    password: Optional[str] = field(default=None, repr=False)

    def __post_init__(self):
        validate_service_url(self.url)
        if not self.validation_policy.timestamp_roots:
            raise ValueError("Timestamping requires explicitly configured TSA trust roots.")


def _load_certificates(path):
    if path is None:
        return ()
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise ValueError
        entries = list(pem.unarmor(data, multiple=True))
        if not entries or any(kind != "CERTIFICATE" for kind, _, _ in entries):
            raise ValueError
        return tuple(x509.Certificate.load(der, strict=True) for _, _, der in entries)
    except (OSError, ValueError, TypeError) as e:
        raise ValueError("A configured certificate bundle is not a readable PEM certificate file.") from e


def load_validation_policy(
    trust_roots_path=None,
    intermediates_path=None,
    tsa_trust_roots_path=None,
    crl_urls=(),
) -> ValidationPolicy:
    return ValidationPolicy(
        trust_roots=_load_certificates(trust_roots_path),
        intermediates=_load_certificates(intermediates_path),
        tsa_trust_roots=_load_certificates(tsa_trust_roots_path),
        crl_urls=tuple(crl_urls),
    )


async def fetch_service(url, *, data=None, username=None, password=None, timestamp=False):
    """One configured HTTPS endpoint, no redirects/proxies/decompression, with total deadline."""
    validate_service_url(url)
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS, connect=5, sock_read=5)
    auth = aiohttp.BasicAuth(username, password or "") if username is not None else None
    headers = {"Accept-Encoding": "identity"}
    if timestamp:
        headers.update(
            {"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"}
        )
    try:
        async with aiohttp.ClientSession(
            timeout=timeout,
            trust_env=False,
            auto_decompress=False,
            cookie_jar=aiohttp.DummyCookieJar(),
        ) as session:
            async with session.request(
                "POST" if data is not None else "GET",
                url,
                data=data,
                auth=auth,
                headers=headers,
                allow_redirects=False,
            ) as response:
                if response.status != 200:
                    raise NetworkPolicyError("The configured service did not return a successful response.")
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise NetworkPolicyError("Compressed service responses are not accepted.")
                if timestamp and response.content_type != "application/timestamp-reply":
                    raise NetworkPolicyError("The timestamp service returned an unexpected response format.")
                if response.content_length is not None and response.content_length > MAX_RESPONSE_BYTES:
                    raise NetworkPolicyError("The service response is too large.")
                content = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    content.extend(chunk)
                    if len(content) > MAX_RESPONSE_BYTES:
                        raise NetworkPolicyError("The service response is too large.")
                return bytes(content)
    except (aiohttp.ClientError, TimeoutError, OSError) as e:
        raise NetworkPolicyError(
            "The configured service could not be reached securely within the time limit."
        ) from e


def validation_context(policy, *, tsa=False, crls=(), check_revocation=False):
    rule = RevocationCheckingRule.CRL_REQUIRED if check_revocation else RevocationCheckingRule.NO_CHECK
    return ValidationContext(
        trust_roots=list(policy.timestamp_roots if tsa else policy.trust_roots),
        other_certs=list(policy.intermediates),
        allow_fetching=False,
        crls=list(crls),
        ocsps=[],
        revinfo_policy=CertRevTrustPolicy(RevocationCheckingPolicy(rule, rule)),
    )


def verdict(status, message, checked_at=None):
    return {"status": status, "checked_at": checked_at, "message": message}


async def fetch_crls(policy):
    results = []

    async def fetch_all():
        for url in policy.crl_urls:
            try:
                body = await fetch_service(url)
                if pem.detect(body):
                    kind, _, body = pem.unarmor(body)
                    if kind not in ("X509 CRL", "CRL"):
                        continue
                results.append(crl.CertificateList.load(body, strict=True))
            except (NetworkPolicyError, ValueError, TypeError):
                continue

    try:
        async with asyncio.timeout(CRL_BATCH_TIMEOUT_SECONDS):
            await fetch_all()
    except TimeoutError:
        pass
    return tuple(results)


async def check_certificate(cert, embedded_certs, policy, *, tsa=False, online=False, crls=()):
    checked = datetime.now(timezone.utc).isoformat()
    roots = policy.timestamp_roots if tsa else policy.trust_roots
    revocation = verdict("not_checked", "Revocation was not checked.")
    if not roots:
        return verdict("not_checked", "No explicit trust roots are configured."), revocation

    async def validate(revocation_required):
        validator = CertificateValidator(
            cert,
            intermediate_certs=embedded_certs,
            validation_context=validation_context(
                policy, tsa=tsa, crls=crls, check_revocation=revocation_required
            ),
        )
        if tsa:
            return await validator.async_validate_usage(set(), {"time_stamping"})
        usages = cert.key_usage_value
        if usages is not None and not usages.native.intersection({"digital_signature", "non_repudiation"}):
            raise ValueError("Certificate cannot be used for document signing.")
        return await validator.async_validate_path()

    try:
        await validate(False)
        trust = verdict("trusted", "Certificate chain validates to an explicitly configured root.", checked)
    except (InvalidCertificateError, PathBuildingError, PathValidationError, ValueError):
        return verdict(
            "untrusted", "Certificate chain or current validity could not be validated.", checked
        ), revocation
    except Exception:  # noqa: BLE001 - an unsupported certificate does not become trusted
        return verdict("unknown", "Certificate chain could not be checked.", checked), revocation
    if online:
        if not policy.crl_urls:
            revocation = verdict("unknown", "No CRL service URLs are configured.", checked)
        else:
            try:
                await validate(True)
                revocation = verdict("good", "Fresh signed CRLs cover the certificate chain.", checked)
            except RevokedError:
                revocation = verdict(
                    "revoked", "A signed CRL reports a certificate in this chain as revoked.", checked
                )
            except Exception:  # noqa: BLE001 - missing, stale or invalid CRLs never count as good
                revocation = verdict(
                    "unknown", "Fresh valid CRLs for the complete chain are unavailable.", checked
                )
    return trust, revocation


def timestamp_details(sig, policy, *, online=False, crls=()):
    not_checked = verdict("not_checked", "Certificate trust was not checked.")
    result = {
        "status": "absent",
        "time": None,
        "certificate_trust": not_checked,
        "revocation": verdict("not_checked", "Revocation was not checked."),
        "message": "No cryptographic timestamp is present.",
    }
    try:
        is_document_timestamp = sig.sig_object_type == "/DocTimeStamp"
        tokens = (
            [sig.signed_data]
            if is_document_timestamp
            else list(extract_tst_data_iter(sig.signer_info, signed=False))
        )
        if not tokens:
            return result
        result.update(status="unknown", message="The timestamp could not be checked.")
        if len(tokens) != 1:
            return result
        ts_context = validation_context(policy, tsa=True)
        if is_document_timestamp:
            status = validate_pdf_timestamp(sig, ts_context)
        else:
            signature_status = validate_pdf_signature(
                sig,
                validation_context(ValidationPolicy()),
                ts_validation_context=ts_context,
            )
            status = signature_status.timestamp_validity
        if status is None:
            return result
        result["time"] = status.timestamp.isoformat()
        certificates = extract_certificate_info(tokens[0])
        trust, revocation = asyncio.run(
            check_certificate(
                status.signing_cert,
                certificates.other_certs,
                policy,
                tsa=True,
                online=online,
                crls=crls,
            )
        )
        if (
            policy.timestamp_roots
            and not status.signing_cert.not_valid_before
            <= status.timestamp
            <= status.signing_cert.not_valid_after
        ):
            trust = verdict(
                "untrusted",
                "The TSA certificate was not valid at the timestamp time.",
                datetime.now(timezone.utc).isoformat(),
            )
        result.update(certificate_trust=trust, revocation=revocation)
        # pyHanko validates the CMS and binds the token to the signature bytes (or PDF digest).
        if (
            not status.intact
            or not status.valid
            or status.timestamp > datetime.now(timezone.utc) + timedelta(minutes=5)
        ):
            result.update(status="invalid", message="The timestamp signature or message binding is invalid.")
        else:
            result.update(
                status="valid", message="The cryptographic timestamp and message binding are valid."
            )
    except Exception:  # noqa: BLE001 - unsupported tokens remain explicitly unknown
        result.update(status="unknown", message="The timestamp could not be checked.")
    return result


def signature_security_details(sig, policy, *, online=False, crls=()):
    trust, revocation = asyncio.run(
        check_certificate(
            sig.signer_cert,
            sig.other_embedded_certs,
            policy,
            tsa=sig.sig_object_type == "/DocTimeStamp",
            online=online,
            crls=crls,
        )
    )
    return {
        "certificate_trust": trust,
        "revocation": revocation,
        "timestamp": timestamp_details(sig, policy, online=online, crls=crls),
    }


class ConfiguredTimeStamper(TimeStamper):
    def __init__(self, config: TimestampConfig):
        super().__init__(include_nonce=True)
        self.config = config
        self.deadline = time.monotonic() + TIMESTAMP_JOB_TIMEOUT_SECONDS

    async def async_request_tsa_response(self, req):
        try:
            started_at = datetime.now(timezone.utc)
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            async with asyncio.timeout(remaining):
                body = await fetch_service(
                    self.config.url,
                    data=req.dump(),
                    username=self.config.username,
                    password=self.config.password,
                    timestamp=True,
                )
            response = tsp.TimeStampResp.load(body, strict=True)
            if response["status"]["status"].native != "granted":
                raise ValueError
            info = response["time_stamp_token"]["content"]["encap_content_info"]["content"].parsed
            generated_at = info["gen_time"].native
            received_at = datetime.now(timezone.utc)
            if not started_at - timedelta(minutes=5) <= generated_at <= received_at + timedelta(minutes=5):
                raise ValueError
            expected, actual = req["message_imprint"], info["message_imprint"]
            if (
                expected["hash_algorithm"]["algorithm"].native != actual["hash_algorithm"]["algorithm"].native
                or expected["hashed_message"].native != actual["hashed_message"].native
                or req["nonce"].native != info["nonce"].native
            ):
                raise ValueError
            return response
        except Exception as e:  # noqa: BLE001 - no remote error text, URL, nonce or password in user errors
            raise NetworkPolicyError(
                "The timestamp service did not return a valid matching timestamp response."
            ) from e
