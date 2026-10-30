"""Generated PKI/CRLs and local RFC3161 responses; never real user keys or remote services."""

import asyncio
import datetime
import io
from dataclasses import dataclass, replace

import pytest
from asn1crypto import crl, keys, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper

import certificate_validation as cv
from signer import SigningError, sign_pdf_multiple, validate_pdf_document
from tests.conftest import Identity, make_pdf
from tests.signed_fixtures import sign_as, signed_linearized_layout

NOW = datetime.datetime.now(datetime.timezone.utc)
URLS = ("https://pki.test/root.crl", "https://pki.test/issuer.crl")


@dataclass
class Authority:
    key: object
    cert: x509.Certificate

    @property
    def asn1_cert(self):
        return asn1_x509.Certificate.load(self.cert.public_bytes(serialization.Encoding.DER))


def issue(name, issuer=None, *, ca=False, tsa=False, start=-1, end=365):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.cert.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW + datetime.timedelta(days=start))
        .not_valid_after(NOW + datetime.timedelta(days=end))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer.key.public_key() if issuer else key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=not ca and not tsa,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if tsa:
        cert = cert.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
    if not ca:
        # Hostile certificate-controlled URLs must never be consulted, even in online mode.
        cert = cert.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier("https://attacker.invalid/issuer"),
                    ),
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("https://attacker.invalid/ocsp"),
                    ),
                ]
            ),
            critical=False,
        ).add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        [x509.UniformResourceIdentifier("https://attacker.invalid/issuer.crl")],
                        None,
                        None,
                        None,
                    ),
                ]
            ),
            critical=False,
        )
    return Authority(key, cert.sign(issuer.key if issuer else key, hashes.SHA256()))


def identity_of(authority):
    p12 = pkcs12.serialize_key_and_certificates(
        b"test",
        authority.key,
        authority.cert,
        None,
        serialization.BestAvailableEncryption(b"generated-only"),
    )
    return Identity(authority.key, authority.cert, p12, "generated-only")


def make_crl(issuer, revoked=(), *, stale=False, bad_signature=False):
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.cert.subject)
        .last_update(NOW - datetime.timedelta(days=3) if stale else NOW - datetime.timedelta(hours=1))
        .next_update(NOW - datetime.timedelta(days=1) if stale else NOW + datetime.timedelta(days=1))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False
        )
        .add_extension(x509.CRLNumber(1), critical=False)
    )
    for cert in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(cert.serial_number)
            .revocation_date(NOW - datetime.timedelta(minutes=30))
            .build()
        )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if bad_signature else issuer.key
    return crl.CertificateList.load(
        builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    )


@pytest.fixture(scope="module")
def pki():
    root = issue("Configured root", ca=True)
    intermediate = issue("Configured intermediate", root, ca=True)
    leaf = issue("Document signer", intermediate)
    tsa = issue("Timestamp authority", intermediate, tsa=True)
    return root, intermediate, leaf, tsa


def policy_for(pki):
    root, intermediate, _, _ = pki
    return cv.ValidationPolicy((root.asn1_cert,), (intermediate.asn1_cert,), URLS)


def check(authority, policy, **kwargs):
    return asyncio.run(cv.check_certificate(authority.asn1_cert, (), policy, **kwargs))


def test_explicit_root_and_intermediate_chain_and_no_system_fallback(pki):
    root, intermediate, leaf, _ = pki
    trust, rev = check(leaf, policy_for(pki))
    assert trust["status"] == "trusted" and trust["checked_at"]
    assert rev["status"] == "not_checked"
    assert check(leaf, cv.ValidationPolicy())[0]["status"] == "not_checked"
    assert check(leaf, cv.ValidationPolicy((root.asn1_cert,)))[0]["status"] == "untrusted"
    wrong = issue("Wrong root", ca=True)
    assert (
        check(leaf, cv.ValidationPolicy((wrong.asn1_cert,), (intermediate.asn1_cert,)))[0]["status"]
        == "untrusted"
    )


@pytest.mark.parametrize("start,end", [(-10, -1), (1, 10)])
def test_expired_or_future_certificate_does_not_validate(pki, start, end):
    leaf = issue("Outside validity", pki[1], start=start, end=end)
    assert check(leaf, policy_for(pki))[0]["status"] == "untrusted"


@pytest.mark.parametrize(
    "case,expected",
    [
        ("good", "good"),
        ("revoked", "revoked"),
        ("revoked-intermediate", "revoked"),
        ("stale", "unknown"),
        ("bad-signature", "unknown"),
        ("wrong-issuer", "unknown"),
        ("missing-intermediate-status", "unknown"),
        ("missing", "unknown"),
    ],
)
def test_crls_require_valid_fresh_status_for_the_complete_chain(pki, case, expected):
    root, intermediate, leaf, _ = pki
    root_crl = make_crl(root, [intermediate.cert] if case == "revoked-intermediate" else [])
    leaf_crl = make_crl(
        intermediate,
        [leaf.cert] if case == "revoked" else [],
        stale=case == "stale",
        bad_signature=case == "bad-signature",
    )
    if case == "wrong-issuer":
        leaf_crl = make_crl(issue("Unrelated CA", ca=True))
    crls = (root_crl, leaf_crl)
    if case == "missing-intermediate-status":
        crls = (leaf_crl,)
    elif case == "missing":
        crls = ()
    trust, revocation = check(leaf, policy_for(pki), online=True, crls=crls)
    assert trust["status"] == "trusted"  # mathematical chain validity is reported separately
    assert revocation["status"] == expected


def test_policy_loads_pem_bundles_and_rejects_keys_or_invalid_urls(pki, tmp_path):
    roots, intermediates = tmp_path / "roots.pem", tmp_path / "intermediates.pem"
    roots.write_bytes(pki[0].cert.public_bytes(serialization.Encoding.PEM))
    intermediates.write_bytes(pki[1].cert.public_bytes(serialization.Encoding.PEM))
    policy = cv.load_validation_policy(roots, intermediates, crl_urls=URLS)
    assert [cert.dump() for cert in policy.trust_roots] == [pki[0].asn1_cert.dump()]
    assert [cert.dump() for cert in policy.intermediates] == [pki[1].asn1_cert.dump()]
    roots.write_text("not a certificate")
    with pytest.raises(ValueError, match="PEM"):
        cv.load_validation_policy(roots)
    for url in (
        "http://pki.test/a",
        "https://user:password@pki.test/a",
        "file:///tmp/a",
        "https://pki.test/#x",
    ):
        with pytest.raises(ValueError):
            cv.ValidationPolicy(crl_urls=(url,))


def test_validation_contacts_only_configured_crls_after_opt_in(pki, monkeypatch):
    root, intermediate, leaf, _ = pki
    responses = dict(zip(URLS, [make_crl(root).dump(), make_crl(intermediate).dump()], strict=True))
    calls = []

    async def forbidden_request(*args, **kwargs):
        pytest.fail("A certificate-controlled network request was attempted")

    async def fetch(url, **kwargs):
        calls.append(url)
        return responses[url]

    monkeypatch.setattr(cv, "fetch_service", fetch)
    monkeypatch.setattr(cv.aiohttp.ClientSession, "_request", forbidden_request)
    signed = sign_as(make_pdf(), identity_of(leaf))
    policy = policy_for(pki)
    offline = validate_pdf_document(signed, validation_policy=policy)
    assert not calls
    assert offline["signatures"][0]["certificate_trust"]["status"] == "trusted"
    assert offline["signatures"][0]["revocation"]["status"] == "not_checked"
    online = validate_pdf_document(signed, validation_policy=policy, online_revocation=True)
    assert calls == list(URLS)
    assert online["signatures"][0]["revocation"]["status"] == "good"
    assert online["signatures"][0]["timestamp"]["status"] == "absent"


def dummy_tsa(pki):
    tsa = pki[3]
    private_key = keys.PrivateKeyInfo.load(
        tsa.key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return DummyTimeStamper(tsa.asn1_cert, private_key)


def install_tsa(monkeypatch, pki, failure=None):
    tsa = dummy_tsa(pki)
    if failure == "backdated":
        tsa.fixed_dt = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
    elif failure == "future":
        tsa.fixed_dt = NOW + datetime.timedelta(hours=1)
    calls = []

    async def fetch(url, **kwargs):
        calls.append((url, kwargs))
        if failure == "timeout":
            raise cv.NetworkPolicyError("Service timeout")
        req = tsp.TimeStampReq.load(kwargs["data"])
        if failure == "nonce":
            req["nonce"] = req["nonce"].native + 1
        if failure == "imprint":
            req["message_imprint"]["hashed_message"] = b"x" * len(
                req["message_imprint"]["hashed_message"].native
            )
        response = tsa.request_tsa_response(req)
        if failure == "signature":
            info = response["time_stamp_token"]["content"]["signer_infos"][0]
            info["signature"] = b"x" * len(info["signature"].native)
        return response.dump()

    monkeypatch.setattr(cv, "fetch_service", fetch)
    return calls


@pytest.mark.parametrize("existing", [False, True], ids=["unsigned", "linearized-counter-sign"])
def test_every_new_signature_gets_a_verified_timestamp(pki, identity, monkeypatch, existing):
    calls = install_tsa(monkeypatch, pki)
    config = cv.TimestampConfig("https://tsa.test/", policy_for(pki))
    original = signed_linearized_layout(identity) if existing else make_pdf()
    output = sign_pdf_multiple(
        original,
        identity.p12,
        identity.password,
        [
            {"page": 0, "type": "signature", "x": 100, "y": 100},
            {"page": 0, "type": "signature", "x": 100, "y": 200},
        ],
        timestamp_config=config,
    )
    assert len(calls) == 3  # one cached sizing response plus each real signature's token
    if existing:
        assert output.startswith(original)
    report = validate_pdf_document(output, validation_policy=policy_for(pki))
    assert report["can_countersign"]
    added = report["signatures"][-2:]
    assert all(sig["timestamp"]["status"] == "valid" for sig in added)
    assert all(sig["timestamp"]["certificate_trust"]["status"] == "trusted" for sig in added)
    assert all(sig["integrity"] == sig["cryptography"] == "valid" for sig in report["signatures"])


@pytest.mark.parametrize(
    "failure", ["nonce", "imprint", "signature", "untrusted", "timeout", "backdated", "future"]
)
def test_requested_timestamp_failure_never_returns_an_untimestamped_file(
    pki,
    identity,
    monkeypatch,
    failure,
    caplog,
):
    install_tsa(monkeypatch, pki, failure)
    policy = policy_for(pki)
    if failure == "untrusted":
        policy = replace(policy, tsa_trust_roots=(issue("Wrong TSA root", ca=True).asn1_cert,))
    config = cv.TimestampConfig("https://tsa.test/", policy, username="test", password="secret-tsa-password")
    with pytest.raises(SigningError, match="Timestamping failed") as exc:
        sign_pdf_multiple(
            make_pdf(),
            identity.p12,
            identity.password,
            [{"page": 0, "type": "signature", "x": 100, "y": 100}],
            timestamp_config=config,
        )
    assert "secret-tsa-password" not in str(exc.value)
    assert "secret-tsa-password" not in caplog.text


def test_offline_signing_never_contacts_the_tsa(identity, monkeypatch):
    async def fail(*args, **kwargs):
        raise AssertionError("Unexpected network contact")

    monkeypatch.setattr(cv, "fetch_service", fail)
    output = sign_pdf_multiple(
        make_pdf(), identity.p12, identity.password, [{"page": 0, "type": "signature", "x": 100, "y": 100}]
    )
    assert validate_pdf_document(output)["signatures"][0]["timestamp"]["status"] == "absent"


def test_historical_timestamp_outside_tsa_certificate_validity_is_not_trusted(pki, identity):
    tsa = dummy_tsa(pki)
    tsa.fixed_dt = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
    writer = IncrementalPdfFileWriter(io.BytesIO(make_pdf()))
    signer = signers.SimpleSigner.load_pkcs12_data(identity.p12, [], identity.password.encode())
    output = io.BytesIO()
    signers.PdfSigner(
        signers.PdfSignatureMetadata(field_name="Historical"),
        signer=signer,
        timestamper=tsa,
        new_field_spec=fields.SigFieldSpec("Historical"),
    ).sign_pdf(writer, output=output)
    timestamp = validate_pdf_document(output.getvalue(), validation_policy=policy_for(pki))["signatures"][0][
        "timestamp"
    ]
    assert timestamp["status"] == "valid"  # CMS mathematics and certificate validity remain distinct
    assert timestamp["certificate_trust"]["status"] == "untrusted"
    assert "timestamp time" in timestamp["certificate_trust"]["message"]
