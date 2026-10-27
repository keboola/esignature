"""Shared fixtures: throwaway certificates and synthetic PDFs built in memory."""

import datetime
import io
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

import pymupdf
import pytest
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

P12_PASSWORD = "test-password"


@dataclass(frozen=True)
class Identity:
    """A generated key pair, certificate and the matching P12 archive."""

    key: rsa.RSAPrivateKey
    cert: x509.Certificate
    p12: bytes
    password: str

    @property
    def asn1_cert(self) -> asn1_x509.Certificate:
        return asn1_x509.Certificate.load(self.cert.public_bytes(serialization.Encoding.DER))


def make_identity(
    common_name: str = "Jan Novák",
    password: str = P12_PASSWORD,
    valid_from_days: int = -1,
    valid_to_days: int = 365,
    include_key: bool = True,
) -> Identity:
    """Generate a self-signed signing certificate and a P12 archive for it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=valid_from_days))
        .not_valid_after(now + datetime.timedelta(days=valid_to_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    encryption = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )
    p12 = pkcs12.serialize_key_and_certificates(
        b"test", key if include_key else None, cert, None, encryption
    )
    return Identity(key=key, cert=cert, p12=p12, password=password)


@pytest.fixture(scope="session")
def identity() -> Identity:
    """Default valid identity, generated once per test session (read-only)."""
    return make_identity()


def make_pdf(
    pages: int = 1,
    width: float = 595,
    height: float = 842,
    mediabox: Optional[Sequence[float]] = None,
    cropbox: Optional[Sequence[float]] = None,
    rotate: int = 0,
    user_unit: Optional[float] = None,
    text: Optional[str] = None,
) -> bytes:
    """Build a PDF whose pages all share the given raw page geometry."""
    doc = pymupdf.open()
    for _ in range(pages):
        page = doc.new_page(width=width, height=height)
        if text:
            page.insert_text((72, 72), text)
        xref = page.xref
        if mediabox is not None:
            doc.xref_set_key(xref, "MediaBox", "[%s]" % " ".join(str(v) for v in mediabox))
        if cropbox is not None:
            doc.xref_set_key(xref, "CropBox", "[%s]" % " ".join(str(v) for v in cropbox))
        if rotate:
            doc.xref_set_key(xref, "Rotate", str(rotate))
        if user_unit is not None:
            doc.xref_set_key(xref, "UserUnit", str(user_unit))
    data = doc.tobytes()
    doc.close()
    return data


def validate_all(pdf_bytes: bytes, identity: Identity) -> List:
    """Validate every embedded signature with the test certificate as the only trust root."""
    reader = PdfFileReader(io.BytesIO(pdf_bytes))
    statuses = []
    for sig in reader.embedded_signatures:
        context = ValidationContext(trust_roots=[identity.asn1_cert], allow_fetching=False)
        statuses.append((sig, validate_pdf_signature(sig, context)))
    return statuses


def assert_all_signatures_ok(pdf_bytes: bytes, identity: Identity, expected: int) -> List:
    """Assert there are ``expected`` signatures and each is intact, valid, trusted and DocMDP-ok."""
    results = validate_all(pdf_bytes, identity)
    assert len(results) == expected
    for sig, status in results:
        assert status.intact, f"{sig.field_name}: not intact"
        assert status.valid, f"{sig.field_name}: not valid"
        assert status.trusted, f"{sig.field_name}: not trusted"
        assert status.docmdp_ok, f"{sig.field_name}: docmdp not ok"
        assert status.bottom_line, f"{sig.field_name}: {status.summary()}"
    return results


def ink_bbox(page: pymupdf.Page, zoom: int = 4) -> Tuple[float, float, float, float]:
    """Bounding box of dark pixels on the rendered (displayed) page, in points.

    Independent of PyMuPDF's coordinate API: it measures what a viewer actually shows.
    """
    pix = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom), colorspace=pymupdf.csGRAY, alpha=False)
    samples, stride = pix.samples, pix.stride
    xs, ys = [], []
    for row in range(pix.height):
        line = samples[row * stride: row * stride + pix.width]
        dark = [i for i, value in enumerate(line) if value < 128]
        if dark:
            ys.append(row)
            xs.append(dark[0])
            xs.append(dark[-1])
    assert xs, "nothing drawn on the page"
    return min(xs) / zoom, min(ys) / zoom, (max(xs) + 1) / zoom, (max(ys) + 1) / zoom
