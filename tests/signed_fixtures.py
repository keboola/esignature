"""Already-signed input fixtures for counter-signing tests, built in memory with pyHanko.

Party A signs first (approval, certification, locks, FieldMDP, timestamps, odd formats); the
tests then counter-sign as party B through ``sign_pdf_multiple``. Negative controls tamper with
A's revision history the way a careless or malicious tool would.
"""

import asyncio
import contextlib
import datetime
import hashlib
import io
from typing import Iterable, List, Optional, Sequence, Tuple

from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.fields import FieldMDPAction, FieldMDPSpec, MDPPerm
from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper
from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp
from pyhanko_certvalidator import ValidationContext

from tests.conftest import Identity


def _simple_signer(identity: Identity) -> signers.SimpleSigner:
    return signers.SimpleSigner.load_pkcs12_data(identity.p12, [], identity.password.encode())


def sign_as(
    pdf: bytes,
    identity: Identity,
    field_name: str = "A",
    box: Optional[Tuple[float, float, float, float]] = (300, 600, 450, 650),
    certify: Optional[MDPPerm] = None,
    lock: Optional[MDPPerm] = None,
    field_mdp: Optional[FieldMDPSpec] = None,
    page: int = 0,
) -> bytes:
    """Sign ``pdf`` incrementally as ``identity`` with a new (visible by default) field.

    certify: certification signature with this DocMDP permission (catalog /Perms /DocMDP).
    lock: approval signature with /Lock /P <lock> (PDF 2.0); FieldMDP defaults to Include [field].
    field_mdp: FieldMDP transform on an approval signature.
    """
    writer = IncrementalPdfFileWriter(io.BytesIO(pdf), strict=False)
    spec_kwargs = {}
    meta_kwargs = {}
    if lock is not None:
        writer.ensure_output_version((2, 0))
        spec_kwargs["field_mdp_spec"] = field_mdp or FieldMDPSpec(FieldMDPAction.INCLUDE, [field_name])
        spec_kwargs["doc_mdp_update_value"] = lock
    elif field_mdp is not None:
        spec_kwargs["field_mdp_spec"] = field_mdp
    if certify is not None:
        meta_kwargs = {"certify": True, "docmdp_permissions": certify}
    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(field_name=field_name, **meta_kwargs),
        signer=_simple_signer(identity),
        new_field_spec=fields.SigFieldSpec(field_name, box=box, on_page=page, **spec_kwargs),
    )
    out = io.BytesIO()
    pdf_signer.sign_pdf(writer, output=out)
    return out.getvalue()


# --- Document timestamps with a local test TSA ----------------------------------------------------

class TestTsa:
    """A self-signed time stamping authority (EKU timeStamping) that works offline."""

    __test__ = False  # not a pytest class

    def __init__(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .sign(key, hashes.SHA256())
        )
        self.asn1_cert = asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
        self._key = asn1_keys.PrivateKeyInfo.load(key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    def timestamp(self, pdf: bytes, field_name: str = "DocTS") -> bytes:
        writer = IncrementalPdfFileWriter(io.BytesIO(pdf), strict=False)
        stamper = signers.PdfTimeStamper(
            DummyTimeStamper(tsa_cert=self.asn1_cert, tsa_key=self._key), field_name=field_name)
        out = io.BytesIO()
        stamper.timestamp_pdf(writer, "sha256", ValidationContext(trust_roots=[self.asn1_cert]), output=out)
        return out.getvalue()


# --- Legal name escapes ------------------------------------------------------------------------------

ESCAPED_NAMES = {"/ByteRange", "/SubFilter", "/Type"}


@contextlib.contextmanager
def escaped_signature_names():
    """While active, pyHanko writes /ByteRange, /SubFilter and /Type with a legal #xx escape on
    their first letter (/#42yteRange ...). Readers decode these; byte scanners do not."""
    original = generic.NameObject.write_to_stream

    def write(self, stream, handler=None, container_ref=None):
        if str(self) in ESCAPED_NAMES:
            stream.write(b"/#%02X" % ord(str(self)[1]) + str(self)[2:].encode("ascii"))
        else:
            original(self, stream, handler, container_ref)

    generic.NameObject.write_to_stream = write
    try:
        yield
    finally:
        generic.NameObject.write_to_stream = original


# --- Unnamed signature fields ----------------------------------------------------------------------

@contextlib.contextmanager
def unnamed_signature_fields(widget_only: bool = False):
    """While active, pyHanko writes signature fields WITHOUT /T (optional per PDF 32000 12.7.4.1).

    widget_only: also write the form's /Fields as empty, so the signed field is reachable only
    through the page's /Annots.
    """
    original = generic.DictionaryObject.write_to_stream

    def write(self, stream, handler=None, container_ref=None):
        if self.get("/FT") == "/Sig" or (widget_only and "/Fields" in self):
            copy = generic.DictionaryObject(
                {k: v for k, v in self.items() if not (k == "/T" and self.get("/FT") == "/Sig")})
            if widget_only and "/Fields" in copy:
                copy[generic.NameObject("/Fields")] = generic.ArrayObject()
            original(copy, stream, handler, container_ref)
        else:
            original(self, stream, handler, container_ref)

    generic.DictionaryObject.write_to_stream = write
    try:
        yield
    finally:
        generic.DictionaryObject.write_to_stream = original


# --- Damaged and unusual files ---------------------------------------------------------------------

def unsupported_subfilter(signed: bytes) -> bytes:
    """Rename A's /SubFilter to an unknown value of the same length (offsets stay valid)."""
    old = b"/adbe.pkcs7.detached"
    assert signed.count(old) == 1
    return signed.replace(old, b"/adbe.xxxxx.detached")


def broken_startxref(pdf: bytes) -> bytes:
    """Point the last startxref at a wrong offset (MuPDF repairs it, pyHanko cannot parse it)."""
    return pdf[:pdf.rfind(b"startxref")] + b"startxref\n12345\n%%EOF\n"


def hybrid_xref_pdf() -> bytes:
    """A one-page hybrid-reference file: classic xref table plus /XRefStm for an object stream."""
    out = io.BytesIO()
    out.write(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}

    def obj(number: int, body: bytes) -> None:
        offsets[number] = out.tell()
        out.write(b"%d 0 obj\n" % number + body + b"\nendobj\n")

    content = b"BT /F1 24 Tf 72 720 Td (Hybrid reference file) Tj ET"
    obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    obj(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
           b"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>")
    obj(4, b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
    # Object 6 (the document info) lives only in object stream 5.
    inner = b"<< /Producer (hybrid fixture) >>"
    header = b"6 0 "
    obj(5, b"<< /Type /ObjStm /N 1 /First %d /Length %d >>\nstream\n" % (len(header), len(header + inner))
        + header + inner + b"\nendstream")
    xref_stm_data = bytes([2, 0, 5, 0])  # W [1 2 1]: type 2, in object stream 5, index 0
    obj(7, b"<< /Type /XRef /Size 8 /Index [6 1] /W [1 2 1] /Length %d >>\nstream\n" % len(xref_stm_data)
        + xref_stm_data + b"\nendstream")
    xref_offset = out.tell()
    # Object 6 is absent from the table (two subsections); only the /XRefStm supplies it.
    out.write(b"xref\n0 6\n0000000000 65535 f \n")
    for number in range(1, 6):
        out.write(b"%010d 00000 n \n" % offsets[number])
    out.write(b"7 1\n%010d 00000 n \n" % offsets[7])
    out.write(b"trailer\n<< /Size 8 /Root 1 0 R /Info 6 0 R /XRefStm %d >>\n" % offsets[7])
    out.write(b"startxref\n%d\n%%%%EOF\n" % xref_offset)
    return out.getvalue()


# --- Negative controls: changes after A that A's signature does not permit ------------------------

def _writer(pdf: bytes) -> IncrementalPdfFileWriter:
    return IncrementalPdfFileWriter(io.BytesIO(pdf), strict=False)


def _write(writer: IncrementalPdfFileWriter) -> bytes:
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def edit_page_content_after(signed: bytes) -> bytes:
    """Append a content stream to page 1 in an unsigned incremental update."""
    writer = _writer(signed)
    stream = generic.StreamObject(stream_data=b"q 0 0 1 rg 10 10 100 100 re f Q")
    writer.add_stream_to_page(0, writer.add_object(stream))
    return _write(writer)


def rotate_page_after(signed: bytes) -> bytes:
    """Change /Rotate of page 1 in an unsigned incremental update."""
    writer = _writer(signed)
    page_ref = writer.find_page_for_modification(0)[0]
    page = page_ref.get_object()
    page["/Rotate"] = generic.NumberObject(90)
    writer.update_container(page)
    return _write(writer)


def _signature_field(writer: IncrementalPdfFileWriter, name: str) -> generic.DictionaryObject:
    for fq_name, _, field_ref in fields.enumerate_sig_fields(writer):
        if fq_name == name:
            return field_ref.get_object()
    raise KeyError(name)


def replace_appearance_after(signed: bytes, field_name: str = "A") -> bytes:
    """Replace the normal appearance of A's widget with a different drawing."""
    writer = _writer(signed)
    field = _signature_field(writer, field_name)
    stream = generic.StreamObject(
        {generic.NameObject("/BBox"): generic.ArrayObject([generic.FloatObject(v) for v in (0, 0, 150, 50)]),
         generic.NameObject("/Subtype"): generic.NameObject("/Form"),
         generic.NameObject("/Type"): generic.NameObject("/XObject")},
        stream_data=b"0 0 1 rg 0 0 150 50 re f",
    )
    field["/AP"] = generic.DictionaryObject({generic.NameObject("/N"): writer.add_object(stream)})
    writer.update_container(field)
    return _write(writer)


def remove_field_after(signed: bytes, field_name: str = "A") -> bytes:
    """Remove A's field from the form and its widget from the page."""
    writer = _writer(signed)
    acroform = writer.root["/AcroForm"]
    kept = generic.ArrayObject(
        ref for ref in acroform["/Fields"] if ref.get_object().get("/T") != field_name)
    acroform["/Fields"] = kept
    writer.update_container(acroform)
    page_ref = writer.find_page_for_modification(0)[0]
    page = page_ref.get_object()
    if "/Annots" in page:
        page["/Annots"] = generic.ArrayObject(
            ref for ref in page["/Annots"] if ref.get_object().get("/T") != field_name)
        writer.update_container(page)
    return _write(writer)


def replace_signature_in_same_field(signed: bytes, replacer: Identity, field_name: str = "A") -> bytes:
    """Clear A's /V (and any catalog /Perms) in one revision, then sign the SAME field as
    ``replacer``: the field name survives, A's signature does not."""
    writer = _writer(signed)
    field = _signature_field(writer, field_name)
    del field["/V"]
    writer.update_container(field)
    if "/Perms" in writer.root:
        del writer.root["/Perms"]
        writer.update_root()
    cleared = _write(writer)
    writer = _writer(cleared)
    out = io.BytesIO()
    signers.PdfSigner(
        signers.PdfSignatureMetadata(field_name=field_name), signer=_simple_signer(replacer),
    ).sign_pdf(writer, output=out)
    return out.getvalue()


def hide_signature_history(signed: bytes, field_name: str = "A") -> bytes:
    """Remove A's field and widget, overwrite the field and signature-value objects with plain
    dictionaries (so the CURRENT object graph has no signature), then break startxref."""
    writer = _writer(signed)
    field = _signature_field(writer, field_name)
    value_ref = field.raw_get("/V")
    field_ref = next(ref for ref in writer.root["/AcroForm"]["/Fields"]
                     if ref.get_object().get("/T") == field_name)
    hidden = remove_field_after(signed, field_name)
    writer = _writer(hidden)
    for ref in (field_ref, value_ref):
        plain = generic.DictionaryObject({generic.NameObject("/Note"): generic.TextStringObject("plain")})
        writer.objects[(ref.generation, ref.idnum)] = plain
    return broken_startxref(_write(writer))


def with_revisions(pdf: bytes, count: int) -> bytes:
    """Append ``count`` incremental revisions that only change the document /Info."""
    for number in range(count):
        writer = _writer(pdf)
        info = generic.DictionaryObject({
            generic.NameObject("/Producer"): generic.TextStringObject(f"revision {number}")})
        writer._info = writer.add_object(info)
        writer.trailer["/Info"] = writer._info
        pdf = _write(writer)
    return pdf


def corrupt_signature_contents(signed: bytes) -> bytes:
    """Overwrite the first bytes of A's CMS blob (/Contents hex), keeping every offset."""
    start = signed.index(b"/Contents <") + len(b"/Contents <")
    return signed[:start] + b"ffff" + signed[start + 4:]


def signed_linearized_layout(
    identity: Identity, hidden_complete_main: bool = False, omit_main_root: bool = False,
) -> bytes:
    """Synthetic signed initial document with disjoint first-page/main xref sections.

    Like linearized PDFs, the early first-page xref points forward through /Prev to the
    main xref at EOF. The signature lives in the main section, the catalog in the early one.
    Fixed-width placeholders let us sign the initial layout without rewriting a signed PDF.
    No private/user document data is used.
    """
    output = io.BytesIO()
    offsets = {}
    output.write(b"%PDF-1.7\n")

    def obj(number, body):
        offsets[number] = output.tell()
        output.write(b"%d 0 obj\n" % number + body + b"\nendobj\n")

    def num(value):
        return b"%010d" % value

    obj(1, b"<< /Linearized 1 /L LLLLLLLLLL /E EEEEEEEEEE /T TTTTTTTTTT /O 2 /N 1 /H [0 0] >>")
    early_xref = output.tell()
    output.write(b"xref\n0 2\n0000000000 65535 f \n" + num(offsets[1]) + b" 00000 n \n")
    output.write(b"10 2\nCCCCCCCCCC 00000 n \nPPPPPPPPPP 00000 n \n")
    output.write(b"trailer\n<< /Size 12 /Root 10 0 R /Prev MMMMMMMMMM >>\nstartxref\n0\n%%EOF\n")
    current_fields = b"[]" if hidden_complete_main else b"[3 0 R]"
    obj(10, b"<< /Type /Catalog /Pages 11 0 R /AcroForm << /Fields " + current_fields + b" /SigFlags 3 >> >>")
    obj(11, b"<< /Type /Pages /Kids [2 0 R] /Count 1 >>")
    end_first = output.tell()
    obj(2, b"<< /Type /Page /Parent 11 0 R /MediaBox [0 0 595 842] "
           b"/Resources << >> /Contents 5 0 R /Annots [3 0 R] >>")
    obj(3, b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (A) /V 4 0 R /Rect [300 600 450 650] /P 2 0 R >>")
    obj(4, b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached "
        b"/ByteRange [0000000000 0000000000 0000000000 0000000000] /Contents <" + b"0" * 32768 + b"> >>")
    obj(5, b"<< /Length 0 >>\nstream\n\nendstream")
    if hidden_complete_main:
        # Hostile layout: the main xref is a complete older graph with A, while the
        # first-page trailer installs a disjoint new catalog that hides A.
        obj(6, b"<< /Type /Catalog /Pages 11 0 R /AcroForm << /Fields [3 0 R] /SigFlags 3 >> >>")
    main_xref = output.tell()
    output.write(b"xref\n2 5\n" if hidden_complete_main else b"xref\n2 4\n")
    for number in range(2, 7 if hidden_complete_main else 6):
        output.write(num(offsets[number]) + b" 00000 n \n")
    root = b"6" if hidden_complete_main else b"10"
    root_entry = b"" if omit_main_root else b" /Root " + root + b" 0 R"
    output.write(b"trailer\n<< /Size 12" + root_entry + b" >>\nstartxref\n"
                 + str(early_xref).encode() + b"\n%%EOF\n")
    pdf = output.getvalue()
    for placeholder, value in ((b"LLLLLLLLLL", len(pdf)), (b"EEEEEEEEEE", end_first),
                               (b"TTTTTTTTTT", main_xref), (b"MMMMMMMMMM", main_xref),
                               (b"CCCCCCCCCC", offsets[10]), (b"PPPPPPPPPP", offsets[11])):
        pdf = pdf.replace(placeholder, num(value))
    start = pdf.index(b"/Contents <") + len(b"/Contents ")
    end = start + 32770
    byte_range = b"[" + b" ".join(num(n) for n in (0, start, end, len(pdf) - end)) + b"]"
    pdf = pdf.replace(b"[0000000000 0000000000 0000000000 0000000000]", byte_range)
    digest = hashlib.sha256(pdf[:start] + pdf[end:]).digest()
    cms = asyncio.run(_simple_signer(identity).async_sign(digest, "sha256")).dump().hex().encode()
    assert len(cms) <= 32768
    return pdf[:start + 1] + cms.ljust(32768, b"0") + pdf[end - 1:]


# --- Assertions ------------------------------------------------------------------------------------

def assert_every_signature_ok(
    pdf: bytes,
    trust_roots: Iterable[asn1_x509.Certificate],
    expected_names: Sequence[str],
    strict: bool = True,
) -> List:
    """Every embedded signature and timestamp: intact, valid, trusted (explicit roots only),
    docmdp_ok, and for signatures the overall bottom line. Field names must match exactly.

    ``strict=False`` is needed for hybrid-reference files, whose validation pyHanko refuses in
    strict mode by policy (the production checks also read with strict=False).
    """
    roots = list(trust_roots)
    reader = PdfFileReader(io.BytesIO(pdf), strict=strict)
    results = []
    for sig in reader.embedded_signatures:
        context = ValidationContext(trust_roots=roots, allow_fetching=False)
        if sig.sig_object_type == "/DocTimeStamp":
            status = validate_pdf_timestamp(sig, context)
            docmdp_ok = sig.summarise_integrity_info()["docmdp_ok"]
            assert status.intact and status.valid and status.trusted, f"{sig.field_name}: {status}"
            assert docmdp_ok, f"{sig.field_name}: docmdp not ok"
        else:
            status = validate_pdf_signature(sig, context)
            assert status.intact, f"{sig.field_name}: not intact"
            assert status.valid, f"{sig.field_name}: not valid"
            assert status.trusted, f"{sig.field_name}: not trusted"
            assert status.docmdp_ok, f"{sig.field_name}: docmdp not ok ({status.modification_level})"
            assert status.bottom_line, f"{sig.field_name}: {status.summary()}"
        results.append((sig, status))
    assert [sig.field_name for sig, _ in results] == list(expected_names)
    return results
