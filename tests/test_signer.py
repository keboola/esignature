"""End-to-end tests of sign_pdf_multiple with a throwaway self-signed certificate.

Every signature in every output is checked for integrity, cryptographic validity, trust (the test
certificate is the only trust root) and permitted modifications (DocMDP).
"""

import io

import pymupdf
import pytest
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.fields import MDPPerm

from geometry import PlacementError
from signer import (
    CertificateValidationError,
    PdfInputError,
    format_page_ranges,
    sign_pdf_multiple,
)
from tests.conftest import (
    assert_all_signatures_ok,
    ink_bbox,
    make_identity,
    make_pdf,
    validate_all,
)
from tests.test_geometry import CROP, DISPLAYED, GEOMETRY_CASES, MEDIA


def sig(page=0, x=100.0, y=100.0):
    return {"page": page, "type": "signature", "x": x, "y": y}


def initials(page=0, x=500.0, y=780.0):
    return {"page": page, "type": "initials", "x": x, "y": y}


def sign(pdf, identity, placements, **kwargs):
    return sign_pdf_multiple(pdf, identity.p12, identity.password, placements, **kwargs)


def signature_count(pdf_bytes):
    return len(PdfFileReader(io.BytesIO(pdf_bytes)).embedded_signatures)


# --- R1: several signatures, initials and protocol keep every signature valid -------------

def test_multiple_signatures_initials_and_protocol_all_valid(identity):
    pdf = make_pdf(pages=3, text="Contract")
    placements = [sig(0), sig(1), sig(1, y=300)] + [initials(p) for p in range(3)]

    out = sign(pdf, identity, placements, add_protocol_page=True)

    results = assert_all_signatures_ok(out, identity, expected=3)
    assert [s.field_name for s, _ in results] == ["Signature_1", "Signature_2", "Signature_3"]
    doc = pymupdf.open(stream=out, filetype="pdf")
    assert doc.page_count == 4
    assert "Digital Signature Protocol" in doc[3].get_text()


# --- D7': lock is an approval-signature lock on the last signature ------------------------

def test_lock_keeps_file_readable_and_all_signatures_valid(identity):
    pdf = make_pdf(pages=2)

    out = sign(pdf, identity, [sig(0), sig(1)], lock_after_signing=True, add_protocol_page=True)

    results = assert_all_signatures_ok(out, identity, expected=2)
    reader = PdfFileReader(io.BytesIO(out))
    assert "/Encrypt" not in reader.trailer
    assert str(reader.root["/Version"]) == "/2.0"
    last, _ = results[-1]
    assert last.docmdp_level == MDPPerm.NO_CHANGES
    lock = last.sig_field["/Lock"]
    assert lock["/Action"] == "/All"
    assert lock["/P"] == 1
    first, _ = results[0]
    assert "/Lock" not in first.sig_field


def test_edit_after_lock_is_detected(identity):
    out = sign(make_pdf(), identity, [sig()], lock_after_signing=True)
    writer = IncrementalPdfFileWriter(io.BytesIO(out))
    content = generic.StreamObject(stream_data=b"0 0 1 rg 10 10 100 100 re f")
    writer.add_stream_to_page(0, writer.add_object(content))
    tampered = io.BytesIO()
    writer.write(tampered)

    (signature, status), = validate_all(tampered.getvalue(), identity)

    assert status.intact and status.valid
    assert status.docmdp_ok is False
    assert not status.bottom_line


def test_without_lock_has_no_lock_dictionary(identity):
    out = sign(make_pdf(), identity, [sig()])
    (signature, _), = assert_all_signatures_ok(out, identity, expected=1)
    assert "/Lock" not in signature.sig_field
    assert signature.docmdp_level is None


# --- D6 / R9: initials are visual marks covered by the document signature(s) --------------

def test_initials_only_adds_one_invisible_signature(identity):
    out = sign(make_pdf(pages=2), identity, [initials(0), initials(1)])

    (signature, _), = assert_all_signatures_ok(out, identity, expected=1)
    rect = [float(v) for v in signature.sig_field.get("/Rect", [0, 0, 0, 0])]
    assert rect[2] - rect[0] == 0 and rect[3] - rect[1] == 0
    doc = pymupdf.open(stream=out, filetype="pdf")
    assert all("JN" in page.get_text() for page in doc)


def test_initials_on_fifty_pages_use_one_signature(identity):
    pdf = make_pdf(pages=50)
    out = sign(pdf, identity, [sig(49)] + [initials(p) for p in range(50)])
    assert_all_signatures_ok(out, identity, expected=1)


# --- D10 / R10: protocol page continues instead of truncating ----------------------------

def test_protocol_overflows_to_more_pages_without_truncation(identity):
    placements = [sig(page, x=20 + (i % 3) * 180, y=20 + (i // 3) * 60)
                  for page in range(4) for i in range(10)]
    placements += [initials(p) for p in (0, 1, 2)]
    out = sign(make_pdf(pages=4), identity, placements, add_protocol_page=True)

    assert signature_count(out) == 40
    doc = pymupdf.open(stream=out, filetype="pdf")
    assert doc.page_count > 5
    protocol_text = "".join(doc[p].get_text() for p in range(4, doc.page_count))
    for number in range(1, 41):
        assert f"{number}. Digital signature - page" in protocol_text
    assert "Initials on pages: 1-3" in protocol_text


def test_format_page_ranges():
    assert format_page_ranges([0, 1, 2, 4, 6, 7]) == "1-3, 5, 7-8"
    assert format_page_ranges([3]) == "4"
    assert format_page_ranges([2, 0, 1, 1]) == "1-3"


# --- R4 / R6 / D3': mark and field are where the user put them, text upright -------------

# Expected direction of upright text in PyMuPDF unrotated page space, per /Rotate.
UPRIGHT_DIRECTION = {0: (1, 0), 90: (0, -1), 180: (-1, 0), 270: (0, 1)}


@pytest.mark.parametrize("case", GEOMETRY_CASES)
def test_drawn_mark_and_field_match_displayed_rect(identity, case):
    kwargs, expected_raw = GEOMETRY_CASES[case]
    pdf = make_pdf(**kwargs)

    out = sign(pdf, identity, [sig(x=DISPLAYED.x0, y=DISPLAYED.y0)])

    (signature, _), = assert_all_signatures_ok(out, identity, expected=1)
    widget_rect = [float(v) for v in signature.sig_field["/Rect"]]
    assert widget_rect == pytest.approx(expected_raw, abs=0.01)

    page = pymupdf.open(stream=out, filetype="pdf")[0]
    assert page.rotation == kwargs.get("rotate", 0)
    # The box border is 0.5 pt wide, centred on the rect edge; pixels are 0.25 pt.
    assert ink_bbox(page) == pytest.approx(tuple(DISPLAYED), abs=0.6)
    directions = {
        tuple(round(v) for v in line["dir"])
        for block in page.get_text("dict")["blocks"]
        for line in block.get("lines", [])
    }
    assert directions == {UPRIGHT_DIRECTION[page.rotation]}


def test_crop_offset_page_example_from_design(identity):
    """MediaBox [20 30 620 830], CropBox [70 100 570 750], /Rotate 90, displayed (40,50,190,100)."""
    pdf = make_pdf(mediabox=MEDIA, cropbox=CROP, rotate=90)
    out = sign(pdf, identity, [sig(x=40, y=50)])
    (signature, _), = assert_all_signatures_ok(out, identity, expected=1)
    assert [float(v) for v in signature.sig_field["/Rect"]] == pytest.approx([120, 140, 170, 290])


def test_user_unit_page_is_rejected(identity):
    with pytest.raises(PlacementError, match="UserUnit"):
        sign(make_pdf(user_unit=2), identity, [sig()])


# --- D8: input policy --------------------------------------------------------------------

def test_already_signed_pdf_is_rejected(identity):
    writer = IncrementalPdfFileWriter(io.BytesIO(make_pdf()))
    signer = signers.SimpleSigner.load_pkcs12_data(identity.p12, [], identity.password.encode())
    signed = signers.sign_pdf(writer, signers.PdfSignatureMetadata(field_name="Existing"), signer=signer)

    with pytest.raises(PdfInputError, match="already signed"):
        sign(signed.getvalue(), identity, [sig()])


@pytest.mark.parametrize("user_pw", ["", "open-me"])
def test_encrypted_pdf_is_rejected(identity, user_pw):
    doc = pymupdf.open(stream=make_pdf(), filetype="pdf")
    encrypted = doc.tobytes(encryption=pymupdf.PDF_ENCRYPT_AES_256, owner_pw="owner", user_pw=user_pw,
                            permissions=pymupdf.PDF_PERM_PRINT)

    with pytest.raises(PdfInputError, match="encrypted"):
        sign(encrypted, identity, [sig()])


def test_unreadable_pdf_is_rejected(identity):
    with pytest.raises(PdfInputError, match="not a readable PDF"):
        sign(b"%PDF-1.7 garbage", identity, [sig()])


def test_existing_unsigned_field_name_is_not_reused(identity):
    writer = IncrementalPdfFileWriter(io.BytesIO(make_pdf()))
    fields.append_signature_field(writer, fields.SigFieldSpec("Signature_1", box=(10, 10, 60, 40)))
    pdf = io.BytesIO()
    writer.write(pdf)

    out = sign(pdf.getvalue(), identity, [sig()])

    (signature, _), = assert_all_signatures_ok(out, identity, expected=1)
    assert signature.field_name == "Signature_2"


# --- D9: certificate handling ------------------------------------------------------------

def test_empty_password_p12_signs():
    identity = make_identity(password="")
    out = sign(make_pdf(), identity, [sig()])
    assert_all_signatures_ok(out, identity, expected=1)


@pytest.mark.parametrize(
    "identity_kwargs, password, message",
    [
        (dict(), "wrong-password", "password"),
        (dict(include_key=False), None, "private key"),
        (dict(valid_from_days=-60, valid_to_days=-1), None, "expired"),
        (dict(valid_from_days=5, valid_to_days=60), None, "not yet valid"),
    ],
)
def test_certificate_errors_are_clear_and_never_leak_password(identity_kwargs, password, message):
    identity = make_identity(**identity_kwargs)
    password = identity.password if password is None else password

    with pytest.raises(CertificateValidationError, match=message) as excinfo:
        sign_pdf_multiple(make_pdf(), identity.p12, password, [sig()])

    assert password not in str(excinfo.value)


def test_garbage_p12_is_rejected():
    with pytest.raises(CertificateValidationError, match="P12"):
        sign_pdf_multiple(make_pdf(), b"not a p12", "secret-pass", [sig()])


# --- Retry after partial success: no shared mutable state ---------------------------------

def test_signing_same_input_twice_gives_two_independent_valid_outputs(identity):
    pdf = make_pdf(pages=2)
    original = bytes(pdf)
    placements = [sig(0), initials(1)]

    first = sign(pdf, identity, placements, lock_after_signing=True, add_protocol_page=True)
    second = sign(pdf, identity, placements, lock_after_signing=True, add_protocol_page=True)

    assert pdf == original
    assert placements == [sig(0), initials(1)]
    for out in (first, second):
        results = assert_all_signatures_ok(out, identity, expected=1)
        assert results[0][0].field_name == "Signature_1"
    assert first != second


def test_long_signer_name_stays_inside_the_box():
    identity = make_identity(common_name="Ing. Maximilian Alexandr Konstantin Novák-Dvořáková Ph.D.")
    out = sign(make_pdf(), identity, [sig(x=DISPLAYED.x0, y=DISPLAYED.y0)])
    assert_all_signatures_ok(out, identity, expected=1)
    page = pymupdf.open(stream=out, filetype="pdf")[0]
    assert ink_bbox(page) == pytest.approx(tuple(DISPLAYED), abs=0.6)
    spans = [span for block in page.get_text("dict")["blocks"] for line in block.get("lines", [])
             for span in line["spans"]]
    assert any("Maximilian" in span["text"] for span in spans)
    for span in spans:
        assert pymupdf.Rect(span["bbox"]) in DISPLAYED + (-0.5, -0.5, 0.5, 0.5), span["text"]
