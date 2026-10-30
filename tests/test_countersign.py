"""Counter-signing documents already signed by another party (design S1-S10, risks K1-K19).

Party A signs the fixtures with pyHanko; party B counter-signs through ``sign_pdf_multiple``.
Every signature in every successful output is checked for intact, valid, trusted (A, B and the test
TSA are the only, explicit trust roots), docmdp_ok and bottom_line, and the output must start
with the original bytes.
"""

import io
import shutil
import subprocess
import time

import pymupdf
import pytest
from PIL import Image, ImageChops
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import FieldMDPAction, FieldMDPSpec, MDPPerm

import signer as signer_module
from signer import (
    CODE_INVALID_EXISTING,
    CODE_LOCKED_DOCUMENT,
    CODE_SIGNED_DOCUMENT,
    CODE_TOO_MANY_REVISIONS,
    CODE_TOO_MANY_SIGNATURES,
    PdfInputError,
    SigningError,
    sign_pdf_multiple,
)
from tests.conftest import make_identity, make_pdf
from tests.signed_fixtures import (
    TestTsa,
    assert_every_signature_ok,
    broken_startxref,
    corrupt_signature_contents,
    edit_page_content_after,
    escaped_signature_names,
    hide_signature_history,
    hybrid_xref_pdf,
    remove_field_after,
    replace_appearance_after,
    replace_signature_in_same_field,
    rotate_page_after,
    sign_as,
    signed_linearized_layout,
    unnamed_signature_fields,
    unsupported_subfilter,
    with_revisions,
)
from tests.test_geometry import CROP, DISPLAYED, GEOMETRY_CASES, MEDIA

SECRET = "B0b-S3cret-pass"


@pytest.fixture(scope="module")
def party_a():
    return make_identity(common_name="Alice Original")


@pytest.fixture(scope="module")
def party_b():
    return make_identity(common_name="Bob Countersigner", password=SECRET)


@pytest.fixture(scope="module")
def tsa():
    return TestTsa()


@pytest.fixture(scope="module")
def signed_by_a(party_a):
    return sign_as(make_pdf(pages=2, text="Contract signed by A"), party_a)


def sig(page=0, x=100.0, y=100.0):
    return {"page": page, "type": "signature", "x": x, "y": y}


def countersign(pdf, identity, placements=None, **kwargs):
    return sign_pdf_multiple(pdf, identity.p12, identity.password, placements or [sig()], **kwargs)


def roots(*identities):
    return [identity.asn1_cert for identity in identities]


def assert_rejected(pdf, identity, code, match, placements=None, **kwargs):
    with pytest.raises(PdfInputError, match=match) as excinfo:
        countersign(pdf, identity, placements, **kwargs)
    assert excinfo.value.code == code
    assert identity.password not in str(excinfo.value)
    return excinfo.value


# --- S1/S4/S6: approval signatures are preserved, output extends the original ---------------------

def test_countersigning_keeps_the_original_signature_valid(party_a, party_b, signed_by_a):
    out = countersign(signed_by_a, party_b, [sig(0), sig(1, y=300)])

    assert out.startswith(signed_by_a)
    assert_every_signature_ok(out, roots(party_a, party_b), ["A", "Signature_1", "Signature_2"])


def test_countersigning_with_lock_keeps_every_signature_valid(party_a, party_b, signed_by_a):
    """S7: the approval /Lock on B's last signature and the PDF 2.0 bump keep A valid."""
    out = countersign(signed_by_a, party_b, [sig(0), sig(1)], lock_after_signing=True)

    assert out.startswith(signed_by_a)
    results = assert_every_signature_ok(out, roots(party_a, party_b), ["A", "Signature_1", "Signature_2"])
    last, _ = results[-1]
    assert last.docmdp_level == MDPPerm.NO_CHANGES
    assert str(PdfFileReader(io.BytesIO(out)).root["/Version"]) == "/2.0"


def test_signed_mode_never_saves_the_document(party_a, party_b, signed_by_a, monkeypatch):
    """S4: no PyMuPDF serialisation of the input at all on the signed path."""
    def guard(method):
        original = getattr(pymupdf.Document, method)

        def forbidden(self, *args, **kwargs):
            if self.page_count and "Contract signed by A" in self[0].get_text():
                raise AssertionError(f"the signed input was serialised with {method}")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(pymupdf.Document, method, forbidden)

    unsigned_control = make_pdf(text="Contract signed by A")
    for method in ("tobytes", "write", "save", "ez_save"):
        guard(method)
    # Control: the guard does catch the unsigned path, which saves once by design.
    with pytest.raises(SigningError):
        countersign(unsigned_control, party_b)

    out = countersign(signed_by_a, party_b)

    assert out.startswith(signed_by_a)
    assert_every_signature_ok(out, roots(party_a, party_b), ["A", "Signature_1"])


@pytest.mark.parametrize("extra", ["protocol", "initials"])
def test_initials_or_protocol_on_a_signed_document_are_refused(party_b, signed_by_a, extra):
    placements = [sig()]
    kwargs = {}
    if extra == "protocol":
        kwargs["add_protocol_page"] = True
    else:
        placements.append({"page": 0, "type": "initials", "x": 500, "y": 780})

    error = assert_rejected(signed_by_a, party_b, CODE_SIGNED_DOCUMENT, "already signed",
                            placements, **kwargs)
    assert "Initials and the protocol page" in str(error)


# --- K1/K2: certification, /Lock and FieldMDP restrictions -------------------------------------------

@pytest.mark.parametrize("permission", [MDPPerm.NO_CHANGES, MDPPerm.FILL_FORMS, MDPPerm.ANNOTATE])
def test_certified_documents_are_refused(party_a, party_b, permission):
    certified = sign_as(make_pdf(), party_a, certify=permission)
    assert_rejected(certified, party_b, CODE_LOCKED_DOCUMENT, "certified or locked")


@pytest.mark.parametrize("permission", [MDPPerm.NO_CHANGES, MDPPerm.FILL_FORMS])
def test_approval_lock_is_refused(party_a, party_b, permission):
    locked = sign_as(make_pdf(), party_a, lock=permission)
    assert_rejected(locked, party_b, CODE_LOCKED_DOCUMENT, "certified or locked")


@pytest.mark.parametrize("spec", [
    FieldMDPSpec(FieldMDPAction.ALL),
    FieldMDPSpec(FieldMDPAction.EXCLUDE, ["A"]),
], ids=["all", "exclude-existing"])
def test_fieldmdp_that_locks_new_fields_is_refused(party_a, party_b, spec):
    restricted = sign_as(make_pdf(), party_a, field_mdp=spec)
    assert_rejected(restricted, party_b, CODE_LOCKED_DOCUMENT, "certified or locked")


def test_fieldmdp_include_existing_only_allows_new_fields(party_a, party_b):
    restricted = sign_as(make_pdf(), party_a, field_mdp=FieldMDPSpec(FieldMDPAction.INCLUDE, ["A"]))

    out = countersign(restricted, party_b)

    assert out.startswith(restricted)
    assert_every_signature_ok(out, roots(party_a, party_b), ["A", "Signature_1"])


# --- K3/K4: unsupported formats and document timestamps ------------------------------------------------

def test_unsupported_subfilter_is_signed_but_refused(party_a, party_b, signed_by_a):
    odd = unsupported_subfilter(signed_by_a)
    # pyHanko's embedded_signatures skips it; it must still count as signed.
    assert PdfFileReader(io.BytesIO(odd)).embedded_signatures == []
    assert_rejected(odd, party_b, CODE_INVALID_EXISTING, "cannot be checked")


def test_document_timestamp_stays_valid_after_countersigning(party_a, party_b, tsa, signed_by_a):
    stamped = tsa.timestamp(signed_by_a)

    out = countersign(stamped, party_b)

    assert out.startswith(stamped)
    assert_every_signature_ok(out, roots(party_a, party_b) + [tsa.asn1_cert], ["A", "DocTS", "Signature_1"])


def test_timestamp_only_document_counts_as_signed(party_b, tsa):
    stamped = tsa.timestamp(make_pdf())

    assert_rejected(stamped, party_b, CODE_SIGNED_DOCUMENT, "already signed",
                    [sig()], add_protocol_page=True)
    out = countersign(stamped, party_b)
    assert out.startswith(stamped)
    assert_every_signature_ok(out, roots(party_b) + [tsa.asn1_cert], ["DocTS", "Signature_1"])


# --- K5/K6/K7: damaged, hybrid and malformed inputs ------------------------------------------------------

DAMAGED = ("This PDF is damaged and may contain signatures; it cannot be signed safely. "
           "Re-save it with another PDF tool first.")


def test_signed_pdf_with_broken_startxref_is_refused_as_damaged(party_b, signed_by_a):
    error = assert_rejected(broken_startxref(signed_by_a), party_b, CODE_INVALID_EXISTING, "damaged")
    assert str(error) == DAMAGED


def test_hybrid_xref_signed_document_is_countersigned(party_a, party_b):
    hybrid = hybrid_xref_pdf()
    assert b"/XRefStm" in hybrid
    signed = sign_as(hybrid, party_a)

    out = countersign(signed, party_b)

    assert out.startswith(signed)
    assert_every_signature_ok(out, roots(party_a, party_b), ["A", "Signature_1"], strict=False)


def deep_field_tree_pdf(depth: int) -> bytes:
    doc = pymupdf.open()
    doc.new_page()
    xrefs = [doc.get_new_xref() for _ in range(depth)]
    for level, xref in enumerate(xrefs):
        kids = f"/Kids [{xrefs[level + 1]} 0 R]" if level + 1 < depth else "/FT /Sig"
        doc.update_object(xref, f"<< /T (f{level}) {kids} >>")
    doc.xref_set_key(doc.pdf_catalog(), "AcroForm", f"<< /Fields [{xrefs[0]} 0 R] >>")
    return doc.tobytes()


def test_field_tree_deeper_than_the_limit_is_refused(party_b):
    with pytest.raises(PdfInputError, match="malformed form fields"):
        countersign(deep_field_tree_pdf(signer_module.MAX_FIELD_TREE_DEPTH + 5), party_b)


def test_field_tree_pyhanko_cannot_walk_is_never_treated_as_unsigned(party_b, monkeypatch):
    def broken(_handler):
        raise RecursionError("cyclic tree")

    monkeypatch.setattr(signer_module, "_signed_in_any_revision", broken)
    with pytest.raises(PdfInputError, match="malformed form fields"):
        countersign(make_pdf(), party_b)


# --- K8/K9: histories that are already invalid stay refused (negative controls) -------------------------

@pytest.mark.parametrize("tamper", [
    rotate_page_after,
    edit_page_content_after,
    replace_appearance_after,
    remove_field_after,
], ids=["rotation-change", "page-content-edit", "replaced-appearance", "removed-field"])
def test_disallowed_change_after_a_is_refused(party_b, signed_by_a, tamper):
    tampered = tamper(signed_by_a)
    assert tampered.startswith(signed_by_a)
    assert_rejected(tampered, party_b, CODE_INVALID_EXISTING, "not intact or the document was changed")


def test_signed_then_fully_resaved_pdf_is_refused(party_b, signed_by_a):
    resaved = pymupdf.open(stream=signed_by_a, filetype="pdf").tobytes(garbage=3)
    assert_rejected(resaved, party_b, CODE_INVALID_EXISTING, "not intact")


# --- K15: bound on existing signatures, configurable ---------------------------------------------------

def signed_n_times(identity, count: int) -> bytes:
    pdf = make_pdf()
    for number in range(count):
        pdf = sign_as(pdf, identity, field_name=f"A{number}", box=None)
    return pdf


def test_more_existing_signatures_than_the_default_limit_are_refused(party_a, party_b):
    many = signed_n_times(party_a, signer_module.DEFAULT_MAX_EXISTING_SIGNATURES + 1)
    with pytest.raises(PdfInputError, match="already has 21 signatures; at most 20"):
        countersign(many, party_b)


def test_existing_signature_limit_is_a_parameter(party_a, party_b):
    three = signed_n_times(party_a, 3)
    with pytest.raises(PdfInputError, match="at most 2"):
        countersign(three, party_b, max_existing_signatures=2)

    out = countersign(three, party_b, max_existing_signatures=3)
    assert_every_signature_ok(out, roots(party_a, party_b), ["A0", "A1", "A2", "Signature_1"])


# --- Failure scenarios: retry, fail-closed post-check, no secrets ----------------------------------------

def test_countersigning_the_same_input_twice_gives_two_independent_valid_outputs(
        party_a, party_b, signed_by_a):
    original = bytes(signed_by_a)
    placements = [sig(0), sig(1)]

    first = countersign(signed_by_a, party_b, placements, lock_after_signing=True)
    second = countersign(signed_by_a, party_b, placements, lock_after_signing=True)

    assert signed_by_a == original
    assert placements == [sig(0), sig(1)]
    assert first != second
    for out in (first, second):
        assert out.startswith(original)
        assert_every_signature_ok(out, roots(party_a, party_b), ["A", "Signature_1", "Signature_2"])


def test_post_check_fails_closed_when_an_original_signature_reports_broken(
        party_b, signed_by_a, monkeypatch):
    real = signer_module._signature_preserved
    calls = []

    def broken_after_signing(sig):
        calls.append(sig.field_name)
        if len(calls) > 1 and sig.field_name == "A":  # the pre-check passed; now in the post-check
            return False
        return real(sig)

    monkeypatch.setattr(signer_module, "_signature_preserved", broken_after_signing)
    with pytest.raises(SigningError, match="without breaking the existing signatures"):
        countersign(signed_by_a, party_b)
    assert calls.count("A") == 2


def test_post_check_fails_closed_when_validation_itself_errors(party_b, signed_by_a, monkeypatch):
    real = signer_module._signature_preserved
    calls = []

    def explode_after_signing(sig):
        calls.append(sig.field_name)
        if len(calls) > 1:
            raise ValueError("validator crashed")
        return real(sig)

    monkeypatch.setattr(signer_module, "_signature_preserved", explode_after_signing)
    with pytest.raises(SigningError, match="without breaking the existing signatures"):
        countersign(signed_by_a, party_b)


def test_pre_check_validation_error_is_a_clear_refusal(party_b, signed_by_a, monkeypatch, caplog):
    def explode(_sig):
        raise ValueError(f"validator crashed {SECRET}")

    monkeypatch.setattr(signer_module, "_signature_preserved", explode)
    assert_rejected(signed_by_a, party_b, CODE_INVALID_EXISTING, "cannot be checked")
    assert SECRET not in caplog.text


def test_refusals_never_contain_the_password(party_a, party_b, caplog):
    certified = sign_as(make_pdf(), party_a, certify=MDPPerm.NO_CHANGES)
    for pdf in (certified, broken_startxref(sign_as(make_pdf(), party_a))):
        with pytest.raises(PdfInputError) as excinfo:
            countersign(pdf, party_b)
        assert SECRET not in str(excinfo.value)
    assert SECRET not in caplog.text


# --- K10/K18: rotation, raw widget rect and rendered pixels ---------------------------------------------

FIXED_TIME = "2026-01-02 03:04:05 UTC"
ZOOM = 2


def render(page: pymupdf.Page, annots: bool = True) -> Image.Image:
    pix = page.get_pixmap(matrix=pymupdf.Matrix(ZOOM, ZOOM), alpha=False, annots=annots)
    return Image.frombytes("RGB", (pix.width, pix.height), pix.samples)


def upright_mark(name: str) -> Image.Image:
    with signer_module._build_signature_mark(name, None) as mark:
        return render(mark[0])


def differing_fraction(a: Image.Image, b: Image.Image) -> float:
    assert a.size == b.size
    diff = ImageChops.difference(a, b).convert("L").point(lambda value: 255 if value > 64 else 0)
    return diff.histogram()[255] / (a.size[0] * a.size[1])


def assert_mark_upright_at(page: pymupdf.Page, rect: pymupdf.Rect, name: str) -> None:
    """The displayed page shows exactly the upright mark in ``rect`` (pixel comparison)."""
    shown = render(page).crop(tuple(round(v * ZOOM) for v in rect))
    expected = upright_mark(name)
    assert differing_fraction(shown, expected) < 0.005
    # The artwork is asymmetric: an upside-down mark would be caught.
    assert differing_fraction(shown, expected.rotate(180)) > 0.02


ROTATION_CASES = {
    0: GEOMETRY_CASES["crop-offset"][1],
    90: GEOMETRY_CASES["crop-offset-rot90"][1],
    180: GEOMETRY_CASES["crop-offset-rot180"][1],
    270: GEOMETRY_CASES["crop-offset-rot270"][1],
}


@pytest.fixture
def fixed_time(monkeypatch):
    monkeypatch.setattr(signer_module, "_format_signing_time", lambda _when: FIXED_TIME)


@pytest.mark.parametrize("signed_input", [False, True], ids=["unsigned", "countersigned"])
@pytest.mark.parametrize("rotation", sorted(ROTATION_CASES))
def test_mark_is_upright_and_field_rect_is_raw_on_rotated_pages(
        party_a, party_b, fixed_time, rotation, signed_input):
    pdf = make_pdf(mediabox=MEDIA, cropbox=CROP, rotate=rotation)
    if signed_input:
        pdf = sign_as(pdf, party_a, box=None)

    out = countersign(pdf, party_b, [sig(x=DISPLAYED.x0, y=DISPLAYED.y0)])

    names = (["A"] if signed_input else []) + ["Signature_1"]
    results = assert_every_signature_ok(out, roots(party_a, party_b), names)
    widget = results[-1][0].sig_field
    assert [float(v) for v in widget["/Rect"]] == pytest.approx(ROTATION_CASES[rotation], abs=0.01)
    with pymupdf.open(stream=out, filetype="pdf") as doc:
        page = doc[0]
        assert page.rotation == rotation
        assert_mark_upright_at(page, DISPLAYED, "Bob Countersigner")
        # S1: the signature is the widget appearance, not page content.
        assert render(page, annots=False).getextrema() == ((255, 255), (255, 255), (255, 255))


# --- Fix round 1: history, repair fallback, revision budget, unreadable CMS, field tree ----------

@pytest.mark.parametrize("certified", [False, True], ids=["approval", "certified-p1-perms-removed"])
def test_signature_replaced_under_the_same_field_name_is_refused(party_a, party_b, certified):
    """Historical signatures are identified by field name AND signed byte range."""
    original = sign_as(make_pdf(), party_a, certify=MDPPerm.NO_CHANGES if certified else None)
    replaced = replace_signature_in_same_field(original, party_b)

    assert_rejected(replaced, party_b, CODE_INVALID_EXISTING, "not intact or the document was changed")


def test_hidden_signed_history_with_broken_startxref_is_never_repaired(party_a, party_b):
    hidden = hide_signature_history(sign_as(make_pdf(), party_a))

    assert_rejected(hidden, party_b, CODE_INVALID_EXISTING, "damaged")


@pytest.mark.parametrize("marker", [
    b"/ByteRange [0 1 2 3]", b"/Type/Sig ", b"/Type/Sig>>", b"/Type \n /Sig>>", b"/SubFilter /x",
    b"/DocTimeStamp", b"/#42yteRange [0 1 2 3]", b"/#54ype /#53ig", b"/Sub#46ilter /x",
    b"/Type /ObjStm", b"/Type /Obj#53tm",
])
def test_any_raw_signature_marker_in_an_unparsable_file_blocks_repair(party_b, marker):
    """Name escapes are decoded before the scan; object streams could hide markers."""
    pdf = make_pdf()
    tail = pdf.rfind(b"startxref")
    planted = pdf[:tail] + b"99 0 obj\n<< " + marker + b" >>\nendobj\n" + pdf[tail:]
    error = assert_rejected(broken_startxref(planted), party_b, CODE_INVALID_EXISTING, "damaged")
    assert str(error) == DAMAGED


def test_unparsable_file_without_signature_markers_is_still_repaired(party_b):
    out = countersign(broken_startxref(make_pdf(text="hello")), party_b)
    assert_every_signature_ok(out, roots(party_b), ["Signature_1"])


@pytest.mark.parametrize("signed_input", [False, True], ids=["unsigned", "signed"])
def test_too_many_revisions_are_refused_quickly(party_a, party_b, signed_input):
    pdf = sign_as(make_pdf(), party_a, box=None) if signed_input else make_pdf()
    many = with_revisions(pdf, signer_module.DEFAULT_MAX_REVISIONS + 1 - (1 if signed_input else 0))

    started = time.monotonic()
    error = assert_rejected(many, party_b, CODE_TOO_MANY_REVISIONS, "too many revisions")
    assert time.monotonic() - started < 3
    assert f"at most {signer_module.DEFAULT_MAX_REVISIONS}" in str(error)


def test_revision_limit_is_a_parameter(party_b):
    five = with_revisions(make_pdf(), 4)  # 5 revisions in total
    assert_rejected(five, party_b, CODE_TOO_MANY_REVISIONS, "too many revisions", max_revisions=4)
    countersign(five, party_b, max_revisions=5)


def test_unsigned_hundred_revision_file_signs_quickly(party_b):
    """Every parsable input has its history walked; the revision cap keeps that cheap."""
    hundred = with_revisions(make_pdf(), signer_module.DEFAULT_MAX_REVISIONS - 1)
    started = time.monotonic()
    out = countersign(hundred, party_b)
    elapsed = time.monotonic() - started
    print(f"unsigned {signer_module.DEFAULT_MAX_REVISIONS}-revision file signed in {elapsed:.2f} s")
    assert elapsed < 2
    assert_every_signature_ok(out, roots(party_b), ["Signature_1"])


# --- Fix round 2: classification without raw-byte scanning for parsable files -------------------------

@pytest.fixture(scope="module")
def escaped_signed(party_a):
    with escaped_signature_names():
        signed = sign_as(make_pdf(), party_a)
    assert b"/#42yteRange" in signed and b"/ByteRange" not in signed
    return signed


def test_escaped_names_signed_original_is_countersigned_as_signed(party_a, party_b, escaped_signed):
    out = countersign(escaped_signed, party_b)
    assert out.startswith(escaped_signed)
    assert_every_signature_ok(out, roots(party_a, party_b), ["A", "Signature_1"])
    assert_rejected(escaped_signed, party_b, CODE_SIGNED_DOCUMENT, "already signed",
                    [sig()], add_protocol_page=True)


def test_escaped_names_hidden_history_is_refused(party_b, escaped_signed):
    hidden = remove_field_after(escaped_signed)
    assert_rejected(hidden, party_b, CODE_INVALID_EXISTING, "not intact or the document was changed")


def test_escaped_names_signed_original_with_broken_startxref_is_refused(party_b, escaped_signed):
    error = assert_rejected(broken_startxref(escaped_signed), party_b, CODE_INVALID_EXISTING, "damaged")
    assert str(error) == DAMAGED


def test_byterange_in_metadata_of_an_unsigned_pdf_is_not_a_signature(party_b):
    doc = pymupdf.open()
    doc.new_page()
    doc.set_metadata({"subject": "Example /ByteRange for a PDF training manual"})
    pdf = doc.tobytes()
    assert b"/ByteRange" in pdf

    out = countersign(pdf, party_b, add_protocol_page=True)

    assert_every_signature_ok(out, roots(party_b), ["Signature_1"])


def test_seed_value_subfilter_with_broken_startxref_fails_closed(party_b):
    """Accepted false refusal: an unparsable file that mentions /SubFilter cannot be repaired."""
    error = assert_rejected(broken_startxref(seed_value_form()), party_b, CODE_INVALID_EXISTING, "damaged")
    assert str(error) == DAMAGED


def test_linearized_unsigned_pdf_signs(party_b, tmp_path):
    qpdf = shutil.which("qpdf")
    if qpdf is None:
        pytest.skip("PyMuPDF 2.0 no longer linearizes and qpdf is not installed")
    source, target = tmp_path / "in.pdf", tmp_path / "linear.pdf"
    source.write_bytes(make_pdf(pages=3, text="Linearized"))
    subprocess.run([qpdf, "--linearize", str(source), str(target)], check=True)
    linear = target.read_bytes()
    assert b"/Linearized" in linear[:1024]

    out = countersign(linear, party_b, add_protocol_page=True)

    assert_every_signature_ok(out, roots(party_b), ["Signature_1"])


def test_unreadable_signature_cms_is_a_clear_refusal(party_a, party_b):
    corrupt = corrupt_signature_contents(sign_as(make_pdf(), party_a))
    assert_rejected(corrupt, party_b, CODE_INVALID_EXISTING, "cannot be checked")


def test_non_dictionary_field_entry_is_refused_as_malformed(party_b):
    doc = pymupdf.open()
    doc.new_page()
    number = doc.get_new_xref()
    doc.update_object(number, "42")
    doc.xref_set_key(doc.pdf_catalog(), "AcroForm", f"<< /Fields [{number} 0 R] >>")
    with pytest.raises(PdfInputError, match="malformed form fields"):
        countersign(doc.tobytes(), party_b)


def test_invalid_existing_message_tells_the_user_what_to_do(party_b, signed_by_a):
    tampered = edit_page_content_after(signed_by_a)
    error = assert_rejected(tampered, party_b, CODE_INVALID_EXISTING, "not intact")
    assert str(error) == (
        "The existing signatures are not intact or the document was changed after it was signed, so a "
        "new signature cannot be added without making that visible. Ask the sender for the original "
        "signed file, or, if the earlier signatures do not need to stay valid, print the document to a "
        "new PDF and sign that.")


def test_existing_signature_limit_carries_a_code(party_a, party_b):
    three = signed_n_times(party_a, 3)
    assert_rejected(three, party_b, CODE_TOO_MANY_SIGNATURES, "at most 2", max_existing_signatures=2)


def seed_value_form() -> bytes:
    doc = pymupdf.open()
    doc.new_page()
    field = doc.get_new_xref()
    doc.update_object(field, "<< /FT /Sig /T (Empty) /SV << /SubFilter [/adbe.pkcs7.detached] >> >>")
    doc.xref_set_key(doc.pdf_catalog(), "AcroForm", f"<< /Fields [{field} 0 R] >>")
    return doc.tobytes()


def test_unsigned_form_with_seed_value_subfilter_is_still_signed_normally(party_b):
    """/SubFilter also appears in seed values of EMPTY fields; only an unparsable file treats it
    as a signature marker."""
    out = countersign(seed_value_form(), party_b, add_protocol_page=True)

    assert_every_signature_ok(out, roots(party_b), ["Signature_1"])


# --- Fix round 3: classification does not depend on field names ----------------------------------------

UNCHECKABLE = ("This document contains a signature that this tool cannot check, so it cannot be "
               "counter-signed safely.")


def forbid_saves(monkeypatch) -> list:
    calls = []

    def guard(method):
        original = getattr(pymupdf.Document, method)

        def recording(self, *args, **kwargs):
            calls.append(method)
            return original(self, *args, **kwargs)

        monkeypatch.setattr(pymupdf.Document, method, recording)

    for method in ("tobytes", "write", "save", "ez_save"):
        guard(method)
    return calls


@pytest.mark.parametrize("widget_only", [False, True], ids=["in-fields", "widget-only"])
def test_unnamed_signed_field_is_refused_and_never_saved(party_a, party_b, monkeypatch, widget_only):
    with unnamed_signature_fields(widget_only=widget_only):
        unnamed = sign_as(make_pdf(), party_a)
    assert b"/ByteRange" in unnamed and b"/T (A)" not in unnamed

    saves = forbid_saves(monkeypatch)
    error = assert_rejected(unnamed, party_b, CODE_INVALID_EXISTING, "cannot check")
    assert str(error) == UNCHECKABLE
    assert saves == []


def test_unnamed_signed_field_in_an_earlier_revision_is_refused(party_a, party_b, monkeypatch):
    with unnamed_signature_fields():
        unnamed = sign_as(make_pdf(), party_a)
    later = with_revisions(unnamed, 2)

    saves = forbid_saves(monkeypatch)
    error = assert_rejected(later, party_b, CODE_INVALID_EXISTING, "cannot check")
    assert str(error) == UNCHECKABLE
    assert saves == []


def test_catalog_perms_alone_counts_as_signed(party_b, monkeypatch):
    doc = pymupdf.open()
    doc.new_page()
    perms = doc.get_new_xref()
    doc.update_object(perms, "<< /DocMDP << /Type /Sig >> >>")
    doc.xref_set_key(doc.pdf_catalog(), "Perms", f"{perms} 0 R")
    pdf = doc.tobytes()

    saves = forbid_saves(monkeypatch)
    with pytest.raises(PdfInputError) as excinfo:
        countersign(pdf, party_b)
    assert excinfo.value.code == CODE_INVALID_EXISTING
    assert saves == []


@pytest.mark.parametrize("perms", ["<< >>", "null", "<< /Other 1 >>"])
def test_empty_or_unrelated_perms_do_not_mark_a_pdf_as_signed(party_b, perms):
    doc = pymupdf.open()
    doc.new_page()
    doc.xref_set_key(doc.pdf_catalog(), "Perms", perms)
    pdf = doc.tobytes()

    out = countersign(pdf, party_b, add_protocol_page=True)

    assert_every_signature_ok(out, roots(party_b), ["Signature_1"])


@pytest.mark.parametrize("key", ["DocMDP", "UR3", "UR"])
def test_perms_with_a_signature_entry_counts_as_signed(party_b, key):
    doc = pymupdf.open()
    doc.new_page()
    doc.xref_set_key(doc.pdf_catalog(), "Perms", f"<< /{key} << /Type /Sig >> >>")
    with pytest.raises(PdfInputError) as excinfo:
        countersign(doc.tobytes(), party_b)
    assert excinfo.value.code == CODE_INVALID_EXISTING


def test_revision_cap_applies_to_unparsable_files_before_repair(party_b):
    damaged = broken_startxref(with_revisions(make_pdf(), 1))  # 2 revisions, pyHanko cannot parse
    assert_rejected(damaged, party_b, CODE_TOO_MANY_REVISIONS, "too many revisions", max_revisions=1)


def test_damaged_single_revision_pdf_still_repairs_within_the_cap(party_b):
    out = countersign(broken_startxref(make_pdf(text="hello")), party_b, max_revisions=1)
    assert_every_signature_ok(out, roots(party_b), ["Signature_1"])


@pytest.mark.parametrize("omit_main_root", [False, True])
def test_initial_linearized_signature_in_main_xref_is_preserved(party_a, party_b, omit_main_root):
    original = signed_linearized_layout(party_a, omit_main_root=omit_main_root)
    reader = PdfFileReader(io.BytesIO(original), strict=False)
    assert reader.total_revisions == 2
    assert reader.embedded_signatures[0].signed_revision == 0
    assert signer_module._linearized_document_length(reader) == len(original)

    output = countersign(original, party_b, max_revisions=1)

    assert output.startswith(original)
    report = signer_module.validate_pdf_document(output)
    assert report["can_countersign"]
    assert len(report["signatures"]) == 2
    assert all(s["integrity"] == s["cryptography"] == "valid" for s in report["signatures"])
    assert all(s["modifications"] == "allowed" for s in report["signatures"])
    # Independently inspect with the same default diff policy and explicit fixture trust roots.
    parsed = PdfFileReader(io.BytesIO(output), strict=False)
    signer_module._normalise_linearized_signatures(parsed)
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext
    for embedded in parsed.embedded_signatures:
        status = validate_pdf_signature(embedded, ValidationContext(trust_roots=roots(party_a, party_b)))
        assert status.bottom_line and status.intact and status.valid and status.docmdp_ok


@pytest.mark.parametrize("tamper", [remove_field_after, replace_appearance_after, edit_page_content_after])
@pytest.mark.parametrize("omit_main_root", [False, True])
def test_linearized_history_changes_still_fail_closed(party_a, party_b, tamper, omit_main_root):
    original = signed_linearized_layout(party_a, omit_main_root=omit_main_root)
    changed = tamper(original)
    assert_rejected(changed, party_b, CODE_INVALID_EXISTING, "not intact or the document was changed")


def test_linearized_physical_revision_limit_includes_incremental_suffixes(party_a, party_b):
    original = signed_linearized_layout(party_a)
    later = with_revisions(original, 1)
    assert_rejected(later, party_b, CODE_TOO_MANY_REVISIONS, "too many revisions", max_revisions=1)


def test_forged_linearized_marker_does_not_hide_removed_signature(party_a, party_b):
    original = sign_as(make_pdf(), party_a)
    hidden = remove_field_after(original)
    # A fake dictionary near the header must not authorize skipping signature history.
    planted = hidden.replace(b"%PDF-1.7", b"%PDF-1.7\n% /Linearized 1 /L 999999 /E 100 /T 200", 1)
    assert_rejected(planted, party_b, CODE_INVALID_EXISTING, "damaged")


def test_forged_linearized_pair_cannot_hide_signature_with_a_new_catalog(party_a, party_b):
    forged = signed_linearized_layout(party_a, hidden_complete_main=True)
    reader = PdfFileReader(io.BytesIO(forged), strict=False)
    assert reader.total_revisions == 2
    assert not reader.embedded_signatures
    assert signer_module._linearized_document_length(reader) is None
    report = signer_module.validate_pdf_document(forged)
    assert report["can_countersign"] is False
    assert report["signed"] is not False
    with pytest.raises(PdfInputError):
        countersign(forged, party_b)
