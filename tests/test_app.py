"""The Streamlit UI keeps its bottom-left slider semantics on top of the new placement contract."""

import pymupdf
import pytest

import app
from app import build_placements, initials_offset_limits, sign_from_ui, to_signer_placement
from geometry import validate_placements
from signer import sign_pdf_multiple
from tests.conftest import assert_all_signatures_ok, make_pdf


def test_slider_position_converts_to_top_left_displayed_space():
    assert to_signer_placement("full", 400, 50, 842) == {"type": "signature", "x": 400.0, "y": 742.0}
    assert to_signer_placement("initials", 20, 20, 842) == {"type": "initials", "x": 20.0, "y": 787.0}


def test_slider_position_lands_at_same_bottom_left_pdf_point(identity):
    placement = {"page": 0, **to_signer_placement("full", 400, 50, 842)}

    out = sign_pdf_multiple(make_pdf(), identity.p12, identity.password, [placement])

    (signature, _), = assert_all_signatures_ok(out, identity, expected=1)
    assert [float(v) for v in signature.sig_field["/Rect"]] == pytest.approx([400, 50, 550, 100])


def test_placements_on_pages_missing_from_replaced_pdf_are_dropped():
    signatures = [{"page": 0, "x": 400, "y": 50, "type": "full"},
                  {"page": 1, "x": 400, "y": 50, "type": "full"}]

    placements = build_placements(signatures, [0, 3], [(595, 842)], "right", 0, 0)

    assert [(p["page"], p["type"]) for p in placements] == [(0, "signature"), (0, "initials")]


def test_sign_from_ui_signs_remaining_placements_after_pdf_replaced(identity):
    """Signature placed on page 2, then the upload is replaced by a 1-page PDF."""
    signatures = [{"page": 0, "x": 400, "y": 50, "type": "full"},
                  {"page": 1, "x": 400, "y": 50, "type": "full"}]

    signed, error = sign_from_ui(make_pdf(), identity.p12, identity.password, signatures, [],
                                 "right", 0, 0, lock=False, protocol=False)

    assert error is None
    assert_all_signatures_ok(signed, identity, expected=1)


def test_sign_from_ui_reports_when_no_placement_is_left(identity):
    signatures = [{"page": 1, "x": 400, "y": 50, "type": "full"}]

    signed, error = sign_from_ui(make_pdf(), identity.p12, identity.password, signatures, [],
                                 "right", 0, 0, lock=False, protocol=False)

    assert signed is None and "No signatures" in error


def test_sign_from_ui_turns_unexpected_errors_into_safe_message(identity, monkeypatch):
    def explode(**kwargs):
        raise IndexError(f"list index out of range {kwargs['p12_password']}")

    monkeypatch.setattr(app, "sign_pdf_multiple", explode)
    signatures = [{"page": 0, "x": 400, "y": 50, "type": "full"}]

    signed, error = sign_from_ui(make_pdf(), identity.p12, identity.password, signatures, [],
                                 "right", 0, 0, lock=False, protocol=False)

    assert signed is None
    assert error.startswith("Signing failed")
    assert identity.password not in error and "index" not in error


def test_sign_from_ui_reports_signer_errors(identity):
    signatures = [{"page": 0, "x": 1, "y": 1, "type": "full"}]
    signed, error = sign_from_ui(make_pdf(), identity.p12, "wrong-password", signatures, [],
                                 "right", 0, 0, lock=False, protocol=False)
    assert signed is None
    assert "Certificate validation failed" in error and "wrong-password" not in error


@pytest.mark.parametrize("corner", ["left", "right"])
@pytest.mark.parametrize("size", [(595, 842), (612, 792), (120, 105)])
def test_initials_slider_limits_keep_the_box_on_the_page(corner, size):
    (x_min, x_max), (y_min, y_max) = initials_offset_limits(corner)
    doc = pymupdf.open(stream=make_pdf(width=size[0], height=size[1]), filetype="pdf")
    placements = []
    for offset_x in (x_min, x_max):
        for offset_y in (y_min, y_max):
            placements += build_placements([], [0], [size], corner, offset_x, offset_y)

    validate_placements(doc, placements)
