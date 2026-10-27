"""Unit tests for the placement contract and the displayed -> raw PDF conversion.

Expected raw coordinates are calculated by hand from the PDF spec, never by a round trip through
PyMuPDF matrices. For a CropBox [cx0 cy0 cx1 cy1] and a displayed rect (dx0, dy0, dx1, dy1):
    /Rotate 0:   X = cx0 + dx,  Y = cy1 - dy
    /Rotate 90:  X = cx0 + dy,  Y = cy0 + dx
    /Rotate 180: X = cx1 - dx,  Y = cy0 + dy
    /Rotate 270: X = cx1 - dy,  Y = cy1 - dx
"""

import math

import pymupdf
import pytest

from geometry import (
    PlacementError,
    convert_displayed_rect,
    validate_placements,
)
from tests.conftest import make_pdf

MEDIA = [20, 30, 620, 830]
CROP = [70, 100, 570, 750]
DISPLAYED = pymupdf.Rect(40, 50, 190, 100)

GEOMETRY_CASES = {
    "a4": (dict(), (40, 742, 190, 792)),
    "a4-rot90": (dict(rotate=90), (50, 40, 100, 190)),
    "mediabox-offset": (dict(mediabox=MEDIA), (60, 730, 210, 780)),
    "crop-offset": (dict(mediabox=MEDIA, cropbox=CROP), (110, 650, 260, 700)),
    "crop-offset-rot90": (dict(mediabox=MEDIA, cropbox=CROP, rotate=90), (120, 140, 170, 290)),
    "crop-offset-rot180": (dict(mediabox=MEDIA, cropbox=CROP, rotate=180), (380, 150, 530, 200)),
    "crop-offset-rot270": (dict(mediabox=MEDIA, cropbox=CROP, rotate=270), (470, 560, 520, 710)),
}


def open_pdf(**kwargs) -> pymupdf.Document:
    return pymupdf.open(stream=make_pdf(**kwargs), filetype="pdf")


@pytest.mark.parametrize("case", GEOMETRY_CASES)
def test_convert_displayed_rect_matches_hand_calculation(case):
    kwargs, expected = GEOMETRY_CASES[case]
    doc = open_pdf(**kwargs)
    page = doc[0]
    rotation_before = page.rotation

    geometry = convert_displayed_rect(page, DISPLAYED)

    assert geometry.pdf_rect == pytest.approx(expected, abs=1e-6)
    assert geometry.rotation == kwargs.get("rotate", 0)
    assert page.rotation == rotation_before


def placement(**overrides):
    base = {"page": 0, "type": "signature", "x": 100.0, "y": 100.0}
    base.update(overrides)
    return base


def test_validate_accepts_box_touching_page_edges():
    doc = open_pdf(width=300, height=200)
    result = validate_placements(doc, [placement(x=150, y=150), placement(type="initials", x=0, y=0)])
    assert [(p.type, p.x, p.y) for p in result] == [("signature", 150, 150), ("initials", 0, 0)]


def test_validate_uses_displayed_size_on_rotated_page():
    # A 600x300 portrait-stored page rotated 90 is displayed 300 wide, 600 tall.
    doc = open_pdf(width=600, height=300, rotate=90)
    validate_placements(doc, [placement(x=150, y=550)])
    with pytest.raises(PlacementError, match="does not fit"):
        validate_placements(doc, [placement(x=151, y=0)])


@pytest.mark.parametrize(
    "bad, message",
    [
        (placement(page=1), "does not exist"),
        (placement(page=-1), "does not exist"),
        (placement(page=True), "whole number"),
        (placement(page="0"), "whole number"),
        (placement(type="full"), "type must be"),
        (placement(type=[]), "type must be"),
        (placement(type={"a": 1}), "type must be"),
        (placement(x=10**400), "finite"),
        (placement(y=-(10**400)), "finite"),
        (placement(x=math.nan), "finite"),
        (placement(y=math.inf), "finite"),
        (placement(x="10"), "finite"),
        (placement(x=True), "finite"),
        (placement(x=-0.02), "does not fit"),
        (placement(x=595 - 150 + 0.02), "does not fit"),
        (placement(y=842 - 50 + 0.02), "does not fit"),
        ("not a dict", "not an object"),
    ],
)
def test_validate_rejects_bad_placement(bad, message):
    doc = open_pdf()
    with pytest.raises(PlacementError, match=message):
        validate_placements(doc, [bad])


def test_validate_tolerates_rounding_noise():
    doc = open_pdf()
    validate_placements(doc, [placement(x=595 - 150 + 0.005, y=-0.005)])


def test_validate_rejects_box_on_tiny_page():
    doc = open_pdf(width=100, height=40)
    with pytest.raises(PlacementError, match="does not fit"):
        validate_placements(doc, [placement(x=0, y=0)])


def test_validate_rejects_user_unit_page():
    doc = open_pdf(user_unit=2)
    with pytest.raises(PlacementError, match="UserUnit"):
        validate_placements(doc, [placement()])


def test_validate_rejects_empty_and_too_many():
    doc = open_pdf()
    with pytest.raises(PlacementError, match="at least one"):
        validate_placements(doc, [])
    with pytest.raises(PlacementError, match="maximum is 2"):
        validate_placements(doc, [placement()] * 3, max_placements=2)
    with pytest.raises(PlacementError, match="must be a list"):
        validate_placements(doc, {"page": 0})


def _pdf_with_rotate(value: str, on_parent: bool = False) -> bytes:
    doc = pymupdf.open()
    page = doc.new_page(width=600, height=800)
    if on_parent:
        parent = int(doc.xref_get_key(page.xref, "Parent")[1].split()[0])
        doc.xref_set_key(parent, "Rotate", value)
        doc.xref_set_key(page.xref, "Rotate", "null")  # inherit from /Pages
    else:
        doc.xref_set_key(page.xref, "Rotate", value)
    data = doc.tobytes()
    doc.close()
    return data


@pytest.mark.parametrize("value, on_parent", [("45", False), ("100", False), ("45", True), ("90.5", False)])
def test_validate_rejects_rotation_that_is_not_a_multiple_of_90(value, on_parent):
    # PDF.js and PyMuPDF disagree on how such pages are displayed, so the drop point is ambiguous.
    with pymupdf.open(stream=_pdf_with_rotate(value, on_parent), filetype="pdf") as doc:
        with pytest.raises(PlacementError, match="rotation"):
            validate_placements(doc, [{"page": 0, "type": "signature", "x": 10, "y": 10}])


@pytest.mark.parametrize("value", ["-90", "450", "270"])
def test_validate_accepts_rotation_multiples_of_90(value):
    with pymupdf.open(stream=_pdf_with_rotate(value), filetype="pdf") as doc:
        assert validate_placements(doc, [{"page": 0, "type": "signature", "x": 10, "y": 10}])
