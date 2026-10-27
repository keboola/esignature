"""The Streamlit UI keeps its bottom-left slider semantics on top of the new placement contract."""

import pytest

from app import to_signer_placement
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
