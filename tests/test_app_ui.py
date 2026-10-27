"""Streamlit AppTest runs of app.py with the file uploaders replaced by in-memory files."""

from pathlib import Path

from streamlit.testing.v1 import AppTest

from tests.conftest import make_pdf

REPO = Path(__file__).resolve().parent.parent

# AppTest does not drive st.file_uploader, so the script swaps it for a fake that serves files
# placed in session state under "_upload:<label>".
SCRIPT = f"""
import sys
sys.path.insert(0, {str(REPO)!r})
import streamlit as st
import app


class _Upload:
    def __init__(self, name, data):
        self.name = name
        self._data = data

    def getvalue(self):
        return self._data


def _fake_file_uploader(label, **kwargs):
    item = st.session_state.get("_upload:" + label)
    return _Upload(*item) if item else None


st.file_uploader = _fake_file_uploader
app.main()
"""


def placements(at):
    return [(s["page"], s["x"], s["y"]) for s in at.session_state.signatures]


def test_replacing_pdf_keeps_surviving_signature_positions():
    at = AppTest.from_string(SCRIPT, default_timeout=30)
    at.session_state["_upload:PDF Document"] = ("two.pdf", make_pdf(pages=2))
    at.session_state.signatures = [
        {"page": 1, "x": 100, "y": 50, "type": "full"},
        {"page": 0, "x": 200, "y": 50, "type": "full"},
        {"page": 0, "x": 300, "y": 100, "type": "full"},
    ]
    at.run()
    assert not at.exception
    # Page 0 is shown, so the sliders of signatures 2 and 3 now exist.
    assert at.slider(key="sig_x_2").value == 300

    at.session_state["_upload:PDF Document"] = ("one.pdf", make_pdf(pages=1))
    at.run()
    at.run()

    assert not at.exception
    assert placements(at) == [(0, 200, 50), (0, 300, 100)]
