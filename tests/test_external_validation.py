"""An independent PDF implementation verifies synthetic signatures produced by the app."""

import os
import re
import shutil
import subprocess

import pytest

from signer import sign_pdf_multiple
from tests.conftest import make_identity, make_pdf
from tests.signed_fixtures import sign_as, signed_linearized_layout


@pytest.fixture(scope="module")
def countersigner():
    return make_identity(common_name="CI countersigner")


def inspect_with_poppler(pdf, tmp_path, allow_invalid=False):
    pdfsig = shutil.which("pdfsig")
    if pdfsig is None:
        pytest.skip("Install Poppler (poppler-utils) for independent signature validation")
    path = tmp_path / "synthetic.pdf"
    path.write_bytes(pdf)
    result = subprocess.run(
        [pdfsig, "-nocert", "-no-ocsp", str(path)],
        capture_output=True, text=True, timeout=30,
        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
    )
    # Some Poppler releases return 1 for an invalid signature, older ones report it with 0.
    assert result.returncode in ((0, 1) if allow_invalid else (0,)), result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize("linearized", [False, True], ids=["approval", "linearized-initial-signature"])
def test_poppler_verifies_both_signatures_and_detects_tampering(
    identity, countersigner, tmp_path, linearized,
):
    original = (signed_linearized_layout(identity) if linearized
                else sign_as(make_pdf(text="Synthetic contract"), identity))
    output = sign_pdf_multiple(
        original, countersigner.p12, countersigner.password,
        [{"page": 0, "type": "signature", "x": 100, "y": 100}],
    )
    assert output.startswith(original)
    report = inspect_with_poppler(output, tmp_path)
    assert len(re.findall(r"^Signature #\d+:", report, flags=re.MULTILINE)) == 2, report
    assert report.count("Signature Validation: Signature is Valid.") == 2, report
    assert "Signature Field Name: A" in report and "Signature Field Name: Signature_1" in report

    # Negative control: retain byte offsets while changing content covered by the new signature.
    reason = b"/Reason (Electronically signed)"
    assert output.count(reason) == 1
    tampered = output.replace(reason, b"/Reason (Electronically forged)", 1)
    report = inspect_with_poppler(tampered, tmp_path, allow_invalid=True)
    assert report.count("Signature Validation: Signature is Valid.") == 1, report
    assert "Digest Mismatch" in report, report
