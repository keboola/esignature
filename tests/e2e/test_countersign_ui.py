"""Browser end-to-end for counter-signing (design S9, risks K12-K14, K19).

The browser cannot tell a signed document from one with empty signature fields, so the server
decides: the first Sign on a signed PDF returns ``signed_document`` and the editor switches to
signed mode; the second, deliberate Sign adds the signature and keeps A's signature valid.
"""

from concurrent.futures import ThreadPoolExecutor

import pymupdf
import pytest
from playwright.sync_api import Page, expect
from pyhanko.sign.fields import MDPPerm

from tests.conftest import make_identity, make_pdf
from tests.e2e.test_editor import blank_pdf, open_editor, place, sign_and_download, write
from tests.signed_fixtures import assert_every_signature_ok, sign_as

SIGNED_NOTICE = ("This document is already signed. Your signature will be added; initials and the "
                 "protocol page are not available. Click Sign again.")
FIELDS_NOTICE = "This document seems to contain signature fields."
# A's visible widget in fixtures: raw [300 600 450 650] on a 595 x 842 page = displayed (300, 192).
A_WIDGET_DISPLAYED = (300, 192, 450, 242)


def off_loop(function, *args, **kwargs):
    """pyHanko uses asyncio.run, which cannot run on Playwright's event-loop thread."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(function, *args, **kwargs).result()


@pytest.fixture(scope="module")
def party_a():
    return make_identity(common_name="Alice Original")


@pytest.fixture(scope="module")
def party_b():
    return make_identity(common_name="Bob Countersigner")


@pytest.fixture(scope="module")
def signed_by_a(party_a):
    return off_loop(sign_as, make_pdf(pages=2, text="Contract signed by A"), party_a)


RECORD_SIGN_FORMS = """
window.__signForms = [];
const originalFetch = window.fetch;
window.fetch = (input, init) => {
  if (String(input).includes("/api/sign") && init && init.body instanceof FormData) {
    window.__signForms.push({
      protocol: init.body.get("protocol"),
      lock: init.body.get("lock"),
      placements: JSON.parse(init.body.get("placements")),
    });
  }
  return originalFetch(input, init);
};
"""


def sign_forms(page: Page) -> list:
    """The form fields of every /api/sign request the page sent (recorded by RECORD_SIGN_FORMS)."""
    return page.evaluate("window.__signForms")


def canvas_ink(page: Page, index: int, rect) -> int:
    """Dark pixels the PDF.js canvas shows inside ``rect`` (displayed points) of a page."""
    return page.evaluate("""([index, rect]) => {
        const slot = document.querySelector(`.page[data-page-index="${index}"]`);
        const canvas = slot.querySelector("canvas");
        const ctx = canvas.getContext("2d");
        const cssScale = parseFloat(slot.style.getPropertyValue("--s"));
        const scale = canvas.width / (parseFloat(slot.style.width) / cssScale);
        const [x0, y0, x1, y1] = rect.map((v) => Math.round(v * scale));
        const data = ctx.getImageData(x0, y0, x1 - x0, y1 - y0).data;
        let dark = 0;
        for (let i = 0; i < data.length; i += 4) if (data[i] + data[i + 1] + data[i + 2] < 300) dark += 1;
        return dark;
    }""", [index, list(rect)])


# --- K12/K13/K19: first Sign switches to signed mode, the second one counter-signs ----------------

def test_signed_pdf_switches_to_signed_mode_and_second_sign_keeps_both_valid(
        page: Page, base_url, tmp_path, party_a, party_b, signed_by_a):
    page.add_init_script(RECORD_SIGN_FORMS)
    open_editor(page, base_url, tmp_path, signed_by_a, party_b)
    expect(page.locator("#doc-notice")).to_contain_text(FIELDS_NOTICE)
    # The heuristic notice does not disable anything.
    expect(page.locator("#opt-protocol")).to_be_enabled()
    expect(page.locator("#initials-on")).to_be_enabled()

    page.check("#opt-protocol")
    page.check("#initials-on")
    expect(page.locator(".mark-initials")).to_have_count(2)
    x, y = place(page, 0, 200, 450, 595)

    page.click("#sign")
    expect(page.locator("#sign-notice")).to_have_text(SIGNED_NOTICE)
    expect(page.locator("#opt-protocol")).not_to_be_checked()
    expect(page.locator("#opt-protocol")).to_be_disabled()
    expect(page.locator("#initials-on")).not_to_be_checked()
    expect(page.locator("#initials-on")).to_be_disabled()
    expect(page.locator("#initials-options")).to_be_hidden()
    expect(page.locator(".mark-initials")).to_have_count(0)
    expect(page.locator(".mark-signature")).to_have_count(1)
    expect(page.locator("#download")).to_be_hidden()
    expect(page.locator("#sign-error")).to_be_hidden()
    # Further edits must not re-enable the initials (renderInitials respects signed mode).
    page.keyboard.press("ArrowRight")
    expect(page.locator("#initials-on")).to_be_disabled()
    x += 1

    signed = sign_and_download(page)

    first_form, second_form = sign_forms(page)
    assert first_form["protocol"] == "true"
    assert any(p["type"] == "initials" for p in first_form["placements"])
    assert second_form["protocol"] == "false"
    second = second_form["placements"]
    assert [p["type"] for p in second] == ["signature"]
    assert (second[0]["x"], second[0]["y"]) == pytest.approx((x, y))
    assert signed.startswith(signed_by_a)
    off_loop(assert_every_signature_ok, signed, [party_a.asn1_cert, party_b.asn1_cert], ["A", "Signature_1"])
    with pymupdf.open(stream=signed, filetype="pdf") as doc:
        assert doc.page_count == 2  # no protocol page

    # K19: PDF.js shows the new widget appearance when the signed output is opened.
    page.set_input_files("#pdf-input", write(tmp_path, "countersigned.pdf", signed))
    expect(page.locator('.page[data-page-index="0"][data-rendered="true"]')).to_be_visible()
    expect(page.locator("#sign-notice")).to_be_hidden()
    assert canvas_ink(page, 0, (x + 5, y + 5, x + 145, y + 45)) > 100
    assert canvas_ink(page, 0, (x + 5, y + 60, x + 145, y + 100)) == 0


def test_overlap_with_an_existing_signature_shows_a_warning(
        page: Page, base_url, tmp_path, party_b, signed_by_a):
    open_editor(page, base_url, tmp_path, signed_by_a, party_b)
    x0, y0, x1, y1 = A_WIDGET_DISPLAYED
    place(page, 0, (x0 + x1) / 2, (y0 + y1) / 2, 595)
    expect(page.locator(".mark.overlap")).to_have_count(1)
    expect(page.locator(".mark.overlap .mark-overlap")).to_be_visible()
    expect(page.locator("#sign-hint")).to_contain_text("overlaps an existing signature field")
    expect(page.locator("#sign")).to_be_enabled()  # a warning, not a block

    place(page, 1, 300, 600, 595)
    expect(page.locator(".mark.overlap")).to_have_count(1)


def test_replacing_the_document_resets_signed_mode(page: Page, base_url, tmp_path, party_b, signed_by_a):
    open_editor(page, base_url, tmp_path, signed_by_a, party_b)
    page.check("#opt-protocol")
    place(page, 0, 200, 450, 595)
    page.click("#sign")
    expect(page.locator("#sign-notice")).to_be_visible()

    page.set_input_files("#pdf-input", write(tmp_path, "plain.pdf", blank_pdf(2)))
    expect(page.locator("#doc-info")).to_have_text("2 pages")
    expect(page.locator("#sign-notice")).to_be_hidden()
    expect(page.locator("#doc-notice")).to_be_hidden()
    expect(page.locator("#opt-protocol")).to_be_enabled()
    expect(page.locator("#initials-on")).to_be_enabled()
    page.check("#opt-protocol")
    page.check("#initials-on")
    place(page, 0, 200, 450, 595)
    signed = sign_and_download(page)
    with pymupdf.open(stream=signed, filetype="pdf") as doc:
        assert doc.page_count == 3  # the protocol page is back


def test_certified_document_shows_the_locked_message(page: Page, base_url, tmp_path, party_a, party_b):
    certified = off_loop(sign_as, make_pdf(), party_a, certify=MDPPerm.NO_CHANGES)
    open_editor(page, base_url, tmp_path, certified, party_b)
    place(page, 0, 200, 450, 595)
    page.click("#sign")
    expect(page.locator("#sign-hint")).to_contain_text(
        "The document was certified or locked by a previous signer and does not allow new signatures.")
    expect(page.locator("#sign")).to_be_disabled()
    expect(page.locator(".mark-signature")).to_have_count(1)  # placements kept
    page.keyboard.press("ArrowRight")  # editing does not unblock it
    expect(page.locator("#sign")).to_be_disabled()

    page.set_input_files("#pdf-input", write(tmp_path, "plain.pdf", blank_pdf(1)))
    expect(page.locator("#doc-info")).to_have_text("1 page")
    place(page, 0, 200, 450, 595)
    expect(page.locator("#sign")).to_be_enabled()
