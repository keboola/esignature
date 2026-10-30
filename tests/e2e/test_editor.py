"""Browser end-to-end: the real PDF.js + CSS coordinate path, checked against the signed PDF."""

import io
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

import pymupdf
import pytest
from PIL import Image
from playwright.sync_api import Page, expect

from tests.conftest import P12_PASSWORD, ink_bbox, make_identity
from tests.conftest import assert_all_signatures_ok as _assert_all_signatures_ok

FONT = Path(__file__).resolve().parents[2] / "fonts" / "DancingScript-Regular.ttf"
SIG_W, SIG_H = 150, 50


@pytest.fixture(scope="module")
def identity():
    return make_identity()


def assert_all_signatures_ok(pdf: bytes, identity, expected: int) -> None:
    """pyHanko validation uses asyncio.run, which cannot run on Playwright's event-loop thread."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(_assert_all_signatures_ok, pdf, identity, expected).result()


def write(tmp_path: Path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def blank_pdf(pages: int = 1, rotate_second: bool = False) -> bytes:
    doc = pymupdf.open()
    for _ in range(pages):
        doc.new_page(width=595, height=842)
    if rotate_second:
        doc[1].set_rotation(90)
    data = doc.tobytes()
    doc.close()
    return data


def open_editor(page: Page, base_url: str, tmp_path: Path, pdf: bytes, identity) -> None:
    page.goto(base_url)
    page.set_input_files("#pdf-input", write(tmp_path, "doc.pdf", pdf))
    expect(page.locator('.page[data-page-index="0"][data-rendered="true"]')).to_be_visible()
    page.set_input_files("#p12-input", write(tmp_path, "cert.p12", identity.p12))
    page.fill("#password", identity.password)
    expect(page.locator("#cert-status.ok")).to_be_visible()


def overlay_box(page: Page, index: int):
    overlay = page.locator(f'.overlay[data-page-index="{index}"]')
    overlay.scroll_into_view_if_needed()
    return overlay.bounding_box()


def scale_of(page: Page, index: int, displayed_width: float) -> float:
    return overlay_box(page, index)["width"] / displayed_width


def place(page: Page, index: int, cx_pt: float, cy_pt: float, displayed_width: float):
    """Arm placement and click at the given displayed-page point; returns the expected top-left."""
    page.click("#add-signature")
    box = overlay_box(page, index)
    scale = box["width"] / displayed_width
    # Scroll the viewer so the target point is in the middle of the window, then click it.
    page.eval_on_selector("#viewer", "(el, dy) => { el.scrollTop += dy; }",
                          box["y"] + cy_pt * scale - 450)
    box = page.locator(f'.overlay[data-page-index="{index}"]').bounding_box()
    page.mouse.click(box["x"] + cx_pt * scale, box["y"] + cy_pt * scale)
    return cx_pt - SIG_W / 2, cy_pt - SIG_H / 2


def drag_selected(page: Page, dx_pt: float, dy_pt: float, scale: float) -> None:
    mark = page.locator(".mark.selected")
    box = mark.bounding_box()
    x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
    page.mouse.move(x, y)
    page.mouse.down()
    page.mouse.move(x + dx_pt * scale / 2, y + dy_pt * scale / 2, steps=4)
    page.mouse.move(x + dx_pt * scale, y + dy_pt * scale, steps=4)
    page.mouse.up()


def sign_and_download(page: Page) -> bytes:
    expect(page.locator("#sign"), page.locator("#sign-hint").text_content()).to_be_enabled()
    page.click("#sign")
    expect(page.locator("#download")).to_be_visible(timeout=30_000)
    with page.expect_download() as download:
        page.click("#download")
    return Path(download.value.path()).read_bytes()


def mark_data(page: Page, selector: str = ".mark.selected"):
    mark = page.locator(selector)
    return float(mark.get_attribute("data-x")), float(mark.get_attribute("data-y"))


def assert_mark_at(pdf: bytes, page_index: int, x: float, y: float, w: float = SIG_W, h: float = SIG_H):
    with pymupdf.open(stream=pdf, filetype="pdf") as doc:
        bbox = ink_bbox(doc[page_index])
    assert bbox == pytest.approx((x, y, x + w, y + h), abs=1.0)


# --- D22 / R21: click to place, drag, sign; normal and /Rotate 90 page -------------------------

def test_click_place_drag_and_sign_lands_within_one_point(page: Page, base_url, tmp_path, identity):
    open_editor(page, base_url, tmp_path, blank_pdf(2, rotate_second=True), identity)

    # Page 1: portrait 595 x 842.
    x0, y0 = place(page, 0, 200, 300, 595)
    scale = scale_of(page, 0, 595)
    assert mark_data(page) == pytest.approx((x0, y0), abs=0.01)
    drag_selected(page, 120, 200, scale)
    first = (x0 + 120, y0 + 200)
    assert mark_data(page) == pytest.approx(first, abs=0.01)

    # Page 2: /Rotate 90, displayed as landscape 842 x 595.
    x1, y1 = place(page, 1, 600, 150, 842)
    drag_selected(page, -100, 300, scale)
    second = (x1 - 100, y1 + 300)
    assert mark_data(page) == pytest.approx(second, abs=0.01)
    expect(page.locator("#signature-list li")).to_have_count(2)

    signed = sign_and_download(page)
    assert_all_signatures_ok(signed, identity, expected=2)
    assert_mark_at(signed, 0, *first)
    assert_mark_at(signed, 1, *second)


def test_keyboard_nudge_moves_by_one_and_ten_points(page: Page, base_url, tmp_path, identity):
    open_editor(page, base_url, tmp_path, blank_pdf(1), identity)
    x, y = place(page, 0, 300, 400, 595)
    for _ in range(3):
        page.keyboard.press("ArrowRight")
    page.keyboard.press("Shift+ArrowDown")
    page.keyboard.press("ArrowUp")
    expected = (x + 3, y + 10 - 1)
    assert mark_data(page) == pytest.approx(expected, abs=0.01)

    signed = sign_and_download(page)
    assert_mark_at(signed, 0, *expected)

    page.locator(".mark-signature").focus()
    page.keyboard.press("Delete")
    expect(page.locator(".mark-signature")).to_have_count(0)


def test_shared_initials_with_explicit_corner(page: Page, base_url, tmp_path, identity):
    open_editor(page, base_url, tmp_path, blank_pdf(3), identity)
    page.check("#initials-on")
    page.select_option("#initials-pages", "all-but-last")
    expect(page.locator(".mark-initials")).to_have_count(2)
    page.select_option("#initials-corner", "bl")
    page.fill("#initials-mx", "30")
    page.fill("#initials-my", "40")
    assert mark_data(page, '.mark[data-kind="initials"][data-page="0"]') == pytest.approx((30, 842 - 40 - 35))

    page.fill("#initials-mx", "900")
    expect(page.locator("#initials-warning")).to_contain_text("do not fit on pages 1-2")
    expect(page.locator("#sign")).to_be_disabled()
    page.fill("#initials-mx", "30")

    signed = sign_and_download(page)
    assert_all_signatures_ok(signed, identity, expected=1)
    for index in (0, 1):
        assert_mark_at(signed, index, 30, 842 - 40 - 35, 50, 35)
    with pymupdf.open(stream=signed, filetype="pdf") as doc:
        assert doc[2].get_pixmap().is_unicolor


# --- R16: certificate text is never interpreted as HTML ----------------------------------------

def test_certificate_name_with_markup_renders_as_text(page: Page, base_url, tmp_path):
    hostile = make_identity(common_name="<img src=x onerror=alert(1)>")
    dialogs = []
    page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.dismiss()))
    open_editor(page, base_url, tmp_path, blank_pdf(1), hostile)
    expect(page.locator("#cert-name")).to_contain_text("<img src=x onerror=alert")
    place(page, 0, 200, 200, 595)
    expect(page.locator(".mark-name")).to_contain_text("<img src=x")
    assert page.locator("img").count() == 0
    assert dialogs == []


# --- R22: replacing the PDF clears placements --------------------------------------------------

def test_replacing_the_pdf_clears_placements_and_result(page: Page, base_url, tmp_path, identity):
    open_editor(page, base_url, tmp_path, blank_pdf(2), identity)
    place(page, 0, 200, 200, 595)
    place(page, 1, 300, 300, 595)
    expect(page.locator(".mark-signature")).to_have_count(2)
    sign_and_download(page)

    page.set_input_files("#pdf-input", write(tmp_path, "other.pdf", blank_pdf(3)))
    expect(page.locator('.page[data-page-index="2"]')).to_have_count(1)
    expect(page.locator(".mark-signature")).to_have_count(0)
    expect(page.locator("#signature-list li")).to_have_count(0)
    expect(page.locator("#download")).to_be_hidden()
    expect(page.locator("#doc-info")).to_have_text("3 pages")
    expect(page.locator("#sign")).to_be_disabled()


# --- R20 / R33: offline rendering with images and embedded fonts -------------------------------

def rich_pdf() -> bytes:
    """A page with a JPEG, a JPEG 2000 image (PDF.js decodes it with WASM) and an embedded font."""
    def image(fmt: str, color) -> bytes:
        buffer = io.BytesIO()
        Image.new("RGB", (120, 80), color).save(buffer, fmt)
        return buffer.getvalue()

    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    page.insert_image(pymupdf.Rect(50, 50, 290, 210), stream=image("JPEG", (200, 30, 30)))
    page.insert_image(pymupdf.Rect(305, 50, 545, 210), stream=image("JPEG2000", (30, 30, 200)))
    page.insert_font(fontname="dancing", fontfile=str(FONT))
    page.insert_text((50, 300), "Embedded font sample", fontname="dancing", fontsize=36)
    page.insert_text((50, 360), "Standard font sample", fontname="helv", fontsize=24)
    data = doc.tobytes()
    doc.close()
    return data


def test_renders_offline_with_all_other_origins_blocked(page: Page, base_url, tmp_path, identity):
    own = urlparse(base_url).netloc
    foreign, problems = [], []

    def gate(route):
        url = urlparse(route.request.url)
        if url.scheme in ("http", "https") and url.netloc != own:
            foreign.append(route.request.url)
            route.abort()
        else:
            route.continue_()

    page.route("**/*", gate)
    page.on("console", lambda msg: problems.append(msg.text) if msg.type in ("error", "warning") else None)
    page.on("pageerror", lambda error: problems.append(str(error)))
    open_editor(page, base_url, tmp_path, rich_pdf(), identity)

    pixels = page.evaluate("""() => {
        const canvas = document.querySelector('.page[data-page-index="0"] canvas');
        const ctx = canvas.getContext('2d');
        const sx = canvas.width / 595, sy = canvas.height / 842;
        const at = (x, y) => Array.from(ctx.getImageData(Math.round(x * sx), Math.round(y * sy), 1, 1).data);
        let textInk = 0;
        for (let x = 50; x < 400; x += 1) {
          for (let y = 270; y < 310; y += 2) {
            const [r, g, b] = at(x, y);
            if (r + g + b < 300) textInk += 1;
          }
        }
        return {jpeg: at(170, 130), jpx: at(425, 130), textInk};
    }""")
    assert foreign == []
    assert [m for m in problems if not re.search(r"favicon", m)] == []
    red, blue = pixels["jpeg"], pixels["jpx"]
    assert red[0] > 150 and red[2] < 90, red
    assert blue[2] > 150 and blue[0] < 90, blue
    assert pixels["textInk"] > 50

    place(page, 0, 300, 600, 595)
    assert_all_signatures_ok(sign_and_download(page), identity, expected=1)


def test_wrong_password_shows_error_and_blocks_signing(page: Page, base_url, tmp_path, identity):
    page.goto(base_url)
    page.set_input_files("#pdf-input", write(tmp_path, "doc.pdf", blank_pdf(1)))
    page.set_input_files("#p12-input", write(tmp_path, "cert.p12", identity.p12))
    page.fill("#password", P12_PASSWORD + "-wrong")
    expect(page.locator("#cert-status.bad")).to_contain_text("wrong password")
    place(page, 0, 200, 200, 595)
    expect(page.locator("#sign")).to_be_disabled()


# --- Fix round 1 regressions -------------------------------------------------------------------

def text_pdf(text: str, pages: int = 1, width: float = 595, height: float = 842) -> bytes:
    doc = pymupdf.open()
    for _ in range(pages):
        doc.new_page(width=width, height=height).insert_text((72, 100), text, fontsize=14)
    data = doc.tobytes()
    doc.close()
    return data


def test_signs_the_bytes_that_were_previewed_even_if_the_file_changes_on_disk(
        page: Page, base_url, tmp_path, identity):
    open_editor(page, base_url, tmp_path, text_pdf("PRICE: 1000 EUR"), identity)
    place(page, 0, 300, 400, 595)
    write(tmp_path, "doc.pdf", text_pdf("PRICE: 9999 EUR"))  # same path, new content
    write(tmp_path, "cert.p12", b"garbage")
    signed = sign_and_download(page)
    with pymupdf.open(stream=signed, filetype="pdf") as doc:
        text = doc[0].get_text()
    assert "PRICE: 1000 EUR" in text and "9999" not in text


SLOW_READ = """
const original = File.prototype.arrayBuffer;
File.prototype.arrayBuffer = function () {
  if (this.name === "slow.pdf") {
    return new Promise((resolve) => setTimeout(() => resolve(original.call(this)), 1500));
  }
  return original.call(this);
};
"""


def test_a_slow_earlier_file_read_never_replaces_the_newer_document(page: Page, base_url, tmp_path):
    page.add_init_script(SLOW_READ)
    page.goto(base_url)
    page.set_input_files("#pdf-input", write(tmp_path, "slow.pdf", text_pdf("A", 2, 842, 595)))
    page.set_input_files("#pdf-input", write(tmp_path, "fast.pdf", text_pdf("B", 1)))
    expect(page.locator('.page[data-page-index="0"][data-rendered="true"]')).to_be_visible()
    page.wait_for_timeout(2500)  # the slow read has resolved by now
    expect(page.locator(".page")).to_have_count(1)
    expect(page.locator("#doc-info")).to_have_text("1 page")
    expect(page.locator("#pdf-name")).to_have_text("fast.pdf")
    box = overlay_box(page, 0)
    assert box["height"] > box["width"]  # portrait B, not landscape A


def test_replacing_the_pdf_resets_initials(page: Page, base_url, tmp_path, identity):
    open_editor(page, base_url, tmp_path, blank_pdf(2), identity)
    page.check("#initials-on")
    expect(page.locator(".mark-initials")).to_have_count(2)
    page.set_input_files("#pdf-input", write(tmp_path, "other.pdf", blank_pdf(1)))
    expect(page.locator("#doc-info")).to_have_text("1 page")
    expect(page.locator("#initials-on")).not_to_be_checked()
    expect(page.locator("#initials-options")).to_be_hidden()
    expect(page.locator(".mark-initials")).to_have_count(0)
    expect(page.locator("#sign")).to_be_disabled()


SLOW_SIGN = """
window.__signCalls = 0;
const originalFetch = window.fetch;
window.fetch = async (input, init) => {
  if (String(input).includes("/api/sign")) {
    window.__signCalls += 1;
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
  return originalFetch(input, init);
};
"""


def test_editing_while_signing_keeps_sign_disabled_and_discards_the_stale_result(
        page: Page, base_url, tmp_path, identity):
    page.add_init_script(SLOW_SIGN)
    open_editor(page, base_url, tmp_path, blank_pdf(1), identity)
    place(page, 0, 300, 400, 595)
    page.click("#sign")
    page.check("#opt-protocol")  # an edit while the request is in flight
    expect(page.locator("#sign")).to_be_disabled()
    expect(page.locator("#sign-hint")).to_contain_text("changed while signing", timeout=10_000)
    expect(page.locator("#download")).to_be_hidden()
    assert page.evaluate("window.__signCalls") == 1
    signed = sign_and_download(page)
    assert page.evaluate("window.__signCalls") == 2
    with pymupdf.open(stream=signed, filetype="pdf") as doc:
        assert doc.page_count == 2  # the protocol page chosen during the first request


def test_keys_on_the_download_link_do_not_edit_the_document(page: Page, base_url, tmp_path, identity):
    open_editor(page, base_url, tmp_path, blank_pdf(1), identity)
    x, y = place(page, 0, 300, 400, 595)
    sign_and_download(page)
    page.focus("#download")
    for key in ("ArrowRight", "ArrowDown", "Backspace", "Delete"):
        page.keyboard.press(key)
    assert mark_data(page, ".mark-signature") == pytest.approx((x, y))
    expect(page.locator("#download")).to_be_visible()


def test_signature_cannot_be_placed_on_a_page_smaller_than_the_box(page: Page, base_url, tmp_path, identity):
    doc = pymupdf.open()
    doc.new_page(width=120, height=40)
    doc.new_page(width=595, height=842)
    pdf = doc.tobytes()
    open_editor(page, base_url, tmp_path, pdf, identity)
    page.click("#add-signature")
    box = overlay_box(page, 0)
    page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
    expect(page.locator(".mark-signature")).to_have_count(0)
    expect(page.locator("#place-banner")).to_contain_text("too small")


def test_initials_misfit_reason_is_shown_next_to_sign(page: Page, base_url, tmp_path, identity):
    open_editor(page, base_url, tmp_path, blank_pdf(3), identity)
    page.check("#initials-on")
    page.fill("#initials-my", "900")
    expect(page.locator("#sign-hint")).to_contain_text("pages 1-3")
    expect(page.locator("#sign")).to_be_disabled()


def test_all_five_steps_are_visible_without_scrolling_at_1280x800(page: Page, base_url, tmp_path, identity):
    page.set_viewport_size({"width": 1280, "height": 800})
    open_editor(page, base_url, tmp_path, blank_pdf(2), identity)
    place(page, 0, 300, 400, 595)
    page.check("#initials-on")
    page.eval_on_selector(".steps", "el => { el.scrollTop = 0; }")  # as the user first sees it
    for selector in ("#step-document h2", "#step-certificate h2", "#step-options h2", "#opt-protocol",
                     "#opt-lock", "#step-place h2", "#add-signature", "#step-sign h2", "#sign"):
        box = page.locator(selector).bounding_box()
        assert box["y"] >= 0 and box["y"] + box["height"] <= 800, f"{selector} is off screen"
        hit = page.evaluate(
            "([x, y, sel]) => { const el = document.elementFromPoint(x, y);"
            " return !!el && (el.closest(sel) !== null || el.contains(document.querySelector(sel))); }",
            [box["x"] + box["width"] / 2, box["y"] + box["height"] / 2, selector])
        assert hit, f"{selector} is covered"


STALLED_CERT_CHECK = """
window.__certCalls = 0;
const originalFetch = window.fetch;
window.fetch = async (input, init) => {
  if (String(input).includes("/api/certificate")) {
    window.__certCalls += 1;
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
  return originalFetch(input, init);
};
const originalRead = File.prototype.arrayBuffer;
File.prototype.arrayBuffer = function () {
  if (this.name === "unreadable.p12") return Promise.reject(new DOMException("gone", "NotReadableError"));
  return originalRead.call(this);
};
"""


def test_certificate_status_matches_state_after_a_check_is_superseded_by_a_failed_read(
        page: Page, base_url, tmp_path, identity):
    page.add_init_script(STALLED_CERT_CHECK)
    page.goto(base_url)
    page.fill("#password", identity.password)
    page.set_input_files("#p12-input", write(tmp_path, "good.p12", identity.p12))
    page.wait_for_function("() => window.__certCalls === 1")  # check A is now pending
    page.set_input_files("#p12-input", write(tmp_path, "unreadable.p12", b"x"))
    page.wait_for_timeout(2500)  # check A has resolved by now
    expect(page.locator("#cert-status")).to_have_class(re.compile(r"\bbad\b"))
    expect(page.locator("#cert-name")).to_have_text("The certificate file could not be read.")
