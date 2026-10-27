"""Placement contract and page geometry for visible signature marks.

A placement is ``{"page": int, "type": "signature" | "initials", "x": float, "y": float}``.

``page`` is 0-based. ``x``/``y`` are the TOP-LEFT corner of the mark box in PDF points in the
page AS DISPLAYED: PyMuPDF ``page.rect`` space (CropBox, /Rotate applied, origin top-left).
This is the same space PDF.js shows at scale 1, so a frontend only divides CSS pixels by its
scale. Box sizes are fixed per type and given in displayed orientation.

The single conversion from displayed space to drawing space and to raw PDF user space lives in
:func:`convert_displayed_rect`; both the drawn appearance and the signature field rectangle are
derived from its result, so they cannot diverge.
"""

import contextlib
import math
from dataclasses import dataclass
from typing import Any, Iterator, List, Optional, Sequence, Tuple

import pymupdf

PLACEMENT_SIGNATURE = "signature"
PLACEMENT_INITIALS = "initials"

# Box sizes in points, in displayed orientation.
BOX_SIZES = {
    PLACEMENT_SIGNATURE: (150.0, 50.0),
    PLACEMENT_INITIALS: (50.0, 35.0),
}

# Tolerance for the "box inside page" check, in points.
FIT_TOLERANCE = 0.01

# Default upper bound for placements in one signing request.
DEFAULT_MAX_PLACEMENTS = 1000


class PlacementError(ValueError):
    """Raised when a placement is invalid. The message is safe to show to the user."""


@dataclass(frozen=True)
class Placement:
    """A validated placement in displayed page space."""

    page: int
    type: str
    x: float
    y: float

    @property
    def size(self) -> Tuple[float, float]:
        """Box (width, height) in displayed orientation."""
        return BOX_SIZES[self.type]

    @property
    def displayed_rect(self) -> pymupdf.Rect:
        """Box rectangle in displayed page space (top-left origin)."""
        width, height = self.size
        return pymupdf.Rect(self.x, self.y, self.x + width, self.y + height)


@dataclass(frozen=True)
class PlacementGeometry:
    """Result of converting one displayed rectangle.

    Attributes:
        unrotated_rect: Rectangle in PyMuPDF unrotated page space. Draw here while the page
            rotation is temporarily 0 (see :func:`unrotated_page`).
        pdf_rect: (x0, y0, x1, y1) in raw PDF default user space (bottom-left origin, MediaBox and
            CropBox offsets included). Used for the signature field /Rect.
        rotation: Page /Rotate value; text drawn with ``rotate=rotation`` is upright as displayed.
    """

    unrotated_rect: pymupdf.Rect
    pdf_rect: Tuple[float, float, float, float]
    rotation: int


def _page_user_unit(page: pymupdf.Page) -> float:
    """Return the page /UserUnit (1.0 when absent)."""
    kind, value = page.parent.xref_get_key(page.xref, "UserUnit")
    if kind in ("null", "undefined") or not value:
        return 1.0
    try:
        return float(value)
    except ValueError:
        return float("nan")


def _raw_page_rotation(page: pymupdf.Page) -> Optional[float]:
    """The page's /Rotate as written (inherited from /Pages parents), or None if it is not a number.

    PyMuPDF normalises invalid values, PDF.js handles them differently, so callers must not rely on
    ``page.rotation`` alone to know how a viewer displays the page.
    """
    doc = page.parent
    xref = page.xref
    for _ in range(64):  # bounded walk up the page tree
        kind, value = doc.xref_get_key(xref, "Rotate")
        if kind not in ("null", "undefined"):
            try:
                return float(value)
            except ValueError:
                return None
        kind, value = doc.xref_get_key(xref, "Parent")
        if kind != "xref":
            break
        xref = int(value.split()[0])
    return 0.0


@contextlib.contextmanager
def unrotated_page(page: pymupdf.Page) -> Iterator[int]:
    """Temporarily set the page rotation to 0 and yield the original rotation.

    PyMuPDF 2.0 loses CropBox offsets in ``page.transformation_matrix`` and in drawing when the
    page is rotated, so conversion and drawing both happen on the unrotated page.
    """
    rotation = page.rotation
    if rotation:
        page.set_rotation(0)
    try:
        yield rotation
    finally:
        if rotation:
            page.set_rotation(rotation)


def convert_displayed_rect(page: pymupdf.Page, displayed_rect: pymupdf.Rect) -> PlacementGeometry:
    """Convert a displayed-space rectangle to drawing space and raw PDF user space.

    This is the only coordinate conversion used for signing: the appearance is drawn at
    ``unrotated_rect`` and the signature field gets ``pdf_rect``.
    """
    unrotated = pymupdf.Rect(displayed_rect) * page.derotation_matrix
    with unrotated_page(page) as rotation:
        pdf = unrotated * ~page.transformation_matrix
    pdf.normalize()
    return PlacementGeometry(
        unrotated_rect=unrotated,
        pdf_rect=(pdf.x0, pdf.y0, pdf.x1, pdf.y1),
        rotation=rotation,
    )


def _finite_float(value: Any) -> Optional[float]:
    """Return ``value`` as a finite float, or None if it is not an int/float or not finite.

    bool is rejected; integers too large for a float (e.g. 10**400) count as not finite.
    """
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def validate_placements(
    doc: pymupdf.Document,
    raw_placements: Sequence[Any],
    max_placements: int = DEFAULT_MAX_PLACEMENTS,
) -> List[Placement]:
    """Validate raw placements against the document and return typed placements.

    Raises:
        PlacementError: With a user-safe message naming the offending placement (1-based).
    """
    if not isinstance(raw_placements, (list, tuple)):
        raise PlacementError("Placements must be a list.")
    if not raw_placements:
        raise PlacementError("Add at least one signature or initials before signing.")
    if len(raw_placements) > max_placements:
        raise PlacementError(
            f"Too many placements ({len(raw_placements)}); the maximum is {max_placements}."
        )

    page_count = doc.page_count
    result = []
    for number, raw in enumerate(raw_placements, start=1):
        label = f"Placement {number}"
        if not isinstance(raw, dict):
            raise PlacementError(f"{label} is not an object.")

        page_index = raw.get("page")
        if not isinstance(page_index, int) or isinstance(page_index, bool):
            raise PlacementError(f"{label}: page must be a whole number.")
        if not 0 <= page_index < page_count:
            raise PlacementError(
                f"{label}: page {page_index + 1} does not exist (the document has {page_count} pages)."
            )

        kind = raw.get("type")
        if not isinstance(kind, str) or kind not in BOX_SIZES:
            raise PlacementError(f"{label}: type must be 'signature' or 'initials'.")

        x, y = _finite_float(raw.get("x")), _finite_float(raw.get("y"))
        if x is None or y is None:
            raise PlacementError(f"{label}: position must be finite numbers.")

        page = doc[page_index]
        user_unit = _page_user_unit(page)
        if user_unit != 1.0:
            raise PlacementError(
                f"{label}: page {page_index + 1} uses a non-standard unit size (/UserUnit), "
                "which is not supported."
            )

        rotate = _raw_page_rotation(page)
        if rotate is None or not math.isfinite(rotate) or rotate % 90 != 0:
            raise PlacementError(
                f"{label}: page {page_index + 1} has an invalid rotation (/Rotate is not a multiple "
                "of 90 degrees), so its layout is ambiguous. Fix the page rotation and try again."
            )

        placement = Placement(page=page_index, type=kind, x=x, y=y)
        box = placement.displayed_rect
        bounds = page.rect
        if (
            box.x0 < bounds.x0 - FIT_TOLERANCE
            or box.y0 < bounds.y0 - FIT_TOLERANCE
            or box.x1 > bounds.x1 + FIT_TOLERANCE
            or box.y1 > bounds.y1 + FIT_TOLERANCE
        ):
            raise PlacementError(
                f"{label}: the {kind} box does not fit inside page {page_index + 1}."
            )
        result.append(placement)
    return result
