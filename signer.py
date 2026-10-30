"""PDF signing functionality using pyhanko with visual signatures.

Every full signature is a NEW signature field added in its own incremental revision; the field's
widget appearance is the signature mark (imported as a form XObject and counter-rotated for the
page /Rotate). Signatures are never drawn into page content.

Unsigned input:
1. Open the PDF once (MuPDF may repair it), draw the initials into page contents and append the
   optional protocol page(s), then save once. Nothing is signed yet, so a full save is fine.
2. Add the signatures incrementally. No full save happens after the first signature.
   If only initials are placed, one invisible signature is added so the document is still signed.

Signed input (counter-signing):
- Classification runs on the ORIGINAL bytes before any serialisation (see _classify_input).
- The original bytes are never re-serialised; initials and the protocol page are refused.
- Existing signatures are checked before signing (_check_existing_signatures) and re-validated in
  the output (_post_check); the output must start with the original bytes.

Placements follow the contract documented in :mod:`geometry`.
"""

import asyncio
import io
import logging
import re
import traceback
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import pymupdf
from cryptography.hazmat.primitives.serialization import pkcs12
from pyhanko.pdf_utils import content, generic, layout
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.fields import FieldMDPAction, FieldMDPSpec, MDPPerm
from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata
from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp
from pyhanko.sign.validation.pdf_embedded import read_certification_data
from pyhanko.stamp import NoOpStampStyle, StaticStampStyle
from pyhanko_certvalidator import ValidationContext

from certificate_validation import (
    ConfiguredTimeStamper,
    TimestampConfig,
    ValidationPolicy,
    fetch_crls,
    signature_security_details,
    timestamp_details,
)
from geometry import (
    BOX_SIZES,
    DEFAULT_MAX_PLACEMENTS,
    PLACEMENT_INITIALS,
    PLACEMENT_SIGNATURE,
    Placement,
    PlacementError,
    convert_displayed_rect,
    unrotated_page,
    validate_placements,
)

logger = logging.getLogger(__name__)

# Path to signature font (Dancing Script for fancy name)
FONT_PATH = Path(__file__).parent / "fonts" / "DancingScript-Regular.ttf"

GITHUB_URL = "https://github.com/keboola/esignature"

# Width of the mark border in points. The border is drawn fully inside the box.
BORDER_WIDTH = 0.5

# PDF version required for approval-signature document locking (/Lock /P).
LOCK_PDF_VERSION = (2, 0)

__all__ = [
    "SigningError",
    "CertificateValidationError",
    "PdfInputError",
    "PlacementError",
    "load_signer_from_p12",
    "validate_certificate",
    "get_certificate_info",
    "get_signer_name",
    "get_initials",
    "sanitize_signer_name",
    "format_page_ranges",
    "sign_pdf_multiple",
    "validate_pdf_document",
]


class SigningError(Exception):
    """Base class for signing errors. The message is safe to show to the user."""


class CertificateValidationError(SigningError):
    """Raised when the P12 cannot be used for signing (password, key, validity)."""


class PdfInputError(SigningError):
    """Raised when the input PDF is not accepted for signing.

    ``code`` is an optional machine-readable reason for the API (``signed_document``,
    ``locked_document``, ``invalid_existing_signatures``).
    """

    def __init__(self, message: str, code: Optional[str] = None) -> None:
        super().__init__(message)
        self.code = code


def load_signer_from_p12(
    p12_bytes: bytes,
    p12_password: str,
) -> signers.SimpleSigner:
    """Load a signer from PKCS12 certificate bytes. An empty password is allowed.

    Raises:
        CertificateValidationError: With a user-safe message; the password is never included.
    """
    # An empty password may mean "no encryption" (None) or an empty passphrase (b"").
    candidates = [p12_password.encode("utf-8")] if p12_password else [None, b""]
    for passphrase in candidates:
        try:
            key, cert, _ = pkcs12.load_key_and_certificates(p12_bytes, passphrase)
        except ValueError:
            continue
        break
    else:
        raise CertificateValidationError(
            "Could not open the P12 certificate: wrong password or not a valid P12 file."
        )

    if key is None:
        raise CertificateValidationError("The P12 file does not contain a private key.")
    if cert is None:
        raise CertificateValidationError("The P12 file does not contain a certificate.")

    try:
        return signers.SimpleSigner.load_pkcs12_data(
            pkcs12_bytes=p12_bytes,
            other_certs=[],
            passphrase=passphrase,
        )
    except ValueError as e:
        raise CertificateValidationError(
            "The key or certificate in the P12 file is not supported."
        ) from e


def get_signer_name_from_signer(signer: signers.SimpleSigner) -> str:
    """Extract the common name (CN) from the signer's certificate."""
    cn = signer.signing_cert.subject.native.get('common_name')
    return cn or "Unknown"


def get_certificate_info(signer: signers.SimpleSigner) -> Dict:
    """
    Extract detailed information from the signer's certificate.

    All string values are sanitized to prevent injection attacks.

    Returns:
        Dict with certificate details
    """
    def sanitize_cert_field(value: str, max_length: int = 100) -> str:
        """Sanitize a certificate field value."""
        if not value:
            return ''
        # Remove control characters and limit length
        sanitized = ''.join(
            c for c in str(value)
            if unicodedata.category(c) not in ('Cc', 'Cf', 'Co', 'Cs')
        )
        sanitized = sanitized.replace('\x00', '').strip()
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length - 3] + "..."
        return sanitized

    cert = signer.signing_cert

    # Subject info - sanitize all string values
    subject = cert.subject.native
    issuer = cert.issuer.native
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after

    # Serial number - format as hex, limit length
    serial = cert.serial_number
    serial_str = format(serial, 'X') if serial else ''
    if len(serial_str) > 64:
        serial_str = serial_str[:61] + "..."

    return {
        'subject_cn': sanitize_cert_field(subject.get('common_name', 'Unknown')),
        'subject_org': sanitize_cert_field(subject.get('organization_name', '')),
        'subject_country': sanitize_cert_field(subject.get('country_name', ''), max_length=50),
        'issuer_cn': sanitize_cert_field(issuer.get('common_name', 'Unknown')),
        'issuer_org': sanitize_cert_field(issuer.get('organization_name', '')),
        'valid_from': not_before.strftime('%d.%m.%Y %H:%M') if not_before else '',
        'valid_to': not_after.strftime('%d.%m.%Y %H:%M') if not_after else '',
        'serial_number': serial_str,
    }


def get_signer_name(p12_bytes: bytes, p12_password: str) -> str:
    """Extract and sanitize the common name (CN) from a P12 certificate.

    Raises:
        CertificateValidationError: If the P12 cannot be opened.
    """
    signer = load_signer_from_p12(p12_bytes, p12_password)
    return sanitize_signer_name(get_signer_name_from_signer(signer))


def get_initials(name: str) -> str:
    """
    Generate initials from a name.

    Examples:
        "Jan Novak" -> "JN"
        "Ing. Jan Novak Ph.D." -> "JN"
        "Marie Anna Kovarova" -> "MAK"
    """
    # Remove academic titles
    titles = ['ing.', 'mgr.', 'bc.', 'mudr.', 'judr.', 'phdr.', 'rndr.',
              'doc.', 'prof.', 'ph.d.', 'csc.', 'drsc.', 'mba', 'dis.']

    name_lower = name.lower()
    for title in titles:
        name_lower = name_lower.replace(title, '')

    # Split into words and take first letters
    words = [w.strip() for w in name_lower.split() if w.strip()]
    initials = ''.join(w[0].upper() for w in words if w and w[0].isalpha())

    return initials if initials else "?"


def validate_certificate(signer: signers.SimpleSigner) -> None:
    """
    Validate the signer's certificate for security requirements.

    Checks:
        - Certificate is not expired
        - Certificate is already valid (not future-dated)

    Raises:
        CertificateValidationError: If validation fails
    """
    cert = signer.signing_cert
    now = datetime.now(timezone.utc)

    not_after = cert.not_valid_after
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    if not_after < now:
        days_expired = (now - not_after).days
        raise CertificateValidationError(
            f"Certificate expired {days_expired} days ago "
            f"(expired on {not_after.strftime('%Y-%m-%d %H:%M UTC')})"
        )

    not_before = cert.not_valid_before
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_before > now:
        raise CertificateValidationError(
            f"Certificate not yet valid "
            f"(valid from {not_before.strftime('%Y-%m-%d %H:%M UTC')})"
        )

    # Warn if expiring soon (within 30 days) - not an error
    days_until_expiry = (not_after - now).days
    if days_until_expiry <= 30:
        logger.warning(
            "Certificate expires in %d days (on %s)",
            days_until_expiry, not_after.strftime('%Y-%m-%d'),
        )


# Maximum length for signer name (prevents DoS via extremely long names)
MAX_SIGNER_NAME_LENGTH = 100


def sanitize_signer_name(name: str) -> str:
    """
    Sanitize the signer name extracted from certificate for safe display.

    Security measures:
        - Remove control characters
        - Remove potentially dangerous Unicode characters
        - Limit length to prevent buffer issues
        - Normalize Unicode to NFC form
        - Remove null bytes and other binary characters
        - Strip leading/trailing whitespace

    Args:
        name: Raw name from certificate CN field

    Returns:
        Sanitized name safe for display in PDF
    """
    if not name:
        return "Unknown"

    # Normalize Unicode to NFC (composed form)
    name = unicodedata.normalize('NFC', name)

    # Remove null bytes and control characters (except space)
    # Control characters are in categories Cc (control) and Cf (format)
    sanitized = []
    for char in name:
        category = unicodedata.category(char)
        # Allow letters, numbers, punctuation, symbols, and regular spaces
        if category not in ('Cc', 'Cf', 'Co', 'Cs'):  # Control, Format, Private Use, Surrogate
            sanitized.append(char)

    name = ''.join(sanitized)

    # Remove specific dangerous patterns
    # - Null bytes (already handled above, but be explicit)
    name = name.replace('\x00', '')
    # - PDF escape sequences that could be interpreted
    name = name.replace('\\', '/')  # Backslash to forward slash
    # - Parentheses that could break PDF strings
    name = name.replace('(', '[').replace(')', ']')

    # Remove excessive whitespace
    name = re.sub(r'\s+', ' ', name)

    # Strip leading/trailing whitespace
    name = name.strip()

    # Limit length
    if len(name) > MAX_SIGNER_NAME_LENGTH:
        name = name[:MAX_SIGNER_NAME_LENGTH - 3] + "..."

    # Final check - if empty after sanitization, return default
    if not name:
        return "Unknown"

    return name


def normalize_text(text: str) -> str:
    """
    Normalize text for PDF fonts that don't support full Unicode.
    Converts Czech characters to ASCII equivalents.
    """
    replacements = {
        'á': 'a', 'č': 'c', 'ď': 'd', 'é': 'e', 'ě': 'e', 'í': 'i',
        'ň': 'n', 'ó': 'o', 'ř': 'r', 'š': 's', 'ť': 't', 'ú': 'u',
        'ů': 'u', 'ý': 'y', 'ž': 'z',
        'Á': 'A', 'Č': 'C', 'Ď': 'D', 'É': 'E', 'Ě': 'E', 'Í': 'I',
        'Ň': 'N', 'Ó': 'O', 'Ř': 'R', 'Š': 'S', 'Ť': 'T', 'Ú': 'U',
        'Ů': 'U', 'Ý': 'Y', 'Ž': 'Z',
    }
    for orig, repl in replacements.items():
        text = text.replace(orig, repl)
    return text


def format_page_ranges(page_indices: Iterable[int]) -> str:
    """Format 0-based page indices as 1-based ranges, e.g. [0, 1, 2, 4] -> "1-3, 5"."""
    pages = sorted(set(page_indices))
    parts = []
    start = previous = None
    for page in pages:
        if start is None:
            start = previous = page
        elif page == previous + 1:
            previous = page
        else:
            parts.append((start, previous))
            start = previous = page
    if start is not None:
        parts.append((start, previous))
    return ", ".join(f"{a + 1}" if a == b else f"{a + 1}-{b + 1}" for a, b in parts)


# --- Visible marks ---------------------------------------------------------------------------

def _format_signing_time(signed_at: datetime) -> str:
    """Format the local signing time with its timezone abbreviation."""
    local = signed_at.astimezone()
    return f"{local.strftime('%Y-%m-%d %H:%M:%S')} {local.tzname() or ''}".strip()


def _fit_text(
    text: str,
    font: pymupdf.Font,
    max_width: float,
    fontsize: float,
    min_fontsize: float,
    step: float = 0.5,
) -> Tuple[str, float]:
    """Shrink ``text`` down to ``min_fontsize`` to fit ``max_width``; then abbreviate with "...".

    Returns:
        (text to draw, font size)
    """
    while fontsize > min_fontsize and font.text_length(text, fontsize=fontsize) > max_width:
        fontsize = max(min_fontsize, fontsize - step)
    if font.text_length(text, fontsize=fontsize) <= max_width:
        return text, fontsize
    ellipsis = "..."
    shortened = text
    while shortened and font.text_length(shortened + ellipsis, fontsize=fontsize) > max_width:
        shortened = shortened[:-1]
    return shortened.rstrip() + ellipsis, fontsize


def _new_mark_page(mark_doc: pymupdf.Document, kind: str) -> pymupdf.Page:
    """Create an upright mark page of the box size with a white box and a border."""
    width, height = BOX_SIZES[kind]
    page = mark_doc.new_page(width=width, height=height)
    inset = BORDER_WIDTH / 2
    page.draw_rect(
        pymupdf.Rect(inset, inset, width - inset, height - inset),
        color=(0, 0, 0), fill=(1, 1, 1), width=BORDER_WIDTH,
    )
    return page


def _build_signature_mark(signer_name: str, signed_at: datetime) -> pymupdf.Document:
    """One-page PDF with the full signature appearance in displayed (upright) orientation."""
    mark_doc = pymupdf.open()
    page = _new_mark_page(mark_doc, PLACEMENT_SIGNATURE)

    name_font = "helv"
    name = normalize_text(signer_name)
    if FONT_PATH.is_file():
        page.insert_font(fontname="dancing", fontfile=str(FONT_PATH))
        name_font = "dancing"
        name = signer_name
    else:
        logger.warning("Signature font not found at %s, using Helvetica", FONT_PATH)

    # Shrink, and if needed abbreviate, long names so they stay inside the box.
    # The protocol page always shows the full name.
    font = pymupdf.Font(fontfile=str(FONT_PATH)) if name_font == "dancing" else pymupdf.Font("helv")
    name, fontsize = _fit_text(name, font, BOX_SIZES[PLACEMENT_SIGNATURE][0] - 10, 14.0, 6.0)
    page.insert_text((5, 18), name, fontsize=fontsize, fontname=name_font, color=(0, 0, 0))
    page.insert_text((5, 32), _format_signing_time(signed_at), fontsize=8, fontname="helv",
                     color=(0.3, 0.3, 0.3))
    page.insert_text((5, 44), "github.com/keboola/esignature", fontsize=6, fontname="helv",
                     color=(0.5, 0.5, 0.5))
    return mark_doc


def _build_initials_mark(signer_name: str) -> pymupdf.Document:
    """One-page PDF with the initials appearance (centred letters) in upright orientation."""
    mark_doc = pymupdf.open()
    page = _new_mark_page(mark_doc, PLACEMENT_INITIALS)
    width, height = BOX_SIZES[PLACEMENT_INITIALS]
    # Helvetica has no Czech diacritics
    text = normalize_text(get_initials(signer_name))
    text, fontsize = _fit_text(text, pymupdf.Font("helv"), width - 6, 18.0, 6.0, step=1.0)
    text_width = pymupdf.get_text_length(text, "helv", fontsize)
    page.insert_text(((width - text_width) / 2, height / 2 + fontsize * 0.35), text,
                     fontsize=fontsize, fontname="helv", color=(0, 0, 0))
    return mark_doc


def _draw_initials(
    doc: pymupdf.Document,
    placements: Sequence[Placement],
    signer_name: str,
) -> None:
    """Draw every initials placement into page contents (unsigned input only)."""
    initials = [p for p in placements if p.type == PLACEMENT_INITIALS]
    if not initials:
        return
    mark = _build_initials_mark(signer_name)
    try:
        for placement in initials:
            page = doc[placement.page]
            geometry = convert_displayed_rect(page, placement.displayed_rect)
            with unrotated_page(page) as rotation:
                page.show_pdf_page(geometry.unrotated_rect, mark, 0, rotate=rotation)
    finally:
        mark.close()


def _signature_boxes(doc: pymupdf.Document, placements: Sequence[Placement]) -> List["SignatureBox"]:
    """Raw widget rectangle and page rotation for each signature placement, in order.

    ``doc`` is only read (its page rotation is changed temporarily by the conversion and restored).
    """
    boxes = []
    for placement in placements:
        if placement.type != PLACEMENT_SIGNATURE:
            continue
        geometry = convert_displayed_rect(doc[placement.page], placement.displayed_rect)
        boxes.append(SignatureBox(placement.page, geometry.pdf_rect, geometry.rotation))
    return boxes


# --- Protocol page ---------------------------------------------------------------------------

PROTOCOL_PAGE_SIZE = (595, 842)
PROTOCOL_MARGIN = 50
PROTOCOL_BOTTOM = 842 - 80  # last baseline; the footer lives below


def _split_token(word: str, fontsize: float, max_width: float) -> List[str]:
    """Split a token wider than ``max_width`` into character chunks that fit."""
    chunks: List[str] = []
    current = ""
    for char in word:
        if current and pymupdf.get_text_length(current + char, "helv", fontsize) > max_width:
            chunks.append(current)
            current = char
        else:
            current += char
    chunks.append(current)
    return chunks


def _wrap(text: str, fontsize: float, max_width: float) -> List[str]:
    """Greedy word wrap for Helvetica text; tokens longer than a line are split."""
    lines: List[str] = []
    current = ""
    words = []
    for token in text.split(" "):
        if pymupdf.get_text_length(token, "helv", fontsize) > max_width:
            words.extend(_split_token(token, fontsize, max_width))
        else:
            words.append(token)
    for word in words:
        candidate = f"{current} {word}" if current else word
        if current and pymupdf.get_text_length(candidate, "helv", fontsize) > max_width:
            lines.append(current)
            current = word
        else:
            current = candidate
    lines.append(current)
    return lines


def _protocol_lines(
    placements: Sequence[Placement],
    signer_name: str,
    cert_info: Dict,
    original_page_count: int,
    signed_at: datetime,
) -> List[Tuple[str, float, float, float]]:
    """Build protocol content as (text, fontsize, indent, gap_before) entries."""
    header, text = 12, 10
    lines: List[Tuple[str, float, float, float]] = []

    def section(title: str, rows: Sequence[str]) -> None:
        lines.append((title, header, 0, 25 if lines else 0))
        for i, row in enumerate(rows):
            lines.append((row, text, 10, 18 if i == 0 else 0))

    section("Document Information:", [
        f"Number of pages: {original_page_count}",
        f"Signing date: {_format_signing_time(signed_at)}",
    ])

    cert_rows = [f"Owner: {normalize_text(cert_info.get('subject_cn', '') or signer_name)}"]
    if cert_info.get('subject_org'):
        cert_rows.append(f"Organization: {normalize_text(cert_info['subject_org'])}")
    cert_rows.append(f"Issuer: {normalize_text(cert_info.get('issuer_cn', ''))}")
    if cert_info.get('issuer_org'):
        cert_rows.append(f"Issuer Org: {normalize_text(cert_info['issuer_org'])}")
    cert_rows += [
        f"Valid from: {cert_info.get('valid_from', '')}",
        f"Valid until: {cert_info.get('valid_to', '')}",
        f"Serial number: {cert_info.get('serial_number', '')}",
    ]
    section("Certificate Used:", cert_rows)

    signature_rows = [
        f"{number}. Digital signature - page {p.page + 1}"
        for number, p in enumerate((p for p in placements if p.type == PLACEMENT_SIGNATURE), start=1)
    ]
    initials_pages = [p.page for p in placements if p.type == PLACEMENT_INITIALS]
    if initials_pages:
        signature_rows.append(f"Initials on pages: {format_page_ranges(initials_pages)}")
    if not any(p.type == PLACEMENT_SIGNATURE for p in placements):
        signature_rows.insert(0, "Document signature (not visible on a page)")
    section("Applied Signatures:", signature_rows)

    section("Signature Verification:", [
        "The digital signature can be verified in Adobe Acrobat Reader",
        "or any other PDF viewer that supports digital signatures.",
        "",
        "The signature contains:",
        "- Timestamp of signing moment",
        "- Signer identity from certificate",
        "- Cryptographic hash of the document",
        "- Certificate chain for verification",
    ])
    return lines


def _append_protocol_pages(
    doc: pymupdf.Document,
    placements: Sequence[Placement],
    signer_name: str,
    cert_info: Dict,
    signed_at: datetime,
) -> None:
    """Append protocol page(s); content continues on further pages instead of being cut."""
    width, height = PROTOCOL_PAGE_SIZE
    margin = PROTOCOL_MARGIN
    original_page_count = doc.page_count
    page: Optional[pymupdf.Page] = None
    y = 0.0

    def new_page(continued: bool) -> pymupdf.Page:
        new = doc.new_page(width=width, height=height)
        title = "Digital Signature Protocol" + (" (continued)" if continued else "")
        new.insert_text((margin, 50), title, fontsize=18, fontname="helv")
        new.draw_line((margin, 90), (width - margin, 90), width=1)
        new.draw_line((margin, height - 50), (width - margin, height - 50), width=0.5)
        new.insert_text((margin, height - 35), f"Created by Keboola eSignature | {GITHUB_URL}",
                        fontsize=8, fontname="helv", color=(0.4, 0.4, 0.4))
        return new

    page = new_page(continued=False)
    y = 115.0
    for text, fontsize, indent, gap in _protocol_lines(
        placements, signer_name, cert_info, original_page_count, signed_at
    ):
        y += gap
        for wrapped in _wrap(text, fontsize, width - 2 * margin - indent):
            if y > PROTOCOL_BOTTOM:
                page = new_page(continued=True)
                y = 115.0
            if wrapped:
                page.insert_text((margin + indent, y), wrapped, fontsize=fontsize, fontname="helv")
            y += 14


# --- Input policy -------------------------------------------------------------------------------

# Guard against cyclic or absurdly deep AcroForm trees.
MAX_FIELD_TREE_DEPTH = 64

# Default upper bound for existing signatures validated before counter-signing (config overrides it).
DEFAULT_MAX_EXISTING_SIGNATURES = 20

# Default upper bound for revisions (incremental updates) of an input PDF (config overrides it).
DEFAULT_MAX_REVISIONS = 100

# Machine-readable error codes for the API (see PdfInputError.code).
CODE_SIGNED_DOCUMENT = "signed_document"
CODE_LOCKED_DOCUMENT = "locked_document"
CODE_INVALID_EXISTING = "invalid_existing_signatures"
CODE_TOO_MANY_SIGNATURES = "too_many_signatures"
CODE_TOO_MANY_REVISIONS = "too_many_revisions"

MSG_SIGNED_EXTRAS = (
    "This document is already signed. Initials and the protocol page cannot be added without "
    "breaking the existing signatures."
)
MSG_DAMAGED_SIGNED = (
    "This PDF is damaged and may contain signatures; it cannot be signed safely. "
    "Re-save it with another PDF tool first."
)
MSG_UNSUPPORTED_SIGNATURE = (
    "This PDF contains a signature that cannot be checked (unsupported or unreadable format), "
    "so it cannot be counter-signed safely."
)
MSG_INVALID_EXISTING = (
    "The existing signatures are not intact or the document was changed after it was signed, so a new "
    "signature cannot be added without making that visible. Ask the sender for the original signed "
    "file, or, if the earlier signatures do not need to stay valid, print the document to a new PDF "
    "and sign that."
)
MSG_UNCHECKABLE_SIGNATURE = (
    "This document contains a signature that this tool cannot check, so it cannot be counter-signed safely."
)
MSG_LOCKED = (
    "The document was certified or locked by a previous signer and does not allow new signatures."
)
MSG_BROKE_EXISTING = "Could not add a signature without breaking the existing signatures."
MSG_MALFORMED_FIELDS = (
    "The PDF has malformed form fields and cannot be signed. Re-save it with another PDF tool and try again."
)


def _deref(value: Any) -> Any:
    """Resolve an indirect reference to its object; other values are returned unchanged."""
    return value.get_object() if isinstance(value, generic.IndirectObject) else value


def _acroform_field_names(reader: Any) -> Set[str]:
    """All fully qualified field names in the AcroForm tree plus every parent prefix.

    Fields without widgets and inline field dictionaries are included, so a generated name never
    collides with an existing field or with the parent of one (e.g. "Signature_1.child").

    The tree must be traversable completely (fail closed): inline field entries, a /Kids or /Fields
    value that is not an array, or nesting deeper than MAX_FIELD_TREE_DEPTH raise PdfInputError,
    because an incomplete walk could miss a signature or a name.
    """
    names: Set[str] = set()
    acroform = _deref(reader.root.get("/AcroForm"))
    if acroform is None or isinstance(acroform, generic.NullObject):
        return names
    if not isinstance(acroform, generic.DictionaryObject):
        raise PdfInputError(MSG_MALFORMED_FIELDS)
    seen: Set[Tuple[int, int]] = set()

    def walk(items: Any, prefix: str, depth: int) -> None:
        items = _deref(items)
        if items is None or isinstance(items, generic.NullObject):
            return
        if depth > MAX_FIELD_TREE_DEPTH or not isinstance(items, generic.ArrayObject):
            raise PdfInputError(MSG_MALFORMED_FIELDS)
        for item in items:
            if not isinstance(item, generic.IndirectObject):
                # Field entries must be indirect references (PDF 32000 12.7.3); pyhanko cannot
                # safely add a field next to inline ones.
                raise PdfInputError(MSG_MALFORMED_FIELDS)
            key = (item.idnum, item.generation)
            if key in seen:
                continue
            seen.add(key)
            field = item.get_object()
            if not isinstance(field, generic.DictionaryObject):
                # Not a field (a number, a dangling reference...): the tree is not what it claims.
                raise PdfInputError(MSG_MALFORMED_FIELDS)
            partial = _deref(field.get("/T"))
            name = prefix
            if partial is not None:
                name = f"{prefix}.{partial}" if prefix else str(partial)
                names.add(name)
            walk(field.get("/Kids"), name, depth + 1)

    walk(acroform.get("/Fields"), "", 0)
    for name in list(names):
        parts = name.split(".")
        names.update(".".join(parts[:i]) for i in range(1, len(parts)))
    return names


def _open_input_document(pdf_bytes: bytes) -> pymupdf.Document:
    """Open the input with PyMuPDF and reject unreadable and encrypted files.

    The document is only read here; it is serialised later only for unsigned input.
    """
    try:
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    except RuntimeError as e:  # pymupdf.FileDataError / EmptyFileError
        raise PdfInputError("The file is not a readable PDF.") from e
    try:
        encrypt_kind, _ = doc.xref_get_key(-1, "Encrypt")
        if doc.needs_pass or doc.is_encrypted or encrypt_kind not in ("null", "undefined"):
            raise PdfInputError(
                "The PDF is encrypted or password-protected. Remove the protection and try again."
            )
    except BaseException:
        doc.close()
        raise
    return doc


# Fail-closed scan for files pyHanko cannot parse. Name escapes (/#42yteRange) are decoded first;
# an object stream (/ObjStm) could hide any of the markers in compressed data, so it counts too.
_NAME_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
_RAW_SIGNATURE_MARKERS = re.compile(
    rb"/ByteRange|/SubFilter|/DocTimeStamp|/ObjStm|/Type\s*/Sig(?![A-Za-z0-9])")


def _may_contain_signatures(original: bytes) -> bool:
    """True if the raw bytes of an UNPARSABLE file could hold a signature in any revision.

    Only used when pyHanko cannot parse the file; false positives (a damaged file that merely
    mentions these names) are accepted.
    """
    decoded = _NAME_ESCAPE.sub(lambda match: bytes([int(match.group(1), 16)]), original)
    return _RAW_SIGNATURE_MARKERS.search(decoded) is not None


@dataclass(frozen=True)
class InputClassification:
    """Whether the original bytes are signed, plus pyHanko's reader of them when it could parse them."""

    signed: bool
    reader: Optional[PdfFileReader]


def _check_revision_count(revisions: int, max_revisions: int) -> None:
    """Bound the work per revision (history walk, diff analysis, repair) before any of it starts."""
    if revisions > max_revisions:
        raise PdfInputError(
            f"The PDF has too many revisions ({revisions}); at most {max_revisions} are supported.",
            code=CODE_TOO_MANY_REVISIONS,
        )


def _object_key(item: Any, resolved: Any) -> Tuple[Any, ...]:
    if isinstance(item, generic.IndirectObject):
        return ("ref", item.idnum, item.generation)
    return ("inline", id(resolved))


def _is_null(value: Any) -> bool:
    value = _deref(value)
    return value is None or isinstance(value, generic.NullObject)


def _filled_signature_holders(handler: Any) -> Set[Tuple[Any, ...]]:
    """Keys of every dictionary holding the /V of a signature field, in one revision.

    Independent of field names: walks the form tree (/FT inherited from parents) AND every page's
    annotations (widgets; /FT and /V looked up through /Parent), so unnamed fields and fields
    missing from /Fields are found too.
    """
    holders: Set[Tuple[Any, ...]] = set()
    root = handler.root

    def walk_fields(items: Any, inherited_ft: Any, depth: int, seen: Set[Tuple[Any, ...]]) -> None:
        items = _deref(items)
        if not isinstance(items, generic.ArrayObject):
            return
        if depth > MAX_FIELD_TREE_DEPTH:
            raise PdfInputError(MSG_MALFORMED_FIELDS)
        for item in items:
            node = _deref(item)
            key = _object_key(item, node)
            if key in seen or not isinstance(node, generic.DictionaryObject):
                continue
            seen.add(key)
            ft = _deref(node.get("/FT", inherited_ft))
            if ft == "/Sig" and not _is_null(node.get("/V")):
                holders.add(key)
            walk_fields(node.get("/Kids"), ft, depth + 1, seen)

    acroform = _deref(root.get("/AcroForm"))
    if isinstance(acroform, generic.DictionaryObject):
        walk_fields(acroform.get("/Fields"), None, 0, set())

    def signature_holder(item: Any) -> Optional[Tuple[Any, ...]]:
        """Walk up /Parent from an annotation: the dict with /V if the field type is /Sig."""
        ft = None
        holder = None
        node, ref = _deref(item), item
        for _ in range(MAX_FIELD_TREE_DEPTH):
            if not isinstance(node, generic.DictionaryObject):
                break
            if holder is None and not _is_null(node.get("/V")):
                holder = _object_key(ref, node)
            if ft is None and "/FT" in node:
                ft = _deref(node["/FT"])
            if "/Parent" not in node:
                break
            ref = node.raw_get("/Parent")
            node = _deref(ref)
        else:
            raise PdfInputError(MSG_MALFORMED_FIELDS)
        return holder if ft == "/Sig" else None

    def walk_pages(node_ref: Any, depth: int, seen: Set[Tuple[Any, ...]]) -> None:
        node = _deref(node_ref)
        key = _object_key(node_ref, node)
        if key in seen or not isinstance(node, generic.DictionaryObject):
            return
        if depth > MAX_FIELD_TREE_DEPTH:
            raise PdfInputError(MSG_MALFORMED_FIELDS)
        seen.add(key)
        kids = _deref(node.get("/Kids"))
        if isinstance(kids, generic.ArrayObject):
            for kid in kids:
                walk_pages(kid, depth + 1, seen)
        annots = _deref(node.get("/Annots"))
        if isinstance(annots, generic.ArrayObject):
            for annot in annots:
                holder = signature_holder(annot)
                if holder is not None:
                    holders.add(holder)

    walk_pages(root.raw_get("/Pages") if "/Pages" in root else None, 0, set())
    return holders


def _has_signature_permissions(root: Any) -> bool:
    """Catalog /Perms that refers to a signature (/DocMDP certification or /UR3, /UR usage
    rights). An empty or unrelated /Perms, or /Perms null, is not a signature."""
    perms = _deref(root.get("/Perms"))
    return isinstance(perms, generic.DictionaryObject) and any(
        key in perms for key in ("/DocMDP", "/UR3", "/UR"))


def _linearized_document_length(reader: PdfFileReader) -> Optional[int]:
    """Recognise the TWO xref sections of the first linearized physical revision.

    pyHanko exposes the main xref as revision 0 and the first-page xref as revision 1.
    Revision 0 alone is incomplete, and a signature stored there really signs revision 1.
    A marker alone is insufficient: the original length, EOF pointer, physical section order,
    main-xref hint and disjoint object definitions must agree. Later revisions are never skipped.
    """
    if reader.total_revisions < 2:
        return None
    main = reader.xrefs.get_xref_container_info(0)
    first = reader.xrefs.get_xref_container_info(1)
    if not 0 < first.start_location < first.end_location < main.start_location:
        return None
    stream = reader.stream
    position = stream.tell()
    try:
        stream.seek(0)
        head = stream.read(1024)
        # Only the first indirect object may be the linearization dictionary.
        match = re.match(rb"%PDF-[^\r\n]+[\r\n]+(?:%[^\r\n]*[\r\n]+|\s)*\d+\s+\d+\s+obj\s*", head)
        if match is None:
            return None
        stream.seek(match.end())
        linear = generic.read_object(stream, generic.TrailerReference(reader))
        if not isinstance(linear, generic.DictionaryObject) or linear.get("/Linearized") != 1:
            return None
        length, end_first, main_hint = (linear.get(key) for key in ("/L", "/E", "/T"))
        if not all(isinstance(v, generic.NumberObject) for v in (length, end_first, main_hint)):
            return None
        length, end_first, main_hint = int(length), int(end_first), int(main_hint)
        stream.seek(0, io.SEEK_END)
        if not main.end_location < length <= stream.tell():
            return None
        if not first.end_location < end_first <= main.start_location:
            return None
        if not main.declared_startxref - 1 <= main_hint < main.end_location:
            return None
        stream.seek(max(0, length - 128))
        eof = stream.read(min(length, 128))
        tail = re.search(rb"startxref\s+(\d+)\s+%%EOF\s*\Z", eof)
        if tail is None or int(tail.group(1)) != first.declared_startxref:
            return None
        # A genuine incremental overwrite cannot masquerade as the two disjoint halves.
        main_refs = reader.xrefs.explicit_refs_in_revision(0)
        first_refs = reader.xrefs.explicit_refs_in_revision(1)
        if main_refs & first_refs:
            return None
        # Both halves must describe the SAME catalog, supplied only by the first-page half.
        # qpdf omits /Root from the incomplete main trailer altogether.
        # Otherwise a forged pair could hide a complete older document under a new trailer root.
        main_trailer = reader.trailer.flatten(0)
        main_root = main_trailer.raw_get("/Root") if "/Root" in main_trailer else None
        first_root = reader.trailer.flatten(1).raw_get("/Root")
        if not isinstance(first_root, generic.IndirectObject):
            return None
        root_ref = first_root.reference
        if main_root is not None and (
            not isinstance(main_root, generic.IndirectObject) or main_root.reference != root_ref
        ):
            return None
        if root_ref not in first_refs:
            return None
        if reader.xrefs.get_historical_ref(root_ref, 0) is not None:
            return None
        return length
    except (KeyError, ValueError, TypeError, PdfError):
        return None
    finally:
        stream.seek(position)


def _document_revisions(reader: PdfFileReader) -> range:
    """Complete logical revisions; keep both xrefs available to the resolver and diff policy."""
    return range(1 if _linearized_document_length(reader) is not None else 0, reader.total_revisions)


def _normalise_linearized_signatures(reader: PdfFileReader) -> None:
    length = _linearized_document_length(reader)
    if length is None:
        return
    for sig in reader.embedded_signatures:
        byte_range = _byte_range(sig)
        if (sig.signed_revision == 0 and len(byte_range) == 4 and byte_range[0] == 0
                and byte_range[2] + byte_range[3] == length):
            # Only the index changes. Coverage, CMS integrity and DEFAULT diff analysis still run.
            sig.signed_revision = 1


def _signed_in_any_revision(reader: PdfFileReader) -> bool:
    """True if the current or any earlier revision holds a signature, by any of:
    a filled /Sig field in the form tree or among page widgets (names optional), a catalog
    /Perms with /DocMDP, /UR3 or /UR, or a signature pyHanko embeds. pyHanko's resolver decodes name escapes,
    object streams and hybrid cross-reference sections, so nothing depends on byte spelling."""
    try:
        if reader.embedded_signatures:
            return True
    except Exception:  # noqa: BLE001 - unreadable signature data is still signature data
        return True
    for revision in _document_revisions(reader):
        resolver = reader.get_historical_resolver(revision)
        if _has_signature_permissions(resolver.root) or _filled_signature_holders(resolver):
            return True
    return False


def _check_all_signatures_checkable(reader: PdfFileReader) -> None:
    """Refuse signatures the name-based checks cannot see (e.g. fields without /T, or widgets
    missing from /Fields): every filled /Sig holder must be one pyHanko enumerates by name."""
    for revision in _document_revisions(reader):
        resolver = reader.get_historical_resolver(revision)
        named = {
            ("ref", ref.idnum, ref.generation)
            for _, _, ref in fields.enumerate_sig_fields(resolver, filled_status=True)
            if isinstance(ref, generic.IndirectObject)
        }
        if _filled_signature_holders(resolver) - named:
            raise PdfInputError(MSG_UNCHECKABLE_SIGNATURE, code=CODE_INVALID_EXISTING)


def _classify_input(original: bytes, max_revisions: int) -> InputClassification:
    """Decide signed vs unsigned on the ORIGINAL bytes, before any PyMuPDF serialisation.

    - Parsable by pyHanko (strict=False, so hybrid-reference files parse): first the revision cap
      (bounds the work), then the signature history of EVERY revision -> signed if any revision
      had a filled signature field. No raw-byte scanning.
    - Not parsable: fail closed. Only a raw scan without signature markers (after decoding name
      escapes, see _may_contain_signatures) lets MuPDF repair the file as unsigned.
    - A form tree that cannot be traversed completely -> rejected.
    """
    try:
        reader = PdfFileReader(io.BytesIO(original), strict=False)
        reader.root  # noqa: B018 - force the trailer and catalog to be read
    except Exception as e:  # noqa: BLE001 - any parse failure means "could not parse"
        # The cross-reference chain is unreadable, so count revisions from the raw bytes: every
        # revision (incremental update) ends with its own %%EOF marker.
        _check_revision_count(original.count(b"%%EOF"), max_revisions)
        if _may_contain_signatures(original):
            raise PdfInputError(MSG_DAMAGED_SIGNED, code=CODE_INVALID_EXISTING) from e
        return InputClassification(signed=False, reader=None)

    _check_revision_count(len(_document_revisions(reader)), max_revisions)
    try:
        _acroform_field_names(reader)
        signed = _signed_in_any_revision(reader)
    except PdfInputError:
        raise
    except Exception as e:  # noqa: BLE001 - a tree pyHanko cannot walk is not proof of "unsigned"
        raise PdfInputError(MSG_MALFORMED_FIELDS) from e
    return InputClassification(signed=signed, reader=reader)


# --- Existing signatures (signed input) ------------------------------------------------------------

@dataclass(frozen=True)
class ExistingSignature:
    """Identity of an original signature: its field name and the bytes it covers."""

    name: str
    byte_range: Tuple[int, ...]


def _byte_range(sig: Any) -> Tuple[int, ...]:
    return tuple(int(v) for v in sig.sig_object["/ByteRange"])


def _historical_signature_identities(reader: PdfFileReader) -> Set[ExistingSignature]:
    """Every filled signature (field name + signed byte range) in every revision.

    A signature that was later removed, or replaced by another value under the same field name,
    shows up here but not among the current signatures.
    """
    identities: Set[ExistingSignature] = set()
    for revision in _document_revisions(reader):
        resolver = reader.get_historical_resolver(revision)
        for name, value, _ in fields.enumerate_sig_fields(resolver, filled_status=True):
            byte_range = _deref(_deref(value).get("/ByteRange"))
            if not isinstance(byte_range, generic.ArrayObject):
                raise PdfInputError(MSG_UNSUPPORTED_SIGNATURE, code=CODE_INVALID_EXISTING)
            identities.add(ExistingSignature(name, tuple(int(v) for v in byte_range)))
    return identities


def _signature_status(sig: Any) -> Tuple[Any, Dict[str, Any]]:
    """Offline cryptographic/integrity checks; certificate trust is not a verdict here."""
    context = ValidationContext(trust_roots=[], allow_fetching=False)
    if sig.sig_object_type == "/DocTimeStamp":
        status = validate_pdf_timestamp(sig, context)
    else:
        status = validate_pdf_signature(sig, context)
    return status, sig.summarise_integrity_info()


def _signature_preserved(sig: Any) -> bool:
    """True if ``sig`` is intact, cryptographically valid and its later changes are permitted.

    Uses pyHanko's DEFAULT diff policy. Trust is deliberately not required: a counter-signer
    cannot make a stranger's certificate trusted, only keep the signature unbroken.
    Validation errors propagate; callers decide how to fail closed.
    """
    status, integrity = _signature_status(sig)
    return bool(status.intact and status.valid and integrity["docmdp_ok"])


def validate_pdf_document(
    pdf_bytes: bytes,
    max_existing_signatures: int = DEFAULT_MAX_EXISTING_SIGNATURES,
    max_revisions: int = DEFAULT_MAX_REVISIONS,
    validation_policy: Optional[ValidationPolicy] = None,
    online_revocation: bool = False,
) -> Dict[str, Any]:
    """Inspect ORIGINAL PDF bytes locally without a signing key or document rewriting.

    Report byte integrity, mathematical signature validity and permitted changes separately.
    Only operator-configured roots establish certificate trust. Revocation uses configured
    CRL URLs after explicit opt-in; no certificate/PDF-controlled URLs are fetched. This does
    not assert qualified-signature status or legal validity.
    """
    doc = _open_input_document(pdf_bytes)
    doc.close()
    result: Dict[str, Any] = {
        "signed": None,
        "signature_count": 0,
        "signatures": [],
        "can_countersign": False,
        "blocking_reason": None,
        "trust": {"status": "not_checked", "message": "Certificate trust chains are not checked."},
        "revocation": {
            "status": "not_checked", "message": "Certificate revocation is not checked (offline).",
        },
    }

    def blocked(error: PdfInputError) -> Dict[str, Any]:
        result["blocking_reason"] = {"code": error.code or "invalid_pdf", "message": str(error)}
        return result

    try:
        classification = _classify_input(pdf_bytes, max_revisions)
    except PdfInputError as e:
        return blocked(e)
    result["signed"] = classification.signed
    if classification.reader is None:
        # The signing path may repair an unsigned PDF; inspection cannot validate a repaired copy.
        return blocked(PdfInputError("The PDF needs repair before its signatures can be inspected."))
    reader = classification.reader
    policy = validation_policy or ValidationPolicy()
    try:
        filled = list(fields.enumerate_sig_fields(reader, filled_status=True))
        result["signature_count"] = len(filled)
        if len(filled) > max_existing_signatures:
            raise PdfInputError(
                f"The document has too many signatures to check (limit {max_existing_signatures}).",
                code=CODE_TOO_MANY_SIGNATURES,
            )
        _normalise_linearized_signatures(reader)
        # Network access is explicit, capped, and only to operator-configured CRL URLs.
        crls = (asyncio.run(fetch_crls(policy))
                if online_revocation and (policy.trust_roots or policy.timestamp_roots) else ())
        for sig in reader.embedded_signatures:
            signer_name = sig.signer_cert.subject.native.get("common_name") or "Unknown"
            entry = {
                "field_name": sanitize_signer_name(sig.field_name),
                "signer": sanitize_signer_name(signer_name),
                "integrity": "unknown", "cryptography": "unknown", "modifications": "unknown",
                "coverage": None, "modification_level": None,
            }
            try:
                status, integrity = _signature_status(sig)
                entry.update({
                    "integrity": "valid" if status.intact else "invalid",
                    "cryptography": "valid" if status.valid else "invalid",
                    "modifications": {True: "allowed", False: "disallowed"}.get(
                        integrity["docmdp_ok"], "unknown"),
                    "coverage": getattr(status.coverage, "name", None),
                    "modification_level": getattr(status.modification_level, "name", None),
                })
            except Exception:  # noqa: BLE001 - unsupported CMS/algorithms produce an honest unknown
                entry["error"] = "This signature could not be checked."
            entry.update(signature_security_details(sig, policy, online=online_revocation, crls=crls))
            result["signatures"].append(entry)
        if policy.trust_roots or policy.timestamp_roots:
            result["trust"] = {
                "status": "checked", "message": "Certificate chains checked against configured roots.",
            }
        if online_revocation and (policy.trust_roots or policy.timestamp_roots):
            result["revocation"] = {
                "status": "checked", "message": "See each signature for the CRL revocation result.",
            }
        if classification.signed:
            names = _signature_field_names(1, _acroform_field_names(reader))
            _check_existing_signatures(reader, names, max_existing_signatures)
        result["can_countersign"] = True
    except PdfInputError as e:
        return blocked(e)
    except Exception:  # noqa: BLE001 - unreadable signature structures are not unsigned input
        return blocked(PdfInputError(MSG_UNSUPPORTED_SIGNATURE, code=CODE_INVALID_EXISTING))
    return result


def _check_existing_signatures(
    reader: PdfFileReader,
    new_names: Sequence[str],
    max_existing: int,
) -> List[ExistingSignature]:
    """Pre-check for counter-signing (S5): reject anything that new signatures could break.

    Returns:
        The identity of every original signature, for the post-check.
    """
    try:
        _check_all_signatures_checkable(reader)
    except PdfInputError:
        raise
    except Exception as e:  # noqa: BLE001 - a history we cannot walk is not a checked history
        raise PdfInputError(MSG_UNCHECKABLE_SIGNATURE, code=CODE_INVALID_EXISTING) from e
    filled = list(fields.enumerate_sig_fields(reader, filled_status=True))
    if len(filled) > max_existing:
        raise PdfInputError(
            f"The document already has {len(filled)} signatures; at most {max_existing} existing "
            "signatures can be checked before counter-signing.",
            code=CODE_TOO_MANY_SIGNATURES,
        )
    try:
        # Parses every signature's CMS blob; an unreadable one must be a clear refusal.
        _normalise_linearized_signatures(reader)
        embedded = reader.embedded_signatures
        current = {ExistingSignature(sig.field_name, _byte_range(sig)) for sig in embedded}
        historical = _historical_signature_identities(reader)
    except PdfInputError:
        raise
    except Exception as e:  # noqa: BLE001 - unreadable signature data
        logger.warning("Existing signatures could not be read: %s", type(e).__name__)
        raise PdfInputError(MSG_UNSUPPORTED_SIGNATURE, code=CODE_INVALID_EXISTING) from e
    if len(embedded) != len(filled):
        # pyHanko skips signatures with an unsupported /SubFilter.
        raise PdfInputError(MSG_UNSUPPORTED_SIGNATURE, code=CODE_INVALID_EXISTING)
    if historical - current:
        # A signature from an earlier revision was removed or replaced under the same name.
        raise PdfInputError(MSG_INVALID_EXISTING, code=CODE_INVALID_EXISTING)
    if not filled and not historical:
        raise PdfInputError(MSG_UNSUPPORTED_SIGNATURE, code=CODE_INVALID_EXISTING)

    if read_certification_data(reader) is not None:
        raise PdfInputError(MSG_LOCKED, code=CODE_LOCKED_DOCUMENT)
    for sig in embedded:
        # docmdp_level covers certification references and approval /Lock /P alike.
        if sig.docmdp_level is not None:
            raise PdfInputError(MSG_LOCKED, code=CODE_LOCKED_DOCUMENT)
        if sig.fieldmdp is not None and any(sig.fieldmdp.is_locked(name) for name in new_names):
            raise PdfInputError(MSG_LOCKED, code=CODE_LOCKED_DOCUMENT)

    identities = []
    for sig in embedded:
        try:
            preserved = _signature_preserved(sig)
        except Exception as e:  # noqa: BLE001 - an unverifiable signature must not be risked
            logger.warning("Existing signature could not be validated: %s", type(e).__name__)
            raise PdfInputError(MSG_UNSUPPORTED_SIGNATURE, code=CODE_INVALID_EXISTING) from e
        if not preserved:
            raise PdfInputError(MSG_INVALID_EXISTING, code=CODE_INVALID_EXISTING)
        identities.append(ExistingSignature(sig.field_name, _byte_range(sig)))
    return identities


def _post_check(
    output: bytes,
    original: bytes,
    existing: Sequence[ExistingSignature],
    new_names: Sequence[str],
) -> None:
    """Post-check for counter-signing (S6), fail closed: every original signature (same field,
    same signed bytes) and every new one must still be preserved, and the original bytes must be
    an unchanged prefix of the output."""
    if not output.startswith(original):
        raise SigningError(MSG_BROKE_EXISTING)
    try:
        reader = PdfFileReader(io.BytesIO(output), strict=False)
        _normalise_linearized_signatures(reader)
        by_name = {sig.field_name: sig for sig in reader.embedded_signatures}
        for identity in existing:
            sig = by_name.get(identity.name)
            if sig is None or _byte_range(sig) != identity.byte_range or not _signature_preserved(sig):
                raise SigningError(MSG_BROKE_EXISTING)
        for name in new_names:
            sig = by_name.get(name)
            if sig is None or not _signature_preserved(sig):
                raise SigningError(MSG_BROKE_EXISTING)
    except SigningError:
        raise
    except Exception as e:  # noqa: BLE001 - a check that cannot run is a failed check
        logger.warning("Post-signing validation failed: %s", type(e).__name__)
        raise SigningError(MSG_BROKE_EXISTING) from e


# --- Signing ----------------------------------------------------------------------------------------

@dataclass(frozen=True)
class SignatureBox:
    """Where one signature goes: page index, raw widget /Rect (None = invisible) and page /Rotate."""

    page: int
    rect: Optional[Tuple[float, float, float, float]]
    rotation: int


def _signature_field_names(count: int, taken: Set[str]) -> List[str]:
    """Generate ``count`` unique names Signature_N that do not collide with ``taken``."""
    names = []
    number = 1
    while len(names) < count:
        name = f"Signature_{number}"
        if name not in taken:
            names.append(name)
        number += 1
    return names


def _fmt(value: float) -> str:
    return f"{value:g}"


def _appearance_style(writer: IncrementalPdfFileWriter, mark_pdf: bytes, rotation: int) -> StaticStampStyle:
    """Widget appearance: the upright mark, counter-rotated for the page /Rotate (S1).

    The mark page is imported as a form XObject into THIS writer (resources are writer-bound, so
    every incremental revision builds its own). The transform rotates the artwork
    counter-clockwise in PDF space by the page rotation, so viewers show it upright; the
    appearance box is the raw widget size (width and height swap at 90 and 270 degrees).
    """
    width, height = BOX_SIZES[PLACEMENT_SIGNATURE]
    transforms = {
        0: ("1 0 0 1 0 0", width, height),
        90: (f"0 1 -1 0 {_fmt(height)} 0", height, width),
        180: (f"-1 0 0 -1 {_fmt(width)} {_fmt(height)}", width, height),
        270: (f"0 -1 1 0 0 {_fmt(width)}", height, width),
    }
    matrix, box_width, box_height = transforms[rotation % 360]
    resources = content.PdfResources()
    resources.xobject["/Mark"] = writer.import_page_as_xobject(
        PdfFileReader(io.BytesIO(mark_pdf)), page_ix=0
    )
    background = content.RawContent(
        f"q {matrix} cm /Mark Do Q".encode("ascii"),
        resources=resources,
        box=layout.BoxConstraints(width=box_width, height=box_height),
    )
    return StaticStampStyle(
        background=background,
        border_width=0,
        background_opacity=1,
        background_layout=layout.SimpleBoxLayoutRule(
            x_align=layout.AxisAlignment.ALIGN_MIN,
            y_align=layout.AxisAlignment.ALIGN_MIN,
            margins=layout.Margins.uniform(0),
            inner_content_scaling=layout.InnerScaling.NO_SCALING,
        ),
    )


def _apply_signatures(
    base_pdf: bytes,
    signer: signers.SimpleSigner,
    boxes: Sequence[SignatureBox],
    names: Sequence[str],
    mark_pdf: bytes,
    lock_after_signing: bool,
    reason: str,
    timestamper=None,
) -> bytes:
    """Add one incremental signature per box; each new field's widget shows the mark (S1).

    The last signature carries the lock when requested. Never rewrites earlier bytes.
    """
    current = base_pdf
    for index, (box, name) in enumerate(zip(boxes, names, strict=True)):
        is_last = index == len(boxes) - 1
        writer = IncrementalPdfFileWriter(io.BytesIO(current), strict=False)
        existing = {fq_name for fq_name, _, _ in fields.enumerate_sig_fields(writer)}
        if name in existing:
            # pyhanko would silently reuse the field and ignore its rectangle and lock.
            raise SigningError("Could not create a new signature field in this PDF.")
        lock_kwargs = {}
        meta_kwargs = {}
        if lock_after_signing:
            if index == 0:
                writer.ensure_output_version(LOCK_PDF_VERSION)
            if is_last:
                lock_kwargs = {
                    "field_mdp_spec": FieldMDPSpec(action=FieldMDPAction.ALL),
                    "doc_mdp_update_value": MDPPerm.NO_CHANGES,
                }
                meta_kwargs = {"docmdp_permissions": MDPPerm.NO_CHANGES}
        field_spec = fields.SigFieldSpec(
            sig_field_name=name,
            box=box.rect,
            on_page=box.page,
            **lock_kwargs,
        )
        stamp_style = (
            NoOpStampStyle() if box.rect is None else _appearance_style(writer, mark_pdf, box.rotation)
        )
        pdf_signer = signers.PdfSigner(
            signature_meta=PdfSignatureMetadata(
                field_name=name, reason=reason, location='', **meta_kwargs
            ),
            signer=signer,
            stamp_style=stamp_style,
            new_field_spec=field_spec,
            timestamper=timestamper,
        )
        out = io.BytesIO()
        pdf_signer.sign_pdf(writer, output=out)
        current = out.getvalue()
        if not current.startswith(base_pdf):
            raise SigningError("Could not add the signature incrementally.")
    return current


def sign_pdf_multiple(
    pdf_bytes: bytes,
    p12_bytes: bytes,
    p12_password: str,
    signatures: List[Dict],
    lock_after_signing: bool = False,
    add_protocol_page: bool = False,
    reason: str = "Electronically signed",
    max_placements: int = DEFAULT_MAX_PLACEMENTS,
    max_existing_signatures: int = DEFAULT_MAX_EXISTING_SIGNATURES,
    max_revisions: int = DEFAULT_MAX_REVISIONS,
    timestamp_config: Optional[TimestampConfig] = None,
) -> bytes:
    """
    Sign a PDF document with visible signatures and initials.

    Unsigned input: MuPDF may repair it; initials and the protocol page are drawn into page
    content with one full save; then every signature is added incrementally.

    Signed input (counter-signing): the original bytes are never re-serialised. Existing
    signatures are checked first (S5), new signatures are appended incrementally, and every
    original signature is re-validated in the output (S6). Initials and the protocol page are
    refused (they would change signed page content).

    Args:
        pdf_bytes: PDF document to sign as bytes (not modified)
        p12_bytes: PKCS12 certificate file contents
        p12_password: Password to decrypt the P12 file (may be empty)
        signatures: Placements as described in :mod:`geometry`:
            ``{"page": int (0-based), "type": "signature" | "initials", "x": float, "y": float}``
            with x/y the top-left corner of the box in displayed page space.
        lock_after_signing: Lock the document with the last signature (approval-signature
            /Lock with NO_CHANGES, PDF 2.0). Requests no further changes; enforcement depends
            on the PDF viewer.
        add_protocol_page: Whether to append protocol page(s)
        reason: Reason for signing
        max_placements: Upper bound for the number of placements
        max_existing_signatures: Upper bound for signatures already in the document
        max_revisions: Upper bound for revisions (incremental updates) of the input

    Returns:
        Signed PDF as bytes

    Raises:
        CertificateValidationError, PdfInputError, PlacementError, SigningError: All with
            user-safe messages that never contain the password. PdfInputError may carry a
            machine-readable ``code`` (CODE_*).
    """
    try:
        signer = load_signer_from_p12(p12_bytes, p12_password)
        validate_certificate(signer)
        signer_name = sanitize_signer_name(get_signer_name_from_signer(signer))
        cert_info = get_certificate_info(signer)
        signed_at = datetime.now(timezone.utc)
        original = bytes(pdf_bytes)

        doc = _open_input_document(original)
        try:
            classification = _classify_input(original, max_revisions)
            placements = validate_placements(doc, signatures, max_placements)
            boxes = _signature_boxes(doc, placements)
            if classification.signed:
                assert classification.reader is not None
                names = _signature_field_names(len(boxes), _acroform_field_names(classification.reader))
                existing = _check_existing_signatures(
                    classification.reader, names, max_existing_signatures
                )
                if add_protocol_page or len(boxes) != len(placements):
                    raise PdfInputError(MSG_SIGNED_EXTRAS, code=CODE_SIGNED_DOCUMENT)
                base = original  # no save of any kind in signed mode
            else:
                _draw_initials(doc, placements, signer_name)
                if not boxes:
                    # Initials only: one invisible document signature.
                    boxes = [SignatureBox(page=0, rect=None, rotation=0)]
                if add_protocol_page:
                    _append_protocol_pages(doc, placements, signer_name, cert_info, signed_at)
                # The only full save: nothing is signed yet.
                base = doc.tobytes()
                try:
                    taken = _acroform_field_names(PdfFileReader(io.BytesIO(base), strict=False))
                except PdfError as e:
                    raise PdfInputError("The file is not a readable PDF.") from e
                names = _signature_field_names(len(boxes), taken)
        finally:
            doc.close()

        mark_doc = _build_signature_mark(signer_name, signed_at)
        try:
            mark_pdf = mark_doc.tobytes()  # the separate mark document, never the input
        finally:
            mark_doc.close()

        try:
            timestamper = ConfiguredTimeStamper(timestamp_config) if timestamp_config is not None else None
            output = _apply_signatures(
                base, signer, boxes, names, mark_pdf, lock_after_signing, reason, timestamper=timestamper,
            )
            if timestamp_config is not None:
                _check_requested_timestamps(output, names, timestamp_config.validation_policy)
        except Exception:
            if timestamp_config is not None:
                raise SigningError(
                    "Timestamping failed or its trusted timestamp could not be verified. "
                    "No signed file was returned."
                ) from None
            raise
        if classification.signed:
            _post_check(output, original, existing, names)
        return output

    except (SigningError, PlacementError):
        raise
    except Exception as e:  # noqa: BLE001 - single top-level boundary: never leak internals
        _log_unexpected_error(e, p12_password)
        raise SigningError(
            "Signing failed because of an unexpected problem with the PDF or the certificate."
        ) from e


def _check_requested_timestamps(output, names, policy):
    reader = PdfFileReader(io.BytesIO(output), strict=False)
    _normalise_linearized_signatures(reader)
    by_name = {sig.field_name: sig for sig in reader.embedded_signatures}
    for name in names:
        sig = by_name.get(name)
        if sig is None or not _signature_preserved(sig):
            raise SigningError("The timestamped signature could not be verified.")
        timestamp = timestamp_details(sig, policy)
        if timestamp["status"] != "valid" or timestamp["certificate_trust"]["status"] != "trusted":
            raise SigningError("The requested trusted timestamp could not be verified.")


def _log_unexpected_error(error: BaseException, p12_password: str) -> None:
    """Log an unexpected error with traceback, with the P12 password masked out."""
    details = "".join(traceback.format_exception(error))
    if p12_password:
        details = details.replace(p12_password, "***")
    logger.error("Signing failed unexpectedly:\n%s", details)
