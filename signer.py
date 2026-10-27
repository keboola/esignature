"""PDF signing functionality using pyhanko with visual signatures.

Signing order (keeps every signature valid):

1. Open the PDF once, draw ALL visible marks (signatures and initials) into page contents and
   append the optional protocol page(s), then save once. Nothing is signed yet, so a full save is fine.
2. Add the cryptographic signatures, each as a pyhanko incremental update with a signature field
   whose widget rectangle covers its drawn mark and has no appearance of its own (the mark is
   page content). No full save happens after the first signature.

Initials are visual marks covered by the document signature(s). If only initials are placed, one
invisible signature is added so the document is still signed.

Placements follow the contract documented in :mod:`geometry`.
"""

import io
import logging
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import pymupdf
from cryptography.hazmat.primitives.serialization import pkcs12
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.fields import FieldMDPAction, FieldMDPSpec, MDPPerm
from pyhanko.sign.general import SigningError as PyhankoSigningError
from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata
from pyhanko.stamp import NoOpStampStyle

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
]


class SigningError(Exception):
    """Base class for signing errors. The message is safe to show to the user."""


class CertificateValidationError(SigningError):
    """Raised when the P12 cannot be used for signing (password, key, validity)."""


class PdfInputError(SigningError):
    """Raised when the input PDF is not accepted for signing."""


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

    # Shrink long names so they stay inside the box
    font = pymupdf.Font(fontfile=str(FONT_PATH)) if name_font == "dancing" else pymupdf.Font("helv")
    fontsize = 14.0
    while fontsize > 6 and font.text_length(name, fontsize=fontsize) > BOX_SIZES[PLACEMENT_SIGNATURE][0] - 10:
        fontsize -= 0.5
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
    fontsize = 18
    while fontsize > 6 and pymupdf.get_text_length(text, "helv", fontsize) > width - 6:
        fontsize -= 1
    text_width = pymupdf.get_text_length(text, "helv", fontsize)
    page.insert_text(((width - text_width) / 2, height / 2 + fontsize * 0.35), text,
                     fontsize=fontsize, fontname="helv", color=(0, 0, 0))
    return mark_doc


def _draw_marks(
    doc: pymupdf.Document,
    placements: Sequence[Placement],
    signer_name: str,
    signed_at: datetime,
) -> List[Tuple[int, Tuple[float, float, float, float]]]:
    """Draw every placement into page contents.

    Returns:
        (page index, raw PDF rect) for each signature placement, in order, for the signature fields.
    """
    marks = {
        PLACEMENT_SIGNATURE: _build_signature_mark(signer_name, signed_at),
        PLACEMENT_INITIALS: _build_initials_mark(signer_name),
    }
    signature_boxes = []
    try:
        for placement in placements:
            page = doc[placement.page]
            geometry = convert_displayed_rect(page, placement.displayed_rect)
            with unrotated_page(page) as rotation:
                page.show_pdf_page(geometry.unrotated_rect, marks[placement.type], 0, rotate=rotation)
            if placement.type == PLACEMENT_SIGNATURE:
                signature_boxes.append((placement.page, geometry.pdf_rect))
    finally:
        for mark_doc in marks.values():
            mark_doc.close()
    return signature_boxes


# --- Protocol page ---------------------------------------------------------------------------

PROTOCOL_PAGE_SIZE = (595, 842)
PROTOCOL_MARGIN = 50
PROTOCOL_BOTTOM = 842 - 80  # last baseline; the footer lives below


def _wrap(text: str, fontsize: float, max_width: float) -> List[str]:
    """Greedy word wrap for Helvetica text."""
    lines: List[str] = []
    current = ""
    for word in text.split(" "):
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


# --- Input policy and signing ----------------------------------------------------------------

def _open_input_pdf(pdf_bytes: bytes) -> pymupdf.Document:
    """Open the input PDF, rejecting unreadable, encrypted and already-signed documents."""
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
        try:
            reader = PdfFileReader(io.BytesIO(pdf_bytes), strict=False)
            already_signed = bool(reader.embedded_signatures)
        except PdfError as e:
            raise PdfInputError("The file is not a readable PDF.") from e
        if already_signed:
            raise PdfInputError(
                "The PDF is already signed. Adding signatures to signed documents is not supported."
            )
    except PdfInputError:
        doc.close()
        raise
    return doc


def _existing_field_names(doc: pymupdf.Document) -> Set[str]:
    """Names of all form fields with widgets in the document."""
    return {widget.field_name for page in doc for widget in page.widgets() if widget.field_name}


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


def _apply_signatures(
    prepared_pdf: bytes,
    signer: signers.SimpleSigner,
    boxes: Sequence[Tuple[int, Optional[Tuple[float, float, float, float]]]],
    names: Sequence[str],
    lock_after_signing: bool,
    reason: str,
) -> bytes:
    """Add one incremental signature per box. The last one carries the lock when requested."""
    current = prepared_pdf
    for index, ((page_index, box), name) in enumerate(zip(boxes, names, strict=True)):
        is_last = index == len(boxes) - 1
        writer = IncrementalPdfFileWriter(io.BytesIO(current), strict=False)
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
            box=box,
            on_page=page_index,
            **lock_kwargs,
        )
        pdf_signer = signers.PdfSigner(
            signature_meta=PdfSignatureMetadata(
                field_name=name, reason=reason, location='', **meta_kwargs
            ),
            signer=signer,
            stamp_style=NoOpStampStyle(),
            new_field_spec=field_spec,
        )
        out = io.BytesIO()
        pdf_signer.sign_pdf(writer, output=out)
        current = out.getvalue()
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
) -> bytes:
    """
    Sign a PDF document with visible signatures and initials.

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

    Returns:
        Signed PDF as bytes

    Raises:
        CertificateValidationError, PdfInputError, PlacementError, SigningError: All with
            user-safe messages that never contain the password.
    """
    signer = load_signer_from_p12(p12_bytes, p12_password)
    validate_certificate(signer)
    signer_name = sanitize_signer_name(get_signer_name_from_signer(signer))
    cert_info = get_certificate_info(signer)
    signed_at = datetime.now(timezone.utc)

    try:
        doc = _open_input_pdf(pdf_bytes)
        try:
            placements = validate_placements(doc, signatures, max_placements)
            boxes: List[Tuple[int, Optional[Tuple[float, float, float, float]]]]
            boxes = list(_draw_marks(doc, placements, signer_name, signed_at))
            if not boxes:
                # Initials only: one invisible document signature.
                boxes = [(0, None)]
            names = _signature_field_names(len(boxes), _existing_field_names(doc))
            if add_protocol_page:
                _append_protocol_pages(doc, placements, signer_name, cert_info, signed_at)
            # The only full save: nothing is signed yet.
            prepared = doc.tobytes()
        finally:
            doc.close()

        return _apply_signatures(prepared, signer, boxes, names, lock_after_signing, reason)

    except (SigningError, PlacementError):
        raise
    except (PdfError, PyhankoSigningError, RuntimeError, ValueError, KeyError) as e:
        logger.exception("Signing failed")
        raise SigningError(
            "Signing failed because of an unexpected problem with the PDF or the certificate."
        ) from e
