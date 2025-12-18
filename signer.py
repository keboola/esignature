"""PDF signing functionality using pyhanko with visual signatures."""

import io
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Tuple

import fitz  # PyMuPDF
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, fields
from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.stamp import TextStampStyle

# Note: pyhanko.pdf_utils.font.opentype removed - using PyMuPDF for custom font rendering


# Path to signature font (Dancing Script for fancy name)
FONT_PATH = Path(__file__).parent / "fonts" / "DancingScript-Regular.ttf"

# Signature appearance constants
SIGNATURE_WIDTH = 150
SIGNATURE_HEIGHT = 50
INITIALS_WIDTH = 50
INITIALS_HEIGHT = 35


def load_signer_from_p12(
    p12_bytes: bytes,
    p12_password: str,
) -> signers.SimpleSigner:
    """Load a signer from PKCS12 certificate bytes."""
    try:
        signer = signers.SimpleSigner.load_pkcs12_data(
            pkcs12_bytes=p12_bytes,
            other_certs=[],
            passphrase=p12_password.encode('utf-8'),
        )
        return signer
    except Exception as e:
        raise ValueError(f"Failed to load P12 certificate: {str(e)}") from e


def get_signer_name_from_signer(signer: signers.SimpleSigner) -> str:
    """Extract the common name (CN) from the signer's certificate."""
    try:
        cert = signer.signing_cert
        subject = cert.subject
        cn = subject.native.get('common_name', None)
        if cn:
            return cn
        return "Unknown"
    except Exception:
        return "Unknown"


def get_certificate_info(signer: signers.SimpleSigner) -> Dict:
    """
    Extract detailed information from the signer's certificate.

    Returns:
        Dict with certificate details
    """
    try:
        cert = signer.signing_cert

        # Subject info
        subject = cert.subject.native
        cn = subject.get('common_name', 'Unknown')
        org = subject.get('organization_name', '')
        country = subject.get('country_name', '')

        # Issuer info
        issuer = cert.issuer.native
        issuer_cn = issuer.get('common_name', 'Unknown')
        issuer_org = issuer.get('organization_name', '')

        # Validity
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after

        # Serial number
        serial = cert.serial_number

        return {
            'subject_cn': cn,
            'subject_org': org,
            'subject_country': country,
            'issuer_cn': issuer_cn,
            'issuer_org': issuer_org,
            'valid_from': not_before.strftime('%d.%m.%Y %H:%M') if not_before else '',
            'valid_to': not_after.strftime('%d.%m.%Y %H:%M') if not_after else '',
            'serial_number': format(serial, 'X') if serial else '',  # Hex format
        }
    except Exception:
        return {
            'subject_cn': 'Unknown',
            'subject_org': '',
            'subject_country': '',
            'issuer_cn': 'Unknown',
            'issuer_org': '',
            'valid_from': '',
            'valid_to': '',
            'serial_number': '',
        }


def get_signer_name(p12_bytes: bytes, p12_password: str) -> str:
    """Extract the common name (CN) from a P12 certificate."""
    try:
        signer = load_signer_from_p12(p12_bytes, p12_password)
        return get_signer_name_from_signer(signer)
    except Exception:
        return "Unknown"


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


def render_signature_appearance(
    pdf_bytes: bytes,
    page_num: int,
    x: float,
    y: float,
    width: float,
    height: float,
    signer_name: str,
    signature_type: str = "full",
    font_path: Optional[Path] = None,
) -> bytes:
    """
    Render a custom signature appearance on the PDF using PyMuPDF.

    This allows mixed fonts: name in Dancing Script, date in Helvetica.

    Args:
        pdf_bytes: The PDF document
        page_num: Page number (0-indexed)
        x: X position from left edge
        y: Y position from bottom edge
        width: Width of signature box
        height: Height of signature box
        signer_name: Name of the signer
        signature_type: "full" for signature with date, "initials" for just initials
        font_path: Path to the fancy font file

    Returns:
        Modified PDF bytes with visual appearance added
    """
    if font_path is None:
        font_path = FONT_PATH

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    page = doc[page_num]

    # Convert from PDF coordinates (origin at bottom-left) to PyMuPDF (origin at top-left)
    page_height = page.rect.height
    rect_top = page_height - y - height
    rect = fitz.Rect(x, rect_top, x + width, rect_top + height)

    # Draw white background
    page.draw_rect(rect, color=(0, 0, 0), fill=(1, 1, 1), width=0.5)

    if signature_type == "initials":
        # Initials: just the letters, centered, larger font
        initials = get_initials(signer_name)
        # Normalize to remove Czech diacritics (Helvetica doesn't support them)
        initials = normalize_text(initials)

        # Center the initials in the box
        text_x = x + width / 2
        text_y = rect_top + height / 2 + 6  # Adjust for vertical centering

        page.insert_text(
            (text_x, text_y),
            initials,
            fontsize=18,
            fontname="helv",
            color=(0, 0, 0),
            render_mode=0,
        )

    else:  # full signature
        # Load the fancy font for the name
        try:
            page.insert_font(fontname="dancing", fontfile=str(font_path))
            name_font = "dancing"
        except Exception:
            name_font = "helv"

        # Line 1: Name in fancy font (Dancing Script)
        name_y = rect_top + 18
        page.insert_text(
            (x + 5, name_y),
            signer_name,
            fontsize=14,
            fontname=name_font,
            color=(0, 0, 0),
        )

        # Line 2: Date/time in normal font (Helvetica)
        now = datetime.now()
        date_str = now.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
        if not date_str.endswith(('CET', 'CEST', 'UTC', 'GMT')):
            # Add timezone indicator
            import time
            if time.daylight:
                tz = time.tzname[1]
            else:
                tz = time.tzname[0]
            date_str = now.strftime("%Y-%m-%d %H:%M:%S") + f" {tz}"

        date_y = rect_top + 32
        page.insert_text(
            (x + 5, date_y),
            date_str,
            fontsize=8,
            fontname="helv",
            color=(0.3, 0.3, 0.3),
        )

        # Line 3: GitHub URL in small font
        url_y = rect_top + 44
        page.insert_text(
            (x + 5, url_y),
            "github.com/keboola/esignature",
            fontsize=6,
            fontname="helv",
            color=(0.5, 0.5, 0.5),
        )

    # Save and return
    output = io.BytesIO()
    doc.save(output)
    doc.close()

    return output.getvalue()


def create_minimal_stamp_style() -> TextStampStyle:
    """
    Create a minimal stamp style for pyhanko.

    Since we render the visual appearance ourselves, we just need
    a minimal stamp for pyhanko's signature field.
    """
    text_style = TextBoxStyle(font_size=1)
    stamp_style = TextStampStyle(
        stamp_text=" ",  # Minimal text
        text_box_style=text_style,
        border_width=0,
    )
    return stamp_style


def create_protocol_page(
    pdf_bytes: bytes,
    signatures_info: List[Dict],
    signer_name: str,
    cert_info: Dict,
    github_url: str = "https://github.com/keboola/esignature",
) -> bytes:
    """
    Create a protocol page with signature and certificate information.
    """
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")

    # Create new A4 page
    page = doc.new_page(width=595, height=842)

    # Define styles
    title_font_size = 18
    header_font_size = 12
    text_font_size = 10
    small_font_size = 8

    y_pos = 50
    margin = 50

    # Normalize name for display
    signer_name_normalized = normalize_text(signer_name)

    # Title
    page.insert_text(
        (margin, y_pos),
        "Digital Signature Protocol",
        fontsize=title_font_size,
        fontname="helv",
    )
    y_pos += 40

    # Horizontal line
    page.draw_line((margin, y_pos), (595 - margin, y_pos), width=1)
    y_pos += 25

    # Document information
    page.insert_text(
        (margin, y_pos),
        "Document Information:",
        fontsize=header_font_size,
        fontname="helv",
    )
    y_pos += 18

    original_page_count = len(doc) - 1
    now = datetime.now()

    doc_info = [
        f"Number of pages: {original_page_count}",
        f"Signing date: {now.strftime('%Y-%m-%d %H:%M:%S')}",
    ]

    for line in doc_info:
        page.insert_text((margin + 10, y_pos), line, fontsize=text_font_size, fontname="helv")
        y_pos += 14

    y_pos += 15

    # Certificate information
    page.insert_text(
        (margin, y_pos),
        "Certificate Used:",
        fontsize=header_font_size,
        fontname="helv",
    )
    y_pos += 18

    cert_lines = [
        f"Owner: {normalize_text(cert_info.get('subject_cn', ''))}",
    ]
    if cert_info.get('subject_org'):
        cert_lines.append(f"Organization: {normalize_text(cert_info.get('subject_org', ''))}")

    cert_lines.extend([
        f"Issuer: {normalize_text(cert_info.get('issuer_cn', ''))}",
    ])
    if cert_info.get('issuer_org'):
        cert_lines.append(f"Issuer Org: {normalize_text(cert_info.get('issuer_org', ''))}")

    cert_lines.extend([
        f"Valid from: {cert_info.get('valid_from', '')}",
        f"Valid until: {cert_info.get('valid_to', '')}",
        f"Serial number: {cert_info.get('serial_number', '')}",
    ])

    for line in cert_lines:
        page.insert_text((margin + 10, y_pos), line, fontsize=text_font_size, fontname="helv")
        y_pos += 14

    y_pos += 15

    # Signature list
    page.insert_text(
        (margin, y_pos),
        "Applied Signatures:",
        fontsize=header_font_size,
        fontname="helv",
    )
    y_pos += 18

    # Count signatures and initials separately
    full_sigs = [s for s in signatures_info if s.get("type") != "initials"]
    initials_sigs = [s for s in signatures_info if s.get("type") == "initials"]

    for i, sig in enumerate(full_sigs):
        sig_page = sig.get("page", 0) + 1
        text = f"{i + 1}. Digital signature - page {sig_page}"
        page.insert_text((margin + 10, y_pos), text, fontsize=text_font_size, fontname="helv")
        y_pos += 14

    if initials_sigs:
        pages_with_initials = sorted(set(s.get("page", 0) + 1 for s in initials_sigs))
        pages_str = ", ".join(str(p) for p in pages_with_initials)
        text = f"Initials - pages: {pages_str}"
        page.insert_text((margin + 10, y_pos), text, fontsize=text_font_size, fontname="helv")
        y_pos += 14

    y_pos += 20

    # Verification information
    page.insert_text(
        (margin, y_pos),
        "Signature Verification:",
        fontsize=header_font_size,
        fontname="helv",
    )
    y_pos += 18

    verification_text = [
        "The digital signature can be verified in Adobe Acrobat Reader",
        "or any other PDF viewer that supports digital signatures.",
        "",
        "The signature contains:",
        "- Timestamp of signing moment",
        "- Signer identity from certificate",
        "- Cryptographic hash of the document",
        "- Certificate chain for verification",
    ]

    for line in verification_text:
        page.insert_text((margin + 10, y_pos), line, fontsize=text_font_size, fontname="helv")
        y_pos += 14

    # Footer
    page.draw_line((margin, 792 - 50), (595 - margin, 792 - 50), width=0.5)

    footer_text = f"Created by Keboola eSignature | {github_url}"
    page.insert_text(
        (margin, 792 - 35),
        footer_text,
        fontsize=small_font_size,
        fontname="helv",
        color=(0.4, 0.4, 0.4),
    )

    # Save to bytes
    output = io.BytesIO()
    doc.save(output)
    doc.close()

    return output.getvalue()


def sign_pdf_multiple(
    pdf_bytes: bytes,
    p12_bytes: bytes,
    p12_password: str,
    signatures: List[Dict],
    lock_after_signing: bool = False,
    add_protocol_page: bool = False,
    reason: str = "Electronically signed",
) -> bytes:
    """
    Sign a PDF document with multiple visible signatures.

    Args:
        pdf_bytes: PDF document to sign as bytes
        p12_bytes: PKCS12 certificate file contents
        p12_password: Password to decrypt the P12 file
        signatures: List of signature positions, each dict has:
            - page: Page number (0-indexed)
            - x: X-coordinate from left edge in PDF points
            - y: Y-coordinate from bottom edge in PDF points
            - type: "full" or "initials" (default: "full")
            - width: Optional custom width
            - height: Optional custom height
        lock_after_signing: Whether to lock the PDF after signing
        add_protocol_page: Whether to add a protocol page
        reason: Reason for signing

    Returns:
        Signed PDF as bytes
    """
    if not signatures:
        raise ValueError("At least one signature position is required")

    try:
        # Load the signer
        signer = load_signer_from_p12(p12_bytes, p12_password)
        signer_name = get_signer_name_from_signer(signer)
        cert_info = get_certificate_info(signer)

        # Add protocol page if requested
        current_pdf = pdf_bytes
        if add_protocol_page:
            current_pdf = create_protocol_page(
                current_pdf,
                signatures,
                signer_name,
                cert_info,
            )

        # Create minimal stamp style (visual appearance is rendered separately)
        stamp_style = create_minimal_stamp_style()

        # Add each signature incrementally
        for i, sig in enumerate(signatures):
            page_number = sig["page"]
            x = sig["x"]
            y = sig["y"]
            sig_type = sig.get("type", "full")

            # Size based on signature type
            if sig_type == "initials":
                width = sig.get("width", INITIALS_WIDTH)
                height = sig.get("height", INITIALS_HEIGHT)
            else:
                width = sig.get("width", SIGNATURE_WIDTH)
                height = sig.get("height", SIGNATURE_HEIGHT)

            # Step 1: Render the visual appearance using PyMuPDF
            current_pdf = render_signature_appearance(
                pdf_bytes=current_pdf,
                page_num=page_number,
                x=x,
                y=y,
                width=width,
                height=height,
                signer_name=signer_name,
                signature_type=sig_type,
            )

            # Step 2: Apply cryptographic signature using pyhanko
            field_name = f"Signature_{i + 1}"

            # Create field specification at the same location
            sig_field = fields.SigFieldSpec(
                sig_field_name=field_name,
                box=(x, y, x + width, y + height),
                on_page=page_number,
            )

            # Signature metadata
            signature_meta = PdfSignatureMetadata(
                field_name=field_name,
                reason=reason,
                location='',
            )

            # Prepare PDF writer
            pdf_stream = io.BytesIO(current_pdf)
            pdf_writer = IncrementalPdfFileWriter(pdf_stream, strict=False)

            # Sign
            pdf_signer = signers.PdfSigner(
                signature_meta=signature_meta,
                signer=signer,
                stamp_style=stamp_style,
                new_field_spec=sig_field,
            )

            out = io.BytesIO()
            pdf_signer.sign_pdf(pdf_writer, output=out)
            current_pdf = out.getvalue()

        # Lock PDF if requested
        if lock_after_signing:
            current_pdf = lock_pdf_for_editing(current_pdf)

        return current_pdf

    except Exception as e:
        raise ValueError(f"Failed to sign PDF: {str(e)}") from e


def lock_pdf_for_editing(pdf_bytes: bytes) -> bytes:
    """
    Lock PDF to prevent editing (but allow viewing and printing).
    """
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")

    perm = fitz.PDF_PERM_PRINT | fitz.PDF_PERM_COPY | fitz.PDF_PERM_ACCESSIBILITY

    import secrets
    owner_pass = secrets.token_hex(16)

    output = io.BytesIO()
    doc.save(
        output,
        encryption=fitz.PDF_ENCRYPT_AES_256,
        permissions=perm,
        owner_pw=owner_pass,
        user_pw="",
    )
    doc.close()

    return output.getvalue()


# Maintain backward compatibility
def sign_pdf(
    pdf_bytes: bytes,
    p12_bytes: bytes,
    p12_password: str,
    page_number: int,
    x: float,
    y: float,
    width: float = 150,
    height: float = 50,
    reason: str = "Electronically signed",
    custom_text: Optional[str] = None,
) -> bytes:
    """Sign a PDF document with a single visible signature (legacy API)."""
    return sign_pdf_multiple(
        pdf_bytes=pdf_bytes,
        p12_bytes=p12_bytes,
        p12_password=p12_password,
        signatures=[{
            "page": page_number,
            "x": x,
            "y": y,
            "width": width,
            "height": height,
            "type": "full",
        }],
        reason=reason,
    )
