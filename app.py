"""
Streamlit application for signing PDF documents.
Supports multiple signatures on different pages, initials, and protocol.
"""

import io
from typing import Tuple, List, Dict

import fitz  # PyMuPDF
import streamlit as st
from PIL import Image, ImageDraw

from signer import sign_pdf_multiple, get_signer_name, get_initials


# Constants for rendering
PREVIEW_DPI = 120
PDF_DPI = 72
SIGNATURE_WIDTH = 150  # Signature width in PDF points
SIGNATURE_HEIGHT = 50  # Signature height in PDF points
INITIALS_WIDTH = 50    # Initials width in PDF points
INITIALS_HEIGHT = 35   # Initials height in PDF points
MAX_PREVIEW_WIDTH = 600  # Maximum preview width in pixels

# Colors to distinguish signatures
SIGNATURE_COLORS = {
    "full": (0, 100, 200),     # blue for signatures
    "initials": (100, 150, 50),  # green for initials
}

# Margins for initials
INITIALS_MARGIN = 20  # Margin from page edge in PDF points


def pdf_page_to_image(
    pdf_bytes: bytes,
    page_num: int = 0,
    max_width: int = MAX_PREVIEW_WIDTH
) -> Tuple[Image.Image, float, float, float]:
    """Convert PDF page to image with limited width."""
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    page = doc[page_num]

    page_width = page.rect.width
    page_height = page.rect.height

    base_scale = PREVIEW_DPI / PDF_DPI
    base_width = page_width * base_scale

    if base_width > max_width:
        scale_factor = max_width / base_width
    else:
        scale_factor = 1.0

    final_scale = base_scale * scale_factor

    mat = fitz.Matrix(final_scale, final_scale)
    pix = page.get_pixmap(matrix=mat)
    img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

    doc.close()
    return img, page_width, page_height, final_scale


def get_pdf_page_count(pdf_bytes: bytes) -> int:
    """Return the number of pages in PDF."""
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    count = len(doc)
    doc.close()
    return count


def draw_signature_boxes(
    img: Image.Image,
    signatures: List[Dict],
    page_num: int,
    page_width_pts: float,
    page_height_pts: float,
    selected_idx: int = -1,
) -> Image.Image:
    """Draw signature rectangles on page image."""
    img_copy = img.copy()
    draw = ImageDraw.Draw(img_copy, 'RGBA')

    for i, sig in enumerate(signatures):
        if sig["page"] != page_num:
            continue

        sig_type = sig.get("type", "full")
        color = SIGNATURE_COLORS.get(sig_type, SIGNATURE_COLORS["full"])

        # Size based on type
        if sig_type == "initials":
            sig_width = INITIALS_WIDTH
            sig_height = INITIALS_HEIGHT
        else:
            sig_width = SIGNATURE_WIDTH
            sig_height = SIGNATURE_HEIGHT

        sig_width_px = int(sig_width * (img.width / page_width_pts))
        sig_height_px = int(sig_height * (img.height / page_height_pts))

        x_pts = sig["x"]
        y_pts = sig["y"]

        pixel_x = int(x_pts * (img.width / page_width_pts))
        pixel_y = int((page_height_pts - y_pts - sig_height) * (img.height / page_height_pts))

        is_selected = (i == selected_idx)
        border_width = 4 if is_selected else 2

        fill_color = (*color, 60)
        draw.rectangle(
            [pixel_x, pixel_y, pixel_x + sig_width_px, pixel_y + sig_height_px],
            fill=fill_color,
        )
        draw.rectangle(
            [pixel_x, pixel_y, pixel_x + sig_width_px, pixel_y + sig_height_px],
            outline=color,
            width=border_width,
        )

        # Label
        label = f"#{i + 1}" if sig_type == "full" else "I"
        draw.text((pixel_x + 5, pixel_y + 5), label, fill=color)

    return img_copy


def get_initials_position(
    corner: str,
    page_width: float,
    page_height: float,
    offset_x: int = 0,
    offset_y: int = 0,
) -> Tuple[float, float]:
    """Calculate initials position for given corner."""
    margin = INITIALS_MARGIN

    if corner == "left":
        x = margin + offset_x
    else:  # right
        x = page_width - INITIALS_WIDTH - margin + offset_x

    y = margin + offset_y

    return x, y


def main():
    st.set_page_config(
        page_title="Keboola eSignature",
        page_icon="",
        layout="wide"
    )

    # Initialize session state
    if "signatures" not in st.session_state:
        st.session_state.signatures = []
    if "signed_pdf" not in st.session_state:
        st.session_state.signed_pdf = None
    if "signer_name" not in st.session_state:
        st.session_state.signer_name = None
    if "selected_signature" not in st.session_state:
        st.session_state.selected_signature = -1
    if "initials_corner" not in st.session_state:
        st.session_state.initials_corner = "right"
    if "initials_pages" not in st.session_state:
        st.session_state.initials_pages = []
    if "initials_offset_x" not in st.session_state:
        st.session_state.initials_offset_x = 0
    if "initials_offset_y" not in st.session_state:
        st.session_state.initials_offset_y = 0
    if "current_page" not in st.session_state:
        st.session_state.current_page = 0
    if "active_tab" not in st.session_state:
        st.session_state.active_tab = "signatures"

    # Sidebar with controls
    with st.sidebar:
        st.header("Keboola eSignature")
        st.caption("PDF Digital Signing Application")
        st.markdown("---")

        # File uploads
        st.subheader("1. Upload Files")

        pdf_file = st.file_uploader(
            "PDF Document",
            type=["pdf"],
            help="Select the PDF document to sign"
        )

        p12_file = st.file_uploader(
            "P12 Certificate",
            type=["p12", "pfx"],
            help="Select your digital certificate"
        )

        password = st.text_input(
            "Certificate Password",
            type="password",
            help="Enter the password to unlock your certificate"
        )

        # Certificate info
        if p12_file and password:
            try:
                signer_name = get_signer_name(p12_file.getvalue(), password)
                st.session_state.signer_name = signer_name
                initials = get_initials(signer_name)
                st.success(f"Certificate: **{signer_name}**")
                st.info(f"Initials: **{initials}**")
            except Exception as e:
                st.error(f"Certificate error: {str(e)}")
                st.session_state.signer_name = None

        st.markdown("---")

        # Signing options
        if pdf_file:
            st.subheader("2. Options")

            lock_pdf = st.checkbox(
                "Lock PDF after signing",
                value=False,
                help="Prevent modifications after signing"
            )

            add_protocol = st.checkbox(
                "Add protocol page",
                value=True,
                help="Add a page with signature information"
            )

            st.markdown("---")

            # Summary
            sig_count = len([s for s in st.session_state.signatures if s.get("type") != "initials"])
            init_pages = st.session_state.initials_pages
            init_count = len(init_pages)

            st.subheader("Summary")
            if sig_count:
                st.write(f"- {sig_count} signature(s)")
            if init_count:
                pages_str = ", ".join(str(p + 1) for p in sorted(init_pages))
                st.write(f"- Initials on pages: {pages_str}")
            if not sig_count and not init_count:
                st.write("No signatures or initials added yet")

            st.markdown("---")

            # Sign button
            has_signatures = sig_count > 0 or init_count > 0
            can_sign = pdf_file and p12_file and password and has_signatures

            if st.button("Sign PDF", type="primary", use_container_width=True, disabled=not can_sign):
                try:
                    with st.spinner("Signing document..."):
                        pdf_bytes = pdf_file.getvalue()
                        all_signatures = []

                        # Add regular signatures
                        for sig in st.session_state.signatures:
                            all_signatures.append({
                                "page": sig["page"],
                                "x": sig["x"],
                                "y": sig["y"],
                                "type": sig.get("type", "full"),
                            })

                        # Add initials
                        for page in st.session_state.initials_pages:
                            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
                            p = doc[page]
                            pw, ph = p.rect.width, p.rect.height
                            doc.close()

                            init_x, init_y = get_initials_position(
                                st.session_state.initials_corner,
                                pw, ph,
                                st.session_state.initials_offset_x,
                                st.session_state.initials_offset_y,
                            )

                            all_signatures.append({
                                "page": page,
                                "x": init_x,
                                "y": init_y,
                                "type": "initials",
                            })

                        # Sign
                        signed_pdf_bytes = sign_pdf_multiple(
                            pdf_bytes=pdf_file.getvalue(),
                            p12_bytes=p12_file.getvalue(),
                            p12_password=password,
                            signatures=all_signatures,
                            lock_after_signing=lock_pdf,
                            add_protocol_page=add_protocol,
                        )

                        st.session_state.signed_pdf = signed_pdf_bytes
                        st.success("PDF signed successfully!")

                except Exception as e:
                    st.error(f"Signing error: {str(e)}")
                    st.session_state.signed_pdf = None

            if st.session_state.signed_pdf:
                original_name = pdf_file.name
                signed_name = original_name.replace(".pdf", "_signed.pdf")

                st.download_button(
                    label="Download Signed PDF",
                    data=st.session_state.signed_pdf,
                    file_name=signed_name,
                    mime="application/pdf",
                    use_container_width=True,
                )

        st.markdown("---")
        st.markdown("[GitHub](https://github.com/padak/esignature)")

    # Main content area
    st.title("PDF Signature Placement")

    if not pdf_file:
        st.info("Upload a PDF document and certificate in the sidebar to get started.")
        return

    pdf_bytes = pdf_file.getvalue()
    page_count = get_pdf_page_count(pdf_bytes)

    # Tabs for signature types
    tab_signature, tab_initials = st.tabs(["Signatures", "Initials"])

    # ============== SIGNATURES TAB ==============
    with tab_signature:
        st.markdown("**Digital Signature** - full signature with date")

        # Page selector and buttons
        col_page, col_add, col_clear = st.columns([2, 1, 1])

        with col_page:
            page_num_sig = st.selectbox(
                "Page",
                options=range(page_count),
                format_func=lambda x: f"Page {x + 1} of {page_count}",
                key="page_selector_sig"
            )

        with col_add:
            if st.button("+ Add Signature", type="primary", key="add_sig"):
                new_sig = {
                    "page": page_num_sig,
                    "x": 400,
                    "y": 50,
                    "type": "full",
                }
                st.session_state.signatures.append(new_sig)
                st.session_state.selected_signature = len(st.session_state.signatures) - 1
                st.rerun()

        with col_clear:
            if st.button("Remove All", key="clear_sigs"):
                st.session_state.signatures = [
                    s for s in st.session_state.signatures if s.get("type") == "initials"
                ]
                st.session_state.selected_signature = -1
                st.rerun()

        # Preview and controls for signatures
        try:
            img, page_width_pts, page_height_pts, scale = pdf_page_to_image(pdf_bytes, page_num_sig)

            # Build list of all signatures for display (including initials preview)
            all_display_sigs = list(st.session_state.signatures)

            # Add initials preview if this page has initials
            if page_num_sig in st.session_state.initials_pages:
                init_x, init_y = get_initials_position(
                    st.session_state.initials_corner,
                    page_width_pts,
                    page_height_pts,
                    st.session_state.initials_offset_x,
                    st.session_state.initials_offset_y,
                )
                all_display_sigs.append({
                    "page": page_num_sig,
                    "x": init_x,
                    "y": init_y,
                    "type": "initials",
                })

            # Signatures for this page only
            page_signatures = [(i, sig) for i, sig in enumerate(st.session_state.signatures)
                              if sig["page"] == page_num_sig and sig.get("type") != "initials"]

            col_preview, col_controls = st.columns([3, 2])

            with col_preview:
                img_with_boxes = draw_signature_boxes(
                    img,
                    all_display_sigs,
                    page_num_sig,
                    page_width_pts,
                    page_height_pts,
                    st.session_state.selected_signature,
                )
                st.image(img_with_boxes, caption=f"Page {page_num_sig + 1}")

                # Legend
                st.markdown("""
                <small>
                <span style="color: rgb(0,100,200);">&#9632;</span> Signature &nbsp;
                <span style="color: rgb(100,150,50);">&#9632;</span> Initials
                </small>
                """, unsafe_allow_html=True)

            with col_controls:
                if page_signatures:
                    st.markdown("**Signatures on this page:**")

                    for idx, (global_idx, sig) in enumerate(page_signatures):
                        with st.expander(
                            f"Signature #{global_idx + 1}",
                            expanded=(global_idx == st.session_state.selected_signature)
                        ):
                            new_x = st.slider(
                                "Position X",
                                min_value=0,
                                max_value=int(page_width_pts - SIGNATURE_WIDTH),
                                value=int(sig["x"]),
                                key=f"sig_x_{global_idx}",
                            )

                            new_y = st.slider(
                                "Position Y",
                                min_value=0,
                                max_value=int(page_height_pts - SIGNATURE_HEIGHT),
                                value=int(sig["y"]),
                                key=f"sig_y_{global_idx}",
                            )

                            if new_x != sig["x"] or new_y != sig["y"]:
                                st.session_state.signatures[global_idx]["x"] = new_x
                                st.session_state.signatures[global_idx]["y"] = new_y
                                st.session_state.selected_signature = global_idx
                                st.rerun()

                            if st.button("Remove", key=f"del_{global_idx}"):
                                st.session_state.signatures.pop(global_idx)
                                st.session_state.selected_signature = -1
                                st.rerun()
                else:
                    st.info("No signatures on this page. Click '+ Add Signature' to add one.")

                # Info about initials
                if page_num_sig in st.session_state.initials_pages:
                    st.markdown("---")
                    st.success("Initials will be placed on this page")

        except Exception as e:
            st.error(f"Error loading PDF: {str(e)}")

    # ============== INITIALS TAB ==============
    with tab_initials:
        st.markdown("**Initials** - 'seen by' confirmation mark")

        # Position settings
        col_corner, col_offset = st.columns(2)

        with col_corner:
            corner = st.radio(
                "Corner position",
                options=["left", "right"],
                format_func=lambda x: "Bottom left" if x == "left" else "Bottom right",
                horizontal=True,
                key="initials_corner_select"
            )
            st.session_state.initials_corner = corner

        with col_offset:
            offset_x = st.slider(
                "Offset X",
                -50, 50, st.session_state.initials_offset_x,
                key="init_offset_x_slider"
            )
            offset_y = st.slider(
                "Offset Y",
                -50, 50, st.session_state.initials_offset_y,
                key="init_offset_y_slider"
            )

            # Store offsets in session state
            st.session_state.initials_offset_x = offset_x
            st.session_state.initials_offset_y = offset_y

        # Page selection for initials
        st.markdown("**Select pages for initials:**")

        col_all, col_none = st.columns([1, 1])
        with col_all:
            if st.button("Select all pages", key="select_all_pages"):
                st.session_state.initials_pages = list(range(page_count))
                st.rerun()
        with col_none:
            if st.button("Clear selection", key="clear_pages"):
                st.session_state.initials_pages = []
                st.rerun()

        # Multiselect for page selection
        page_options = list(range(page_count))
        selected_pages = st.multiselect(
            "Pages for initials",
            options=page_options,
            default=st.session_state.initials_pages,
            format_func=lambda x: f"Page {x + 1}",
            key="initials_multiselect",
        )

        st.session_state.initials_pages = selected_pages

        if selected_pages:
            st.success(f"Initials will be placed on {len(selected_pages)} page(s): {', '.join(str(p+1) for p in sorted(selected_pages))}")

        # Preview for initials tab
        st.markdown("---")
        st.markdown("**Preview**")

        page_num_init = st.selectbox(
            "Preview page",
            options=range(page_count),
            format_func=lambda x: f"Page {x + 1} of {page_count}",
            key="page_selector_init"
        )

        try:
            img, page_width_pts, page_height_pts, scale = pdf_page_to_image(pdf_bytes, page_num_init)

            # Build display list - show signatures and initials
            all_display_sigs = [s for s in st.session_state.signatures if s["page"] == page_num_init]

            # Add initials for this page if selected
            if page_num_init in st.session_state.initials_pages:
                init_x, init_y = get_initials_position(
                    st.session_state.initials_corner,
                    page_width_pts,
                    page_height_pts,
                    offset_x,
                    offset_y,
                )
                all_display_sigs.append({
                    "page": page_num_init,
                    "x": init_x,
                    "y": init_y,
                    "type": "initials",
                })

            img_with_boxes = draw_signature_boxes(
                img,
                all_display_sigs,
                page_num_init,
                page_width_pts,
                page_height_pts,
                -1,  # No selection in initials tab
            )

            col_preview_init, col_info_init = st.columns([3, 2])

            with col_preview_init:
                st.image(img_with_boxes, caption=f"Page {page_num_init + 1}")

            with col_info_init:
                if page_num_init in st.session_state.initials_pages:
                    st.success("Initials will be placed on this page")
                else:
                    st.info("No initials on this page. Select this page in the list above.")

                # Show any signatures on this page
                sigs_on_page = [s for s in st.session_state.signatures
                               if s["page"] == page_num_init and s.get("type") != "initials"]
                if sigs_on_page:
                    st.markdown(f"*{len(sigs_on_page)} signature(s) on this page*")

        except Exception as e:
            st.error(f"Error loading PDF: {str(e)}")


if __name__ == "__main__":
    main()
