# Keboola eSignature

Sign PDF documents with your own P12/PFX certificate, on your own computer.

eSignature is a small local web app: a PDF-viewer-like editor where you place visible signatures
and initials on the pages, and a signer that adds cryptographically valid PDF signatures
(via pyHanko) behind those marks. Nothing is uploaded anywhere: the app listens on
`127.0.0.1` only, and the document and certificate are held in memory just for the request.

![Keboola eSignature editor](docs/screenshot.png)

## Features

- **Continuous-scroll viewer** – all pages in one column, rendered lazily by PDF.js; zoom in/out
  or fit to width.
- **Click to place, drag to move** – arm "Add signature", click where it should go, drag it to
  adjust. Arrow keys nudge by 1 pt (Shift: 10 pt), Delete removes it.
- **Multiple signatures** – each visible signature is its own cryptographic signature; all of them
  stay valid.
- **Initials (paraph)** – one shared initials mark in an explicit corner (bottom right or bottom
  left) with margins in points, on all pages, all except the last, or a custom page list. Dragging
  it on any page moves it on every selected page. Pages where it would not fit are listed and
  signing is blocked until fixed.
- **Protocol page** – optional summary page with certificate and signature details.
- **Lock after signing** – the last signature requests that no further changes are made
  (enforcement depends on the PDF viewer).

## Run it

Requirements: Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/keboola/esignature.git
cd esignature
uv run esignature
```

Then open <http://127.0.0.1:8501>. Stop it with Ctrl+C.

### Configuration

All settings are optional environment variables with safe defaults. An invalid value stops the
app at startup with a message naming the variable.

| Variable | Default | Meaning |
|---|---|---|
| `ESIGN_HOST` | `127.0.0.1` | Bind address; only `127.0.0.1` or `localhost` are accepted |
| `ESIGN_PORT` | `8501` | Port |
| `ESIGN_MAX_PDF_MB` | `50` | Largest PDF accepted |
| `ESIGN_MAX_P12_KB` | `256` | Largest certificate file accepted |
| `ESIGN_MAX_PLACEMENTS` | `1000` | Most signatures + initials in one signing |
| `ESIGN_MAX_IN_FLIGHT` | `2` | Requests handled at once; more get "busy, try again" |

## How to use

1. **Document** – choose a PDF (or drop it onto the page area). It is opened in the browser.
2. **Certificate** – choose your `.p12`/`.pfx` file and type its password (leave it empty if the
   certificate has none). The app checks it and shows the name, issuer and validity.
3. **Place** – click "Add signature", then click on a page. Drag the box to fine-tune it, or
   select it and use the arrow keys. Turn on "Initials on pages" for a paraph on each page.
   The boxes show a preview; the real mark contains your name, the signing time and a link.
4. **Options** – add a protocol page and/or lock the PDF.
5. **Sign** – click "Sign document", then "Download signed PDF".

Encrypted PDFs and PDFs that already carry a signature are rejected with a clear message.

## Security notes

- Listens on loopback only and rejects requests whose `Host` header is not `127.0.0.1` or
  `localhost` (protects against DNS rebinding).
- Every API call must come from the app's own page: the exact `Origin` and a random per-launch
  token (embedded in the page) are required; there is no CORS.
- Upload size is capped while the body streams in, uploads are kept in memory (never written to a
  temporary file), and only a few requests are admitted at a time.
- All PDF and certificate work runs on a single worker thread.
- Responses are `Cache-Control: no-store` with a strict Content-Security-Policy; certificate and
  file names are always shown as plain text.
- No request bodies, passwords or documents are logged or stored. This is "no persistence by the
  app", not secure memory erasure: Python and browser memory or OS swap are outside its control.
- PDF.js (5.7.284) is vendored under `static/vendor/pdfjs/`, so the editor works fully offline.

## Development

```bash
uv sync
uv run playwright install chromium   # once, for the browser tests
uv run pytest                        # signer, API and browser end-to-end tests
uv run ruff check
```

Project layout:

```
server.py      FastAPI app: security middleware, admission, API, static files, entry point
config.py      Settings from environment variables
signer.py      Signing (pyHanko + PyMuPDF): marks, protocol page, signatures, lock
geometry.py    Placement contract and page-space conversion
static/        Frontend: index.html, app.css, js/ (ES modules), vendor/pdfjs/
fonts/         Dancing Script (signature font, OFL)
tests/         pytest suite; tests/e2e/ drives the real app in Chromium
```

### Placement contract

A placement is `{page, type: "signature" | "initials", x, y}`: `page` is 0-based and `x`/`y` are
the top-left corner of the box in PDF points on the page **as displayed** (crop box, rotation
applied, origin top-left), which is exactly PDF.js's viewport at scale 1. Box sizes are fixed:
signature 150 × 50 pt, initials 50 × 35 pt. The server converts this once to PDF coordinates, for
both the drawn mark and the signature field.

## License

MIT for the application. Dancing Script font: SIL Open Font License 1.1 (Pablo Impallari).
PDF.js: Apache License 2.0 (`static/vendor/pdfjs/LICENSE`).
