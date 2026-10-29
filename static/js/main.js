// Editor controller: panel steps, placement interactions and signing.
// Untrusted text (file names, certificate fields, server messages) is only ever set via textContent.

import { checkCertificate, signDocument } from "./api.js";
import {
  BOX,
  addSignature,
  clampToPage,
  createState,
  formatPages,
  initialsInstances,
  initialsMargins,
  placementsPayload,
  removeSignature,
} from "./placements.js";
import { Viewer } from "./viewer.js";

const $ = (id) => document.getElementById(id);

const els = {
  viewer: $("viewer"),
  pages: $("pages"),
  emptyState: $("empty-state"),
  emptyChoose: $("empty-choose"),
  docTitle: $("doc-title"),
  zoomIn: $("zoom-in"),
  zoomOut: $("zoom-out"),
  zoomLabel: $("zoom-label"),
  pdfInput: $("pdf-input"),
  pdfName: $("pdf-name"),
  docInfo: $("doc-info"),
  docNotice: $("doc-notice"),
  p12Input: $("p12-input"),
  p12Name: $("p12-name"),
  password: $("password"),
  certStatus: $("cert-status"),
  certName: $("cert-name"),
  certDetails: $("cert-details"),
  addSignature: $("add-signature"),
  placeBanner: $("place-banner"),
  placeBannerText: $("place-banner-text"),
  placeCancel: $("place-cancel"),
  signatureList: $("signature-list"),
  initialsOn: $("initials-on"),
  initialsOptions: $("initials-options"),
  initialsPages: $("initials-pages"),
  initialsCustomField: $("initials-custom-field"),
  initialsCustom: $("initials-custom"),
  initialsCorner: $("initials-corner"),
  initialsMx: $("initials-mx"),
  initialsMy: $("initials-my"),
  initialsWarning: $("initials-warning"),
  optProtocol: $("opt-protocol"),
  optLock: $("opt-lock"),
  sign: $("sign"),
  signHint: $("sign-hint"),
  signNotice: $("sign-notice"),
  signError: $("sign-error"),
  download: $("download"),
};

const viewer = new Viewer(els.viewer, els.pages);
const state = createState();

// The PDF and P12 are read ONCE when chosen; signing uploads exactly these bytes, so the signed
// document is the one that was previewed even if the file changes on disk afterwards.
const app = {
  pdf: null, // {name, bytes: ArrayBuffer} once read
  p12: null, // {name, bytes: ArrayBuffer} once read
  p12Seq: 0,
  staleNotice: null,
  cert: null, // {name, initials, ...} once the certificate checked out
  certError: null,
  certChecking: false,
  certSeq: 0,
  docSeq: 0,
  signSeq: 0,
  signing: false,
  placing: false,
  resultUrl: null,
  drag: null,
  // Per document; reset on every document change (see resetDocumentPolicy).
  signatureFields: [], // [{page, x, y, w, h}] signature widgets from PDF.js, displayed space
  signaturesHint: false, // the document seems to contain signature fields (heuristic only)
  signedMode: false, // the server said this document is already signed: signatures only
  blockedMessage: null, // the server refused this document (locked / invalid existing signatures)
};

const SIGNED_MODE_NOTICE = "This document is already signed. Your signature will be added; initials "
  + "and the protocol page are not available. Click Sign again.";
const SIGNATURE_FIELDS_NOTICE = "This document seems to contain signature fields. If it is already "
  + "signed, initials and the protocol page are not available.";

// --- Signed result -------------------------------------------------------------------------------

function clearResult() {
  if (app.resultUrl) URL.revokeObjectURL(app.resultUrl);
  app.resultUrl = null;
  els.download.hidden = true;
  els.download.removeAttribute("href");
  els.signError.hidden = true;
  els.signError.textContent = "";
}

/**
 * Any change to inputs invalidates the signed result. A sign request still in flight keeps Sign
 * disabled until it finishes, but its response is discarded (see sign()).
 */
function changed() {
  app.signSeq += 1;
  app.staleNotice = null;
  clearResult();
  render();
}

function resetInitials() {
  state.initials = createState().initials;
  els.initialsOn.checked = state.initials.enabled;
  els.initialsPages.value = state.initials.preset;
  els.initialsCustom.value = state.initials.custom;
  els.initialsCorner.value = state.initials.corner;
  els.initialsMx.value = String(state.initials.mx);
  els.initialsMy.value = String(state.initials.my);
}

// --- Document ------------------------------------------------------------------------------------

function resetDocumentPolicy() {
  app.signatureFields = [];
  app.signaturesHint = false;
  app.signedMode = false;
  app.blockedMessage = null;
}

/**
 * The server is authoritative about signed documents (PDF.js cannot tell filled from empty
 * signature fields). Signed mode: protocol unchecked and disabled, initials cleared and disabled
 * (state AND controls), signature placements kept; the user must click Sign again.
 */
function enterSignedMode() {
  app.signedMode = true;
  els.optProtocol.checked = false;
  resetInitials();
  if (state.selected?.kind === "initials") state.selected = null;
}

async function openPdf(file) {
  if (!file) return;
  const seq = ++app.docSeq;
  // A new document starts from scratch: no marks, no initials, no result.
  app.pdf = null;
  state.signatures = [];
  state.pageSizes = [];
  state.selected = null;
  resetInitials();
  resetDocumentPolicy();
  setPlacing(false);
  viewer.close();
  els.pdfName.textContent = file.name;
  els.docTitle.textContent = file.name;
  els.docInfo.textContent = "Opening…";
  els.emptyState.hidden = true;
  changed();
  try {
    const bytes = await file.arrayBuffer();
    if (seq !== app.docSeq) return; // a newer file was chosen meanwhile
    // PDF.js takes ownership of the buffer it gets, so it gets a copy.
    const { sizes, signatureFields, signaturesHint } = await viewer.open(bytes.slice(0));
    if (seq !== app.docSeq) return;
    app.pdf = { name: file.name, bytes };
    state.pageSizes = sizes;
    app.signatureFields = signatureFields;
    app.signaturesHint = signaturesHint || signatureFields.length > 0;
    autoFit = true;
    viewer.setScale(viewer.fitWidthScale());
    els.docInfo.textContent = `${sizes.length} page${sizes.length === 1 ? "" : "s"}`;
  } catch (error) {
    if (seq !== app.docSeq || error?.message === "superseded") return;
    app.pdf = null;
    viewer.close();
    els.docInfo.textContent = "";
    els.docTitle.textContent = "No document open";
    els.pdfName.textContent = "No file chosen";
    els.emptyState.hidden = false;
    showError(error?.name === "PasswordException"
      ? "This PDF is password protected. Encrypted PDFs cannot be signed."
      : "This file could not be opened as a PDF.");
  }
  render();
}

async function openP12(file) {
  const seq = ++app.p12Seq;
  app.p12 = null;
  els.p12Name.textContent = file ? file.name : "No file chosen";
  certificateChanged();
  if (!file) return;
  try {
    const bytes = await file.arrayBuffer();
    if (seq !== app.p12Seq) return;
    app.p12 = { name: file.name, bytes };
  } catch {
    if (seq !== app.p12Seq) return;
    certificateChanged();
    app.certError = "The certificate file could not be read.";
    render();
    return;
  }
  certificateChanged();
}

function showError(message) {
  els.signError.textContent = message;
  els.signError.hidden = false;
}

// --- Certificate ---------------------------------------------------------------------------------

let certTimer = null;

function certificateChanged() {
  app.cert = null;
  app.certError = null;
  // Any check in flight is now stale (its response is ignored), so it must not keep the
  // status on "Checking…"; a new check sets this again when it starts.
  app.certChecking = false;
  app.certSeq += 1;
  changed();
  clearTimeout(certTimer);
  if (app.p12) certTimer = setTimeout(runCertificateCheck, 350);
}

async function runCertificateCheck() {
  const seq = ++app.certSeq;
  app.certChecking = true;
  render();
  try {
    const info = await checkCertificate(app.p12, els.password.value);
    if (seq !== app.certSeq) return;
    app.cert = info;
  } catch (error) {
    if (seq !== app.certSeq) return;
    app.certError = error.message;
  } finally {
    if (seq === app.certSeq) app.certChecking = false;
  }
  render();
}

// --- Placing and editing marks -------------------------------------------------------------------

function setPlacing(on) {
  app.placing = on && state.pageSizes.length > 0;
  els.placeBannerText.textContent = "Click on a page to place your signature";
  els.placeBanner.hidden = !app.placing;
  els.viewer.classList.toggle("placing", app.placing);
}

function overlayPoint(overlay, event) {
  const rect = overlay.getBoundingClientRect();
  return { x: (event.clientX - rect.left) / viewer.scale, y: (event.clientY - rect.top) / viewer.scale };
}

els.pages.addEventListener("pointerdown", (event) => {
  const overlay = event.target.closest(".overlay");
  if (!overlay || event.target.closest(".mark")) return;
  if (!app.placing) {
    if (state.selected) {
      state.selected = null;
      render();
    }
    return;
  }
  event.preventDefault();
  const page = Number(overlay.dataset.pageIndex);
  const size = state.pageSizes[page];
  if (size.width < BOX.signature.w || size.height < BOX.signature.h) {
    // Stay armed: the user can click another page.
    els.placeBannerText.textContent = `Page ${page + 1} is too small for a signature `
      + `(${BOX.signature.w} × ${BOX.signature.h} pt). Click another page.`;
    return;
  }
  const point = overlayPoint(overlay, event);
  const signature = addSignature(state, page, point.x, point.y);
  state.selected = { kind: "signature", id: signature.id };
  setPlacing(false);
  changed();
  focusSelected();
});

function selectedMark() {
  const sel = state.selected;
  if (!sel) return null;
  if (sel.kind === "signature") {
    const signature = state.signatures.find((s) => s.id === sel.id);
    return signature ? { kind: "signature", page: signature.page, x: signature.x, y: signature.y, signature } : null;
  }
  const inst = initialsInstances(state).instances.find((i) => i.page === sel.page);
  return inst ? { kind: "initials", page: inst.page, x: inst.x, y: inst.y } : null;
}

/** Move the selected mark to (x, y) on its page, clamped inside the page. */
function moveSelected(x, y) {
  const mark = selectedMark();
  if (!mark) return;
  const size = state.pageSizes[mark.page];
  const pos = clampToPage(size, mark.kind, x, y);
  if (mark.kind === "signature") {
    mark.signature.x = pos.x;
    mark.signature.y = pos.y;
  } else {
    // The initials are one shared mark: moving one instance changes the margins for all pages.
    const margins = initialsMargins(size, state.initials, pos.x, pos.y);
    state.initials.mx = round2(margins.mx);
    state.initials.my = round2(margins.my);
    els.initialsMx.value = String(state.initials.mx);
    els.initialsMy.value = String(state.initials.my);
  }
}

function round2(value) {
  return Math.round(value * 100) / 100;
}

function deleteSelected() {
  const sel = state.selected;
  if (!sel) return;
  if (sel.kind === "signature") {
    removeSignature(state, sel.id);
  } else {
    state.initials.enabled = false;
    els.initialsOn.checked = false;
  }
  state.selected = null;
  changed();
}

function focusSelected() {
  const sel = state.selected;
  if (!sel) return;
  const selector = sel.kind === "signature" ? `.mark[data-id="${sel.id}"]` : `.mark[data-kind="initials"][data-page="${sel.page}"]`;
  els.pages.querySelector(selector)?.focus({ preventScroll: true });
}

function startDrag(event, el) {
  if (event.button !== 0) return;
  event.preventDefault();
  event.stopPropagation();
  state.selected = el.dataset.kind === "signature"
    ? { kind: "signature", id: Number(el.dataset.id) }
    : { kind: "initials", page: Number(el.dataset.page) };
  const mark = selectedMark();
  if (!mark) return;
  app.drag = {
    pointerId: event.pointerId,
    startX: event.clientX,
    startY: event.clientY,
    origin: { x: mark.x, y: mark.y },
    restore: snapshot(),
    moved: false,
  };
  el.setPointerCapture(event.pointerId);
  render();
  focusSelected();
}

function snapshot() {
  return { signatures: state.signatures.map((s) => ({ ...s })), mx: state.initials.mx, my: state.initials.my };
}

function restore(saved) {
  state.signatures = saved.signatures;
  state.initials.mx = saved.mx;
  state.initials.my = saved.my;
  els.initialsMx.value = String(saved.mx);
  els.initialsMy.value = String(saved.my);
}

function onDragMove(event) {
  const drag = app.drag;
  if (!drag || event.pointerId !== drag.pointerId) return;
  const dx = (event.clientX - drag.startX) / viewer.scale;
  const dy = (event.clientY - drag.startY) / viewer.scale;
  if (!drag.moved && Math.hypot(dx, dy) * viewer.scale < 2) return;
  drag.moved = true;
  moveSelected(drag.origin.x + dx, drag.origin.y + dy);
  scheduleMarks();
}

function endDrag(event, cancelled) {
  const drag = app.drag;
  if (!drag || (event && event.pointerId !== drag.pointerId)) return;
  app.drag = null;
  if (cancelled) restore(drag.restore);
  if (drag.moved || cancelled) changed();
  else renderMarks();
  focusSelected();
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    if (app.drag) {
      endDrag(null, true);
    } else if (app.placing) {
      setPlacing(false);
    } else if (state.selected) {
      state.selected = null;
      render();
    }
    return;
  }
  // Keys edit marks only when focus is on a mark or on nothing interactive (never on a link,
  // button or form field, e.g. the Download link).
  const target = event.target;
  if (target instanceof Element && !target.closest(".mark")
      && target.closest("a, button, input, select, textarea, [contenteditable]")) return;
  const mark = selectedMark();
  if (!mark || app.drag) return;
  const step = event.shiftKey ? 10 : 1;
  const moves = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] };
  if (moves[event.key]) {
    event.preventDefault();
    const [dx, dy] = moves[event.key];
    moveSelected(mark.x + dx, mark.y + dy);
    changed();
    focusSelected();
  } else if (event.key === "Delete" || event.key === "Backspace") {
    event.preventDefault();
    deleteSelected();
  }
});

// --- Rendering -----------------------------------------------------------------------------------

/** True if a signature box overlaps an existing signature widget on its page. */
function overlapsExistingSignature(signature) {
  const box = BOX.signature;
  return app.signatureFields.some((field) => field.page === signature.page
    && signature.x < field.x + field.w && field.x < signature.x + box.w
    && signature.y < field.y + field.h && field.y < signature.y + box.h);
}

let marksFrame = 0;
function scheduleMarks() {
  if (!marksFrame) {
    marksFrame = requestAnimationFrame(() => {
      marksFrame = 0;
      renderMarks();
    });
  }
}

// Mark elements are reused across renders (keyed by mark), so a drag keeps its pointer capture.
const markEls = new Map();

function markElement(kind, page) {
  const el = document.createElement("div");
  el.className = `mark mark-${kind}`;
  el.tabIndex = 0;
  el.dataset.kind = kind;
  el.dataset.page = String(page);
  el.setAttribute("role", "button");
  el.addEventListener("pointerdown", (event) => startDrag(event, el));
  el.addEventListener("pointermove", onDragMove);
  el.addEventListener("pointerup", (event) => endDrag(event, false));
  el.addEventListener("pointercancel", (event) => endDrag(event, true));
  el.addEventListener("lostpointercapture", (event) => endDrag(event, false));
  if (kind === "signature") {
    for (const [cls, text] of [["mark-name", ""], ["mark-line", "Date and time at signing"],
      ["mark-url", "github.com/keboola/esignature"], ["mark-tag", "Preview"],
      ["mark-overlap", "Overlaps an existing signature"]]) {
      const line = document.createElement("div");
      line.className = cls;
      line.textContent = text;
      el.append(line);
    }
  } else {
    const text = document.createElement("div");
    text.className = "mark-initials-text";
    el.append(text);
  }
  return el;
}

function upsertMark(key, kind, page, x, y, seen) {
  const overlay = viewer.overlay(page);
  if (!overlay) return null;
  let el = markEls.get(key);
  if (!el || el.dataset.page !== String(page)) {
    el?.remove();
    el = markElement(kind, page);
    markEls.set(key, el);
  }
  if (el.parentElement !== overlay) overlay.append(el);
  const box = BOX[kind];
  el.dataset.x = String(x);
  el.dataset.y = String(y);
  el.style.left = `${x * viewer.scale}px`;
  el.style.top = `${y * viewer.scale}px`;
  el.style.width = `${box.w * viewer.scale}px`;
  el.style.height = `${box.h * viewer.scale}px`;
  seen.add(key);
  return el;
}

function renderMarks() {
  const selected = state.selected;
  const seen = new Set();
  state.signatures.forEach((signature, index) => {
    const el = upsertMark(`s${signature.id}`, "signature", signature.page, signature.x, signature.y, seen);
    if (!el) return;
    el.dataset.id = String(signature.id);
    el.setAttribute("aria-label", `Signature ${index + 1} on page ${signature.page + 1}`);
    el.querySelector(".mark-name").textContent = app.cert ? app.cert.name : "Your name";
    el.classList.toggle("selected", selected?.kind === "signature" && selected.id === signature.id);
    el.classList.toggle("overlap", overlapsExistingSignature(signature));
  });
  for (const inst of initialsInstances(state).instances) {
    const el = upsertMark(`i${inst.page}`, "initials", inst.page, inst.x, inst.y, seen);
    if (!el) continue;
    el.setAttribute("aria-label", `Initials on page ${inst.page + 1}`);
    el.querySelector(".mark-initials-text").textContent = app.cert ? app.cert.initials : "AB";
    const isInitials = selected?.kind === "initials";
    el.classList.toggle("selected", isInitials && selected.page === inst.page);
    el.classList.toggle("linked", isInitials && selected.page !== inst.page);
  }
  for (const [key, el] of markEls) {
    if (!seen.has(key)) {
      el.remove();
      markEls.delete(key);
    }
  }
}

function renderList() {
  const items = state.signatures.map((signature, index) => {
    const li = document.createElement("li");
    li.className = "placement-item";
    if (state.selected?.kind === "signature" && state.selected.id === signature.id) li.classList.add("selected");
    const go = document.createElement("button");
    go.type = "button";
    go.className = "placement-go";
    go.textContent = `Signature ${index + 1}`;
    const meta = document.createElement("span");
    meta.className = "muted small";
    meta.textContent = ` · page ${signature.page + 1}`;
    go.append(meta);
    go.addEventListener("click", () => {
      state.selected = { kind: "signature", id: signature.id };
      viewer.scrollToPage(signature.page);
      render();
      focusSelected();
    });
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "icon-button small";
    remove.setAttribute("aria-label", `Remove signature ${index + 1}`);
    remove.textContent = "×";
    remove.addEventListener("click", () => {
      removeSignature(state, signature.id);
      if (state.selected?.id === signature.id) state.selected = null;
      changed();
    });
    li.append(go, remove);
    return li;
  });
  els.signatureList.replaceChildren(...items);
}

function renderCertificate() {
  const show = app.certChecking || app.cert || app.certError;
  els.certStatus.hidden = !show;
  els.certStatus.classList.toggle("ok", Boolean(app.cert));
  els.certStatus.classList.toggle("bad", Boolean(app.certError));
  if (app.certChecking) {
    els.certName.textContent = "Checking certificate…";
    els.certDetails.textContent = "";
  } else if (app.cert) {
    els.certName.textContent = app.cert.name;
    const parts = [];
    if (app.cert.organization) parts.push(app.cert.organization);
    if (app.cert.issuer) parts.push(`Issued by ${app.cert.issuer}`);
    if (app.cert.valid_to) parts.push(`valid until ${app.cert.valid_to}`);
    els.certDetails.textContent = parts.join(" · ");
  } else if (app.certError) {
    els.certName.textContent = app.certError;
    els.certDetails.textContent = "";
  }
}

function renderInitials() {
  const hasDoc = state.pageSizes.length > 0;
  // Signed mode keeps initials off: nothing here may re-enable them.
  els.initialsOn.disabled = !hasDoc || app.signedMode;
  els.initialsOptions.hidden = !state.initials.enabled;
  els.initialsCustomField.hidden = state.initials.preset !== "custom";
  const { instances, misfit, error } = initialsInstances(state);
  const messages = [];
  if (error) messages.push(error);
  if (misfit.length) {
    messages.push(`The initials do not fit on page${misfit.length === 1 ? "" : "s"} ${formatPages(misfit)}. `
      + "Reduce the margins to fix this before signing.");
  }
  if (state.initials.enabled && hasDoc && !error && !instances.length && !misfit.length) {
    messages.push("No pages selected for initials.");
  }
  els.initialsWarning.textContent = messages.join(" ");
  els.initialsWarning.hidden = messages.length === 0;
  return { instances, misfit, error, messages };
}

function signBlocker(initials) {
  if (!app.pdf || !state.pageSizes.length) return "Choose a PDF document.";
  if (!app.p12) return "Choose your P12 / PFX certificate.";
  if (app.certChecking) return "Checking the certificate…";
  if (!app.cert) return app.certError ? "Fix the certificate or password." : "Checking the certificate…";
  if (app.blockedMessage) return `${app.blockedMessage} Choose another document to sign.`;
  // Say exactly what is wrong: the initials settings may be scrolled out of view.
  if (state.initials.enabled && (initials.error || initials.misfit.length)) return initials.messages.join(" ");
  if (!state.signatures.length && !initials.instances.length) return "Add a signature or initials.";
  return null;
}

function render() {
  const hasDoc = state.pageSizes.length > 0;
  els.addSignature.disabled = !hasDoc;
  els.zoomIn.disabled = els.zoomOut.disabled = els.zoomLabel.disabled = !hasDoc;
  els.zoomLabel.textContent = `${Math.round(viewer.scale * 100)}%`;
  renderCertificate();
  const initials = renderInitials();
  renderMarks();
  renderList();
  els.optProtocol.disabled = app.signedMode;
  els.docNotice.textContent = app.signedMode ? "" : (app.signaturesHint ? SIGNATURE_FIELDS_NOTICE : "");
  els.docNotice.hidden = !els.docNotice.textContent;
  els.signNotice.textContent = app.signedMode && !app.resultUrl ? SIGNED_MODE_NOTICE : "";
  els.signNotice.hidden = !els.signNotice.textContent;
  const blocker = signBlocker(initials);
  els.sign.disabled = Boolean(blocker) || app.signing;
  els.sign.textContent = app.signing ? "Signing…" : "Sign document";
  const overlapping = state.signatures.filter(overlapsExistingSignature).length;
  const overlapHint = overlapping
    ? `${overlapping === 1 ? "A signature overlaps" : `${overlapping} signatures overlap`} an existing `
      + "signature field and may hide it. "
    : "";
  let hint = blocker || overlapHint + (app.resultUrl ? "" : "Ready to sign.");
  if (app.signing) hint = app.signSeq === app.signingSeq ? "" : "Inputs changed; this result will be discarded.";
  else if (app.staleNotice) hint = app.staleNotice;
  els.signHint.textContent = hint;
}

// --- Signing -------------------------------------------------------------------------------------

async function sign() {
  if (els.sign.disabled || app.signing) return;
  const seq = ++app.signSeq;
  const docSeq = app.docSeq;
  const pdfName = app.pdf.name;
  clearResult();
  app.staleNotice = null;
  app.signing = true; // only cleared when THIS request finishes, whatever changes meanwhile
  app.signingSeq = seq;
  render();
  try {
    const blob = await signDocument({
      pdf: app.pdf,
      p12: app.p12,
      password: els.password.value,
      // Signed mode sends signatures only and never the protocol, whatever the controls say.
      placements: placementsPayload(state).filter((p) => !app.signedMode || p.type === "signature"),
      lock: els.optLock.checked,
      protocol: els.optProtocol.checked && !app.signedMode,
    });
    if (seq !== app.signSeq) {
      app.staleNotice = "The document or settings changed while signing. Sign again to get an up-to-date file.";
      return;
    }
    app.resultUrl = URL.createObjectURL(blob);
    els.download.href = app.resultUrl;
    els.download.download = signedName(pdfName);
    els.download.hidden = false;
  } catch (error) {
    if (seq !== app.signSeq) {
      app.staleNotice = "The document or settings changed while signing. Sign again to get an up-to-date file.";
      return;
    }
    if (docSeq === app.docSeq && error.code === "signed_document") {
      enterSignedMode();
      changed(); // the options changed: a deliberate second click is needed
      return;
    }
    if (docSeq === app.docSeq && (error.code === "locked_document" || error.code === "invalid_existing_signatures")) {
      app.blockedMessage = error.message; // kept until the document changes
      return;
    }
    showError(error.message);
  } finally {
    app.signing = false;
    render();
  }
}

function signedName(name) {
  const base = name.replace(/\.pdf$/i, "") || "document";
  return `${base}-signed.pdf`;
}

// --- Wiring --------------------------------------------------------------------------------------

els.pdfInput.addEventListener("change", () => {
  const file = els.pdfInput.files?.[0];
  els.pdfInput.value = "";
  openPdf(file);
});
els.emptyChoose.addEventListener("click", () => els.pdfInput.click());

els.viewer.addEventListener("dragover", (event) => {
  if ([...(event.dataTransfer?.types || [])].includes("Files")) {
    event.preventDefault();
    els.viewer.classList.add("dragging-file");
  }
});
els.viewer.addEventListener("dragleave", () => els.viewer.classList.remove("dragging-file"));
els.viewer.addEventListener("drop", (event) => {
  event.preventDefault();
  els.viewer.classList.remove("dragging-file");
  const file = [...(event.dataTransfer?.files || [])].find((f) => /\.pdf$/i.test(f.name) || f.type === "application/pdf");
  if (file) openPdf(file);
});

els.p12Input.addEventListener("change", () => {
  const file = els.p12Input.files?.[0] || null;
  els.p12Input.value = "";
  openP12(file);
});
els.password.addEventListener("input", certificateChanged);

els.addSignature.addEventListener("click", () => setPlacing(!app.placing));
els.placeCancel.addEventListener("click", () => setPlacing(false));

els.initialsOn.addEventListener("change", () => {
  state.initials.enabled = els.initialsOn.checked;
  if (!state.initials.enabled && state.selected?.kind === "initials") state.selected = null;
  changed();
});
els.initialsPages.addEventListener("change", () => {
  state.initials.preset = els.initialsPages.value;
  changed();
});
els.initialsCustom.addEventListener("input", () => {
  state.initials.custom = els.initialsCustom.value;
  changed();
});
els.initialsCorner.addEventListener("change", () => {
  state.initials.corner = els.initialsCorner.value;
  changed();
});
for (const [input, key] of [[els.initialsMx, "mx"], [els.initialsMy, "my"]]) {
  input.addEventListener("input", () => {
    const value = Number(input.value);
    state.initials[key] = input.value.trim() !== "" && Number.isFinite(value) ? value : NaN;
    changed();
  });
}
els.optLock.addEventListener("change", changed);
els.optProtocol.addEventListener("change", changed);
els.sign.addEventListener("click", sign);

// Fit to width follows the window size until the user picks a zoom level.
let autoFit = true;
els.zoomIn.addEventListener("click", () => zoomTo(viewer.scale * 1.2, false));
els.zoomOut.addEventListener("click", () => zoomTo(viewer.scale / 1.2, false));
els.zoomLabel.addEventListener("click", () => zoomTo(viewer.fitWidthScale(), true));

function zoomTo(scale, fit) {
  autoFit = fit;
  viewer.setScale(scale);
  render();
}

let lastWidth = els.viewer.clientWidth;
new ResizeObserver(() => {
  const width = els.viewer.clientWidth;
  if (width === lastWidth) return;
  lastWidth = width;
  if (autoFit && state.pageSizes.length) zoomTo(viewer.fitWidthScale(), true);
}).observe(els.viewer);

window.addEventListener("dragover", (event) => event.preventDefault());
window.addEventListener("drop", (event) => event.preventDefault());

render();
