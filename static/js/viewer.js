// Continuous-scroll PDF viewer on top of PDF.js 5.7.284 (official prebuilt dist, vendored and pinned
// under /static/vendor/pdfjs: pdf.mjs, pdf.worker.mjs, cmaps/, standard_fonts/, wasm/, iccs/).
//
// Pages are laid out as placeholders sized from their viewport at scale 1 (= PDF points as
// displayed, the same space PyMuPDF's page.rect uses), and canvases are rendered lazily:
// only pages near the visible area are rendered, at most MAX_CONCURRENT_RENDERS at a time;
// pages that scroll far away have their render cancelled and their canvas dropped.

import * as pdfjsLib from "/static/vendor/pdfjs/pdf.mjs";

const PDFJS_BASE = new URL("/static/vendor/pdfjs/", window.location.href).href;
pdfjsLib.GlobalWorkerOptions.workerSrc = `${PDFJS_BASE}pdf.worker.mjs`;

const MAX_CONCURRENT_RENDERS = 2;
const MAX_CANVAS_PIXELS = 16_000_000;
export const MIN_SCALE = 0.25;
export const MAX_SCALE = 4;

/** Signature widget rectangles of a page in displayed space at scale 1 (points, top-left origin). */
async function signatureWidgets(page, viewport) {
  let annotations = [];
  try {
    annotations = await page.getAnnotations({ intent: "display" });
  } catch {
    return []; // a broken annotation list only loses the hint and the overlap warning
  }
  const result = [];
  for (const annotation of annotations) {
    if (annotation.fieldType !== "Sig" || !Array.isArray(annotation.rect)) continue;
    const [x1, y1, x2, y2] = viewport.convertToViewportRectangle(annotation.rect);
    const x = Math.min(x1, x2);
    const y = Math.min(y1, y2);
    result.push({ x, y, w: Math.abs(x2 - x1), h: Math.abs(y2 - y1) });
  }
  return result;
}

export class Viewer {
  /**
   * @param {HTMLElement} scroller scrolling container
   * @param {HTMLElement} pagesEl element that receives one .page per PDF page
   */
  constructor(scroller, pagesEl) {
    this.scroller = scroller;
    this.pagesEl = pagesEl;
    this.doc = null;
    this.loadingTask = null;
    this.generation = 0;
    this.scale = 1;
    this.sizes = [];
    this.slots = [];
    this.queue = [];
    this.active = 0;
    this.observer = new IntersectionObserver((entries) => this.#onIntersect(entries), {
      root: scroller,
      rootMargin: "1200px 0px",
    });
  }

  /**
   * Opens a PDF; resolves to {sizes, signatureFields, signaturesHint}. Replaces any open document.
   * - sizes: page sizes in points as displayed;
   * - signatureFields: [{page, x, y, w, h}] rectangles of signature widgets in displayed space
   *   (PDF.js cannot tell filled from empty fields, so these are fields, not signatures);
   * - signaturesHint: the document's /SigFlags say signatures may be present (a hint only).
   * Generation-safe: a newer open() or close() supersedes this one, which then rejects with
   * "superseded" without touching the viewer.
   */
  async open(data) {
    const generation = this.#reset();
    const task = pdfjsLib.getDocument({
      data,
      cMapUrl: `${PDFJS_BASE}cmaps/`,
      cMapPacked: true,
      standardFontDataUrl: `${PDFJS_BASE}standard_fonts/`,
      wasmUrl: `${PDFJS_BASE}wasm/`,
      iccUrl: `${PDFJS_BASE}iccs/`,
      isEvalSupported: false,
      enableXfa: false,
    });
    this.loadingTask = task; // so a later reset can destroy it
    const superseded = () => generation !== this.generation;
    try {
      const doc = await task.promise;
      const sizes = [];
      const signatureFields = [];
      for (let i = 1; i <= doc.numPages && !superseded(); i += 1) {
        const page = await doc.getPage(i);
        const viewport = page.getViewport({ scale: 1 });
        sizes.push({ width: viewport.width, height: viewport.height });
        for (const field of await signatureWidgets(page, viewport)) signatureFields.push({ page: i - 1, ...field });
      }
      if (superseded()) throw new Error("superseded");
      const metadata = await doc.getMetadata().catch(() => null);
      if (superseded()) throw new Error("superseded");
      this.doc = doc;
      this.sizes = sizes;
      this.#buildSlots();
      return { sizes, signatureFields, signaturesHint: Boolean(metadata?.info?.IsSignaturesPresent) };
    } catch (error) {
      if (superseded()) {
        task.destroy();
        throw new Error("superseded");
      }
      throw error;
    }
  }

  close() {
    this.#reset();
  }

  /** Synchronously drops the current document and returns the new generation number. */
  #reset() {
    this.generation += 1;
    this.observer.disconnect();
    for (const slot of this.slots) slot.task?.cancel();
    this.slots = [];
    this.queue = [];
    this.pagesEl.replaceChildren();
    const task = this.loadingTask;
    this.loadingTask = null;
    this.doc = null;
    this.sizes = [];
    task?.destroy();
    return this.generation;
  }

  fitWidthScale() {
    if (!this.sizes.length) return 1;
    const widest = Math.max(...this.sizes.map((s) => s.width));
    const available = this.scroller.clientWidth - 64;
    return Math.min(Math.max(available / widest, MIN_SCALE), 2);
  }

  setScale(scale) {
    scale = Math.min(Math.max(scale, MIN_SCALE), MAX_SCALE);
    if (Math.abs(scale - this.scale) < 1e-6 && this.slots.length) return;
    const ratio = this.scroller.scrollHeight ? this.scroller.scrollTop / this.scroller.scrollHeight : 0;
    this.scale = scale;
    for (const slot of this.slots) {
      this.#sizeSlot(slot);
      slot.task?.cancel();
      slot.renderedScale = null;
    }
    this.scroller.scrollTop = ratio * this.scroller.scrollHeight;
    // Re-render pages that are currently near the viewport.
    this.queue = this.slots.filter((s) => s.near);
    this.#pump();
  }

  /** The overlay layer of a page; boxes inside it are positioned in CSS px = points * scale. */
  overlay(pageIndex) {
    return this.slots[pageIndex]?.overlay;
  }

  scrollToPage(pageIndex) {
    this.slots[pageIndex]?.el.scrollIntoView({ block: "start", behavior: "smooth" });
  }

  #buildSlots() {
    const fragment = document.createDocumentFragment();
    this.slots = this.sizes.map((size, index) => {
      const el = document.createElement("div");
      el.className = "page";
      el.dataset.pageIndex = String(index);
      el.setAttribute("aria-label", `Page ${index + 1}`);
      const canvas = document.createElement("canvas");
      canvas.className = "page-canvas";
      const overlay = document.createElement("div");
      overlay.className = "overlay";
      overlay.dataset.pageIndex = String(index);
      const label = document.createElement("div");
      label.className = "page-label";
      label.textContent = `${index + 1} / ${this.sizes.length}`;
      el.append(canvas, overlay, label);
      fragment.append(el);
      const slot = { index, size, el, canvas, overlay, task: null, renderedScale: null, near: false };
      this.#sizeSlot(slot);
      return slot;
    });
    this.pagesEl.append(fragment);
    for (const slot of this.slots) this.observer.observe(slot.el);
  }

  #sizeSlot(slot) {
    slot.el.style.width = `${slot.size.width * this.scale}px`;
    slot.el.style.height = `${slot.size.height * this.scale}px`;
    slot.el.style.setProperty("--s", String(this.scale));
  }

  #onIntersect(entries) {
    for (const entry of entries) {
      const slot = this.slots[Number(entry.target.dataset.pageIndex)];
      if (!slot || slot.el !== entry.target) continue;
      slot.near = entry.isIntersecting;
      if (slot.near) {
        if (slot.renderedScale !== this.scale && !this.queue.includes(slot)) this.queue.push(slot);
      } else {
        // Far away: cancel any render in progress and free the canvas memory.
        this.queue = this.queue.filter((s) => s !== slot);
        slot.task?.cancel();
        slot.canvas.width = 0;
        slot.canvas.height = 0;
        slot.renderedScale = null;
        delete slot.el.dataset.rendered;
      }
    }
    this.#pump();
  }

  #pump() {
    while (this.active < MAX_CONCURRENT_RENDERS && this.queue.length) {
      const slot = this.queue.shift();
      if (!slot.near || slot.renderedScale === this.scale) continue;
      this.active += 1;
      this.#render(slot).finally(() => {
        this.active -= 1;
        this.#pump();
      });
    }
  }

  async #render(slot) {
    const generation = this.generation;
    const scale = this.scale;
    try {
      const page = await this.doc.getPage(slot.index + 1);
      if (generation !== this.generation || !slot.near || scale !== this.scale) return;
      const dpr = window.devicePixelRatio || 1;
      let outputScale = dpr;
      const viewport = page.getViewport({ scale });
      const pixels = viewport.width * viewport.height * dpr * dpr;
      if (pixels > MAX_CANVAS_PIXELS) outputScale = Math.sqrt(MAX_CANVAS_PIXELS / (viewport.width * viewport.height));
      // Render into an offscreen canvas and swap, so the old bitmap stays visible meanwhile.
      const canvas = document.createElement("canvas");
      canvas.className = "page-canvas";
      canvas.width = Math.floor(viewport.width * outputScale);
      canvas.height = Math.floor(viewport.height * outputScale);
      slot.task = page.render({
        canvas,
        viewport,
        transform: outputScale !== 1 ? [outputScale, 0, 0, outputScale, 0, 0] : null,
        annotationMode: pdfjsLib.AnnotationMode.ENABLE,
      });
      await slot.task.promise;
      slot.task = null;
      if (generation !== this.generation || scale !== this.scale || !slot.near) return;
      slot.canvas.replaceWith(canvas);
      slot.canvas = canvas;
      slot.renderedScale = scale;
      slot.el.dataset.rendered = "true";
    } catch (error) {
      slot.task = null;
      if (error?.name !== "RenderingCancelledException" && generation === this.generation) {
        console.error("Page render failed", error);
      }
    }
  }
}
