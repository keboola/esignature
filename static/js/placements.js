// Placement state in displayed page space (PDF points, top-left origin, /Rotate applied).
// This is the server's placement contract: {page (0-based), type, x, y} = top-left corner of the box.

export const BOX = {
  signature: { w: 150, h: 50 },
  initials: { w: 50, h: 35 },
};

let nextId = 1;

export function createState() {
  return {
    pageSizes: [], // [{width, height}] per page, in points as displayed
    signatures: [], // [{id, page, x, y}]
    initials: { enabled: false, preset: "all", custom: "", corner: "br", mx: 20, my: 20 },
    selected: null, // {kind: "signature", id} | {kind: "initials", page}
  };
}

export function clamp(value, min, max) {
  return Math.min(Math.max(value, min), Math.max(min, max));
}

/** Clamp a box's top-left corner so the whole box stays on the page. */
export function clampToPage(size, kind, x, y) {
  const box = BOX[kind];
  return { x: clamp(x, 0, size.width - box.w), y: clamp(y, 0, size.height - box.h) };
}

export function addSignature(state, page, centerX, centerY) {
  const box = BOX.signature;
  const pos = clampToPage(state.pageSizes[page], "signature", centerX - box.w / 2, centerY - box.h / 2);
  const signature = { id: nextId++, page, ...pos };
  state.signatures.push(signature);
  return signature;
}

export function removeSignature(state, id) {
  state.signatures = state.signatures.filter((s) => s.id !== id);
}

/**
 * Pages (0-based) the initials should go on, from the preset.
 * Returns {pages, error}; "all except last" means the last ORIGINAL page (no protocol page).
 */
export function initialsPages(state) {
  const count = state.pageSizes.length;
  const spec = state.initials;
  if (spec.preset === "all") return { pages: [...Array(count).keys()], error: null };
  if (spec.preset === "all-but-last") return { pages: [...Array(Math.max(count - 1, 0)).keys()], error: null };

  const pages = new Set();
  const text = spec.custom.trim();
  if (!text) return { pages: [], error: "Enter page numbers, for example 1-3, 5." };
  for (const part of text.split(",")) {
    const token = part.trim();
    if (!token) continue;
    const match = /^(\d+)(?:\s*-\s*(\d+))?$/.exec(token);
    if (!match) return { pages: [], error: `"${token}" is not a page number or range.` };
    const from = Number(match[1]);
    const to = match[2] === undefined ? from : Number(match[2]);
    if (from < 1 || to < from || to > count) {
      return { pages: [], error: `Pages must be between 1 and ${count} (got "${token}").` };
    }
    for (let p = from; p <= to; p += 1) pages.add(p - 1);
  }
  return { pages: [...pages].sort((a, b) => a - b), error: null };
}

/** Top-left corner of the shared initials mark on a page of the given size. */
export function initialsPosition(size, spec) {
  const box = BOX.initials;
  const x = spec.corner === "bl" ? spec.mx : size.width - spec.mx - box.w;
  return { x, y: size.height - spec.my - box.h };
}

/** Margins from the chosen corner that put the initials box at (x, y) on a page of this size. */
export function initialsMargins(size, spec, x, y) {
  const box = BOX.initials;
  return {
    mx: spec.corner === "bl" ? x : size.width - x - box.w,
    my: size.height - y - box.h,
  };
}

function fits(size, kind, pos) {
  const box = BOX[kind];
  const eps = 0.005;
  return pos.x >= -eps && pos.y >= -eps && pos.x + box.w <= size.width + eps && pos.y + box.h <= size.height + eps;
}

/** Initials instances: [{page, x, y}] that fit, plus the 0-based pages where the mark does not fit. */
export function initialsInstances(state) {
  if (!state.initials.enabled || !state.pageSizes.length) return { instances: [], misfit: [], error: null };
  const { pages, error } = initialsPages(state);
  const instances = [];
  const misfit = [];
  for (const page of pages) {
    const pos = initialsPosition(state.pageSizes[page], state.initials);
    if (Number.isFinite(pos.x) && Number.isFinite(pos.y) && fits(state.pageSizes[page], "initials", pos)) {
      instances.push({ page, ...pos });
    } else {
      misfit.push(page);
    }
  }
  return { instances, misfit, error };
}

/** The placements sent to the server. */
export function placementsPayload(state) {
  const result = state.signatures.map((s) => ({ page: s.page, type: "signature", x: s.x, y: s.y }));
  for (const inst of initialsInstances(state).instances) {
    result.push({ page: inst.page, type: "initials", x: inst.x, y: inst.y });
  }
  return result;
}

/** "1-3, 5" from 0-based pages. */
export function formatPages(pages) {
  const sorted = [...pages].sort((a, b) => a - b).map((p) => p + 1);
  const parts = [];
  let start = null;
  let prev = null;
  for (const p of sorted) {
    if (start === null) {
      start = prev = p;
    } else if (p === prev + 1) {
      prev = p;
    } else {
      parts.push(start === prev ? `${start}` : `${start}-${prev}`);
      start = prev = p;
    }
  }
  if (start !== null) parts.push(start === prev ? `${start}` : `${start}-${prev}`);
  return parts.join(", ");
}
