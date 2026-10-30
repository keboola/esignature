// Calls to the local signing API. Every POST carries the per-launch token from index.html;
// the browser adds the Origin header, which the server checks too.

const TOKEN = document.querySelector('meta[name="esign-token"]').content;

export class ApiError extends Error {
  /** ``code`` is the server's machine-readable reason (e.g. "signed_document"), or null. */
  constructor(message, status, code = null) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function post(path, form) {
  let response;
  try {
    response = await fetch(path, {
      method: "POST",
      body: form,
      headers: { "X-ESign-Token": TOKEN },
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new ApiError("The eSignature app is not reachable. Is it still running?", 0);
  }
  if (!response.ok) {
    let message = `Request failed (${response.status}).`;
    let code = null;
    try {
      const body = await response.json();
      if (body && typeof body.error === "string") message = body.error;
      if (body && typeof body.code === "string") code = body.code;
    } catch {
      // Not JSON: keep the generic message.
    }
    throw new ApiError(message, response.status, code);
  }
  return response;
}

// Files are passed as {name, bytes} read once when chosen, never as File objects: a File is
// re-read from disk on upload, so its content could differ from what was previewed.
function part(file, type) {
  return [new Blob([file.bytes], { type }), file.name];
}

/** Returns {name, initials, organization, issuer, valid_from, valid_to}. */
export async function checkCertificate(p12, password) {
  const form = new FormData();
  form.append("p12", ...part(p12, "application/x-pkcs12"));
  form.append("password", password);
  return (await post("/api/certificate", form)).json();
}

/** Check signatures in the selected PDF without a signing certificate. */
export async function validateDocument(pdf) {
  const form = new FormData();
  form.append("pdf", ...part(pdf, "application/pdf"));
  return (await post("/api/validate", form)).json();
}

/** Returns the signed PDF as a Blob. */
export async function signDocument({ pdf, p12, password, placements, lock, protocol }) {
  const form = new FormData();
  form.append("pdf", ...part(pdf, "application/pdf"));
  form.append("p12", ...part(p12, "application/x-pkcs12"));
  form.append("password", password);
  form.append("placements", JSON.stringify(placements));
  form.append("lock", lock ? "true" : "false");
  form.append("protocol", protocol ? "true" : "false");
  return (await post("/api/sign", form)).blob();
}
