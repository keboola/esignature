// Calls to the local signing API. Every POST carries the per-launch token from index.html;
// the browser adds the Origin header, which the server checks too.

const TOKEN = document.querySelector('meta[name="esign-token"]').content;

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
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
    try {
      const body = await response.json();
      if (body && typeof body.error === "string") message = body.error;
    } catch {
      // Not JSON: keep the generic message.
    }
    throw new ApiError(message, response.status);
  }
  return response;
}

/** Returns {name, initials, organization, issuer, valid_from, valid_to}. */
export async function checkCertificate(p12File, password) {
  const form = new FormData();
  form.append("p12", p12File);
  form.append("password", password);
  return (await post("/api/certificate", form)).json();
}

/** Returns the signed PDF as a Blob. */
export async function signDocument({ pdfFile, p12File, password, placements, lock, protocol }) {
  const form = new FormData();
  form.append("pdf", pdfFile);
  form.append("p12", p12File);
  form.append("password", password);
  form.append("placements", JSON.stringify(placements));
  form.append("lock", lock ? "true" : "false");
  form.append("protocol", protocol ? "true" : "false");
  return (await post("/api/sign", form)).blob();
}
