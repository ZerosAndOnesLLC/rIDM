/** How long a handed-over file's object URL is kept: WebKit starts the
 * download after `click()` returns, and revoking the URL at once can cancel
 * it. */
const REVOKE_AFTER_MS = 60_000;

/** Hand a fetched file to the browser: the name the server gave it in
 * `Content-Disposition`, else `fallbackName`. */
export async function saveResponse(res: Response, fallbackName: string): Promise<void> {
  const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") ?? "")?.[1] ?? fallbackName;
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  // Some engines only follow a click on a link that is in the document.
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), REVOKE_AFTER_MS);
}
