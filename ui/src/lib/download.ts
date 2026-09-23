/** Hand a fetched file to the browser: the name the server gave it in
 * `Content-Disposition`, else `fallbackName`. */
export async function saveResponse(res: Response, fallbackName: string): Promise<void> {
  const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") ?? "")?.[1] ?? fallbackName;
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
