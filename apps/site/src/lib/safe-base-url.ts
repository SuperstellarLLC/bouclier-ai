/**
 * Validate and normalize a server URL before attaching a credential to it.
 *
 * Query strings, fragments, and embedded userinfo are forbidden so a copied
 * endpoint cannot silently redirect a bearer token into an unexpected URL
 * component. The returned value has trailing slashes removed, which keeps
 * command and `/pipeline` endpoint construction consistent.
 */
export function normalizeSafeHttpsBaseUrl(value: string): string | null {
  // URL.search/hash do not distinguish an empty `?`/`#`, so reject the raw
  // delimiters before parsing as well.
  if (value.includes("?") || value.includes("#")) return null;

  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || !url.hostname) return null;
    return url.href.replace(/\/+$/, "");
  } catch {
    return null;
  }
}
