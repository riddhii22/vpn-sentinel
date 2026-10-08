/** Page-relative URL so the UI works behind a path-prefixed preview proxy. */
export function appUrl(rel: string): string {
  const origin = window.location.origin
  const dir = window.location.pathname.replace(/[^/]*$/, '') || '/'
  return new URL(rel.replace(/^\//, ''), `${origin}${dir}`).toString()
}
