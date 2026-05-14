#ifndef PICOWEB_PRELOAD_H
#define PICOWEB_PRELOAD_H

#include <stddef.h>

/* preload.h — extract HTTP "Link: rel=preload" / "rel=preconnect" /
 * "rel=modulepreload" header lines from a body of HTML, suitable for
 * emission inside an HTTP/1.1 103 Early Hints interim response and/or
 * the final 200 response.
 *
 * Same-origin subresources become rel=preload with an `as=` derived
 * from the source tag/rel. Cross-origin URLs are downgraded to
 * rel=preconnect (only the origin is emitted) so we don't speculatively
 * fetch arbitrary third-party bytes. <link rel="modulepreload"> is
 * preserved verbatim. <link rel="canonical|manifest|icon|dns-prefetch">
 * is skipped. URLs containing CR/LF/control chars are skipped.
 *
 * Output is a sequence of "Link: <value>\r\n" lines (no trailing blank
 * line; caller appends one in the final HTTP response framing). Output
 * is deduplicated on the tuple (url, rel, as, crossorigin, type, media)
 * and capped at PW_PRELOAD_HEADER_CAP bytes; if hints would exceed the
 * cap, lower-priority categories (image < font < script < style) are
 * dropped first.
 *
 * Returns the number of bytes written to `out` (0 if no preloadable
 * subresources were found, or `out_cap` is insufficient for even one
 * entry). The output is NOT NUL-terminated.
 */
#define PW_PRELOAD_HEADER_CAP 4096

size_t pw_preload_extract(const char* html, size_t html_len,
                          const char* host, size_t host_len,
                          char* out, size_t out_cap);

#endif
