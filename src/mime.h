#ifndef METAL_MIME_H
#define METAL_MIME_H

#include <stddef.h>
#include <stdbool.h>

const char* mime_lookup(const char* filename, size_t len);

/* True for text-y MIME types where pre-compression is worthwhile.
 * Covers text/x, application/json, application/javascript,
 * application/xml, image/svg+xml. */
bool mime_is_compressible(const char* mime);

#endif
