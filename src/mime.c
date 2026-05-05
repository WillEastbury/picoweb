#include "mime.h"
#include "util.h"

#include <string.h>

static const struct { const char* ext; const char* mime; } kTable[] = {
    { "html", "text/html; charset=utf-8" },
    { "htm",  "text/html; charset=utf-8" },
    { "css",  "text/css; charset=utf-8" },
    { "js",   "application/javascript; charset=utf-8" },
    { "mjs",  "application/javascript; charset=utf-8" },
    { "json", "application/json; charset=utf-8" },
    { "xml",  "application/xml; charset=utf-8" },
    { "txt",  "text/plain; charset=utf-8" },
    { "md",   "text/markdown; charset=utf-8" },
    { "csv",  "text/csv; charset=utf-8" },
    { "png",  "image/png" },
    { "jpg",  "image/jpeg" },
    { "jpeg", "image/jpeg" },
    { "gif",  "image/gif" },
    { "webp", "image/webp" },
    { "svg",  "image/svg+xml" },
    { "ico",  "image/x-icon" },
    { "bmp",  "image/bmp" },
    { "avif", "image/avif" },
    { "woff", "font/woff" },
    { "woff2","font/woff2" },
    { "ttf",  "font/ttf" },
    { "otf",  "font/otf" },
    { "eot",  "application/vnd.ms-fontobject" },
    { "mp3",  "audio/mpeg" },
    { "wav",  "audio/wav" },
    { "ogg",  "audio/ogg" },
    { "mp4",  "video/mp4" },
    { "webm", "video/webm" },
    { "mov",  "video/quicktime" },
    { "pdf",  "application/pdf" },
    { "zip",  "application/zip" },
    { "gz",   "application/gzip" },
    { "tar",  "application/x-tar" },
    { "7z",   "application/x-7z-compressed" },
    { "wasm", "application/wasm" },
    { "map",  "application/json; charset=utf-8" },
    { "manifest", "text/cache-manifest" },
    { "appcache", "text/cache-manifest" },
};

static const char* kDefault = "application/octet-stream";

const char* mime_lookup(const char* filename, size_t len) {
    if (!filename || len == 0) return kDefault;
    size_t i = len;
    while (i > 0 && filename[i - 1] != '.') i--;
    if (i == 0) return kDefault;
    const char* ext = filename + i;
    size_t ext_len = len - i;
    if (ext_len == 0 || ext_len > 16) return kDefault;
    for (size_t k = 0; k < sizeof(kTable) / sizeof(kTable[0]); k++) {
        size_t kl = strlen(kTable[k].ext);
        if (metal_ieq(ext, ext_len, kTable[k].ext, kl)) return kTable[k].mime;
    }
    return kDefault;
}

bool mime_is_compressible(const char* mime) {
    if (!mime) return false;
    /* text/anything */
    if (strncmp(mime, "text/", 5) == 0) return true;
    /* application/{json,javascript,xml} (with or without ;charset=...) */
    if (strncmp(mime, "application/json", 16) == 0) return true;
    if (strncmp(mime, "application/javascript", 22) == 0) return true;
    if (strncmp(mime, "application/xml", 15) == 0) return true;
    /* SVG: technically image/x but it's XML on the wire — compresses well. */
    if (strncmp(mime, "image/svg+xml", 13) == 0) return true;
    return false;
}
