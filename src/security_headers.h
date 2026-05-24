#ifndef PICOWEB_SECURITY_HEADERS_H
#define PICOWEB_SECURITY_HEADERS_H

#define PICOWEB_SECURITY_HEADERS \
    "X-Content-Type-Options: nosniff\r\n" \
    "X-Frame-Options: DENY\r\n" \
    "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n" \
    "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'\r\n" \
    "Referrer-Policy: strict-origin-when-cross-origin\r\n" \
    "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()\r\n"

#endif
