#include "tls_certs.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The two canonical search locations, in resolution order. The first
 * matches Kubernetes cert-manager: a kubernetes.io/tls Secret
 * (e.g. wfl-www-tls) mounted as a volume at /certs. The second is
 * the cwd-relative mirror so a local developer can replicate the
 * pod's filesystem layout with one mkdir. */
static const char* const CERT_PAIRS[][2] = {
    { "/certs/tls.crt",   "/certs/tls.key"   },
    { "./certs/tls.crt",  "./certs/tls.key"  },
};
static const size_t CERT_PAIRS_N = sizeof(CERT_PAIRS) / sizeof(CERT_PAIRS[0]);

static int both_readable(const char* a, const char* b) {
    return access(a, R_OK) == 0 && access(b, R_OK) == 0;
}

static int copy_path(char* dst, size_t cap, const char* src) {
    size_t n = strlen(src);
    if (n + 1 > cap) return -1;
    memcpy(dst, src, n + 1);
    return 0;
}

int picoweb_tls_locate_certs(const char* cli_cert, const char* cli_key,
                             char* cert_out, char* key_out, size_t cap,
                             void* errstream) {
    FILE* err = errstream ? (FILE*)errstream : stderr;

    if (!cert_out || !key_out || cap == 0) return -1;
    cert_out[0] = '\0';
    key_out[0]  = '\0';

    /* Step 1: CLI flags. Both-or-neither — partial config almost
     * always indicates a typo in a deployment manifest. */
    int have_cli_cert = cli_cert && cli_cert[0];
    int have_cli_key  = cli_key  && cli_key[0];
    if (have_cli_cert ^ have_cli_key) {
        fprintf(err,
            "picoweb: --tls-cert and --tls-key must be specified together "
            "(got --tls-cert=%s --tls-key=%s)\n",
            have_cli_cert ? cli_cert : "<unset>",
            have_cli_key  ? cli_key  : "<unset>");
        return -1;
    }
    if (have_cli_cert && have_cli_key) {
        if (!both_readable(cli_cert, cli_key)) {
            fprintf(err,
                "picoweb: --tls-cert=%s and/or --tls-key=%s not readable\n",
                cli_cert, cli_key);
            return -1;
        }
        if (copy_path(cert_out, cap, cli_cert) != 0 ||
            copy_path(key_out,  cap, cli_key)  != 0) {
            fprintf(err, "picoweb: cert path too long for buffer (cap=%zu)\n", cap);
            return -1;
        }
        return 0;
    }

    /* Step 2 + 3: filesystem search. */
    for (size_t i = 0; i < CERT_PAIRS_N; i++) {
        const char* c = CERT_PAIRS[i][0];
        const char* k = CERT_PAIRS[i][1];
        if (both_readable(c, k)) {
            if (copy_path(cert_out, cap, c) != 0 ||
                copy_path(key_out,  cap, k) != 0) {
                fprintf(err, "picoweb: cert path too long for buffer (cap=%zu)\n", cap);
                return -1;
            }
            return 0;
        }
    }

    /* Step 4: nothing found — report exactly what was tried. */
    fprintf(err,
        "picoweb: --tls requires a certificate. Searched (in order):\n"
        "  --tls-cert / --tls-key (not given)\n");
    for (size_t i = 0; i < CERT_PAIRS_N; i++) {
        fprintf(err, "  %s + %s (not present)\n",
                CERT_PAIRS[i][0], CERT_PAIRS[i][1]);
    }
    return -1;
}
