/* api.c — simple JSON-file CRUD for picoweb. See api.h for protocol. */

#include "api.h"
#include "picowal_api.h"
#include "picowal_db.h"
#include "picowal_query.h"
#include "picowal_validate.h"
#include "../userspace/crypto/hmac.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ----- module config (set once in api_init, read from any worker) ----- */

static char   g_root[512]    = {0};
static size_t g_root_len     = 0;
static int    g_root_fd      = -1;
static char   g_prefix[64]   = {0};
static size_t g_prefix_len   = 0;
static bool   g_enabled      = false;
static picowal_db_t* g_picowal = NULL;
static bool   g_picowal_enabled = false;
static bool   g_picowal_public_http = false;
static char   g_picowal_prefix[64] = {0};
static size_t g_picowal_prefix_len = 0;

#define SCORE_CARD_ID             42u
#define SCORE_TOKEN_TTL_SEC       900
#define SCORE_NONCES_MAX          4096
#define SCORE_RATE_BUCKETS        256
#define SCORE_RATE_CAPACITY       12
#define SCORE_RATE_REFILL_PER_SEC 0.2

typedef struct {
    bool used;
    bool consumed;
    int64_t exp_unix;
    uint8_t nonce[16];
} score_nonce_t;

typedef struct {
    bool used;
    char key[64];
    double tokens;
    int64_t last_unix;
} score_rate_bucket_t;

static pthread_mutex_t g_score_mu = PTHREAD_MUTEX_INITIALIZER;
static uint8_t g_score_secret[32];
static bool g_score_secret_ready = false;
static score_nonce_t g_score_nonces[SCORE_NONCES_MAX];
static score_rate_bucket_t g_score_rate[SCORE_RATE_BUCKETS];

#define AUTH_COOKIE_NAME       "pw_session"
#define AUTH_COOKIE_VALUE_CAP  64
#define AUTH_SUB_CAP           128
#define AUTH_PROVIDER_CAP      16
#define AUTH_SESSIONS_MAX      2048

typedef struct {
    bool used;
    int64_t exp_unix;
    char sid[AUTH_COOKIE_VALUE_CAP + 1];
    char sub[AUTH_SUB_CAP + 1];
    char provider[AUTH_PROVIDER_CAP];
} auth_session_t;

static bool     g_oidc_cookie_auth = false;
static uint32_t g_oidc_cookie_ttl_sec = 900;
static char     g_oidc_google_client_id[256] = {0};
static char     g_oidc_entra_client_id[256] = {0};
static char     g_oidc_entra_tenant[128] = {0};
static pthread_mutex_t g_auth_mu = PTHREAD_MUTEX_INITIALIZER;
static auth_session_t  g_auth_sessions[AUTH_SESSIONS_MAX];

static void resp_status_only(api_resp_t* r, int status, const char* reason);

bool api_enabled(void)              { return g_enabled; }
bool api_picowal_enabled(void)      { return g_picowal_enabled; }
size_t api_max_request_body(void)   { return API_REQ_BODY_CAP; }

bool api_health_path_matches(const char* path, size_t path_len) {
    return path &&
           ((path_len == 8 && memcmp(path, "/healthz", 8) == 0) ||
            (path_len == 7 && memcmp(path, "/readyz", 7) == 0));
}

static const char* public_api_prefix(size_t* out_len) {
    if (g_enabled && g_prefix_len > 0) {
        if (out_len) *out_len = g_prefix_len;
        return g_prefix;
    }
    if (out_len) *out_len = 5;
    return "/api/";
}

static bool score_path_matches(const char* path, size_t path_len) {
    size_t prefix_len = 0;
    const char* prefix = public_api_prefix(&prefix_len);
    return g_picowal_enabled &&
           path_len >= prefix_len + 6 &&
           memcmp(path, prefix, prefix_len) == 0 &&
           memcmp(path + prefix_len, "scores", 6) == 0 &&
           (path_len == prefix_len + 6 ||
            (path_len == prefix_len + 12 &&
             memcmp(path + prefix_len + 6, "/start", 6) == 0));
}

static bool valid_prefix(const char* prefix, size_t cap, const char* label) {
    size_t pl = prefix ? strlen(prefix) : 0;
    if (pl < 2 || pl >= cap) {
        fprintf(stderr, "api: invalid --%s (must be 2..%zu chars, start and end with '/')\n",
                label, cap - 1);
        return false;
    }
    if (prefix[0] != '/' || prefix[pl - 1] != '/') {
        fprintf(stderr, "api: invalid --%s '%s' (must start and end with '/')\n",
                label, prefix);
        return false;
    }
    return true;
}

bool api_path_matches(const char* path, size_t path_len) {
    if (!path) return false;
    if (api_health_path_matches(path, path_len)) return true;
    if (g_enabled &&
        path_len >= g_prefix_len &&
        memcmp(path, g_prefix, g_prefix_len) == 0) return true;
    if (score_path_matches(path, path_len)) return true;
    if (g_picowal_enabled && g_picowal_public_http &&
        path_len >= g_picowal_prefix_len &&
        memcmp(path, g_picowal_prefix, g_picowal_prefix_len) == 0) return true;
    return false;
}

void api_init(const char* root_dir, const char* prefix) {
    if (g_root_fd >= 0) {
        close(g_root_fd);
        g_root_fd = -1;
    }
    g_enabled = false;
    if (!root_dir || !root_dir[0] || !prefix || !prefix[0]) return;

    size_t pl = strlen(prefix);
    if (!valid_prefix(prefix, sizeof(g_prefix), "api-prefix")) return;
    size_t rl = strlen(root_dir);
    if (rl >= sizeof(g_root) - 1) {
        fprintf(stderr, "api: --api-root path too long (%zu >= %zu)\n", rl, sizeof(g_root));
        return;
    }

    bool created_root = false;
    if (mkdir(root_dir, 0700) == 0) {
        created_root = true;
    } else if (errno != EEXIST) {
        fprintf(stderr, "api: cannot create --api-root '%s': %s\n", root_dir, strerror(errno));
        return;
    }

    int root_fd = open(root_dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (root_fd < 0) {
        fprintf(stderr, "api: cannot open --api-root '%s': %s\n", root_dir, strerror(errno));
        return;
    }
    struct stat st;
    if (fstat(root_fd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        close(root_fd);
        fprintf(stderr, "api: --api-root '%s' is not a directory\n", root_dir);
        return;
    }
    if (created_root && fchmod(root_fd, 0700) != 0) {
        close(root_fd);
        fprintf(stderr, "api: cannot set permissions on --api-root '%s': %s\n",
                root_dir, strerror(errno));
        return;
    }

    memcpy(g_root, root_dir, rl);
    g_root[rl] = '\0';
    /* trim trailing slash so we always join with a single "/" */
    while (rl > 1 && g_root[rl - 1] == '/') { g_root[--rl] = '\0'; }
    g_root_len = rl;

    memcpy(g_prefix, prefix, pl);
    g_prefix[pl] = '\0';
    g_prefix_len = pl;
    g_root_fd = root_fd;
    g_enabled = true;
}

bool api_picowal_init(const char* device_path, uint64_t volume_bytes,
                      const char* prefix, bool format) {
    if (!device_path || !device_path[0]) {
        fprintf(stderr, "api: --picowal-device requires a non-empty path\n");
        return false;
    }
    if (!prefix || !prefix[0] ||
        !valid_prefix(prefix, sizeof(g_picowal_prefix), "picowal-prefix")) {
        return false;
    }

    if (!g_picowal) {
        g_picowal = picowal_db_create();
        if (!g_picowal) {
            fprintf(stderr, "api: picowal init failed: out of memory\n");
            return false;
        }
    }
    if (!picowal_db_open(g_picowal, device_path, volume_bytes, format)) {
        fprintf(stderr, "api: picowal open failed for '%s': %s\n",
                device_path, strerror(errno));
        return false;
    }
    size_t pl = strlen(prefix);
    memcpy(g_picowal_prefix, prefix, pl + 1);
    g_picowal_prefix_len = pl;
    g_picowal_enabled = true;
    return true;
}

void api_picowal_set_public(bool public_routes) {
    g_picowal_public_http = public_routes;
}

bool api_picowal_quiesce(void) {
    return g_picowal_enabled && g_picowal && picowal_db_quiesce(g_picowal);
}

void api_picowal_resume(void) {
    if (g_picowal_enabled && g_picowal) picowal_db_resume(g_picowal);
}

bool api_picowal_is_quiesced(void) {
    return g_picowal_enabled && g_picowal && picowal_db_is_quiesced(g_picowal);
}

bool api_oidc_init(bool cookie_auth_enabled, uint32_t cookie_ttl_sec,
                   const char* google_client_id,
                   const char* entra_client_id,
                   const char* entra_tenant) {
    g_oidc_cookie_auth = cookie_auth_enabled;
    if (cookie_ttl_sec > 0) g_oidc_cookie_ttl_sec = cookie_ttl_sec;

    g_oidc_google_client_id[0] = '\0';
    g_oidc_entra_client_id[0] = '\0';
    g_oidc_entra_tenant[0] = '\0';

    if (google_client_id && google_client_id[0]) {
        size_t n = strlen(google_client_id);
        if (n >= sizeof(g_oidc_google_client_id)) {
            fprintf(stderr, "api: --oidc-google-client-id too long\n");
            return false;
        }
        memcpy(g_oidc_google_client_id, google_client_id, n + 1);
    }
    if (entra_client_id && entra_client_id[0]) {
        size_t n = strlen(entra_client_id);
        if (n >= sizeof(g_oidc_entra_client_id)) {
            fprintf(stderr, "api: --oidc-entra-client-id too long\n");
            return false;
        }
        memcpy(g_oidc_entra_client_id, entra_client_id, n + 1);
    }
    if (entra_tenant && entra_tenant[0]) {
        size_t n = strlen(entra_tenant);
        if (n >= sizeof(g_oidc_entra_tenant)) {
            fprintf(stderr, "api: --oidc-entra-tenant too long\n");
            return false;
        }
        memcpy(g_oidc_entra_tenant, entra_tenant, n + 1);
    }

    if (g_oidc_cookie_auth) {
        if (!g_oidc_google_client_id[0] || !g_oidc_entra_client_id[0]) {
            fprintf(stderr, "api: OIDC cookie auth requires both Google and Entra client ids\n");
            return false;
        }
    }
    return true;
}

static int64_t now_unix_sec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec;
}

static bool gen_session_id_hex(char out[AUTH_COOKIE_VALUE_CAP + 1]) {
    uint8_t raw[AUTH_COOKIE_VALUE_CAP / 2];
    size_t got = 0;
    while (got < sizeof(raw)) {
        ssize_t r = getrandom(raw + got, sizeof(raw) - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        got += (size_t)r;
    }
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(raw); i++) {
        out[i * 2] = hex[(raw[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[raw[i] & 0xF];
    }
    out[AUTH_COOKIE_VALUE_CAP] = '\0';
    return true;
}

static bool fill_random(uint8_t* out, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t r = getrandom(out + got, len - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        got += (size_t)r;
    }
    return true;
}

static void hex_encode(const uint8_t* in, size_t len, char* out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[in[i] & 0xF];
    }
    out[len * 2] = '\0';
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hex_decode(const char* in, size_t len, uint8_t* out, size_t out_len) {
    if (len != out_len * 2) return false;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_val(in[i * 2]);
        int lo = hex_val(in[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool score_secret_ready(void) {
    if (g_score_secret_ready) return true;
    pthread_mutex_lock(&g_score_mu);
    if (!g_score_secret_ready) {
        g_score_secret_ready = fill_random(g_score_secret, sizeof(g_score_secret));
    }
    bool ok = g_score_secret_ready;
    pthread_mutex_unlock(&g_score_mu);
    return ok;
}

static bool constant_time_eq(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static uint32_t rate_hash(const char* s) {
    uint32_t h = 2166136261u;
    if (!s || !s[0]) s = "unknown";
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 16777619u;
    }
    return h;
}

static bool score_rate_allow(const api_request_context_t* ctx, const char* suffix,
                             int64_t now_sec) {
    char key[64];
    const char* ip = (ctx && ctx->client_ip[0]) ? ctx->client_ip : "unknown";
    snprintf(key, sizeof(key), "%s:%s", ip, suffix);
    uint32_t start = rate_hash(key) % SCORE_RATE_BUCKETS;
    pthread_mutex_lock(&g_score_mu);
    score_rate_bucket_t* chosen = NULL;
    for (uint32_t i = 0; i < SCORE_RATE_BUCKETS; i++) {
        score_rate_bucket_t* b = &g_score_rate[(start + i) % SCORE_RATE_BUCKETS];
        if (!b->used || strcmp(b->key, key) == 0) {
            chosen = b;
            break;
        }
    }
    if (!chosen) chosen = &g_score_rate[start];
    if (!chosen->used || strcmp(chosen->key, key) != 0) {
        memset(chosen, 0, sizeof(*chosen));
        chosen->used = true;
        snprintf(chosen->key, sizeof(chosen->key), "%s", key);
        chosen->tokens = SCORE_RATE_CAPACITY;
        chosen->last_unix = now_sec;
    }
    int64_t elapsed = now_sec - chosen->last_unix;
    if (elapsed > 0) {
        chosen->tokens += (double)elapsed * SCORE_RATE_REFILL_PER_SEC;
        if (chosen->tokens > SCORE_RATE_CAPACITY) chosen->tokens = SCORE_RATE_CAPACITY;
        chosen->last_unix = now_sec;
    }
    bool ok = chosen->tokens >= 1.0;
    if (ok) chosen->tokens -= 1.0;
    pthread_mutex_unlock(&g_score_mu);
    return ok;
}

static void auth_prune_locked(int64_t now_sec) {
    for (size_t i = 0; i < AUTH_SESSIONS_MAX; i++) {
        if (g_auth_sessions[i].used && g_auth_sessions[i].exp_unix <= now_sec) {
            memset(&g_auth_sessions[i], 0, sizeof(g_auth_sessions[i]));
        }
    }
}

static int auth_find_locked(const char* sid) {
    for (size_t i = 0; i < AUTH_SESSIONS_MAX; i++) {
        if (g_auth_sessions[i].used &&
            memcmp(g_auth_sessions[i].sid, sid, AUTH_COOKIE_VALUE_CAP) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static bool auth_create_session(const char* provider, const char* sub,
                                char out_sid[AUTH_COOKIE_VALUE_CAP + 1]) {
    if (!provider || !provider[0] || !sub || !sub[0]) return false;
    if (!gen_session_id_hex(out_sid)) return false;

    int64_t now_sec = now_unix_sec();
    int64_t exp = now_sec + (int64_t)g_oidc_cookie_ttl_sec;

    pthread_mutex_lock(&g_auth_mu);
    auth_prune_locked(now_sec);
    int slot = -1;
    for (size_t i = 0; i < AUTH_SESSIONS_MAX; i++) {
        if (!g_auth_sessions[i].used) {
            slot = (int)i;
            break;
        }
    }
    if (slot < 0) slot = 0;

    memset(&g_auth_sessions[slot], 0, sizeof(g_auth_sessions[slot]));
    g_auth_sessions[slot].used = true;
    g_auth_sessions[slot].exp_unix = exp;
    memcpy(g_auth_sessions[slot].sid, out_sid, AUTH_COOKIE_VALUE_CAP + 1);
    snprintf(g_auth_sessions[slot].provider, sizeof(g_auth_sessions[slot].provider), "%s", provider);
    snprintf(g_auth_sessions[slot].sub, sizeof(g_auth_sessions[slot].sub), "%s", sub);
    pthread_mutex_unlock(&g_auth_mu);
    return true;
}

static void auth_revoke_session(const char* sid) {
    if (!sid || !sid[0]) return;
    pthread_mutex_lock(&g_auth_mu);
    int idx = auth_find_locked(sid);
    if (idx >= 0) memset(&g_auth_sessions[idx], 0, sizeof(g_auth_sessions[idx]));
    pthread_mutex_unlock(&g_auth_mu);
}

static bool auth_is_valid_session(const char* sid) {
    if (!sid || strlen(sid) != AUTH_COOKIE_VALUE_CAP) return false;
    int64_t now_sec = now_unix_sec();
    bool ok = false;
    pthread_mutex_lock(&g_auth_mu);
    auth_prune_locked(now_sec);
    int idx = auth_find_locked(sid);
    if (idx >= 0 && g_auth_sessions[idx].exp_unix > now_sec) ok = true;
    pthread_mutex_unlock(&g_auth_mu);
    return ok;
}

static bool auth_session_sub_from_sid(const char* sid, char* out, size_t out_cap) {
    if (!sid || !out || out_cap < 2 || strlen(sid) != AUTH_COOKIE_VALUE_CAP) return false;
    int64_t now_sec = now_unix_sec();
    bool ok = false;
    pthread_mutex_lock(&g_auth_mu);
    auth_prune_locked(now_sec);
    int idx = auth_find_locked(sid);
    if (idx >= 0 && g_auth_sessions[idx].exp_unix > now_sec) {
        snprintf(out, out_cap, "%s", g_auth_sessions[idx].sub);
        ok = true;
    }
    pthread_mutex_unlock(&g_auth_mu);
    return ok;
}

static bool cookie_extract(const char* cookie, size_t cookie_len,
                           const char* name, char* out, size_t out_cap) {
    if (!cookie || cookie_len == 0 || !name || !name[0] || !out || out_cap < 2) return false;
    size_t name_len = strlen(name);
    size_t i = 0;
    while (i < cookie_len) {
        while (i < cookie_len &&
               (cookie[i] == ' ' || cookie[i] == '\t' || cookie[i] == ';')) i++;
        if (i >= cookie_len) break;
        size_t key_start = i;
        while (i < cookie_len && cookie[i] != '=' && cookie[i] != ';') i++;
        size_t key_end = i;
        while (key_end > key_start &&
               (cookie[key_end - 1] == ' ' || cookie[key_end - 1] == '\t')) key_end--;
        if (i >= cookie_len || cookie[i] != '=') {
            while (i < cookie_len && cookie[i] != ';') i++;
            continue;
        }
        i++; /* '=' */
        size_t val_start = i;
        while (i < cookie_len && cookie[i] != ';') i++;
        size_t val_end = i;
        while (val_end > val_start &&
               (cookie[val_end - 1] == ' ' || cookie[val_end - 1] == '\t')) val_end--;

        if ((key_end - key_start) == name_len &&
            memcmp(cookie + key_start, name, name_len) == 0) {
            size_t vlen = val_end - val_start;
            if (vlen == 0 || vlen + 1 > out_cap) return false;
            memcpy(out, cookie + val_start, vlen);
            out[vlen] = '\0';
            return true;
        }
    }
    return false;
}

bool api_principal_from_cookie(const char* cookie, size_t cookie_len,
                               char* out_principal, size_t out_cap) {
    if (!out_principal || out_cap < 2) return false;
    char sid[AUTH_COOKIE_VALUE_CAP + 1];
    if (!cookie_extract(cookie, cookie_len, AUTH_COOKIE_NAME, sid, sizeof(sid))) return false;
    return auth_session_sub_from_sid(sid, out_principal, out_cap);
}

static bool json_extract_string_field(const char* json, const char* key,
                                      char* out, size_t out_cap) {
    if (!json || !key || !out || out_cap < 2) return false;
    char needle[96];
    int nn = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (nn <= 0 || (size_t)nn >= sizeof(needle)) return false;

    const char* p = json;
    while ((p = strstr(p, needle)) != NULL) {
        p += (size_t)nn;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p != ':') continue;
        p++;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p != '"') continue;
        p++;

        size_t o = 0;
        while (*p && *p != '"') {
            char ch = *p;
            if (ch == '\\') {
                p++;
                if (!*p) return false;
                switch (*p) {
                case '"': ch = '"'; break;
                case '\\': ch = '\\'; break;
                case '/': ch = '/'; break;
                case 'b': ch = '\b'; break;
                case 'f': ch = '\f'; break;
                case 'n': ch = '\n'; break;
                case 'r': ch = '\r'; break;
                case 't': ch = '\t'; break;
                default: ch = *p; break;
                }
            }
            if (o + 1 >= out_cap) return false;
            out[o++] = ch;
            p++;
        }
        if (*p != '"') return false;
        out[o] = '\0';
        return true;
    }
    return false;
}

static bool json_extract_u32_field(const char* json, const char* key,
                                   uint32_t max, uint32_t* out) {
    if (!json || !key || !out) return false;
    char needle[96];
    int nn = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (nn <= 0 || (size_t)nn >= sizeof(needle)) return false;
    const char* p = json;
    while ((p = strstr(p, needle)) != NULL) {
        p += (size_t)nn;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p != ':') continue;
        p++;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p < '0' || *p > '9') continue;
        uint64_t v = 0;
        while (*p >= '0' && *p <= '9') {
            v = v * 10u + (uint64_t)(*p - '0');
            if (v > max) return false;
            p++;
        }
        *out = (uint32_t)v;
        return true;
    }
    return false;
}

static int b64url_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

static bool b64url_decode(const char* in, size_t in_len, uint8_t* out, size_t out_cap, size_t* out_len) {
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        int v = b64url_val((unsigned char)in[i]);
        if (v < 0) return false;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= out_cap) return false;
            out[o++] = (uint8_t)((acc >> bits) & 0xFFu);
        }
    }
    if (out_len) *out_len = o;
    return true;
}

static bool jwt_decode_payload_json(const char* jwt, char* out_json, size_t out_cap) {
    if (!jwt || !out_json || out_cap < 4) return false;
    const char* dot1 = strchr(jwt, '.');
    if (!dot1) return false;
    const char* dot2 = strchr(dot1 + 1, '.');
    if (!dot2 || dot2 <= dot1 + 1) return false;
    size_t b64_len = (size_t)(dot2 - (dot1 + 1));
    uint8_t tmp[2048];
    size_t dec_len = 0;
    if (b64_len == 0 || b64_len >= sizeof(tmp)) return false;
    if (!b64url_decode(dot1 + 1, b64_len, tmp, sizeof(tmp) - 1, &dec_len)) return false;
    if (dec_len + 1 > out_cap) return false;
    memcpy(out_json, tmp, dec_len);
    out_json[dec_len] = '\0';
    return true;
}

static bool run_curl_capture(char* const argv[], char* out, size_t out_cap,
                             char* err, size_t err_cap) {
    if (!argv || !out || out_cap < 2) return false;
    int pipes[2];
    if (pipe(pipes) != 0) {
        if (err && err_cap) snprintf(err, err_cap, "pipe failed");
        return false;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pipes[0]); close(pipes[1]);
        if (err && err_cap) snprintf(err, err_cap, "fork failed");
        return false;
    }
    if (pid == 0) {
        (void)dup2(pipes[1], STDOUT_FILENO);
        (void)dup2(pipes[1], STDERR_FILENO);
        close(pipes[0]);
        close(pipes[1]);
        execvp("curl", argv);
        _exit(127);
    }

    close(pipes[1]);
    size_t off = 0;
    while (off + 1 < out_cap) {
        ssize_t r = read(pipes[0], out + off, out_cap - 1 - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        off += (size_t)r;
    }
    close(pipes[0]);
    out[off] = '\0';

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        if (err && err_cap) snprintf(err, err_cap, "waitpid failed");
        return false;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (err && err_cap) {
            if (off > 0) snprintf(err, err_cap, "%s", out);
            else snprintf(err, err_cap, "curl exit=%d", WEXITSTATUS(status));
        }
        return false;
    }
    return true;
}

static bool oidc_validate_google(const char* access_token, char* out_sub, size_t out_sub_cap,
                                 char* err, size_t err_cap) {
    if (!g_oidc_google_client_id[0]) {
        if (err && err_cap) snprintf(err, err_cap, "google client id not configured");
        return false;
    }
    char token_arg[API_REQ_BODY_CAP + 32];
    int tn = snprintf(token_arg, sizeof(token_arg), "access_token=%s", access_token);
    if (tn <= 0 || (size_t)tn >= sizeof(token_arg)) {
        if (err && err_cap) snprintf(err, err_cap, "token too large");
        return false;
    }

    char* argv[] = {
        "curl", "-fsS", "--max-time", "5",
        "--get", "--data-urlencode", token_arg,
        "https://oauth2.googleapis.com/tokeninfo",
        NULL
    };
    char buf[4096];
    if (!run_curl_capture(argv, buf, sizeof(buf), err, err_cap)) return false;

    char aud[256];
    if (!json_extract_string_field(buf, "aud", aud, sizeof(aud))) {
        if (err && err_cap) snprintf(err, err_cap, "google token missing aud");
        return false;
    }
    if (strcmp(aud, g_oidc_google_client_id) != 0) {
        if (err && err_cap) snprintf(err, err_cap, "google audience mismatch");
        return false;
    }
    if (!json_extract_string_field(buf, "sub", out_sub, out_sub_cap)) {
        if (err && err_cap) snprintf(err, err_cap, "google token missing sub");
        return false;
    }
    return true;
}

static bool oidc_validate_entra(const char* access_token, char* out_sub, size_t out_sub_cap,
                                char* err, size_t err_cap) {
    if (!g_oidc_entra_client_id[0]) {
        if (err && err_cap) snprintf(err, err_cap, "entra client id not configured");
        return false;
    }
    char authz[API_REQ_BODY_CAP + 64];
    int an = snprintf(authz, sizeof(authz), "Authorization: Bearer %s", access_token);
    if (an <= 0 || (size_t)an >= sizeof(authz)) {
        if (err && err_cap) snprintf(err, err_cap, "token too large");
        return false;
    }
    char* argv[] = {
        "curl", "-fsS", "--max-time", "5",
        "-H", authz,
        "https://graph.microsoft.com/oidc/userinfo",
        NULL
    };
    char userinfo[4096];
    if (!run_curl_capture(argv, userinfo, sizeof(userinfo), err, err_cap)) return false;
    if (!json_extract_string_field(userinfo, "sub", out_sub, out_sub_cap)) {
        if (err && err_cap) snprintf(err, err_cap, "entra userinfo missing sub");
        return false;
    }

    char jwt_payload[2048];
    if (!jwt_decode_payload_json(access_token, jwt_payload, sizeof(jwt_payload))) {
        if (err && err_cap) snprintf(err, err_cap, "entra token is not JWT");
        return false;
    }

    char appid[256] = {0};
    char aud[256] = {0};
    char tid[128] = {0};
    (void)json_extract_string_field(jwt_payload, "appid", appid, sizeof(appid));
    (void)json_extract_string_field(jwt_payload, "aud", aud, sizeof(aud));
    (void)json_extract_string_field(jwt_payload, "tid", tid, sizeof(tid));

    bool app_ok = false;
    if (appid[0] && strcmp(appid, g_oidc_entra_client_id) == 0) app_ok = true;
    if (aud[0] && strcmp(aud, g_oidc_entra_client_id) == 0) app_ok = true;
    if (!app_ok) {
        if (err && err_cap) snprintf(err, err_cap, "entra audience/appid mismatch");
        return false;
    }
    if (g_oidc_entra_tenant[0]) {
        if (!tid[0] || strcmp(tid, g_oidc_entra_tenant) != 0) {
            if (err && err_cap) snprintf(err, err_cap, "entra tenant mismatch");
            return false;
        }
    }
    return true;
}

static bool parse_login_request(const char* body, size_t body_len,
                                char* out_provider, size_t provider_cap,
                                char* out_token, size_t token_cap) {
    if (!body || body_len == 0 || body_len > API_REQ_BODY_CAP) return false;
    char* tmp = (char*)malloc(body_len + 1);
    if (!tmp) return false;
    memcpy(tmp, body, body_len);
    tmp[body_len] = '\0';
    bool ok = json_extract_string_field(tmp, "provider", out_provider, provider_cap) &&
              json_extract_string_field(tmp, "access_token", out_token, token_cap);
    free(tmp);
    return ok;
}

static void resp_cookie_status(api_resp_t* r, int status, const char* reason,
                               const char* cookie_value, uint32_t max_age) {
    r->status = status;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 %d %s\r\n"
                     "Server: picoweb\r\n"
                     "Set-Cookie: " AUTH_COOKIE_NAME "=%s; Max-Age=%u; Path=%s; HttpOnly; Secure; SameSite=Lax\r\n"
                     "Content-Length: 0\r\n"
                     "Cache-Control: no-store\r\n",
                     status, reason, cookie_value ? cookie_value : "", max_age, g_picowal_prefix);
    r->head_len = (n > 0) ? (size_t)n : 0;
}

static bool auth_require_cookie(const char* cookie, size_t cookie_len, api_resp_t* resp) {
    char sid[AUTH_COOKIE_VALUE_CAP + 1];
    if (!cookie_extract(cookie, cookie_len, AUTH_COOKIE_NAME, sid, sizeof(sid))) {
        resp_status_only(resp, 401, "Unauthorized");
        return false;
    }
    if (!auth_is_valid_session(sid)) {
        resp_status_only(resp, 401, "Unauthorized");
        return false;
    }
    return true;
}

static bool header_value_safe(const char* s, size_t n) {
    if (!s || n == 0) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f || c == '\r' || c == '\n') return false;
    }
    return true;
}

static void head_append_bytes(api_resp_t* resp, const char* s, size_t n) {
    if (!resp || !s || n == 0) return;
    if (resp->head_len + n >= sizeof(resp->head)) return;
    memcpy(resp->head + resp->head_len, s, n);
    resp->head_len += n;
    resp->head[resp->head_len] = '\0';
}

void api_apply_cors(api_resp_t* resp,
                    const char* origin, size_t origin_len,
                    const char* acr_headers, size_t acr_headers_len) {
    if (!resp || !origin || origin_len == 0) return;
    if (!header_value_safe(origin, origin_len)) return;

    static const char k_allow_origin[] = "Access-Control-Allow-Origin: ";
    static const char k_vary[] = "Vary: Origin\r\n";
    static const char k_allow_creds[] = "Access-Control-Allow-Credentials: true\r\n";
    static const char k_allow_methods[] =
        "Access-Control-Allow-Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS\r\n";
    static const char k_allow_headers[] = "Access-Control-Allow-Headers: ";
    static const char k_default_headers[] = "Content-Type, X-PW-Auth, X-Score-Token";
    static const char k_max_age[] = "Access-Control-Max-Age: 600\r\n";
    static const char k_crlf[] = "\r\n";

    head_append_bytes(resp, k_allow_origin, sizeof(k_allow_origin) - 1);
    head_append_bytes(resp, origin, origin_len);
    head_append_bytes(resp, k_crlf, 2);
    head_append_bytes(resp, k_vary, sizeof(k_vary) - 1);
    head_append_bytes(resp, k_allow_creds, sizeof(k_allow_creds) - 1);
    head_append_bytes(resp, k_allow_methods, sizeof(k_allow_methods) - 1);
    head_append_bytes(resp, k_allow_headers, sizeof(k_allow_headers) - 1);
    if (acr_headers && acr_headers_len > 0 &&
        acr_headers_len <= 200 && header_value_safe(acr_headers, acr_headers_len)) {
        head_append_bytes(resp, acr_headers, acr_headers_len);
    } else {
        head_append_bytes(resp, k_default_headers, sizeof(k_default_headers) - 1);
    }
    head_append_bytes(resp, k_crlf, 2);
    head_append_bytes(resp, k_max_age, sizeof(k_max_age) - 1);
}

/* ---------- name validation ---------- */

static bool is_valid_name(const char* s, size_t n) {
    if (n == 0 || n > API_NAME_CAP) return false;
    /* reject ".", ".." outright */
    if ((n == 1 && s[0] == '.') ||
        (n == 2 && s[0] == '.' && s[1] == '.')) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        bool ok = (c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') ||
                  c == '-' || c == '_';
        if (!ok) return false;
    }
    return true;
}

/* Split the path AFTER the prefix into {coll, id}. Returns:
 *    2  -> /api/{coll}/{id}        (id may be empty if trailing slash; treat as 0)
 *    1  -> /api/{coll}             (no id segment)
 *   -1  -> malformed
 *
 * out_coll / out_id are pointers into the original path. Lengths are
 * filled in *coll_len / *id_len. */
static int split_path(const char* path, size_t path_len, size_t prefix_len,
                      const char** out_coll, size_t* coll_len,
                      const char** out_id,   size_t* id_len) {
    if (path_len <= prefix_len) return -1;
    const char* p   = path + prefix_len;
    size_t      n   = path_len - prefix_len;

    /* coll = up to next '/' or end */
    size_t s1 = 0;
    while (s1 < n && p[s1] != '/') s1++;
    if (s1 == 0) return -1;
    *out_coll = p; *coll_len = s1;
    if (s1 == n) { *out_id = NULL; *id_len = 0; return 1; }

    /* skip the '/' after coll */
    size_t i = s1 + 1;
    if (i >= n) {
        /* trailing slash with no id */
        *out_id = NULL; *id_len = 0;
        return 1;
    }
    /* id = up to end; reject any further '/' */
    size_t id_start = i;
    while (i < n) {
        if (p[i] == '/') return -1;
        i++;
    }
    *out_id = p + id_start;
    *id_len = i - id_start;
    return 2;
}

static bool parse_u32_dec(const char* s, size_t n, uint32_t max, uint32_t* out) {
    if (!s || n == 0 || !out) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < '0' || c > '9') return false;
        v = v * 10u + (uint64_t)(c - '0');
        if (v > max) return false;
    }
    *out = (uint32_t)v;
    return true;
}

static size_t u32_to_dec(char* out, size_t cap, uint32_t v) {
    if (!out || cap < 2) return 0;
    char rev[16];
    size_t n = 0;
    if (v == 0) {
        out[0] = '0';
        out[1] = '\0';
        return 1;
    }
    while (v && n < sizeof(rev)) {
        rev[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    if (n + 1 > cap) return 0;
    for (size_t i = 0; i < n; i++) out[i] = rev[n - 1 - i];
    out[n] = '\0';
    return n;
}

static bool picowal_path_to_key(const char* coll, size_t coll_len,
                                const char* id, size_t id_len,
                                uint32_t* out_key) {
    uint32_t card = 0, record = 0;
    if (!parse_u32_dec(coll, coll_len, PICOWAL_CARD_MAX, &card)) return false;
    if (!parse_u32_dec(id, id_len, PICOWAL_RECORD_MAX, &record)) return false;
    return picowal_db_pack_key((uint16_t)card, record, out_key);
}

static void trim_inplace(char* s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    size_t i = 0;
    while (s[i] && isspace((unsigned char)s[i])) i++;
    if (i > 0) memmove(s, s + i, strlen(s + i) + 1);
}

static bool csv_has_token(const char* csv, const char* token) {
    if (!csv || !token || !*token) return false;
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", csv);
    char* save = NULL;
    for (char* t = strtok_r(tmp, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        trim_inplace(t);
        if (strcmp(t, token) == 0) return true;
    }
    return false;
}

static bool schema_relation_pack_for_field(const char* joins_csv, const char* field, uint16_t* out_pack) {
    if (!joins_csv || !field || !out_pack) return false;
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", joins_csv);
    char* save = NULL;
    for (char* t = strtok_r(tmp, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        trim_inplace(t);
        char* sep = strchr(t, '=');
        if (!sep) sep = strchr(t, ':');
        if (!sep) continue;
        *sep = '\0';
        char* p = t;
        char* f = sep + 1;
        trim_inplace(p);
        trim_inplace(f);
        uint32_t pid = 0;
        if (!parse_u32_dec(p, strlen(p), PICOWAL_CARD_MAX, &pid)) continue;
        if (strcmp(f, field) != 0) continue;
        *out_pack = (uint16_t)pid;
        return true;
    }
    return false;
}

static bool picowal_read_meta_json(uint16_t meta_pack, uint32_t pack_id, char* out, size_t out_cap) {
    uint32_t key = 0;
    if (!picowal_db_pack_key(meta_pack, pack_id, &key)) return false;
    int n = picowal_db_get_key(g_picowal, key, out, (uint32_t)(out_cap - 1));
    if (n < 0) return false;
    out[n] = '\0';
    return true;
}

static bool picowal_build_form_spec(uint32_t pack_id, char** out_json, size_t* out_len,
                                    int* out_status, char* err, size_t err_cap) {
    if (!out_json || !out_len) return false;
    *out_json = NULL;
    *out_len = 0;
    if (out_status) *out_status = 500;

    char schema[4097];
    if (!picowal_read_meta_json(2, pack_id, schema, sizeof(schema))) {
        if (out_status) *out_status = 404;
        snprintf(err, err_cap, "schema not found");
        return false;
    }
    char fields_csv[1024];
    if (!json_extract_string_field(schema, "fields", fields_csv, sizeof(fields_csv)) || !fields_csv[0]) {
        if (out_status) *out_status = 400;
        snprintf(err, err_cap, "schema fields missing");
        return false;
    }
    char required_csv[512] = {0};
    (void)json_extract_string_field(schema, "required", required_csv, sizeof(required_csv));
    char joins_csv[512] = {0};
    (void)json_extract_string_field(schema, "joins", joins_csv, sizeof(joins_csv));

    char name_doc[4097];
    char pack_name[128] = {0};
    if (picowal_read_meta_json(1, pack_id, name_doc, sizeof(name_doc))) {
        (void)json_extract_string_field(name_doc, "name", pack_name, sizeof(pack_name));
    }

    size_t cap = PICOWAL_DATA_MAX * 2;
    char* out = (char*)malloc(cap);
    if (!out) {
        if (out_status) *out_status = 500;
        snprintf(err, err_cap, "oom");
        return false;
    }

    size_t o = 0;
    int n = 0;
    if (pack_name[0]) {
        n = snprintf(out + o, cap - o, "{\"pack\":%u,\"entity\":\"%s\",\"fields\":[", pack_id, pack_name);
    } else {
        n = snprintf(out + o, cap - o, "{\"pack\":%u,\"entity\":null,\"fields\":[", pack_id);
    }
    if (n <= 0 || (size_t)n >= cap - o) { free(out); snprintf(err, err_cap, "render failed"); return false; }
    o += (size_t)n;

    char fields_copy[1024];
    snprintf(fields_copy, sizeof(fields_copy), "%s", fields_csv);
    char* save = NULL;
    bool first = true;
    for (char* t = strtok_r(fields_copy, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        trim_inplace(t);
        if (!t[0]) continue;
        bool required = required_csv[0] && csv_has_token(required_csv, t);
        uint16_t rel_pack = 0;
        bool is_rel = joins_csv[0] && schema_relation_pack_for_field(joins_csv, t, &rel_pack);
        const char* input = "text";
        if (is_rel) input = "relation";
        else if (strlen(t) > 3 && strcmp(t + strlen(t) - 3, "_id") == 0) input = "number";

        n = snprintf(out + o, cap - o, "%s{\"name\":\"%s\",\"input\":\"%s\",\"required\":%s",
                     first ? "" : ",", t, input, required ? "true" : "false");
        if (n <= 0 || (size_t)n >= cap - o) { free(out); snprintf(err, err_cap, "render failed"); return false; }
        o += (size_t)n;
        if (is_rel) {
            n = snprintf(out + o, cap - o, ",\"relation_pack\":%u", (unsigned)rel_pack);
            if (n <= 0 || (size_t)n >= cap - o) { free(out); snprintf(err, err_cap, "render failed"); return false; }
            o += (size_t)n;
        }
        n = snprintf(out + o, cap - o, "}");
        if (n <= 0 || (size_t)n >= cap - o) { free(out); snprintf(err, err_cap, "render failed"); return false; }
        o += (size_t)n;
        first = false;
    }

    n = snprintf(out + o, cap - o,
                 "],\"actions\":{\"create\":\"%s%u\",\"update\":\"%s%u/{record}\"}}",
                 g_picowal_prefix, pack_id, g_picowal_prefix, pack_id);
    if (n <= 0 || (size_t)n >= cap - o) { free(out); snprintf(err, err_cap, "render failed"); return false; }
    o += (size_t)n;

    *out_json = out;
    *out_len = o;
    return true;
}

static bool json_escape_copy(const char* src, char* out, size_t out_cap) {
    if (!src || !out || out_cap < 2) return false;
    size_t o = 0;
    for (const unsigned char* p = (const unsigned char*)src; *p; p++) {
        const char* esc = NULL;
        char one[2] = {(char)*p, '\0'};
        if (*p == '"' || *p == '\\') {
            one[0] = (char)*p;
            esc = one;
            if (o + 2 >= out_cap) return false;
            out[o++] = '\\';
            out[o++] = *esc;
            continue;
        }
        if (*p == '\n') esc = "n";
        else if (*p == '\r') esc = "r";
        else if (*p == '\t') esc = "t";
        else if (*p < 0x20) esc = " ";
        if (esc) {
            if (esc[0] == ' ') {
                if (o + 1 >= out_cap) return false;
                out[o++] = ' ';
            } else {
                if (o + 2 >= out_cap) return false;
                out[o++] = '\\';
                out[o++] = esc[0];
            }
            continue;
        }
        if (o + 1 >= out_cap) return false;
        out[o++] = (char)*p;
    }
    out[o] = '\0';
    return true;
}

static bool picowal_build_report(const char* body, size_t body_len,
                                 char** out_json, size_t* out_len,
                                 int* out_status, char* err, size_t err_cap) {
    if (!out_json || !out_len) return false;
    *out_json = NULL;
    *out_len = 0;
    if (out_status) *out_status = 400;
    if (!body || body_len == 0 || body_len > PICOWAL_DATA_MAX) {
        snprintf(err, err_cap, "report query body required");
        return false;
    }

    char query_buf[PICOWAL_DATA_MAX + 1];
    memcpy(query_buf, body, body_len);
    query_buf[body_len] = '\0';

    char title[128] = {0};
    if (query_buf[0] == '{') {
        char extracted[PICOWAL_DATA_MAX + 1];
        if (!json_extract_string_field(query_buf, "query", extracted, sizeof(extracted))) {
            snprintf(err, err_cap, "report JSON body requires \"query\"");
            return false;
        }
        (void)json_extract_string_field(query_buf, "title", title, sizeof(title));
        snprintf(query_buf, sizeof(query_buf), "%s", extracted);
    }

    char* result_json = NULL;
    size_t result_len = 0;
    char qerr[128] = {0};
    if (!picowal_query_run(g_picowal, query_buf, &result_json, &result_len, qerr, sizeof(qerr))) {
        snprintf(err, err_cap, "%s", qerr[0] ? qerr : "report query failed");
        return false;
    }

    char esc_title[256] = {0};
    bool has_title = title[0] && json_escape_copy(title, esc_title, sizeof(esc_title));
    size_t cap = result_len + (has_title ? strlen(esc_title) : 0) + 256;
    char* out = (char*)malloc(cap);
    if (!out) {
        free(result_json);
        if (out_status) *out_status = 500;
        snprintf(err, err_cap, "oom");
        return false;
    }
    int n = snprintf(out, cap, "{\"kind\":\"report\",\"generated_at\":%lld%s%s%s,\"report\":%s}",
                     (long long)now_unix_sec(),
                     has_title ? ",\"title\":\"" : "",
                     has_title ? esc_title : "",
                     has_title ? "\"" : "",
                     result_json);
    free(result_json);
    if (n <= 0 || (size_t)n >= cap) {
        free(out);
        if (out_status) *out_status = 500;
        snprintf(err, err_cap, "report render failed");
        return false;
    }
    if (out_status) *out_status = 200;
    *out_json = out;
    *out_len = (size_t)n;
    return true;
}

static bool picowal_build_dashboard(const char* body, size_t body_len,
                                    char** out_json, size_t* out_len,
                                    int* out_status, char* err, size_t err_cap) {
    if (!out_json || !out_len) return false;
    *out_json = NULL;
    *out_len = 0;
    if (out_status) *out_status = 400;
    if (!body || body_len == 0 || body_len > PICOWAL_DATA_MAX) {
        snprintf(err, err_cap, "dashboard body required");
        return false;
    }

    typedef struct {
        char title[96];
        char* report_json;
        size_t report_len;
        bool ok;
        char error[160];
    } panel_result_t;

    panel_result_t panels[8];
    memset(panels, 0, sizeof(panels));
    size_t panel_count = 0;

    char text[PICOWAL_DATA_MAX + 1];
    memcpy(text, body, body_len);
    text[body_len] = '\0';
    for (size_t i = 0; i < body_len; i++) if (text[i] == '\r') text[i] = '\n';

    const char* cursor = text;
    while (*cursor && panel_count < (sizeof(panels) / sizeof(panels[0]))) {
        const char* sep = strstr(cursor, "\n---\n");
        size_t seg_len = sep ? (size_t)(sep - cursor) : strlen(cursor);
        char seg[PICOWAL_DATA_MAX + 1];
        if (seg_len >= sizeof(seg)) seg_len = sizeof(seg) - 1;
        memcpy(seg, cursor, seg_len);
        seg[seg_len] = '\0';
        trim_inplace(seg);
        if (seg[0]) {
            panel_result_t* pr = &panels[panel_count];
            snprintf(pr->title, sizeof(pr->title), "Panel %u", (unsigned)(panel_count + 1));
            char* qtxt = seg;
            char* nl = strchr(seg, '\n');
            if (strncmp(seg, "T:", 2) == 0) {
                if (nl) {
                    *nl = '\0';
                    char* t = seg + 2;
                    trim_inplace(t);
                    if (t[0]) snprintf(pr->title, sizeof(pr->title), "%s", t);
                    qtxt = nl + 1;
                } else {
                    qtxt = seg + 2;
                }
                trim_inplace(qtxt);
            }

            char qerr[128] = {0};
            pr->ok = picowal_query_run(g_picowal, qtxt, &pr->report_json, &pr->report_len, qerr, sizeof(qerr));
            if (!pr->ok) {
                char esc_err[128] = {0};
                const char* src_err = qerr[0] ? qerr : "query failed";
                if (!json_escape_copy(src_err, esc_err, sizeof(esc_err))) snprintf(esc_err, sizeof(esc_err), "query failed");
                snprintf(pr->error, sizeof(pr->error), "%s", esc_err);
            }
            panel_count++;
        }
        if (!sep) break;
        cursor = sep + 5;
    }

    if (panel_count == 0) {
        snprintf(err, err_cap, "dashboard requires at least one panel query");
        return false;
    }

    size_t cap = 256;
    for (size_t i = 0; i < panel_count; i++) {
        cap += 256 + (panels[i].ok ? panels[i].report_len : strlen(panels[i].error));
    }
    char* out = (char*)malloc(cap);
    if (!out) {
        for (size_t i = 0; i < panel_count; i++) free(panels[i].report_json);
        if (out_status) *out_status = 500;
        snprintf(err, err_cap, "oom");
        return false;
    }

    size_t o = 0;
    int n = snprintf(out + o, cap - o, "{\"kind\":\"dashboard\",\"generated_at\":%lld,\"panels\":[",
                     (long long)now_unix_sec());
    if (n <= 0 || (size_t)n >= cap - o) {
        free(out);
        for (size_t i = 0; i < panel_count; i++) free(panels[i].report_json);
        if (out_status) *out_status = 500;
        snprintf(err, err_cap, "dashboard render failed");
        return false;
    }
    o += (size_t)n;

    for (size_t i = 0; i < panel_count; i++) {
        char esc_title[192] = {0};
        if (!json_escape_copy(panels[i].title, esc_title, sizeof(esc_title))) snprintf(esc_title, sizeof(esc_title), "Panel");
        n = snprintf(out + o, cap - o, "%s{\"panel\":%u,\"title\":\"%s\",",
                     (i == 0 ? "" : ","), (unsigned)(i + 1), esc_title);
        if (n <= 0 || (size_t)n >= cap - o) {
            free(out);
            for (size_t j = 0; j < panel_count; j++) free(panels[j].report_json);
            if (out_status) *out_status = 500;
            snprintf(err, err_cap, "dashboard render failed");
            return false;
        }
        o += (size_t)n;
        if (panels[i].ok) {
            n = snprintf(out + o, cap - o, "\"report\":%s}", panels[i].report_json);
        } else {
            n = snprintf(out + o, cap - o, "\"error\":\"%s\"}", panels[i].error);
        }
        if (n <= 0 || (size_t)n >= cap - o) {
            free(out);
            for (size_t j = 0; j < panel_count; j++) free(panels[j].report_json);
            if (out_status) *out_status = 500;
            snprintf(err, err_cap, "dashboard render failed");
            return false;
        }
        o += (size_t)n;
    }
    n = snprintf(out + o, cap - o, "]}");
    if (n <= 0 || (size_t)n >= cap - o) {
        free(out);
        for (size_t i = 0; i < panel_count; i++) free(panels[i].report_json);
        if (out_status) *out_status = 500;
        snprintf(err, err_cap, "dashboard render failed");
        return false;
    }
    o += (size_t)n;

    for (size_t i = 0; i < panel_count; i++) free(panels[i].report_json);
    if (out_status) *out_status = 200;
    *out_json = out;
    *out_len = o;
    return true;
}

static int copy_segment_name(char* out, size_t cap, const char* in, size_t in_len) {
    if (!out || !in || in_len == 0 || in_len + 1 > cap) return ENAMETOOLONG;
    memcpy(out, in, in_len);
    out[in_len] = '\0';
    return 0;
}

static int build_object_filename(char* out, size_t cap,
                                 const char* id, size_t id_len) {
    if (!out || !id || id_len == 0 || id_len > API_NAME_CAP) return EINVAL;
    if (id_len + 6 > cap) return ENAMETOOLONG; /* id + ".json" + NUL */
    memcpy(out, id, id_len);
    memcpy(out + id_len, ".json", 6);
    return 0;
}

static int open_collection_dir(const char* coll, size_t coll_len,
                               bool create_if_missing, int* out_dirfd) {
    if (g_root_fd < 0) return ENOENT;
    char coll_name[API_NAME_CAP + 1];
    int rc = copy_segment_name(coll_name, sizeof(coll_name), coll, coll_len);
    if (rc != 0) return rc;

    if (create_if_missing) {
        if (mkdirat(g_root_fd, coll_name, 0700) != 0 && errno != EEXIST) return errno;
    }

    int dfd = openat(g_root_fd, coll_name, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (dfd < 0) return errno;
    *out_dirfd = dfd;
    return 0;
}

static int write_all_fd(int fd, const char* body, size_t body_len) {
    size_t off = 0;
    while (off < body_len) {
        ssize_t w = write(fd, body + off, body_len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return errno;
        }
        off += (size_t)w;
    }
    return 0;
}

/* ---------- response builders ---------- */

static void resp_status_only(api_resp_t* r, int status, const char* reason) {
    r->status = status;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 %d %s\r\n"
                     "Server: picoweb\r\n"
                     "Content-Length: 0\r\n"
                     "Cache-Control: no-store\r\n",
                     status, reason);
    r->head_len = (n > 0) ? (size_t)n : 0;
}

static void resp_text_error(api_resp_t* r, int status, const char* reason,
                            const char* body) {
    size_t blen = body ? strlen(body) : 0;
    r->status = status;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 %d %s\r\n"
                     "Server: picoweb\r\n"
                     "Content-Type: text/plain; charset=utf-8\r\n"
                     "Content-Length: %zu\r\n"
                     "Cache-Control: no-store\r\n",
                     status, reason, blen);
    r->head_len = (n > 0) ? (size_t)n : 0;
    if (blen) {
        r->body = (char*)malloc(blen);
        if (r->body) {
            memcpy(r->body, body, blen);
            r->body_len = blen;
            r->body_owned = true;
        } else {
            /* OOM: degrade to head-only zero-length */
            r->head_len = 0;
            resp_status_only(r, 500, "Internal Server Error");
        }
    }
}

static void resp_get_body(api_resp_t* r, char* body, size_t blen, bool head_only) {
    r->status = 200;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 200 OK\r\n"
                     "Server: picoweb\r\n"
                     "Content-Type: application/json; charset=utf-8\r\n"
                     "Content-Length: %zu\r\n"
                     "Cache-Control: no-store\r\n",
                     blen);
    r->head_len = (n > 0) ? (size_t)n : 0;
    if (head_only) {
        free(body);
        return;
    }
    r->body = body;
    r->body_len = blen;
    r->body_owned = true;
}

static void resp_json_literal(api_resp_t* r, int status, const char* reason,
                              const char* body, bool head_only) {
    size_t blen = body ? strlen(body) : 0;
    r->status = status;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 %d %s\r\n"
                     "Server: picoweb\r\n"
                     "Content-Type: application/json; charset=utf-8\r\n"
                     "Content-Length: %zu\r\n"
                     "Cache-Control: no-store\r\n",
                     status, reason, blen);
    r->head_len = (n > 0) ? (size_t)n : 0;
    if (head_only || blen == 0) return;
    r->body = (char*)malloc(blen);
    if (!r->body) {
        r->head_len = 0;
        resp_status_only(r, 500, "Internal Server Error");
        return;
    }
    memcpy(r->body, body, blen);
    r->body_len = blen;
    r->body_owned = true;
}

static void dispatch_health(http_method_t method,
                            const char* path, size_t path_len,
                            api_resp_t* resp) {
    if (method != M_GET && method != M_HEAD) {
        resp_status_only(resp, 405, "Method Not Allowed");
        return;
    }
    bool head_only = (method == M_HEAD);
    if (path_len == 8 && memcmp(path, "/healthz", 8) == 0) {
        resp_json_literal(resp, 200, "OK", "{\"status\":\"live\"}\n", head_only);
        return;
    }
    if (path_len == 7 && memcmp(path, "/readyz", 7) == 0) {
        if (!g_picowal) {
            resp_json_literal(resp, 200, "OK",
                              "{\"status\":\"ready\",\"picowal\":\"disabled\"}\n",
                              head_only);
            return;
        }
        if (g_picowal_enabled && picowal_db_healthy(g_picowal)) {
            if (picowal_db_is_quiesced(g_picowal)) {
                resp_json_literal(resp, 200, "OK",
                                  "{\"status\":\"ready\",\"picowal\":\"ready\",\"writes\":\"quiesced\"}\n",
                                  head_only);
                return;
            }
            resp_json_literal(resp, 200, "OK",
                              "{\"status\":\"ready\",\"picowal\":\"ready\",\"writes\":\"enabled\"}\n",
                              head_only);
            return;
        }
        resp_json_literal(resp, 503, "Service Unavailable",
                          "{\"status\":\"not_ready\",\"picowal\":\"unavailable\"}\n",
                          head_only);
        return;
    }
    resp_status_only(resp, 404, "Not Found");
}

static void resp_created(api_resp_t* r, const char* prefix,
                         const char* coll, size_t coll_len,
                         const char* id,   size_t id_len) {
    r->status = 201;
    int n = snprintf(r->head, sizeof(r->head),
                     "HTTP/1.1 201 Created\r\n"
                     "Server: picoweb\r\n"
                     "Location: %s%.*s/%.*s\r\n"
                     "Content-Length: 0\r\n"
                     "Cache-Control: no-store\r\n",
                     prefix,
                     (int)coll_len, coll,
                     (int)id_len, id);
    r->head_len = (n > 0) ? (size_t)n : 0;
}

typedef struct {
    char name[33];
    uint32_t score;
    char ts[32];
    char day[11];
} score_entry_t;

static void score_day_utc(int64_t unix_sec, char out[11]) {
    time_t t = (time_t)unix_sec;
    struct tm tmv;
    if (!gmtime_r(&t, &tmv)) {
        memcpy(out, "1970-01-01", 11);
        return;
    }
    snprintf(out, 11, "%04d-%02d-%02d",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday);
}

static void score_ts_utc(int64_t unix_sec, char out[32]) {
    time_t t = (time_t)unix_sec;
    struct tm tmv;
    if (!gmtime_r(&t, &tmv)) {
        memcpy(out, "1970-01-01T00:00:00Z", 21);
        return;
    }
    strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

static void score_clean_name(const char* in, char out[33]) {
    size_t o = 0;
    if (in) {
        for (size_t i = 0; in[i] && o < 32; i++) {
            unsigned char c = (unsigned char)in[i];
            if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') continue;
            out[o++] = (char)c;
        }
    }
    while (o > 0 && out[o - 1] == ' ') o--;
    if (o == 0) {
        memcpy(out, "anon", 5);
        return;
    }
    out[o] = '\0';
}

static int score_entry_cmp(const void* ap, const void* bp) {
    const score_entry_t* a = (const score_entry_t*)ap;
    const score_entry_t* b = (const score_entry_t*)bp;
    if (a->score != b->score) return (a->score < b->score) ? 1 : -1;
    return strcmp(a->ts, b->ts);
}

static bool score_append_json_entry(char* out, size_t cap, size_t* off,
                                    const score_entry_t* e) {
    int n = snprintf(out + *off, cap - *off,
                     "{\"name\":\"%s\",\"score\":%u,\"ts\":\"%s\",\"day\":\"%s\"}",
                     e->name, e->score, e->ts, e->day);
    if (n < 0 || (size_t)n >= cap - *off) return false;
    *off += (size_t)n;
    return true;
}

static bool score_issue_token(char out[128], int64_t now_sec) {
    if (!score_secret_ready()) return false;
    uint8_t nonce[16];
    if (!fill_random(nonce, sizeof(nonce))) return false;
    int64_t exp = now_sec + SCORE_TOKEN_TTL_SEC;

    char nonce_hex[33];
    hex_encode(nonce, sizeof(nonce), nonce_hex);
    char msg[64];
    int mn = snprintf(msg, sizeof(msg), "%s.%lld", nonce_hex, (long long)exp);
    if (mn <= 0 || (size_t)mn >= sizeof(msg)) return false;
    uint8_t tag[HMAC_SHA256_TAG_LEN];
    hmac_sha256(g_score_secret, sizeof(g_score_secret), msg, (size_t)mn, tag);
    char tag_hex[HMAC_SHA256_TAG_LEN * 2 + 1];
    hex_encode(tag, sizeof(tag), tag_hex);
    int tn = snprintf(out, 128, "%s.%lld.%s", nonce_hex, (long long)exp, tag_hex);
    if (tn <= 0 || tn >= 128) return false;

    pthread_mutex_lock(&g_score_mu);
    size_t slot = SCORE_NONCES_MAX;
    for (size_t i = 0; i < SCORE_NONCES_MAX; i++) {
        if (g_score_nonces[i].used && g_score_nonces[i].exp_unix <= now_sec) {
            memset(&g_score_nonces[i], 0, sizeof(g_score_nonces[i]));
        }
        if (slot == SCORE_NONCES_MAX && !g_score_nonces[i].used) slot = i;
    }
    if (slot == SCORE_NONCES_MAX) slot = (size_t)(rate_hash(nonce_hex) % SCORE_NONCES_MAX);
    g_score_nonces[slot].used = true;
    g_score_nonces[slot].consumed = false;
    g_score_nonces[slot].exp_unix = exp;
    memcpy(g_score_nonces[slot].nonce, nonce, sizeof(nonce));
    pthread_mutex_unlock(&g_score_mu);
    return true;
}

static bool score_consume_token(const char* token, size_t token_len, int64_t now_sec) {
    if (!score_secret_ready() || !token || token_len >= 128 || token_len < 99) return false;
    char tmp[128];
    memcpy(tmp, token, token_len);
    tmp[token_len] = '\0';
    char* dot1 = strchr(tmp, '.');
    if (!dot1) return false;
    char* dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return false;
    *dot1 = '\0';
    *dot2 = '\0';
    const char* nonce_hex = tmp;
    const char* exp_str = dot1 + 1;
    const char* tag_hex = dot2 + 1;
    uint8_t nonce[16];
    uint8_t tag[HMAC_SHA256_TAG_LEN];
    if (!hex_decode(nonce_hex, strlen(nonce_hex), nonce, sizeof(nonce))) return false;
    if (!hex_decode(tag_hex, strlen(tag_hex), tag, sizeof(tag))) return false;
    char* end = NULL;
    long long exp_ll = strtoll(exp_str, &end, 10);
    if (end == exp_str || *end != '\0' || exp_ll <= now_sec) return false;
    char msg[64];
    int mn = snprintf(msg, sizeof(msg), "%s.%lld", nonce_hex, exp_ll);
    if (mn <= 0 || (size_t)mn >= sizeof(msg)) return false;
    uint8_t expected[HMAC_SHA256_TAG_LEN];
    hmac_sha256(g_score_secret, sizeof(g_score_secret), msg, (size_t)mn, expected);
    if (!constant_time_eq(tag, expected, sizeof(tag))) return false;

    bool ok = false;
    pthread_mutex_lock(&g_score_mu);
    for (size_t i = 0; i < SCORE_NONCES_MAX; i++) {
        if (!g_score_nonces[i].used) continue;
        if (g_score_nonces[i].exp_unix <= now_sec) {
            memset(&g_score_nonces[i], 0, sizeof(g_score_nonces[i]));
            continue;
        }
        if (!g_score_nonces[i].consumed &&
            g_score_nonces[i].exp_unix == (int64_t)exp_ll &&
            memcmp(g_score_nonces[i].nonce, nonce, sizeof(nonce)) == 0) {
            g_score_nonces[i].consumed = true;
            ok = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_score_mu);
    return ok;
}

static bool score_parse_entry(const char* json, size_t len, score_entry_t* out) {
    if (!json || !out || len == 0 || len > PICOWAL_DATA_MAX) return false;
    char tmp[PICOWAL_DATA_MAX + 1];
    memcpy(tmp, json, len);
    tmp[len] = '\0';
    char name[64];
    uint32_t score = 0;
    char ts[32] = {0};
    char day[11] = {0};
    if (!json_extract_string_field(tmp, "name", name, sizeof(name))) return false;
    if (!json_extract_u32_field(tmp, "score", 1000000000u, &score)) return false;
    if (!json_extract_string_field(tmp, "ts", ts, sizeof(ts))) return false;
    (void)json_extract_string_field(tmp, "day", day, sizeof(day));
    memset(out, 0, sizeof(*out));
    score_clean_name(name, out->name);
    out->score = score;
    snprintf(out->ts, sizeof(out->ts), "%s", ts);
    if (day[0]) snprintf(out->day, sizeof(out->day), "%s", day);
    else snprintf(out->day, sizeof(out->day), "%.10s", ts);
    return true;
}

static void dispatch_scores(http_method_t method,
                            const char* path, size_t path_len,
                            const char* body, size_t body_len,
                            const char* score_token, size_t score_token_len,
                            const api_request_context_t* req_ctx,
                            api_resp_t* resp) {
    if (!g_picowal_enabled || !g_picowal) {
        resp_status_only(resp, 404, "Not Found");
        return;
    }
    int64_t now = now_unix_sec();
    size_t prefix_len = 0;
    (void)public_api_prefix(&prefix_len);
    bool is_start = path_len == prefix_len + 12 &&
                    memcmp(path + prefix_len, "scores/start", 12) == 0;
    if (!score_rate_allow(req_ctx, is_start ? "start" : "scores", now)) {
        resp_text_error(resp, 429, "Too Many Requests", "rate limit exceeded\n");
        return;
    }
    if (is_start) {
        if (method != M_POST) {
            resp_status_only(resp, 405, "Method Not Allowed");
            return;
        }
        char token[128];
        if (!score_issue_token(token, now)) {
            resp_text_error(resp, 500, "Internal Server Error", "token issue failed\n");
            return;
        }
        char* out = (char*)malloc(192);
        if (!out) {
            resp_status_only(resp, 500, "Internal Server Error");
            return;
        }
        int n = snprintf(out, 192, "{\"token\":\"%s\",\"expiresIn\":%d}\n",
                         token, SCORE_TOKEN_TTL_SEC);
        resp_get_body(resp, out, (size_t)n, false);
        return;
    }

    if (method == M_GET || method == M_HEAD) {
        uint32_t records[2048];
        uint32_t nrec = picowal_api_list(g_picowal, SCORE_CARD_ID, records,
                                         (uint32_t)(sizeof(records) / sizeof(records[0])));
        score_entry_t all[2048];
        score_entry_t today[2048];
        size_t all_n = 0, today_n = 0;
        char day[11];
        score_day_utc(now, day);
        for (uint32_t i = 0; i < nrec; i++) {
            char buf[PICOWAL_DATA_MAX + 1];
            uint32_t got = 0;
            if (picowal_api_get(g_picowal, SCORE_CARD_ID, records[i], buf,
                                PICOWAL_DATA_MAX, &got) != PICOWAL_API_OK) {
                continue;
            }
            score_entry_t e;
            if (!score_parse_entry(buf, got, &e) || e.score == 0) continue;
            if (all_n < sizeof(all) / sizeof(all[0])) all[all_n++] = e;
            if (strcmp(e.day, day) == 0 && today_n < sizeof(today) / sizeof(today[0])) {
                today[today_n++] = e;
            }
        }
        qsort(all, all_n, sizeof(all[0]), score_entry_cmp);
        qsort(today, today_n, sizeof(today[0]), score_entry_cmp);
        if (all_n > 20) all_n = 20;
        if (today_n > 20) today_n = 20;
        char* out = (char*)malloc(8192);
        if (!out) {
            resp_status_only(resp, 500, "Internal Server Error");
            return;
        }
        size_t off = 0;
        off += (size_t)snprintf(out + off, 8192 - off, "{\"alltime\":[");
        for (size_t i = 0; i < all_n; i++) {
            if (i) out[off++] = ',';
            if (!score_append_json_entry(out, 8192, &off, &all[i])) goto scores_oom;
        }
        off += (size_t)snprintf(out + off, 8192 - off, "],\"today\":[");
        for (size_t i = 0; i < today_n; i++) {
            if (i) out[off++] = ',';
            if (!score_append_json_entry(out, 8192, &off, &today[i])) goto scores_oom;
        }
        if (off + 3 >= 8192) goto scores_oom;
        memcpy(out + off, "]}\n", 3);
        off += 3;
        resp_get_body(resp, out, off, method == M_HEAD);
        return;
scores_oom:
        free(out);
        resp_text_error(resp, 500, "Internal Server Error", "scores response too large\n");
        return;
    }

    if (method == M_POST) {
        if (body_len == 0 || body_len > 512) {
            resp_status_only(resp, 413, "Payload Too Large");
            return;
        }
        if (!score_consume_token(score_token, score_token_len, now)) {
            resp_text_error(resp, 401, "Unauthorized", "invalid score token\n");
            return;
        }
        char tmp[513];
        memcpy(tmp, body, body_len);
        tmp[body_len] = '\0';
        char name_raw[64];
        uint32_t score = 0;
        if (!json_extract_string_field(tmp, "name", name_raw, sizeof(name_raw)) ||
            !json_extract_u32_field(tmp, "score", 1000000000u, &score) ||
            score == 0) {
            resp_text_error(resp, 400, "Bad Request", "invalid score\n");
            return;
        }
        char name[33], ts[32], day[11];
        score_clean_name(name_raw, name);
        score_ts_utc(now, ts);
        score_day_utc(now, day);
        char doc[256];
        int dn = snprintf(doc, sizeof(doc),
                          "{\"name\":\"%s\",\"score\":%u,\"ts\":\"%s\",\"day\":\"%s\"}\n",
                          name, score, ts, day);
        if (dn <= 0 || (size_t)dn >= sizeof(doc)) {
            resp_text_error(resp, 400, "Bad Request", "invalid score\n");
            return;
        }
        uint32_t rec = 0;
        picowal_api_status_t st = picowal_api_create_random(g_picowal, SCORE_CARD_ID,
                                                             doc, (uint32_t)dn, &rec);
        if (st != PICOWAL_API_OK) {
            if (st == PICOWAL_API_BUSY) {
                resp_text_error(resp, 503, "Service Unavailable", "storage quiesced\n");
                return;
            }
            resp_text_error(resp, 500, "Internal Server Error", "score write failed\n");
            return;
        }
        resp_status_only(resp, 201, "Created");
        return;
    }

    resp_status_only(resp, 405, "Method Not Allowed");
}

/* ---------- random id generator (hex32) ---------- */

static bool gen_id(char out[33]) {
    uint8_t raw[16];
    /* getrandom() blocks only if the urandom pool is uninitialised; on
     * any real Linux box at server-start time it returns immediately. */
    ssize_t got = 0;
    while (got < (ssize_t)sizeof(raw)) {
        ssize_t r = getrandom(raw + got, sizeof(raw) - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        got += r;
    }
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(raw); i++) {
        out[i * 2 + 0] = hex[raw[i] >> 4];
        out[i * 2 + 1] = hex[raw[i] & 0xf];
    }
    out[32] = '\0';
    return true;
}

/* ---------- file ops ---------- */

/* Read up to API_RESP_BODY_CAP bytes from path into a freshly malloced
 * buffer. Returns:
 *    0  on success (sets *out_buf, *out_len; caller frees buf)
 *   -1  ENOENT
 *   -2  too large (file size > API_RESP_BODY_CAP)
 *   -3  other I/O / OOM
 */
static int read_file_full(const char* coll, size_t coll_len,
                          const char* id, size_t id_len,
                          char** out_buf, size_t* out_len) {
    int coll_fd = -1;
    int d = open_collection_dir(coll, coll_len, false, &coll_fd);
    if (d == ENOENT) return -1;
    if (d != 0) return -3;

    char fname[API_NAME_CAP + 6];
    if (build_object_filename(fname, sizeof(fname), id, id_len) != 0) {
        close(coll_fd);
        return -3;
    }

    int fd = openat(coll_fd, fname, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(coll_fd);
    if (fd < 0) {
        if (errno == ENOENT) return -1;
        return -3;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -3;
    }
    if (st.st_size > (off_t)API_RESP_BODY_CAP) {
        close(fd);
        return -2;
    }
    size_t sz = (size_t)st.st_size;
    char* buf = NULL;
    if (sz > 0) {
        buf = (char*)malloc(sz);
        if (!buf) { close(fd); return -3; }
        size_t off = 0;
        while (off < sz) {
            ssize_t r = read(fd, buf + off, sz - off);
            if (r < 0) {
                if (errno == EINTR) continue;
                free(buf); close(fd); return -3;
            }
            if (r == 0) break; /* truncated — treat as success at off bytes */
            off += (size_t)r;
        }
        sz = off;
    }
    close(fd);
    *out_buf = buf;
    *out_len = sz;
    return 0;
}

/* Write `body` of `body_len` bytes to <root>/<coll>/<id>.json.
 * `excl` selects POST semantics (fail with EEXIST if file exists);
 * otherwise PUT semantics (atomic create-or-replace via tempfile + rename).
 *
 * Returns 0 on success, EEXIST if excl && file exists, or another errno
 * on failure. Auto-creates the {coll} directory on demand.
 */
static int write_file(const char* coll, size_t coll_len,
                      const char* id,   size_t id_len,
                      const char* body, size_t body_len,
                      bool excl) {
    int coll_fd = -1;
    int rc = open_collection_dir(coll, coll_len, true, &coll_fd);
    if (rc != 0) return rc;

    char fname[API_NAME_CAP + 6];
    rc = build_object_filename(fname, sizeof(fname), id, id_len);
    if (rc != 0) {
        close(coll_fd);
        return rc;
    }

    if (excl) {
        int fd = openat(coll_fd, fname,
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                        0600);
        if (fd < 0) {
            int e = errno;
            close(coll_fd);
            return e;
        }
        int e = write_all_fd(fd, body, body_len);
        if (e == 0 && fsync(fd) != 0) e = errno;
        if (close(fd) != 0 && e == 0) e = errno;
        if (e != 0) {
            (void)unlinkat(coll_fd, fname, 0);
            close(coll_fd);
            return e;
        }
        if (fsync(coll_fd) != 0) {
            e = errno;
            close(coll_fd);
            return e;
        }
        close(coll_fd);
        return 0;
    }

    /* PUT: tempfile + rename for atomic replace */
    char tmp[API_NAME_CAP + 32];
    /* tmp = .tmp.<id>.<pid>.<rand> */
    uint8_t r4[4] = {0};
    size_t r4_off = 0;
    while (r4_off < sizeof(r4)) {
        ssize_t g = getrandom(r4 + r4_off, sizeof(r4) - r4_off, 0);
        if (g < 0) {
            if (errno == EINTR) continue;
            break;
        }
        r4_off += (size_t)g;
    }
    int tn = snprintf(tmp, sizeof(tmp), ".tmp.%.*s.%d.%02x%02x%02x%02x",
                      (int)id_len, id, (int)getpid(),
                      r4[0], r4[1], r4[2], r4[3]);
    if (tn <= 0 || (size_t)tn >= sizeof(tmp)) {
        close(coll_fd);
        return ENAMETOOLONG;
    }

    int fd = openat(coll_fd, tmp,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
    if (fd < 0) {
        int e = errno;
        close(coll_fd);
        return e;
    }
    int e = write_all_fd(fd, body, body_len);
    if (e == 0 && fsync(fd) != 0) e = errno;
    if (close(fd) != 0 && e == 0) e = errno;
    if (e != 0) {
        (void)unlinkat(coll_fd, tmp, 0);
        close(coll_fd);
        return e;
    }
    if (renameat(coll_fd, tmp, coll_fd, fname) != 0) {
        e = errno;
        (void)unlinkat(coll_fd, tmp, 0);
        close(coll_fd);
        return e;
    }
    if (fsync(coll_fd) != 0) {
        e = errno;
        close(coll_fd);
        return e;
    }
    close(coll_fd);
    return 0;
}

static int delete_file(const char* coll, size_t coll_len,
                       const char* id, size_t id_len) {
    int coll_fd = -1;
    int d = open_collection_dir(coll, coll_len, false, &coll_fd);
    if (d == ENOENT) return -1;
    if (d != 0) return -3;

    char fname[API_NAME_CAP + 6];
    if (build_object_filename(fname, sizeof(fname), id, id_len) != 0) {
        close(coll_fd);
        return -3;
    }

    if (unlinkat(coll_fd, fname, 0) != 0) {
        int e = errno;
        close(coll_fd);
        if (e == ENOENT) return -1;
        return -3;
    }
    if (fsync(coll_fd) != 0) {
        close(coll_fd);
        return -3;
    }
    close(coll_fd);
    return 0;
}

static void dispatch_picowal_pack_record(http_method_t method, uint16_t meta_pack,
                                         const char* rec, size_t rec_len,
                                         const char* body, size_t body_len,
                                         const char* location_coll,
                                         api_resp_t* resp) {
    uint32_t pack_id = 0;
    if (!parse_u32_dec(rec, rec_len, PICOWAL_CARD_MAX, &pack_id)) {
        resp_text_error(resp, 400, "Bad Request", "invalid metadata pack id\n");
        return;
    }
    uint32_t key = 0;
    if (!picowal_db_pack_key(meta_pack, pack_id, &key)) {
        resp_text_error(resp, 400, "Bad Request", "invalid metadata key\n");
        return;
    }

    if (method == M_GET || method == M_HEAD) {
        char* buf = (char*)malloc(PICOWAL_DATA_MAX);
        if (!buf) {
            resp_text_error(resp, 500, "Internal Server Error", "oom\n");
            return;
        }
        int got = picowal_db_get_key(g_picowal, key, buf, PICOWAL_DATA_MAX);
        if (got < 0) {
            free(buf);
            if (errno == ENOENT) { resp_status_only(resp, 404, "Not Found"); return; }
            resp_text_error(resp, 500, "Internal Server Error", "metadata read failed\n");
            return;
        }
        resp_get_body(resp, buf, (size_t)got, method == M_HEAD);
        return;
    }

    if (method == M_PUT || method == M_POST) {
        if (body_len == 0 || body_len > PICOWAL_DATA_MAX) {
            resp_status_only(resp, 413, "Payload Too Large");
            return;
        }
        bool create_only = (method == M_POST);
        if (picowal_db_put_key(g_picowal, key, body, (uint32_t)body_len, create_only) != 0) {
            if (errno == EEXIST) { resp_status_only(resp, 409, "Conflict"); return; }
            if (errno == EBUSY) {
                resp_text_error(resp, 503, "Service Unavailable", "wal quiesced\n");
                return;
            }
            if (errno == ENOSPC) {
                resp_text_error(resp, 507, "Insufficient Storage", "wal volume full\n");
                return;
            }
            resp_text_error(resp, 500, "Internal Server Error", "metadata write failed\n");
            return;
        }
        if (method == M_POST) {
            resp_created(resp, g_picowal_prefix, location_coll, strlen(location_coll), rec, rec_len);
        } else {
            resp_status_only(resp, 204, "No Content");
        }
        return;
    }

    if (method == M_DELETE) {
        if (picowal_db_delete_key(g_picowal, key) != 0) {
            if (errno == ENOENT) { resp_status_only(resp, 404, "Not Found"); return; }
            if (errno == EBUSY) {
                resp_text_error(resp, 503, "Service Unavailable", "wal quiesced\n");
                return;
            }
            resp_text_error(resp, 500, "Internal Server Error", "metadata delete failed\n");
            return;
        }
        resp_status_only(resp, 204, "No Content");
        return;
    }

    resp_status_only(resp, 405, "Method Not Allowed");
}

static void dispatch_picowal(http_method_t method,
                             const char* path, size_t path_len,
                              const char* body, size_t body_len,
                             const char* cookie, size_t cookie_len,
                             bool has_pw_auth_header,
                             api_resp_t* resp) {
    if (path_len == g_picowal_prefix_len + 10 &&
        memcmp(path + g_picowal_prefix_len, "auth/login", 10) == 0) {
        if (!g_oidc_cookie_auth) {
            resp_status_only(resp, 404, "Not Found");
            return;
        }
        if (method != M_POST) {
            resp_status_only(resp, 405, "Method Not Allowed");
            return;
        }
        if (!has_pw_auth_header) {
            resp_text_error(resp, 403, "Forbidden", "missing X-PW-Auth header\n");
            return;
        }
        char provider[AUTH_PROVIDER_CAP];
        char token[API_REQ_BODY_CAP + 1];
        if (!parse_login_request(body, body_len, provider, sizeof(provider), token, sizeof(token))) {
            resp_text_error(resp, 400, "Bad Request", "expected JSON {\"provider\",\"access_token\"}\n");
            return;
        }
        char sub[AUTH_SUB_CAP + 1];
        char err[256] = {0};
        bool ok = false;
        if (strcmp(provider, "google") == 0) {
            ok = oidc_validate_google(token, sub, sizeof(sub), err, sizeof(err));
        } else if (strcmp(provider, "entra") == 0) {
            ok = oidc_validate_entra(token, sub, sizeof(sub), err, sizeof(err));
        } else {
            resp_text_error(resp, 400, "Bad Request", "provider must be google or entra\n");
            return;
        }
        if (!ok) {
            resp_text_error(resp, 401, "Unauthorized", err[0] ? err : "token validation failed\n");
            return;
        }
        char sid[AUTH_COOKIE_VALUE_CAP + 1];
        if (!auth_create_session(provider, sub, sid)) {
            resp_text_error(resp, 500, "Internal Server Error", "session create failed\n");
            return;
        }
        resp_cookie_status(resp, 204, "No Content", sid, g_oidc_cookie_ttl_sec);
        return;
    }

    if (path_len == g_picowal_prefix_len + 11 &&
        memcmp(path + g_picowal_prefix_len, "auth/logout", 11) == 0) {
        if (!g_oidc_cookie_auth) {
            resp_status_only(resp, 404, "Not Found");
            return;
        }
        if (method != M_POST) {
            resp_status_only(resp, 405, "Method Not Allowed");
            return;
        }
        if (!has_pw_auth_header) {
            resp_text_error(resp, 403, "Forbidden", "missing X-PW-Auth header\n");
            return;
        }
        char sid[AUTH_COOKIE_VALUE_CAP + 1];
        if (cookie_extract(cookie, cookie_len, AUTH_COOKIE_NAME, sid, sizeof(sid))) {
            auth_revoke_session(sid);
        }
        resp_cookie_status(resp, 204, "No Content", "", 0);
        return;
    }

    if (g_oidc_cookie_auth) {
        if (!has_pw_auth_header) {
            resp_text_error(resp, 403, "Forbidden", "missing X-PW-Auth header\n");
            return;
        }
        if (!auth_require_cookie(cookie, cookie_len, resp)) return;
    }

    if (path_len > g_picowal_prefix_len + 9 &&
        memcmp(path + g_picowal_prefix_len, "metadata/", 9) == 0) {
        const char* mp = path + g_picowal_prefix_len + 9;
        size_t mn = path_len - (g_picowal_prefix_len + 9);

        if (mn > 5 && memcmp(mp, "name/", 5) == 0) {
            dispatch_picowal_pack_record(method, 1, mp + 5, mn - 5,
                                         body, body_len, "metadata/name", resp);
            return;
        }
        if (mn > 7 && memcmp(mp, "schema/", 7) == 0) {
            dispatch_picowal_pack_record(method, 2, mp + 7, mn - 7,
                                         body, body_len, "metadata/schema", resp);
            return;
        }
        if (memchr(mp, '/', mn) != NULL) {
            resp_text_error(resp, 400, "Bad Request", "invalid metadata path\n");
            return;
        }

        /* Combined fetch wrapper: GET/HEAD /wal/metadata/{pack} */
        if (!(method == M_GET || method == M_HEAD)) {
            resp_status_only(resp, 405, "Method Not Allowed");
            return;
        }
        uint32_t pack_id = 0;
        if (!parse_u32_dec(mp, mn, PICOWAL_CARD_MAX, &pack_id)) {
            resp_text_error(resp, 400, "Bad Request", "invalid metadata pack id\n");
            return;
        }
        uint32_t k1 = 0, k2 = 0;
        (void)picowal_db_pack_key(1, pack_id, &k1);
        (void)picowal_db_pack_key(2, pack_id, &k2);

        char p1[PICOWAL_DATA_MAX + 1];
        char p2[PICOWAL_DATA_MAX + 1];
        int n1 = picowal_db_get_key(g_picowal, k1, p1, PICOWAL_DATA_MAX);
        int n2 = picowal_db_get_key(g_picowal, k2, p2, PICOWAL_DATA_MAX);
        if (n1 < 0 && n2 < 0) {
            resp_status_only(resp, 404, "Not Found");
            return;
        }
        if (n1 > 0) p1[n1] = '\0';
        if (n2 > 0) p2[n2] = '\0';

        size_t cap = (size_t)(PICOWAL_DATA_MAX * 2 + 256);
        char* out = (char*)malloc(cap);
        if (!out) {
            resp_text_error(resp, 500, "Internal Server Error", "oom\n");
            return;
        }
        int n = snprintf(out, cap,
                         "{\"pack\":%u,\"pack1\":%s,\"pack2\":%s}",
                         pack_id,
                         (n1 >= 0) ? p1 : "null",
                         (n2 >= 0) ? p2 : "null");
        if (n <= 0 || (size_t)n >= cap) {
            free(out);
            resp_text_error(resp, 500, "Internal Server Error", "metadata render failed\n");
            return;
        }
        resp_get_body(resp, out, (size_t)n, method == M_HEAD);
        return;
    }

    if (path_len > g_picowal_prefix_len + 6 &&
        memcmp(path + g_picowal_prefix_len, "forms/", 6) == 0) {
        if (!(method == M_GET || method == M_HEAD)) {
            resp_status_only(resp, 405, "Method Not Allowed");
            return;
        }
        const char* seg = path + g_picowal_prefix_len + 6;
        size_t seg_len = path_len - (g_picowal_prefix_len + 6);
        if (seg_len == 0 || memchr(seg, '/', seg_len) != NULL) {
            resp_text_error(resp, 400, "Bad Request", "invalid forms path\n");
            return;
        }
        uint32_t pack_id = 0;
        if (!parse_u32_dec(seg, seg_len, PICOWAL_CARD_MAX, &pack_id)) {
            resp_text_error(resp, 400, "Bad Request", "invalid form pack id\n");
            return;
        }
        char* form_json = NULL;
        size_t form_len = 0;
        int status = 500;
        char err[128] = {0};
        if (!picowal_build_form_spec(pack_id, &form_json, &form_len, &status, err, sizeof(err))) {
            if (!err[0]) snprintf(err, sizeof(err), "form generation failed");
            if (status == 404) {
                resp_status_only(resp, 404, "Not Found");
            } else if (status == 400) {
                resp_text_error(resp, 400, "Bad Request", err);
            } else {
                resp_text_error(resp, 500, "Internal Server Error", err);
            }
            return;
        }
        resp_get_body(resp, form_json, form_len, method == M_HEAD);
        return;
    }

    if (path_len == g_picowal_prefix_len + 6 &&
        memcmp(path + g_picowal_prefix_len, "report", 6) == 0) {
        if (method != M_POST) {
            resp_status_only(resp, 405, "Method Not Allowed");
            return;
        }
        char* out = NULL;
        size_t out_len = 0;
        int status = 500;
        char err[128] = {0};
        if (!picowal_build_report(body, body_len, &out, &out_len, &status, err, sizeof(err))) {
            if (!err[0]) snprintf(err, sizeof(err), "report generation failed");
            if (status == 400) resp_text_error(resp, 400, "Bad Request", err);
            else resp_text_error(resp, 500, "Internal Server Error", err);
            return;
        }
        resp_get_body(resp, out, out_len, false);
        return;
    }

    if (path_len == g_picowal_prefix_len + 9 &&
        memcmp(path + g_picowal_prefix_len, "dashboard", 9) == 0) {
        if (method != M_POST) {
            resp_status_only(resp, 405, "Method Not Allowed");
            return;
        }
        char* out = NULL;
        size_t out_len = 0;
        int status = 500;
        char err[128] = {0};
        if (!picowal_build_dashboard(body, body_len, &out, &out_len, &status, err, sizeof(err))) {
            if (!err[0]) snprintf(err, sizeof(err), "dashboard generation failed");
            if (status == 400) resp_text_error(resp, 400, "Bad Request", err);
            else resp_text_error(resp, 500, "Internal Server Error", err);
            return;
        }
        resp_get_body(resp, out, out_len, false);
        return;
    }

    if (path_len > g_picowal_prefix_len + 7 &&
        memcmp(path + g_picowal_prefix_len, "schema/", 7) == 0) {
        dispatch_picowal_pack_record(method, 2,
                                     path + g_picowal_prefix_len + 7,
                                     path_len - (g_picowal_prefix_len + 7),
                                     body, body_len, "schema", resp);
        return;
    }

    if (path_len == g_picowal_prefix_len + 5 &&
        memcmp(path + g_picowal_prefix_len, "query", 5) == 0) {
        if (method != M_POST) {
            resp_status_only(resp, 405, "Method Not Allowed");
            return;
        }
        if (body_len == 0 || body_len > PICOWAL_DATA_MAX) {
            resp_text_error(resp, 400, "Bad Request", "query body required\n");
            return;
        }
        char* qtxt = (char*)malloc(body_len + 1);
        if (!qtxt) {
            resp_text_error(resp, 500, "Internal Server Error", "oom\n");
            return;
        }
        memcpy(qtxt, body, body_len);
        qtxt[body_len] = '\0';

        char* out_json = NULL;
        size_t out_len = 0;
        char err[128] = {0};
        bool ok = picowal_query_run(g_picowal, qtxt, &out_json, &out_len, err, sizeof(err));
        free(qtxt);
        if (!ok) {
            if (!err[0]) snprintf(err, sizeof(err), "query failed");
            resp_text_error(resp, 400, "Bad Request", err);
            return;
        }
        resp_get_body(resp, out_json, out_len, false);
        return;
    }

    const char* coll = NULL; size_t coll_len = 0;
    const char* id   = NULL; size_t id_len   = 0;
    int parts = split_path(path, path_len, g_picowal_prefix_len, &coll, &coll_len, &id, &id_len);
    if (parts < 0) {
        resp_text_error(resp, 400, "Bad Request", "invalid wal path\n");
        return;
    }

    switch (method) {
    case M_GET:
    case M_HEAD: {
        if (id_len == 0) {
            resp_text_error(resp, 400, "Bad Request", "missing record id\n");
            return;
        }
        uint32_t key = 0;
        if (!picowal_path_to_key(coll, coll_len, id, id_len, &key)) {
            resp_text_error(resp, 400, "Bad Request", "invalid card/record\n");
            return;
        }
        char* buf = (char*)malloc(PICOWAL_DATA_MAX);
        if (!buf) {
            resp_text_error(resp, 500, "Internal Server Error", "oom\n");
            return;
        }
        int got = picowal_db_get_key(g_picowal, key, buf, PICOWAL_DATA_MAX);
        if (got < 0) {
            free(buf);
            if (errno == ENOENT) { resp_status_only(resp, 404, "Not Found"); return; }
            resp_text_error(resp, 500, "Internal Server Error", "wal read failed\n");
            return;
        }
        resp_get_body(resp, buf, (size_t)got, method == M_HEAD);
        return;
    }

    case M_PUT: {
        if (id_len == 0) {
            resp_text_error(resp, 400, "Bad Request", "missing record id\n");
            return;
        }
        if (body_len > PICOWAL_DATA_MAX) {
            resp_status_only(resp, 413, "Payload Too Large");
            return;
        }
        uint32_t key = 0;
        if (!picowal_path_to_key(coll, coll_len, id, id_len, &key)) {
            resp_text_error(resp, 400, "Bad Request", "invalid card/record\n");
            return;
        }
        uint16_t pack_id = 0;
        uint32_t record_id = 0;
        picowal_db_unpack_key(key, &pack_id, &record_id);
        int vstatus = 400;
        char verr[160] = {0};
        if (!picowal_validate_mutation(g_picowal, pack_id, record_id, PWV_OP_PUT,
                                       body, body_len, &vstatus, verr, sizeof(verr))) {
            if (vstatus == 409) resp_text_error(resp, 409, "Conflict", verr);
            else if (vstatus == 500) resp_text_error(resp, 500, "Internal Server Error", verr);
            else resp_text_error(resp, 400, "Bad Request", verr);
            return;
        }
        if (picowal_db_put_key(g_picowal, key, body, (uint32_t)body_len, false) != 0) {
            if (errno == EBUSY) {
                resp_text_error(resp, 503, "Service Unavailable", "wal quiesced\n");
                return;
            }
            if (errno == ENOSPC) {
                resp_text_error(resp, 507, "Insufficient Storage", "wal volume full\n");
                return;
            }
            resp_text_error(resp, 500, "Internal Server Error", "wal write failed\n");
            return;
        }
        resp_status_only(resp, 204, "No Content");
        return;
    }

    case M_POST: {
        if (body_len > PICOWAL_DATA_MAX) {
            resp_status_only(resp, 413, "Payload Too Large");
            return;
        }
        if (id_len == 0) {
            uint32_t card = 0;
            if (!parse_u32_dec(coll, coll_len, PICOWAL_CARD_MAX, &card)) {
                resp_text_error(resp, 400, "Bad Request", "invalid card\n");
                return;
            }
            int vstatus = 400;
            char verr[160] = {0};
            if (!picowal_validate_mutation(g_picowal, (uint16_t)card, UINT32_MAX, PWV_OP_POST,
                                           body, body_len, &vstatus, verr, sizeof(verr))) {
                if (vstatus == 409) resp_text_error(resp, 409, "Conflict", verr);
                else if (vstatus == 500) resp_text_error(resp, 500, "Internal Server Error", verr);
                else resp_text_error(resp, 400, "Bad Request", verr);
                return;
            }
            for (int attempt = 0; attempt < 32; attempt++) {
                uint32_t record = 0;
                if (getrandom(&record, sizeof(record), 0) != (ssize_t)sizeof(record)) {
                    continue;
                }
                record &= 0x003fffffu;
                uint32_t key = 0;
                if (!picowal_db_pack_key((uint16_t)card, record, &key)) continue;
                if (picowal_db_put_key(g_picowal, key, body, (uint32_t)body_len, true) == 0) {
                    char rid[16];
                    size_t rid_len = u32_to_dec(rid, sizeof(rid), record);
                    if (rid_len == 0) {
                        resp_text_error(resp, 500, "Internal Server Error", "id format failed\n");
                        return;
                    }
                    resp_created(resp, g_picowal_prefix, coll, coll_len, rid, rid_len);
                    return;
                }
                if (errno == ENOSPC) {
                    resp_text_error(resp, 507, "Insufficient Storage", "wal volume full\n");
                    return;
                }
                if (errno == EBUSY) {
                    resp_text_error(resp, 503, "Service Unavailable", "wal quiesced\n");
                    return;
                }
                if (errno != EEXIST) {
                    resp_text_error(resp, 500, "Internal Server Error", "wal write failed\n");
                    return;
                }
            }
            resp_text_error(resp, 500, "Internal Server Error", "id gen retries exhausted\n");
            return;
        }

        uint32_t key = 0;
        if (!picowal_path_to_key(coll, coll_len, id, id_len, &key)) {
            resp_text_error(resp, 400, "Bad Request", "invalid card/record\n");
            return;
        }
        uint16_t pack_id = 0;
        uint32_t record_id = 0;
        picowal_db_unpack_key(key, &pack_id, &record_id);
        int vstatus = 400;
        char verr[160] = {0};
        if (!picowal_validate_mutation(g_picowal, pack_id, record_id, PWV_OP_POST,
                                       body, body_len, &vstatus, verr, sizeof(verr))) {
            if (vstatus == 409) resp_text_error(resp, 409, "Conflict", verr);
            else if (vstatus == 500) resp_text_error(resp, 500, "Internal Server Error", verr);
            else resp_text_error(resp, 400, "Bad Request", verr);
            return;
        }
        if (picowal_db_put_key(g_picowal, key, body, (uint32_t)body_len, true) != 0) {
            if (errno == EEXIST) { resp_status_only(resp, 409, "Conflict"); return; }
            if (errno == EBUSY) {
                resp_text_error(resp, 503, "Service Unavailable", "wal quiesced\n");
                return;
            }
            if (errno == ENOSPC) {
                resp_text_error(resp, 507, "Insufficient Storage", "wal volume full\n");
                return;
            }
            resp_text_error(resp, 500, "Internal Server Error", "wal write failed\n");
            return;
        }
        resp_created(resp, g_picowal_prefix, coll, coll_len, id, id_len);
        return;
    }

    case M_DELETE: {
        if (id_len == 0) {
            resp_text_error(resp, 400, "Bad Request", "missing record id\n");
            return;
        }
        uint32_t key = 0;
        if (!picowal_path_to_key(coll, coll_len, id, id_len, &key)) {
            resp_text_error(resp, 400, "Bad Request", "invalid card/record\n");
            return;
        }
        uint16_t pack_id = 0;
        uint32_t record_id = 0;
        picowal_db_unpack_key(key, &pack_id, &record_id);
        int vstatus = 400;
        char verr[160] = {0};
        if (!picowal_validate_mutation(g_picowal, pack_id, record_id, PWV_OP_DELETE,
                                       NULL, 0, &vstatus, verr, sizeof(verr))) {
            if (vstatus == 409) resp_text_error(resp, 409, "Conflict", verr);
            else if (vstatus == 500) resp_text_error(resp, 500, "Internal Server Error", verr);
            else resp_text_error(resp, 400, "Bad Request", verr);
            return;
        }
        if (picowal_db_delete_key(g_picowal, key) != 0) {
            if (errno == ENOENT) { resp_status_only(resp, 404, "Not Found"); return; }
            if (errno == EBUSY) {
                resp_text_error(resp, 503, "Service Unavailable", "wal quiesced\n");
                return;
            }
            if (errno == ENOSPC) {
                resp_text_error(resp, 507, "Insufficient Storage", "wal volume full\n");
                return;
            }
            resp_text_error(resp, 500, "Internal Server Error", "wal delete failed\n");
            return;
        }
        resp_status_only(resp, 204, "No Content");
        return;
    }

    case M_UNKNOWN:
    default:
        resp_status_only(resp, 405, "Method Not Allowed");
        return;
    }
}

/* ---------- dispatcher ---------- */

void api_dispatch(http_method_t method,
                  const char* path, size_t path_len,
                  const char* body, size_t body_len,
                  const char* cookie, size_t cookie_len,
                  bool has_pw_auth_header,
                 const char* score_token, size_t score_token_len,
                 const api_request_context_t* req_ctx,
                 api_resp_t* resp) {
    memset(resp, 0, sizeof(*resp));
    if (api_health_path_matches(path, path_len)) {
        dispatch_health(method, path, path_len, resp);
        return;
    }
    if (method == M_OPTIONS) {
        if (score_path_matches(path, path_len) ||
            (g_picowal_enabled && g_picowal_public_http &&
             path_len >= g_picowal_prefix_len &&
             memcmp(path, g_picowal_prefix, g_picowal_prefix_len) == 0) ||
            (g_enabled &&
             path_len >= g_prefix_len &&
             memcmp(path, g_prefix, g_prefix_len) == 0)) {
            resp_status_only(resp, 204, "No Content");
        } else {
            resp_status_only(resp, 404, "Not Found");
        }
        return;
    }
    if (score_path_matches(path, path_len)) {
        dispatch_scores(method, path, path_len, body, body_len,
                        score_token, score_token_len, req_ctx, resp);
        return;
    }
    if (g_picowal_enabled && g_picowal_public_http &&
        path_len >= g_picowal_prefix_len &&
        memcmp(path, g_picowal_prefix, g_picowal_prefix_len) == 0) {
        dispatch_picowal(method, path, path_len, body, body_len,
                         cookie, cookie_len, has_pw_auth_header, resp);
        return;
    }
    if (!g_enabled ||
        path_len < g_prefix_len ||
        memcmp(path, g_prefix, g_prefix_len) != 0) {
        resp_status_only(resp, 404, "Not Found");
        return;
    }

    const char* coll = NULL; size_t coll_len = 0;
    const char* id   = NULL; size_t id_len   = 0;
    int parts = split_path(path, path_len, g_prefix_len, &coll, &coll_len, &id, &id_len);
    if (parts < 0 || !is_valid_name(coll, coll_len)) {
        resp_text_error(resp, 400, "Bad Request", "invalid path\n");
        return;
    }
    if (id_len > 0 && !is_valid_name(id, id_len)) {
        resp_text_error(resp, 400, "Bad Request", "invalid id\n");
        return;
    }

    switch (method) {
    case M_GET:
    case M_HEAD: {
        if (id_len == 0) {
            resp_text_error(resp, 400, "Bad Request", "missing id\n");
            return;
        }
        char* buf = NULL; size_t blen = 0;
        int rc = read_file_full(coll, coll_len, id, id_len, &buf, &blen);
        if (rc == -1) { resp_status_only(resp, 404, "Not Found"); return; }
        if (rc == -2) { resp_text_error(resp, 500, "Internal Server Error", "object too large\n"); return; }
        if (rc < 0)   { resp_text_error(resp, 500, "Internal Server Error", "read failed\n"); return; }
        resp_get_body(resp, buf, blen, method == M_HEAD);
        return;
    }

    case M_PUT: {
        if (id_len == 0) {
            resp_text_error(resp, 400, "Bad Request", "missing id\n");
            return;
        }
        if (body_len > API_REQ_BODY_CAP) {
            resp_status_only(resp, 413, "Payload Too Large");
            return;
        }
        int rc = write_file(coll, coll_len, id, id_len, body, body_len, false);
        if (rc != 0) {
            resp_text_error(resp, 500, "Internal Server Error", "write failed\n");
            return;
        }
        resp_status_only(resp, 204, "No Content");
        return;
    }

    case M_POST: {
        if (body_len > API_REQ_BODY_CAP) {
            resp_status_only(resp, 413, "Payload Too Large");
            return;
        }
        if (id_len == 0) {
            /* Auto-generate id; loop on the unlikely EEXIST. */
            char gen[33];
            for (int attempt = 0; attempt < 8; attempt++) {
                if (!gen_id(gen)) {
                    resp_text_error(resp, 500, "Internal Server Error", "id gen failed\n");
                    return;
                }
                int rc = write_file(coll, coll_len, gen, 32, body, body_len, true);
                if (rc == 0) { resp_created(resp, g_prefix, coll, coll_len, gen, 32); return; }
                if (rc != EEXIST) {
                    resp_text_error(resp, 500, "Internal Server Error", "write failed\n");
                    return;
                }
            }
            resp_text_error(resp, 500, "Internal Server Error", "id gen retries exhausted\n");
            return;
        }
        /* Explicit id: create-only */
        int rc = write_file(coll, coll_len, id, id_len, body, body_len, true);
        if (rc == EEXIST) { resp_status_only(resp, 409, "Conflict"); return; }
        if (rc != 0)      { resp_text_error(resp, 500, "Internal Server Error", "write failed\n"); return; }
        resp_created(resp, g_prefix, coll, coll_len, id, id_len);
        return;
    }

    case M_DELETE: {
        if (id_len == 0) {
            resp_text_error(resp, 400, "Bad Request", "missing id\n");
            return;
        }
        int rc = delete_file(coll, coll_len, id, id_len);
        if (rc == -1) { resp_status_only(resp, 404, "Not Found"); return; }
        if (rc != 0)  { resp_text_error(resp, 500, "Internal Server Error", "delete failed\n"); return; }
        resp_status_only(resp, 204, "No Content");
        return;
    }

    case M_UNKNOWN:
    default:
        resp_status_only(resp, 405, "Method Not Allowed");
        return;
    }
}

void api_resp_release(api_resp_t* resp) {
    if (!resp) return;
    if (resp->body_owned && resp->body) {
        free(resp->body);
    }
    resp->body = NULL;
    resp->body_len = 0;
    resp->body_owned = false;
}
