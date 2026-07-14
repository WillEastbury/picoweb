/* picowal_gossip.c — quorum-based leader election over a static
 * registered-follower set. See picowal_gossip.h for the protocol and
 * its deliberate limitations. */

#include "picowal_gossip.h"
#include "picowal_repl.h"
#include "picowal_repl_client.h"
#include "security_headers.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define GOSSIP_MAX_FOLLOWERS   32
#define GOSSIP_ID_MAX          64
#define GOSSIP_TOKEN_MAX       128
#define GOSSIP_PREFIX_MAX      64
#define GOSSIP_TICK_MS         500   /* how often we re-evaluate/re-gossip */
#define GOSSIP_CONNECT_MS      1000  /* best-effort vote POST: short, fire-and-forget */

typedef struct {
    char id[GOSSIP_ID_MAX];
} gossip_follower_t;

static gossip_follower_t g_followers[GOSSIP_MAX_FOLLOWERS];
static int   g_n_followers = 0;
static char  g_self_id[GOSSIP_ID_MAX] = {0};
static int   g_self_idx = -1;
static char  g_token[GOSSIP_TOKEN_MAX] = {0};
static char  g_repl_prefix[GOSSIP_PREFIX_MAX] = {0};
static char  g_prefix[GOSSIP_PREFIX_MAX] = "/gossip/";
static size_t g_prefix_len = 8;
static bool  g_enabled = false;
static picowal_db_t* g_db = NULL;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int      g_term = 0;
static char     g_candidate[GOSSIP_ID_MAX] = {0};
static uint32_t g_vote_bitmask = 0;   /* bit i set => g_followers[i] voted for g_candidate this term */
static volatile bool g_promoted = false;
static bool     g_dead[GOSSIP_MAX_FOLLOWERS] = {0}; /* g_dead[i] => g_followers[i] conclusively failed health checks while it was the known leader; excluded from pick_candidate() so re-election makes forward progress instead of re-nominating the same dead node forever */
static char     g_known_leader[GOSSIP_ID_MAX] = {0}; /* symmetric: every follower learns this the moment quorum is reached for ANY candidate, not just the winner -- see picowal_gossip.h's split-brain caveat and this file's retarget_to_leader() */

bool picowal_gossip_enabled(void) { return g_enabled; }
bool picowal_gossip_is_leader(void) { return g_promoted; }

static int find_follower(const char* id) {
    for (int i = 0; i < g_n_followers; i++) {
        if (strcmp(g_followers[i].id, id) == 0) return i;
    }
    return -1;
}

/* Deterministic candidate pick: lexicographically-smallest registered
 * follower id EXCLUDING any id already conclusively shown unhealthy
 * this process's lifetime (g_dead). Every follower computes the same
 * answer independently, so no separate campaign/nomination round-trip
 * is needed -- they all converge on one candidate for a given
 * election.
 *
 * The g_dead exclusion is NOT cosmetic: without it, once the
 * alphabetically-smallest follower id has been elected and later ALSO
 * dies (a normal, expected event -- leaders fail more than once over a
 * cluster's lifetime), every remaining follower would keep
 * "re-electing" that same dead node on every subsequent failure
 * forever, since plain lexicographic order never changes. Nobody can
 * ever vote a dead node back into quorum, so election would simply
 * never make forward progress past the second leader failure. */
static const char* pick_candidate(void) {
    const char* best = NULL;
    for (int i = 0; i < g_n_followers; i++) {
        if (g_dead[i]) continue;
        if (!best || strcmp(g_followers[i].id, best) < 0) best = g_followers[i].id;
    }
    if (best) return best;
    /* All registered followers marked dead (shouldn't happen with a
     * live quorum still ticking) -- fall back to the plain rule rather
     * than nominating nothing. */
    best = g_followers[0].id;
    for (int i = 1; i < g_n_followers; i++) {
        if (strcmp(g_followers[i].id, best) < 0) best = g_followers[i].id;
    }
    return best;
}

static int popcount32(uint32_t v) {
    int n = 0;
    while (v) { n += (int)(v & 1u); v >>= 1; }
    return n;
}

/* Must be called with g_lock held. Handles BOTH sides of quorum being
 * reached for the current (term, g_candidate):
 *   - Symmetric leader confirmation: the moment votes >= quorum for
 *     ANY candidate (not just this node), records it in g_known_leader
 *     and writes it to *out_new_leader (empty string if nothing new
 *     this call) -- vote tallying is inherently symmetric (every
 *     follower can independently count the same ballots), so there is
 *     no reason only the winner should learn who won. Callers use
 *     out_new_leader to retarget picowal_repl_client OUTSIDE this lock
 *     (network I/O must never happen while g_lock is held).
 *   - Self-promotion: unchanged from the original design -- if the
 *     confirmed candidate is THIS node, flips to writer.
 * out_new_leader must point at a buffer of at least GOSSIP_ID_MAX
 * bytes; may be NULL if the caller doesn't need it (nothing else in
 * this file needs it, but kept as a parameter rather than a global for
 * clarity about what changed on a given call). */
static void check_quorum_locked(char* out_new_leader) {
    if (out_new_leader) out_new_leader[0] = '\0';
    if (g_candidate[0] == '\0') return;
    int votes = popcount32(g_vote_bitmask);
    int quorum = g_n_followers / 2 + 1; /* strictly > 50% of registered followers */
    if (votes < quorum) return;

    if (strcmp(g_known_leader, g_candidate) != 0) {
        snprintf(g_known_leader, sizeof(g_known_leader), "%s", g_candidate);
        if (out_new_leader) snprintf(out_new_leader, GOSSIP_ID_MAX, "%s", g_candidate);
    }

    if (g_promoted || strcmp(g_candidate, g_self_id) != 0) return; /* someone else won, or we already promoted earlier */

    g_promoted = true;
    fprintf(stderr, "picowal_gossip: *** %s PROMOTED TO LEADER (WRITER) via gossip quorum "
            "(term=%d, votes=%d/%d, quorum=%d) ***\n",
            g_self_id, g_term, votes, g_n_followers, quorum);
    picowal_repl_client_stop();
    picowal_db_set_read_only(g_db, false);
    if (!picowal_repl_enabled() && g_repl_prefix[0]) {
        if (!picowal_repl_init(g_repl_prefix)) {
            fprintf(stderr, "picowal_gossip: warning: failed to start repl feed "
                    "after promotion (prefix='%s')\n", g_repl_prefix);
        }
    }
}

/* Builds the "http://host:port/prefix/" URL to hand to
 * picowal_repl_client_retarget() for the given follower id, assuming
 * (as this whole design already does for --picowal-followers to be
 * meaningful at all) every cluster member uses the SAME
 * --picowal-repl-prefix convention. */
static void build_primary_url(const char* id, char* out, size_t out_cap) {
    snprintf(out, out_cap, "http://%s%s", id, g_repl_prefix[0] ? g_repl_prefix : "/repl/");
}

/* Adopts a (term, candidate) if it supersedes what we have, recording
 * voter's ballot. Must be called with g_lock held. Writes the newly-
 * confirmed leader (if any) to out_new_leader -- see
 * check_quorum_locked's doc comment; caller retargets OUTSIDE the
 * lock. */
static void record_vote_locked(int term, const char* candidate, const char* voter, char* out_new_leader) {
    if (out_new_leader) out_new_leader[0] = '\0';
    if (term > g_term) {
        g_term = term;
        snprintf(g_candidate, sizeof(g_candidate), "%s", candidate);
        g_vote_bitmask = 0;
    } else if (term == g_term && g_candidate[0] == '\0') {
        snprintf(g_candidate, sizeof(g_candidate), "%s", candidate);
    }
    if (term != g_term || strcmp(candidate, g_candidate) != 0) return; /* stale/mismatched ballot */
    int vi = find_follower(voter);
    if (vi >= 0) g_vote_bitmask |= (1u << vi);
    check_quorum_locked(out_new_leader);
}

/* ---- best-effort fire-and-forget vote broadcast ------------------- */

static bool split_host_port(const char* id, char* host, size_t host_cap, int* port) {
    const char* colon = strrchr(id, ':');
    if (!colon) return false;
    size_t hlen = (size_t)(colon - id);
    if (hlen == 0 || hlen >= host_cap) return false;
    memcpy(host, id, hlen);
    host[hlen] = '\0';
    *port = atoi(colon + 1);
    return *port > 0 && *port <= 65535;
}

static void gossip_post_vote(const char* peer_id, int term, const char* candidate) {
    char host[GOSSIP_ID_MAX];
    int port = 0;
    if (!split_host_port(peer_id, host, sizeof(host), &port)) return;

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return;

    int fd = -1;
    for (struct addrinfo* a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int cr = connect(fd, a->ai_addr, a->ai_addrlen);
        if (cr == 0) {
            /* connected immediately */
        } else if (errno == EINPROGRESS) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            int pr = poll(&pfd, 1, GOSSIP_CONNECT_MS);
            int soerr = 0; socklen_t solen = sizeof(soerr);
            if (pr <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &solen) != 0 || soerr != 0) {
                close(fd); fd = -1; continue;
            }
        } else {
            close(fd); fd = -1; continue;
        }
        if (flags >= 0) fcntl(fd, F_SETFL, flags);
        struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        break;
    }
    freeaddrinfo(res);
    if (fd < 0) return; /* peer unreachable -- fine, best-effort */

    char body[192];
    int blen = snprintf(body, sizeof(body), "term=%d&candidate=%s&voter=%s",
                        term, candidate, g_self_id);
    char req[384];
    int n = snprintf(req, sizeof(req),
                     "POST %svote HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "X-PW-Write-Token: %s\r\n"
                     "Content-Length: %d\r\n"
                     "Connection: close\r\n"
                     "\r\n%s",
                     g_prefix, host, g_token, blen, body);
    if (n > 0 && (size_t)n < sizeof(req)) {
        size_t sent = 0;
        while (sent < (size_t)n) {
            ssize_t w = send(fd, req + sent, (size_t)n - sent, 0);
            if (w <= 0) break;
            sent += (size_t)w;
        }
        /* Drain/discard the response; we don't need it. Bounded by the
         * same SO_RCVTIMEO set above so this never blocks long. */
        char tmp[256];
        while (recv(fd, tmp, sizeof(tmp), 0) > 0) { /* discard */ }
    }
    close(fd);
}

static void* gossip_thread(void* arg) {
    (void)arg;
    for (;;) {
        usleep(GOSSIP_TICK_MS * 1000);
        if (g_promoted) continue; /* already leader; nothing left to elect */

        if (picowal_repl_client_primary_healthy()) {
            /* Primary looks fine -- clear any stale in-progress election
             * state so a future real failure starts a clean term. */
            pthread_mutex_lock(&g_lock);
            g_candidate[0] = '\0';
            g_vote_bitmask = 0;
            pthread_mutex_unlock(&g_lock);
            continue;
        }

        pthread_mutex_lock(&g_lock);
        if (g_known_leader[0] != '\0') {
            /* The confirmed leader we were following (and, once
             * retargeted, actually polling) has failed enough
             * consecutive health checks -- blacklist it so
             * pick_candidate() below makes forward progress instead of
             * re-nominating the same dead node forever (see
             * pick_candidate's doc comment for why this matters). */
            int di = find_follower(g_known_leader);
            if (di >= 0) g_dead[di] = true;
            fprintf(stderr, "picowal_gossip: known leader %s is unhealthy -- blacklisting it "
                    "and starting a new election\n", g_known_leader);
            g_known_leader[0] = '\0';
        }
        const char* candidate = pick_candidate();
        if (strcmp(candidate, g_candidate) != 0) {
            g_term++;
            snprintf(g_candidate, sizeof(g_candidate), "%s", candidate);
            g_vote_bitmask = 0;
            fprintf(stderr, "picowal_gossip: primary unhealthy -- starting election "
                    "term=%d, nominating %s\n", g_term, g_candidate);
        }
        if (g_self_idx >= 0) g_vote_bitmask |= (1u << g_self_idx);
        int term = g_term;
        char candidate_copy[GOSSIP_ID_MAX];
        snprintf(candidate_copy, sizeof(candidate_copy), "%s", g_candidate);
        char new_leader[GOSSIP_ID_MAX];
        check_quorum_locked(new_leader);
        pthread_mutex_unlock(&g_lock);

        if (new_leader[0] != '\0' && strcmp(new_leader, g_self_id) != 0) {
            /* Quorum just confirmed a DIFFERENT node as leader -- follow
             * it (see picowal_repl_client_retarget's doc comment for why
             * this is necessary: without it, only the winner itself
             * would ever learn it won, and every other follower would
             * stay stuck polling whatever primary they started with). */
            char url[GOSSIP_ID_MAX + 32];
            build_primary_url(new_leader, url, sizeof(url));
            picowal_repl_client_retarget(url);
        }

        for (int i = 0; i < g_n_followers; i++) {
            if (strcmp(g_followers[i].id, g_self_id) == 0) continue;
            gossip_post_vote(g_followers[i].id, term, candidate_copy);
        }
    }
    return NULL;
}

bool picowal_gossip_init(const char* self_id, const char* followers_csv,
                          const char* write_token, picowal_db_t* db,
                          const char* repl_prefix) {
    g_enabled = false;
    if (!self_id || !followers_csv || !write_token || !write_token[0] || !db) return false;
    if (strlen(self_id) >= sizeof(g_self_id)) return false;
    if (strlen(write_token) >= sizeof(g_token)) return false;

    g_n_followers = 0;
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", followers_csv);
    char* saveptr = NULL;
    char* tok = strtok_r(buf, ",", &saveptr);
    while (tok) {
        while (*tok == ' ') tok++;
        if (*tok) {
            if (g_n_followers >= GOSSIP_MAX_FOLLOWERS) {
                fprintf(stderr, "picowal_gossip: too many --picowal-followers entries "
                        "(max %d)\n", GOSSIP_MAX_FOLLOWERS);
                return false;
            }
            if (strlen(tok) >= sizeof(g_followers[0].id)) {
                fprintf(stderr, "picowal_gossip: follower id too long: '%s'\n", tok);
                return false;
            }
            snprintf(g_followers[g_n_followers].id, sizeof(g_followers[0].id), "%s", tok);
            g_n_followers++;
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
    if (g_n_followers < 1) {
        fprintf(stderr, "picowal_gossip: --picowal-followers must list at least one id\n");
        return false;
    }

    snprintf(g_self_id, sizeof(g_self_id), "%s", self_id);
    g_self_idx = find_follower(g_self_id);
    if (g_self_idx < 0) {
        fprintf(stderr, "picowal_gossip: --picowal-node-id '%s' is not present in "
                "--picowal-followers; this node can relay votes but can never be "
                "elected itself\n", g_self_id);
    }
    snprintf(g_token, sizeof(g_token), "%s", write_token);
    if (repl_prefix) snprintf(g_repl_prefix, sizeof(g_repl_prefix), "%s", repl_prefix);
    g_db = db;
    g_term = 0;
    g_candidate[0] = '\0';
    g_vote_bitmask = 0;
    g_promoted = false;

    pthread_t th;
    if (pthread_create(&th, NULL, gossip_thread, NULL) != 0) return false;
    pthread_detach(th);
    g_enabled = true;
    fprintf(stderr, "picowal_gossip: enabled, self=%s, followers=%d, prefix=%s\n",
            g_self_id, g_n_followers, g_prefix);
    return true;
}

bool picowal_gossip_path_matches(const char* path, size_t path_len) {
    return g_enabled && path_len >= g_prefix_len &&
           memcmp(path, g_prefix, g_prefix_len) == 0;
}

static void resp_status_only(api_resp_t* r, int status, const char* reason) {
    r->status = status;
    r->head_len = (size_t)snprintf(r->head, sizeof(r->head),
                                   "HTTP/1.1 %d %s\r\n"
                                   "Server: picoweb\r\n"
                                   "Content-Length: 0\r\n"
                                   PICOWEB_SECURITY_HEADERS,
                                   status, reason);
}

static void resp_json(api_resp_t* r, const char* json, size_t len) {
    r->status = 200;
    r->head_len = (size_t)snprintf(r->head, sizeof(r->head),
                                   "HTTP/1.1 200 OK\r\n"
                                   "Server: picoweb\r\n"
                                   "Content-Type: application/json\r\n"
                                   "Content-Length: %zu\r\n"
                                   PICOWEB_SECURITY_HEADERS
                                   "Cache-Control: no-store\r\n",
                                   len);
    r->body = (char*)malloc(len);
    if (r->body) { memcpy(r->body, json, len); r->body_len = len; r->body_owned = true; }
}

/* Tiny "key=value&key=value" form decoder -- the only shape gossip_post_vote
 * ever emits. */
static bool form_field(const char* body, size_t body_len, const char* key,
                       char* out, size_t out_cap) {
    size_t klen = strlen(key);
    size_t i = 0;
    while (i < body_len) {
        size_t j = i;
        while (j < body_len && body[j] != '&') j++;
        if (j - i > klen && body[i + klen] == '=' && memcmp(body + i, key, klen) == 0) {
            size_t vlen = (j - i - klen - 1);
            if (vlen >= out_cap) vlen = out_cap - 1;
            memcpy(out, body + i + klen + 1, vlen);
            out[vlen] = '\0';
            return true;
        }
        i = j + 1;
    }
    return false;
}

void picowal_gossip_dispatch(http_method_t method,
                              const char* path, size_t path_len,
                              const char* body, size_t body_len,
                              const char* write_token, size_t write_token_len,
                              api_resp_t* resp) {
    if (!api_require_write_token(write_token, write_token_len, resp)) return;

    const char* rest = path + g_prefix_len;
    size_t rest_len = path_len - g_prefix_len;

    if (method == M_GET && rest_len == 6 && memcmp(rest, "status", 6) == 0) {
        pthread_mutex_lock(&g_lock);
        char json[320];
        int n = snprintf(json, sizeof(json),
                         "{\"self\":\"%s\",\"term\":%d,\"candidate\":\"%s\","
                         "\"votes\":%d,\"followers\":%d,\"quorum\":%d,\"promoted\":%s,"
                         "\"known_leader\":\"%s\"}",
                         g_self_id, g_term, g_candidate, popcount32(g_vote_bitmask),
                         g_n_followers, g_n_followers / 2 + 1,
                         g_promoted ? "true" : "false", g_known_leader);
        pthread_mutex_unlock(&g_lock);
        resp_json(resp, json, (size_t)n);
        return;
    }

    if (method == M_POST && rest_len == 4 && memcmp(rest, "vote", 4) == 0) {
        char term_s[16] = {0}, candidate[GOSSIP_ID_MAX] = {0}, voter[GOSSIP_ID_MAX] = {0};
        if (!form_field(body, body_len, "term", term_s, sizeof(term_s)) ||
            !form_field(body, body_len, "candidate", candidate, sizeof(candidate)) ||
            !form_field(body, body_len, "voter", voter, sizeof(voter))) {
            resp_status_only(resp, 400, "Bad Request");
            return;
        }
        int term = atoi(term_s);
        pthread_mutex_lock(&g_lock);
        char new_leader[GOSSIP_ID_MAX];
        record_vote_locked(term, candidate, voter, new_leader);
        pthread_mutex_unlock(&g_lock);
        if (new_leader[0] != '\0' && strcmp(new_leader, g_self_id) != 0) {
            /* Same symmetric retarget as gossip_thread's self-vote path
             * -- this HTTP-received vote is what pushed quorum over the
             * line for THIS follower's view, so retarget here too
             * (network I/O deliberately kept outside g_lock above). */
            char url[GOSSIP_ID_MAX + 32];
            build_primary_url(new_leader, url, sizeof(url));
            picowal_repl_client_retarget(url);
        }
        resp_status_only(resp, 204, "No Content");
        return;
    }

    resp_status_only(resp, 404, "Not Found");
}
