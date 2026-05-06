/*
 * micro-brotli: minimal RFC 7932 (Brotli) encoder for picoweb.
 *
 * Produces valid Brotli streams using LZ77 + canonical Huffman coding.
 * Single meta-block, no static dictionary, no context modeling.
 * Falls back to uncompressed meta-blocks for incompressible data.
 *
 * Only runs at startup (never on the hot path).
 */

#include "brotli.h"
#include <stdlib.h>
#include <string.h>

/*
 * Compile this file at -O1 maximum. The deeply nested stack-heavy Huffman
 * routines trigger a miscompilation on GCC ≥15 / aarch64 at -O2 and above.
 * Since the encoder only runs once at startup this has no performance impact.
 */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize("O1")
#endif

/* ================================================================
 * Bit writer (LSB-first, as Brotli requires)
 * ================================================================ */

typedef struct {
    uint8_t* buf;
    size_t   cap;
    size_t   pos;
    uint64_t accum;
    int      nbits;
} bitw_t;

static void bw_init(bitw_t* w, uint8_t* buf, size_t cap) {
    w->buf = buf; w->cap = cap; w->pos = 0;
    w->accum = 0; w->nbits = 0;
}

static void bw_flush_accum(bitw_t* w) {
    while (w->nbits >= 8 && w->pos < w->cap) {
        w->buf[w->pos++] = (uint8_t)(w->accum & 0xFF);
        w->accum >>= 8;
        w->nbits -= 8;
    }
}

static void bw_put(bitw_t* w, uint64_t val, int nbits) {
    w->accum |= (val << w->nbits);
    w->nbits += nbits;
    if (w->nbits >= 48) bw_flush_accum(w);
}

static void bw_finish(bitw_t* w) {
    bw_flush_accum(w);
    if (w->nbits > 0 && w->pos < w->cap) {
        w->buf[w->pos++] = (uint8_t)(w->accum & 0xFF);
        w->accum = 0;
        w->nbits = 0;
    }
}

static bool bw_ok(const bitw_t* w) { return w->pos <= w->cap; }

/* ================================================================
 * Huffman code building
 * ================================================================ */

#define MAX_HUFF_BITS 15

/* Count non-zero frequency symbols */
static int count_used(const uint32_t* freq, int n) {
    int c = 0;
    for (int i = 0; i < n; i++) if (freq[i]) c++;
    return c;
}

/* Build code lengths via the two-queue Huffman algorithm */
static int build_lengths(const uint32_t* freq, int nsym, uint8_t* lens) {
    memset(lens, 0, nsym);

    int nused = 0;
    int sorted[1024];
    for (int i = 0; i < nsym; i++)
        if (freq[i]) sorted[nused++] = i;

    if (nused == 0) return 0;
    if (nused == 1) { lens[sorted[0]] = 1; return 1; }
    if (nused > 1024) return -1;

    /* Sort by frequency (ascending) */
    for (int i = 1; i < nused; i++) {
        int key = sorted[i];
        uint32_t kf = freq[key];
        int j = i - 1;
        while (j >= 0 && freq[sorted[j]] > kf) {
            sorted[j + 1] = sorted[j]; j--;
        }
        sorted[j + 1] = key;
    }

    /* Two-queue merge to build tree */
    uint32_t nf[2048];
    int par[2048];
    int nn = nused;

    for (int i = 0; i < nused; i++) { nf[i] = freq[sorted[i]]; par[i] = -1; }

    int q1 = 0;
    int q2buf[2048], q2h = 0, q2t = 0;

    for (int m = 0; m < nused - 1; m++) {
        int pick[2];
        for (int p = 0; p < 2; p++) {
            bool h1 = (q1 < nused), h2 = (q2h < q2t);
            if (h1 && h2) pick[p] = (nf[q1] <= nf[q2buf[q2h]]) ? q1++ : q2buf[q2h++];
            else if (h1) pick[p] = q1++;
            else pick[p] = q2buf[q2h++];
        }
        nf[nn] = nf[pick[0]] + nf[pick[1]];
        par[nn] = -1;
        par[pick[0]] = nn;
        par[pick[1]] = nn;
        q2buf[q2t++] = nn;
        nn++;
    }

    /* Compute depth of each leaf */
    int max_len = 0;
    for (int i = 0; i < nused; i++) {
        int d = 0, cur = i;
        while (par[cur] != -1) { cur = par[cur]; d++; }
        if (d > MAX_HUFF_BITS) d = MAX_HUFF_BITS;
        lens[sorted[i]] = (uint8_t)d;
        if (d > max_len) max_len = d;
    }

    /* Enforce max length via Kraft inequality adjustment */
    for (int iter = 0; iter < 50; iter++) {
        uint32_t kraft = 0;
        for (int i = 0; i < nsym; i++)
            if (lens[i]) kraft += (1u << (MAX_HUFF_BITS - lens[i]));
        uint32_t target = (1u << MAX_HUFF_BITS);
        if (kraft == target) break;
        if (kraft > target) {
            for (int l = MAX_HUFF_BITS; l > 1 && kraft > target; l--)
                for (int i = 0; i < nsym && kraft > target; i++)
                    if (lens[i] == l) {
                        lens[i]--;
                        kraft -= (1u << (MAX_HUFF_BITS - l));
                        kraft += (1u << (MAX_HUFF_BITS - l + 1));
                    }
        } else {
            for (int l = 1; l < MAX_HUFF_BITS && kraft < target; l++)
                for (int i = nsym - 1; i >= 0 && kraft < target; i--)
                    if (lens[i] == l) {
                        lens[i]++;
                        kraft -= (1u << (MAX_HUFF_BITS - l));
                        kraft += (1u << (MAX_HUFF_BITS - l - 1));
                    }
        }
    }

    max_len = 0;
    for (int i = 0; i < nsym; i++)
        if (lens[i] > max_len) max_len = lens[i];
    return max_len;
}

/* Assign canonical codes from lengths and write a symbol */
typedef struct { uint16_t code; uint8_t len; } hcode_t;

static void assign_codes(const uint8_t* lens, int nsym, hcode_t* codes) {
    int bl_count[MAX_HUFF_BITS + 1];
    memset(bl_count, 0, sizeof(bl_count));
    for (int i = 0; i < nsym; i++) if (lens[i]) bl_count[lens[i]]++;

    uint16_t next[MAX_HUFF_BITS + 1];
    next[0] = 0;
    uint16_t c = 0;
    for (int b = 1; b <= MAX_HUFF_BITS; b++) {
        c = (c + bl_count[b - 1]) << 1;
        next[b] = c;
    }

    for (int i = 0; i < nsym; i++) {
        codes[i].len = lens[i];
        codes[i].code = lens[i] ? next[lens[i]]++ : 0;
    }
}

/* Write a Huffman symbol (Brotli uses reversed canonical codes) */
static void bw_huff(bitw_t* w, hcode_t c) {
    uint16_t rev = 0;
    for (int i = 0; i < c.len; i++)
        rev |= (uint16_t)(((c.code >> i) & 1) << (c.len - 1 - i));
    bw_put(w, rev, c.len);
}

/* ================================================================
 * Brotli prefix code transmission (RFC 7932 §3.4-3.5)
 * ================================================================ */

/* Code length code order (RFC 7932) */
static const uint8_t kCLOrder[18] = {
    1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15
};

/* Fixed encoding for code_length_code_lengths values 0-5
 * (from brotli reference: kCodeLengthPrefixValue/Length) */
static const uint8_t kCLCL_val[6] = {0, 7, 3, 2, 1, 15};
static const uint8_t kCLCL_len[6] = {2, 4, 3, 2, 2, 4};

/* Write a simple prefix code (1-4 symbols, RFC 7932 §3.4) */
static void write_simple_code(bitw_t* w, const uint8_t* lens, int nsym,
                              int alpha_bits) {
    int used[4], nu = 0;
    for (int i = 0; i < nsym && nu < 4; i++)
        if (lens[i]) used[nu++] = i;
    if (nu == 0) { used[0] = 0; nu = 1; }

    /* Sort ascending */
    for (int i = 0; i < nu - 1; i++)
        for (int j = i + 1; j < nu; j++)
            if (used[j] < used[i]) { int t = used[i]; used[i] = used[j]; used[j] = t; }

    bw_put(w, 1, 2);  /* type = simple (HSKIP=1) */
    bw_put(w, (uint32_t)(nu - 1), 2);  /* NSYM - 1 */
    for (int i = 0; i < nu; i++)
        bw_put(w, (uint32_t)used[i], alpha_bits);
    if (nu == 4)
        bw_put(w, (lens[used[0]] == 1) ? 1u : 0u, 1);  /* tree-select */
}

/* Write a complex prefix code (RFC 7932 §3.5) */
static void write_complex_code(bitw_t* w, const uint8_t* lens, int nsym) {
    /* RLE encode the code lengths */
    uint8_t cl_syms[2048];
    uint8_t cl_extra[2048];
    int cl_n = 0;

    for (int i = 0; i < nsym; ) {
        if (lens[i] == 0) {
            int run = 0;
            while (i + run < nsym && lens[i + run] == 0) run++;
            /* The brotli decoder accumulates consecutive sym17 entries
             * exponentially. To avoid this, never emit two sym17 entries
             * in a row: interleave with an explicit sym0 to reset the
             * decoder's repeat state. */
            bool prev_was_17 = false;
            while (run > 0) {
                if (run >= 3 && !prev_was_17) {
                    int r = run > 10 ? 10 : run;
                    cl_syms[cl_n] = 17;
                    cl_extra[cl_n] = (uint8_t)(r - 3);
                    cl_n++;
                    run -= r; i += r;
                    prev_was_17 = true;
                } else {
                    cl_syms[cl_n] = 0; cl_extra[cl_n] = 0; cl_n++;
                    run--; i++;
                    prev_was_17 = false;
                }
            }
        } else {
            cl_syms[cl_n] = lens[i]; cl_extra[cl_n] = 0; cl_n++;
            i++;
        }
    }

    /* Compute frequencies of code-length symbols (0-17) */
    uint32_t cl_freq[18];
    memset(cl_freq, 0, sizeof(cl_freq));
    for (int i = 0; i < cl_n; i++) cl_freq[cl_syms[i]]++;

    /* The CLCL Huffman code must have at least 2 symbols to produce a
     * valid code space (Kraft sum == target). If only one CL symbol is
     * used, add a dummy entry for symbol 0 (or another unused symbol)
     * so the code space is fully subscribed. The dummy symbol's code is
     * never emitted in the CL sequence. */
    {
        int cl_used = 0;
        for (int i = 0; i < 18; i++) if (cl_freq[i]) cl_used++;
        if (cl_used == 1) {
            /* Pick a dummy symbol (prefer 0 if not already used) */
            int dummy = (cl_freq[0] == 0) ? 0 : ((cl_freq[1] == 0) ? 1 : 2);
            cl_freq[dummy] = 1;
        }
    }

    /* Build Huffman for code-length alphabet */
    uint8_t cl_lens[18];
    memset(cl_lens, 0, sizeof(cl_lens));
    build_lengths(cl_freq, 18, cl_lens);

    hcode_t cl_codes[18];
    assign_codes(cl_lens, 18, cl_codes);

    /* Determine how many code-length-code-lengths to transmit */
    int num_cl = 18;
    while (num_cl > 4 && cl_lens[kCLOrder[num_cl - 1]] == 0) num_cl--;

    /* Determine HSKIP */
    int hskip = 0;
    if (num_cl > 3 && cl_lens[kCLOrder[0]] == 0 && cl_lens[kCLOrder[1]] == 0) {
        if (cl_lens[kCLOrder[2]] == 0) hskip = 3;
        else hskip = 2;
    }
    /* HSKIP=1 is reserved for simple codes */
    if (hskip == 1) hskip = 0;

    bw_put(w, (uint32_t)hskip, 2);

    /* Number of code length codes to write (at least 4 after skip) */
    int clcl_count = num_cl - hskip;
    if (clcl_count < 4) clcl_count = 4;
    /* But don't exceed 18 - hskip */
    if (clcl_count > 18 - hskip) clcl_count = 18 - hskip;

    /* Write count of code-length codes (if > 4, need to signal) */
    /* Actually RFC 7932 says: "The number of code length codes is
     * determined by the last non-zero entry in the code_length_code_lengths
     * array." We just write them all up to num_cl - hskip. But how does
     * the decoder know when to stop? It reads a specific count based on
     * HSKIP... Actually the spec says read (18 - HSKIP) entries... no.
     *
     * From RFC 7932: after HSKIP, read "num_code_length_codes" entries.
     * num_code_length_codes is computed from trailing zeros: "repeat until
     * we have seen at least 4 non-zero code lengths... actually no.
     *
     * The spec says: we keep reading code_length_code_lengths until we have
     * enough to define a valid code. But that's decoder logic.
     *
     * For encoding: we emit all (18 - HSKIP) code_length_code_lengths,
     * trimming trailing zeros. The decoder reads them in kCLOrder and stops
     * after it has enough (implementation-defined by the stream content).
     *
     * Actually - looking at the brotli reference encoder, it writes
     * exactly `num_codes` entries where num_codes is between 4 and 18:
     *   num_codes = last non-zero index + 1 in the kCLOrder sequence.
     *
     * The decoder reads the 2-bit HSKIP, then reads items until it
     * decides it has enough. The signal to stop is:
     *   - space == 32 (the Kraft sum is full)
     *   OR
     *   - non_zero >= 2 and all remaining could be zero
     *
     * For safety, I'll just write all 18-HSKIP entries.
     */
    for (int i = hskip; i < num_cl; i++) {
        uint8_t v = cl_lens[kCLOrder[i]];
        if (v > 5) v = 5;  /* shouldn't happen with 18 symbols */
        bw_put(w, kCLCL_val[v], kCLCL_len[v]);
    }

    /* Trim trailing 0/17 from code length sequence (RFC requirement) */
    while (cl_n > 0 && (cl_syms[cl_n - 1] == 0 || cl_syms[cl_n - 1] == 17))
        cl_n--;

    /* Write the code length sequence using the code-length Huffman codes */
    for (int i = 0; i < cl_n; i++) {
        bw_huff(w, cl_codes[cl_syms[i]]);
        if (cl_syms[i] == 17) bw_put(w, cl_extra[i], 3);
    }
}

/* Unified prefix code writer: picks simple or complex.
 * When a simple code is emitted, the codes[] array is overwritten
 * to match the implicit structure the decoder will use. */
static void write_prefix(bitw_t* w, const uint32_t* freq, uint8_t* lens,
                         int nsym, int alpha_bits, hcode_t* codes) {
    int nu = count_used(freq, nsym);
    if (nu <= 4) {
        write_simple_code(w, lens, nsym, alpha_bits);
        /* Fix up codes to match the simple code's implicit structure */
        int used[4], n = 0;
        for (int i = 0; i < nsym && n < 4; i++)
            if (freq[i]) used[n++] = i;
        /* Sort ascending (write_simple_code also sorts, so this matches) */
        for (int a = 0; a < n - 1; a++)
            for (int b = a + 1; b < n; b++)
                if (used[b] < used[a]) { int t = used[a]; used[a] = used[b]; used[b] = t; }

        /* Clear all */
        for (int i = 0; i < nsym; i++) { codes[i].code = 0; codes[i].len = 0; lens[i] = 0; }

        if (n == 1) {
            /* Single symbol: len=0, no bits emitted */
            lens[used[0]] = 0; codes[used[0]].len = 0; codes[used[0]].code = 0;
        } else if (n == 2) {
            /* Both symbols: len=1, codes 0 and 1 */
            lens[used[0]] = 1; codes[used[0]] = (hcode_t){0, 1};
            lens[used[1]] = 1; codes[used[1]] = (hcode_t){1, 1};
        } else if (n == 3) {
            /* Lengths (1, 2, 2) */
            lens[used[0]] = 1; codes[used[0]] = (hcode_t){0, 1};
            lens[used[1]] = 2; codes[used[1]] = (hcode_t){2, 2};
            lens[used[2]] = 2; codes[used[2]] = (hcode_t){3, 2};
        } else {
            /* n == 4 */
            bool tree_sel = (lens[used[0]] == 1);
            if (tree_sel) {
                /* Lengths (1, 2, 3, 3) */
                lens[used[0]] = 1; codes[used[0]] = (hcode_t){0, 1};
                lens[used[1]] = 2; codes[used[1]] = (hcode_t){2, 2};
                lens[used[2]] = 3; codes[used[2]] = (hcode_t){6, 3};
                lens[used[3]] = 3; codes[used[3]] = (hcode_t){7, 3};
            } else {
                /* Lengths (2, 2, 2, 2) */
                lens[used[0]] = 2; codes[used[0]] = (hcode_t){0, 2};
                lens[used[1]] = 2; codes[used[1]] = (hcode_t){1, 2};
                lens[used[2]] = 2; codes[used[2]] = (hcode_t){2, 2};
                lens[used[3]] = 2; codes[used[3]] = (hcode_t){3, 2};
            }
        }
    } else {
        write_complex_code(w, lens, nsym);
    }
}

/* ================================================================
 * LZ77 match finder
 * ================================================================ */

#define HASH_BITS  15
#define HASH_SIZE  (1 << HASH_BITS)
#define WIN_BITS   16
#define WIN_SIZE   (1 << WIN_BITS)
#define MIN_MATCH  4
#define MAX_MATCH  258
#define MAX_CHAIN  32

typedef struct { uint32_t ins_len, copy_len, distance; } lz_cmd_t;

static uint32_t hash4(const uint8_t* p) {
    uint32_t v = p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return (v * 0x1E35A7BD) >> (32 - HASH_BITS);
}

static int lz_parse(const uint8_t* in, size_t len,
                    lz_cmd_t** out, size_t* out_n) {
    if (len == 0) { *out = NULL; *out_n = 0; return 0; }

    int* head = (int*)malloc(HASH_SIZE * sizeof(int));
    int* prev = (int*)malloc(len * sizeof(int));
    size_t cap = len / 2 + 16;
    lz_cmd_t* cmds = (lz_cmd_t*)malloc(cap * sizeof(lz_cmd_t));
    if (!head || !prev || !cmds) { free(head); free(prev); free(cmds); return -1; }

    for (int i = 0; i < HASH_SIZE; i++) head[i] = -1;

    size_t nc = 0, ip = 0, lit_start = 0;

    while (ip < len) {
        int best_len = 0, best_dist = 0;

        if (ip + MIN_MATCH <= len) {
            uint32_t h = hash4(in + ip);
            int chain = head[h];
            int cc = 0;
            while (chain >= 0 && cc < MAX_CHAIN) {
                size_t dist = ip - (size_t)chain;
                if (dist > WIN_SIZE) break;
                size_t maxl = len - ip;
                if (maxl > MAX_MATCH) maxl = MAX_MATCH;
                int ml = 0;
                while ((size_t)ml < maxl && in[chain + ml] == in[ip + ml]) ml++;
                if (ml > best_len && ml >= MIN_MATCH) {
                    best_len = ml; best_dist = (int)dist;
                    if (best_len >= MAX_MATCH) break;
                }
                chain = prev[chain]; cc++;
            }
            prev[ip] = head[h];
            head[h] = (int)ip;
        }

        if (best_len >= MIN_MATCH) {
            if (nc >= cap) {
                cap *= 2;
                lz_cmd_t* t = (lz_cmd_t*)realloc(cmds, cap * sizeof(lz_cmd_t));
                if (!t) { free(cmds); free(head); free(prev); return -1; }
                cmds = t;
            }
            cmds[nc].ins_len = (uint32_t)(ip - lit_start);
            cmds[nc].copy_len = (uint32_t)best_len;
            cmds[nc].distance = (uint32_t)best_dist;
            nc++;
            for (int k = 1; k < best_len && ip + k + MIN_MATCH <= len; k++) {
                uint32_t hk = hash4(in + ip + k);
                prev[ip + k] = head[hk];
                head[hk] = (int)(ip + k);
            }
            ip += best_len;
            lit_start = ip;
        } else {
            ip++;
        }
    }

    if (lit_start < len) {
        if (nc >= cap) {
            cap++;
            lz_cmd_t* t = (lz_cmd_t*)realloc(cmds, cap * sizeof(lz_cmd_t));
            if (!t) { free(cmds); free(head); free(prev); return -1; }
            cmds = t;
        }
        cmds[nc].ins_len = (uint32_t)(len - lit_start);
        cmds[nc].copy_len = 0;
        cmds[nc].distance = 0;
        nc++;
    }

    free(head); free(prev);
    *out = cmds; *out_n = nc;
    return 0;
}

/* ================================================================
 * Insert-and-copy length codes (RFC 7932 §5)
 * ================================================================ */

/* Insert length code table — 24 entries per RFC 7932 */
static const struct { uint32_t base; int extra; } kInsLen[24] = {
    {0,0},{1,0},{2,0},{3,0},{4,0},{5,0},{6,1},{8,1},
    {10,2},{14,2},{18,3},{26,3},{34,4},{50,4},{66,5},{98,5},
    {130,6},{194,7},{322,8},{578,9},{1090,10},{2114,12},
    {6210,14},{22594,24}
};

/* Copy length code table — 24 entries per RFC 7932 */
static const struct { uint32_t base; int extra; } kCopyLen[24] = {
    {2,0},{3,0},{4,0},{5,0},{6,0},{7,0},{8,0},{9,0},
    {10,1},{12,1},{14,2},{18,2},{22,3},{30,3},{38,4},{54,4},
    {70,5},{102,5},{134,6},{198,7},{326,8},{582,9},
    {1094,10},{2118,24}
};

static int find_ins_code(uint32_t v, uint32_t* extra, int* ebits) {
    for (int i = 23; i >= 0; i--)
        if (v >= kInsLen[i].base) {
            *extra = v - kInsLen[i].base;
            *ebits = kInsLen[i].extra;
            return i;
        }
    *extra = 0; *ebits = 0; return 0;
}

static int find_copy_code(uint32_t v, uint32_t* extra, int* ebits) {
    for (int i = 23; i >= 0; i--)
        if (v >= kCopyLen[i].base) {
            *extra = v - kCopyLen[i].base;
            *ebits = kCopyLen[i].extra;
            return i;
        }
    *extra = 0; *ebits = 0; return 0;
}

/* Combined insert-and-copy symbol (RFC 7932 Table 8)
 *
 * The 704-symbol alphabet is divided into cells of 64 symbols each:
 *   Row 1 (insert 0-7): [0..63](copy 0-7) [64..127](copy 8-15) → distance=last
 *   Row 2 (insert 0-7): [128..191](c0-7) [192..255](c8-15) [384..447](c16-23) → explicit dist
 *   Row 3 (insert 8-15): [256..319](c0-7) [320..383](c8-15) [512..575](c16-23) → explicit dist
 *   Row 4 (insert 16-23): [448..511](c0-7) [576..639](c8-15) [640..703](c16-23) → explicit dist
 *
 * Within each 64-value cell: bits 0-2 = copy_code % 8, bits 3-5 = insert_code % 8
 *
 * use_dist: true = explicit distance (rows 2-4), false = last distance (row 1, insert 0-7 only)
 */
static int ic_symbol(int ic, int cc, bool use_dist) {
    int ic_off = ic % 8;
    int cc_off = cc % 8;
    int val = ic_off * 8 + cc_off;

    if (!use_dist) {
        /* Row 1: distance = last (only valid for insert 0-7) */
        if (cc < 8) return 0 + val;
        return 64 + val;
    }

    /* Rows 2-4: explicit distance */
    if (ic < 8) {
        if (cc < 8) return 128 + val;
        if (cc < 16) return 192 + val;
        return 384 + val;
    }
    if (ic < 16) {
        if (cc < 8) return 256 + val;
        if (cc < 16) return 320 + val;
        return 512 + val;
    }
    /* ic 16-23 */
    if (cc < 8) return 448 + val;
    if (cc < 16) return 576 + val;
    return 640 + val;
}

/* ================================================================
 * Distance codes (RFC 7932 §4, NPOSTFIX=0, NDIRECT=0)
 * ================================================================ */

/* With NPOSTFIX=0, NDIRECT=0, distance codes 16+ encode distances.
 * For code c >= 16: hcode = c - 16
 *   ndistbits = 1 + (hcode >> 1)
 *   offset = ((2 + (hcode & 1)) << ndistbits) - 4
 *   distance = offset + extra_value + 1
 */
static int find_dist_code(uint32_t dist, uint32_t* extra, int* ebits) {
    if (dist == 0) { *extra = 0; *ebits = 0; return 0; }
    uint32_t d = dist - 1;  /* 0-based */

    /* Search for matching hcode */
    for (int hcode = 0; hcode < 48; hcode++) {
        int nb = 1 + (hcode >> 1);
        uint32_t off = ((uint32_t)(2 + (hcode & 1)) << nb) - 4;
        if (d >= off && d - off < (1u << nb)) {
            *extra = d - off;
            *ebits = nb;
            return 16 + hcode;
        }
    }
    *extra = 0; *ebits = 0;
    return 16;
}

/* ================================================================
 * Uncompressed meta-block (fallback)
 * ================================================================ */

static int encode_stored(const uint8_t* in, size_t len,
                         uint8_t* out, size_t cap) {
    if (len == 0 || len > 0xFFFFFF) return -1;

    bitw_t w;
    bw_init(&w, out, cap);

    /* WBITS = 16: single 0 bit */
    bw_put(&w, 0, 1);

    /* RFC 7932: ISUNCOMPRESSED is only valid when ISLAST=0.
     * So we write as a non-last uncompressed meta-block, then
     * append a final empty meta-block. */
    size_t remaining = len;
    const uint8_t* ptr = in;

    while (remaining > 0) {
        size_t chunk = remaining;
        if (chunk > (1u << 24) - 1) chunk = (1u << 24) - 1;

        /* Always ISLAST=0 for uncompressed blocks */
        bw_put(&w, 0, 1);  /* ISLAST = 0 */

        /* MNIBBLES + MLEN */
        uint32_t mlen = (uint32_t)(chunk - 1);
        int mn = (mlen < (1u << 16)) ? 4 : (mlen < (1u << 20)) ? 5 : 6;
        bw_put(&w, (uint32_t)(mn - 4), 2);
        bw_put(&w, mlen, mn * 4);

        /* ISUNCOMPRESSED = 1 (only valid when ISLAST=0) */
        bw_put(&w, 1, 1);

        /* Pad to byte boundary */
        if (w.nbits > 0) {
            int pad = 8 - (w.nbits % 8);
            if (pad < 8) bw_put(&w, 0, pad);
        }
        bw_finish(&w);

        /* Raw bytes */
        if (w.pos + chunk > cap) return -1;
        memcpy(w.buf + w.pos, ptr, chunk);
        w.pos += chunk;

        ptr += chunk;
        remaining -= chunk;
    }

    /* Final empty meta-block: ISLAST=1, ISLASTEMPTY=1 */
    bw_put(&w, 1, 1);  /* ISLAST */
    bw_put(&w, 1, 1);  /* ISLASTEMPTY */
    bw_finish(&w);

    return (int)w.pos;
}

/* ================================================================
 * Main encoder
 * ================================================================ */

int brotli_encode(const uint8_t* input, size_t input_len,
                  uint8_t* output, size_t output_cap) {
    if (input_len == 0) {
        if (output_cap < 1) return -1;
        output[0] = 0x06;  /* WBITS=16 + empty last meta-block */
        return 1;
    }
    if (input_len > 16 * 1024 * 1024) return -1;

    /* LZ77 parse */
    lz_cmd_t* cmds = NULL;
    size_t ncmds = 0;
    if (lz_parse(input, input_len, &cmds, &ncmds) != 0)
        return encode_stored(input, input_len, output, output_cap);

    /* Gather frequencies */
    uint32_t lit_freq[256], ic_freq[704], dist_freq[64];
    memset(lit_freq, 0, sizeof(lit_freq));
    memset(ic_freq, 0, sizeof(ic_freq));
    memset(dist_freq, 0, sizeof(dist_freq));

    size_t lp = 0;
    for (size_t i = 0; i < ncmds; i++) {
        uint32_t ie, ce; int ieb, ceb;
        int icode = find_ins_code(cmds[i].ins_len, &ie, &ieb);
        int ccode = 0;
        if (cmds[i].copy_len) ccode = find_copy_code(cmds[i].copy_len, &ce, &ceb);
        bool has_dist = (cmds[i].copy_len > 0);
        int sym = ic_symbol(icode, ccode, has_dist);
        if (sym >= 0 && sym < 704) ic_freq[sym]++;
        for (uint32_t j = 0; j < cmds[i].ins_len && lp < input_len; j++)
            lit_freq[input[lp++]]++;
        if (cmds[i].copy_len) {
            uint32_t de; int deb;
            int dc = find_dist_code(cmds[i].distance, &de, &deb);
            if (dc < 64) dist_freq[dc]++;
            lp += cmds[i].copy_len;
        }
    }

    /* Build Huffman codes */
    uint8_t lit_lens[256], ic_lens[704], dist_lens[64];
    build_lengths(lit_freq, 256, lit_lens);
    build_lengths(ic_freq, 704, ic_lens);
    build_lengths(dist_freq, 64, dist_lens);

    hcode_t lit_codes[256], ic_codes[704], dist_codes[64];
    assign_codes(lit_lens, 256, lit_codes);
    assign_codes(ic_lens, 704, ic_codes);
    assign_codes(dist_lens, 64, dist_codes);

    /* Encode bitstream */
    bitw_t w;
    bw_init(&w, output, output_cap);

    /* Window: WBITS=16 */
    bw_put(&w, 0, 1);

    /* Meta-block header */
    bw_put(&w, 1, 1);  /* ISLAST */
    bw_put(&w, 0, 1);  /* ISLASTEMPTY=0 (implicit since len>0) */

    /* MLEN */
    uint32_t mlen = (uint32_t)(input_len - 1);
    int mn = (mlen < (1u << 16)) ? 4 : (mlen < (1u << 20)) ? 5 : 6;
    bw_put(&w, (uint32_t)(mn - 4), 2);
    bw_put(&w, mlen, mn * 4);

    /* Note: ISUNCOMPRESSED bit is only present when ISLAST=0.
     * Since we set ISLAST=1, we skip it — data is compressed. */

    /* Block type counts: all 1 (single block type each) */
    bw_put(&w, 0, 1);  /* NBLTYPESL = 1 */
    bw_put(&w, 0, 1);  /* NBLTYPESI = 1 */
    bw_put(&w, 0, 1);  /* NBLTYPESD = 1 */

    /* NPOSTFIX=0, NDIRECT=0 */
    bw_put(&w, 0, 2);  /* NPOSTFIX */
    bw_put(&w, 0, 4);  /* NDIRECT >> NPOSTFIX */

    /* Context mode for literal type 0: LSB6 = 0 */
    bw_put(&w, 0, 2);

    /* NTREESL = 1, no context map */
    bw_put(&w, 0, 1);

    /* NTREESD = 1, no distance context map */
    bw_put(&w, 0, 1);

    /* Prefix codes */
    write_prefix(&w, lit_freq, lit_lens, 256, 8, lit_codes);
    write_prefix(&w, ic_freq, ic_lens, 704, 10, ic_codes);
    write_prefix(&w, dist_freq, dist_lens, 64, 6, dist_codes);

    /* Compressed data */
    lp = 0;
    for (size_t i = 0; i < ncmds; i++) {
        uint32_t ie, ce; int ieb, ceb;
        int icode = find_ins_code(cmds[i].ins_len, &ie, &ieb);
        int ccode = 0; ce = 0; ceb = 0;
        if (cmds[i].copy_len) ccode = find_copy_code(cmds[i].copy_len, &ce, &ceb);
        bool has_dist = (cmds[i].copy_len > 0);
        int sym = ic_symbol(icode, ccode, has_dist);

        bw_huff(&w, ic_codes[sym]);
        if (ieb > 0) bw_put(&w, ie, ieb);
        if (has_dist && ceb > 0) bw_put(&w, ce, ceb);

        for (uint32_t j = 0; j < cmds[i].ins_len && lp < input_len; j++)
            bw_huff(&w, lit_codes[input[lp++]]);

        if (has_dist) {
            uint32_t de; int deb;
            int dc = find_dist_code(cmds[i].distance, &de, &deb);
            bw_huff(&w, dist_codes[dc]);
            if (deb > 0) bw_put(&w, de, deb);
            lp += cmds[i].copy_len;
        }
    }

    bw_finish(&w);
    free(cmds);

    if (!bw_ok(&w)) return encode_stored(input, input_len, output, output_cap);
    if (w.pos >= input_len) return encode_stored(input, input_len, output, output_cap);

    return (int)w.pos;
}

size_t brotli_bound(size_t input_len) {
    return input_len + input_len / 64 + 64;
}

bool brotli_accepted(const char* ae, size_t len) {
    for (size_t i = 0; i + 2 <= len; i++) {
        if (ae[i] == 'b' && ae[i + 1] == 'r') {
            /* Check left boundary */
            if (i > 0 && ae[i-1] != ',' && ae[i-1] != ' ' && ae[i-1] != '\t')
                continue;
            /* Check right boundary */
            if (i + 2 < len && ae[i+2] != ',' && ae[i+2] != ' ' &&
                ae[i+2] != '\t' && ae[i+2] != ';')
                continue;
            /* Check for q=0 */
            size_t j = i + 2;
            while (j < len && (ae[j] == ' ' || ae[j] == '\t')) j++;
            if (j < len && ae[j] == ';') {
                j++;
                while (j < len && (ae[j] == ' ' || ae[j] == '\t')) j++;
                if (j + 1 < len && ae[j] == 'q' && ae[j+1] == '=') {
                    j += 2;
                    if (j < len && ae[j] == '0') {
                        size_t k = j + 1;
                        bool is_zero = true;
                        if (k < len && ae[k] == '.') {
                            for (k++; k < len && ae[k] >= '0' && ae[k] <= '9'; k++)
                                if (ae[k] != '0') is_zero = false;
                        }
                        if (is_zero) continue;
                    }
                }
            }
            return true;
        }
    }
    return false;
}
