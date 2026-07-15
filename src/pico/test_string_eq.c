/* test_string_eq.c -- standalone smoke test for the String.Eq (PV_HOOK_STRING_EQ,
 * hook 0x8D) fix ported into this repo's forked picovm.c. Verifies full-content
 * span equality (not span-handle equality) directly against pv_default_host,
 * mirroring the span_from_bytes idiom already used by src/pico_route.c.
 *
 * Build + run:
 *   cc -O2 -std=c11 -o /tmp/test_string_eq src/pico/test_string_eq.c src/pico/picovm.c
 *   /tmp/test_string_eq
 */
#include "picovm.h"
#include "pico_hooks.h"
#include <stdio.h>
#include <string.h>

/* picovm.c calls brotli_encode/decode for an unrelated compression hook;
 * those live in this repo's separate brotli.c (not needed for this smoke
 * test), so provide no-op stubs purely to satisfy the linker. */
int brotli_decode(const unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int out_cap) {
    (void)in; (void)in_len; (void)out; (void)out_cap; return -1;
}
int brotli_encode(const unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int out_cap, int quality) {
    (void)in; (void)in_len; (void)out; (void)out_cap; (void)quality; return -1;
}

static uint32_t g_arena_top = 0;

static int span_from_bytes(pv_ctx *ctx, const uint8_t *data, int32_t len) {
    uint32_t p = g_arena_top;
    for (int32_t i = 0; i < len; i++) ctx->mem[p + (uint32_t)i] = data[i];
    g_arena_top += (uint32_t)len;
    if (ctx->span_count >= PV_MAX_SPANS) return 0;
    int h = ctx->span_count++;
    ctx->span_ptr[h] = p;
    ctx->span_len[h] = len;
    return h;
}

int main(void) {
    pv_ctx ctx;
    static uint8_t arena[65536];
    pv_init(&ctx);
    ctx.mem = arena;
    ctx.mem_size = (long)sizeof(arena);
    g_arena_top = 0;

    int ha = span_from_bytes(&ctx, (const uint8_t *)"schema", 6);
    int hb = span_from_bytes(&ctx, (const uint8_t *)"schema", 6); /* same bytes, different span */
    int hc = span_from_bytes(&ctx, (const uint8_t *)"query", 5);  /* different bytes */

    int64_t eq_same_content = pv_host2(&ctx, PV_HOOK_STRING_EQ, ha, hb);
    int64_t eq_diff_content = pv_host2(&ctx, PV_HOOK_STRING_EQ, ha, hc);
    int64_t eq_same_handle  = pv_host2(&ctx, PV_HOOK_STRING_EQ, ha, ha);

    int ok = 1;
    if (eq_same_content != 1) { printf("FAIL: identical-content different-span spans should be Eq (got %lld)\n", (long long)eq_same_content); ok = 0; }
    else printf("ok   String.Eq(\"schema\",\"schema\") [different spans] -> 1\n");

    if (eq_diff_content != 0) { printf("FAIL: different-content spans should not be Eq (got %lld)\n", (long long)eq_diff_content); ok = 0; }
    else printf("ok   String.Eq(\"schema\",\"query\") -> 0\n");

    if (eq_same_handle != 1) { printf("FAIL: same-handle spans should be Eq (got %lld)\n", (long long)eq_same_handle); ok = 0; }
    else printf("ok   String.Eq(\"schema\",\"schema\") [same span handle] -> 1\n");

    if (ok) printf("PASS — String.Eq content-equality works correctly\n");
    return ok ? 0 : 1;
}
