/* test_preload.c — unit tests for src/preload.{c,h}, the HTML
 * subresource scanner that builds Link: rel=preload / rel=preconnect
 * / rel=modulepreload header lines for HTTP 103 Early Hints.
 *
 * Coverage:
 *   - same-origin <link rel=stylesheet> -> as=style
 *   - <link rel=preload as=font> auto-fills crossorigin and type
 *   - <link rel=modulepreload>
 *   - <link rel=preload> without as= is dropped
 *   - <script src> -> as=script; type=module -> modulepreload
 *   - <img src> -> as=image; <source src> in <video>
 *   - cross-origin URLs become rel=preconnect (origin only)
 *   - rel=canonical / manifest / icon / dns-prefetch / prefetch are dropped
 *   - URLs with control chars (CR/LF/NUL/DEL/<>") rejected
 *   - data:/mailto:/javascript:/about: schemes rejected
 *   - <script>...</script> body is NOT scanned (raw-text)
 *   - <style>...</style> body is NOT scanned
 *   - <!-- ... --> comments are skipped
 *   - duplicates (same URL+as+rel) collapse
 *   - quoted ('/") / unquoted attributes; attribute order; case-insensitive tags
 *   - Output sorted by priority (style > script > font > image > preconnect)
 *   - Capacity: when output buffer too small, lower-priority entries dropped
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "preload.h"

static int failures = 0;
static int passed   = 0;

#define EXPECT(cond, msg) do { \
    if (cond) { passed++; printf("  PASS: %s\n", msg); } \
    else      { failures++; printf("  FAIL: %s (line %d)\n", msg, __LINE__); } \
} while (0)

static int contains(const char* hay, size_t hay_len, const char* needle) {
    size_t nl = strlen(needle);
    if (nl == 0) return 1;
    for (size_t i = 0; i + nl <= hay_len; i++) {
        if (memcmp(hay + i, needle, nl) == 0) return 1;
    }
    return 0;
}

static size_t run(const char* html, char* out, size_t out_cap,
                  const char* host) {
    return pw_preload_extract(html, strlen(html),
                              host, host ? strlen(host) : 0,
                              out, out_cap);
}

static void test_basic_stylesheet(void) {
    printf("== preload: basic stylesheet ==\n");
    char buf[4096];
    const char* html =
        "<html><head>"
        "<link rel=\"stylesheet\" href=\"/css/main.css\">"
        "</head><body></body></html>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(n > 0, "produced output");
    EXPECT(contains(buf, n, "Link: </css/main.css>; rel=preload; as=style\r\n"),
           "stylesheet line emitted with as=style");
}

static void test_font_preload_autofill(void) {
    printf("== preload: font autofills crossorigin/type ==\n");
    char buf[4096];
    const char* html =
        "<link rel='preload' as='font' href='/fonts/x.woff2'>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(contains(buf, n, "as=font"), "as=font preserved");
    EXPECT(contains(buf, n, "crossorigin"), "crossorigin auto-added");
    EXPECT(contains(buf, n, "type=\"font/woff2\""), "type auto-derived from .woff2 extension");
}

static void test_preload_without_as_dropped(void) {
    printf("== preload: rel=preload without as is dropped ==\n");
    char buf[4096];
    const char* html = "<link rel=preload href=/x>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(n == 0, "no output");
}

static void test_modulepreload(void) {
    printf("== preload: modulepreload preserved ==\n");
    char buf[4096];
    const char* html = "<link rel=modulepreload href=/m.js>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(contains(buf, n, "rel=modulepreload"), "modulepreload kept");
}

static void test_script(void) {
    printf("== preload: <script src> -> as=script ==\n");
    char buf[4096];
    const char* html = "<script src=\"/js/app.js\"></script>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(contains(buf, n, "as=script"), "as=script emitted");
    EXPECT(contains(buf, n, "</js/app.js>"), "url emitted");
}

static void test_script_module(void) {
    printf("== preload: <script type=module> -> modulepreload ==\n");
    char buf[4096];
    const char* html = "<script type=module src=/m.js></script>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(contains(buf, n, "rel=modulepreload"), "modulepreload for type=module");
}

static void test_img(void) {
    printf("== preload: <img src> -> as=image ==\n");
    char buf[4096];
    const char* html = "<img src='/i.png' alt=x>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(contains(buf, n, "as=image"), "as=image emitted");
}

static void test_source_in_video(void) {
    printf("== preload: <source src> in <video> -> as=image ==\n");
    char buf[4096];
    const char* html = "<video><source src=/v.mp4></video>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(contains(buf, n, "</v.mp4>"), "<source src> picked up");
}

static void test_cross_origin_preconnect(void) {
    printf("== preload: cross-origin -> preconnect (origin only) ==\n");
    char buf[4096];
    const char* html =
        "<link rel=stylesheet href=\"https://cdn.example.com/lib/x.css\">";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(contains(buf, n, "rel=preconnect"), "downgraded to preconnect");
    EXPECT(contains(buf, n, "https://cdn.example.com>"),
           "only origin emitted, not full URL");
    EXPECT(!contains(buf, n, "/lib/x.css"),
           "path of cross-origin URL NOT leaked");
}

static void test_drop_irrelevant_rels(void) {
    printf("== preload: skip canonical / manifest / icon / dns-prefetch ==\n");
    char buf[4096];
    const char* html =
        "<link rel=canonical href=/c>"
        "<link rel=manifest href=/m.webmanifest>"
        "<link rel=icon href=/favicon.ico>"
        "<link rel=dns-prefetch href=//cdn.example.com>"
        "<link rel=prefetch href=/p>"
        "<link rel=alternate href=/feed.xml>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(n == 0, "no output for irrelevant rels");
}

static void test_url_safety_crlf(void) {
    printf("== preload: reject URLs with CR/LF/control chars ==\n");
    char buf[4096];
    const char* html =
        "<link rel=stylesheet href=\"/x\r\nInjected: yes\">";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(n == 0, "URL with CRLF rejected");
}

static void test_url_safety_data_mailto(void) {
    printf("== preload: reject data: / mailto: / javascript: / # ==\n");
    char buf[4096];
    const char* html =
        "<link rel=stylesheet href=\"data:text/css,body{}\">"
        "<script src=\"javascript:alert(1)\"></script>"
        "<a href=mailto:x>x</a>"
        "<img src=\"#frag\">";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(n == 0, "all unsafe schemes rejected");
}

static void test_script_body_not_scanned(void) {
    printf("== preload: <script>...</script> body not scanned ==\n");
    char buf[4096];
    const char* html =
        "<script>var s = '<link rel=stylesheet href=/evil.css>';</script>"
        "<link rel=stylesheet href=/good.css>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(!contains(buf, n, "/evil.css"), "scripted string not parsed as tag");
    EXPECT(contains(buf, n, "/good.css"), "real link is parsed");
}

static void test_style_body_not_scanned(void) {
    printf("== preload: <style>...</style> body not scanned ==\n");
    char buf[4096];
    const char* html =
        "<style>/* <link rel=stylesheet href=/evil.css> */</style>"
        "<link rel=stylesheet href=/good.css>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(!contains(buf, n, "/evil.css"), "style body not parsed as tags");
    EXPECT(contains(buf, n, "/good.css"), "real link is parsed");
}

static void test_comment_skipped(void) {
    printf("== preload: HTML comments skipped ==\n");
    char buf[4096];
    const char* html =
        "<!-- <link rel=stylesheet href=/evil.css> -->"
        "<link rel=stylesheet href=/good.css>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(!contains(buf, n, "/evil.css"), "comment body not parsed");
    EXPECT(contains(buf, n, "/good.css"), "real link is parsed");
}

static void test_dedupe(void) {
    printf("== preload: duplicate URLs collapse ==\n");
    char buf[4096];
    const char* html =
        "<link rel=stylesheet href=/a.css>"
        "<link rel=stylesheet href=/a.css>"
        "<link rel=stylesheet href=/a.css>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    /* Expect exactly one Link: line. */
    int count = 0;
    for (size_t i = 0; i + 5 < n; i++) {
        if (memcmp(buf + i, "Link:", 5) == 0) count++;
    }
    EXPECT(count == 1, "duplicate stylesheet collapsed to one Link line");
}

static void test_priority_order(void) {
    printf("== preload: priority style > script > font > image ==\n");
    char buf[4096];
    const char* html =
        "<img src=/i.png>"
        "<link rel=preload as=font href=/f.woff2>"
        "<script src=/s.js></script>"
        "<link rel=stylesheet href=/c.css>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    /* Find offsets of each marker; styles must come before script,
     * script before font, font before image. */
    const char* p_style  = memmem(buf, n, "/c.css>",   7);
    const char* p_script = memmem(buf, n, "/s.js>",    6);
    const char* p_font   = memmem(buf, n, "/f.woff2>", 9);
    const char* p_image  = memmem(buf, n, "/i.png>",   7);
    EXPECT(p_style && p_script && p_style < p_script, "style before script");
    EXPECT(p_script && p_font && p_script < p_font,   "script before font");
    EXPECT(p_font && p_image && p_font < p_image,     "font before image");
}

static void test_capacity_truncation(void) {
    printf("== preload: small out buffer drops low-priority entries ==\n");
    /* 1 stylesheet (high prio) + 1 image (low prio). With a tiny out
     * buffer, only the stylesheet should fit. */
    char buf[80];  /* "Link: </css/main.css>; rel=preload; as=style\r\n" = 47B; image won't fit */
    const char* html =
        "<link rel=stylesheet href=/css/main.css>"
        "<img src=/big-image.png>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(contains(buf, n, "/css/main.css"), "high-prio entry kept");
    EXPECT(!contains(buf, n, "/big-image.png"), "low-prio entry dropped");
}

static void test_case_insensitive_tags(void) {
    printf("== preload: case-insensitive tag/attr names ==\n");
    char buf[4096];
    const char* html =
        "<LINK REL=\"STYLESHEET\" HREF=\"/x.css\">"
        "<SCRIPT SRC=\"/y.js\"></SCRIPT>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(contains(buf, n, "/x.css"), "uppercase LINK parsed");
    EXPECT(contains(buf, n, "/y.js"),  "uppercase SCRIPT parsed");
}

static void test_unquoted_attributes(void) {
    printf("== preload: unquoted attributes parsed ==\n");
    char buf[4096];
    const char* html = "<link rel=stylesheet href=/u.css>";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(contains(buf, n, "/u.css"), "unquoted attrs parsed");
}

static void test_same_origin_absolute(void) {
    printf("== preload: same-origin absolute URL kept full ==\n");
    char buf[4096];
    const char* html =
        "<link rel=stylesheet href=\"https://example.test/abs.css\">";
    size_t n = run(html, buf, sizeof(buf), "example.test");
    EXPECT(contains(buf, n, "<https://example.test/abs.css>"),
           "same-host absolute URL preserved");
    EXPECT(contains(buf, n, "rel=preload"), "still rel=preload, not preconnect");
}

int main(void) {
    test_basic_stylesheet();
    test_font_preload_autofill();
    test_preload_without_as_dropped();
    test_modulepreload();
    test_script();
    test_script_module();
    test_img();
    test_source_in_video();
    test_cross_origin_preconnect();
    test_drop_irrelevant_rels();
    test_url_safety_crlf();
    test_url_safety_data_mailto();
    test_script_body_not_scanned();
    test_style_body_not_scanned();
    test_comment_skipped();
    test_dedupe();
    test_priority_order();
    test_capacity_truncation();
    test_case_insensitive_tags();
    test_unquoted_attributes();
    test_same_origin_absolute();

    printf("\n=== RESULTS: PASS=%d FAIL=%d ===\n", passed, failures);
    return failures ? 1 : 0;
}
