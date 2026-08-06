#!/usr/bin/env python3
"""gen_ide_assets.py -- regenerate src/ide_assets.c (compiled-in hosted
PicoScript WebIDE + PicoWAL workspace + vendored BareMetal.Binary BSO1
codec) so the picoweb executable can serve the real, upstream PicoScript
WebIDE (not a hand-rolled shell) with no filesystem dependency at runtime.

Inputs:
  - ../picoscript/docs/index.html         (sibling picoscript checkout; the
    ACTUAL generated portal -- Guide & Reference / WebIDE / Showcase nav,
    full Monaco editor, dialect tabs, Compile & Run/Step/Reset, debug
    tabs with disassembly/registers/watches -- built by that repo's own
    gen_site.py. Vendored verbatim; picoweb never hand-edits it.)
  - tools/ide_server_bridge.js             (this repo; injected before
    </body> in the vendored HTML above -- the ONLY place that wires the
    real WebIDE to a running picoweb instance: /ide/config, live /wal/
    wiring, PicoSTS login, deploy controls, the top-level PicoWAL tab)
  - tools/ide_picowal_workspace.html       (this repo; a separate,
    visually-isolated PicoWAL workspace page served at
    {ide_prefix}picowal.html and opened from the WebIDE's top-level
    PicoWAL tab via an iframe, so its own styling never collides with the
    vendored portal's CSS)
  - ../baremetaljstools/src/BareMetal.Binary.js  (sibling baremetaljstools
    checkout; vendored byte-for-byte, never modified -- see the "Fast
    Serial (BSO1)" panel in tools/ide_picowal_workspace.html)
  - ../picoscript/vm/pico_hooks.js, picoc.js, picovm.js (sibling picoscript
    checkout; kept as standalone compiled-in assets for backward
    compatibility -- the vendored docs/index.html inlines its own copy of
    the compiler/VM, so these are no longer required by the served pages,
    but existing external tooling/tests may still fetch them directly)

Output:
  - src/ide_assets.c (generated; committed so a normal `make` never needs
    the sibling picoscript/baremetaljstools checkouts)

Run via `make gen-ide-assets` or `python3 tools/gen_ide_assets.py` from the
picoweb repo root (or anywhere -- paths below are resolved relative to this
script's own location, not the current working directory).
"""
import re
import sys
import textwrap
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
PICOSCRIPT_DOCS = REPO_ROOT.parent / "picoscript" / "docs"
PICOSCRIPT_VM = REPO_ROOT.parent / "picoscript" / "vm"
BAREMETALJSTOOLS_SRC = REPO_ROOT.parent / "baremetaljstools" / "src"

HEX_DIGITS = set(b"0123456789abcdefABCDEF")


def c_escape_bytes(data: bytes) -> str:
    """Render `data` as a sequence of adjacent C string literals, one
    source line per input line (for readable diffs), safe against:
      - trigraphs (every literal '?' is escaped as \\?, regardless of how
        many appear consecutively)
      - hex-escape digit-swallowing ambiguity (\\xHH followed by another
        hex digit): the literal is closed and reopened immediately after
        any \\xHH escape if the next byte is itself a hex digit, since
        adjacent string literals concatenate in C.
    Returns the literal text WITHOUT a trailing ';' -- caller wraps it in
    a declaration.
    """
    lines = []
    parts = []   # literal segments for the current output line
    buf = []     # chars accumulated for the current segment

    def flush_part():
        parts.append("".join(buf))
        buf.clear()

    def flush_line():
        flush_part()
        non_empty = [p for p in parts if p != ""]
        rendered = " ".join('"%s"' % p for p in non_empty) if non_empty else '""'
        lines.append(rendered)
        parts.clear()

    n = len(data)
    for i in range(n):
        b = data[i]
        if b == 0x0A:            # '\n'
            buf.append("\\n")
            flush_line()
            continue
        if b == 0x22:             # '"'
            buf.append('\\"')
        elif b == 0x5C:           # '\\'
            buf.append("\\\\")
        elif b == 0x3F:           # '?' -- guard against trigraphs
            buf.append("\\?")
        elif b == 0x09:           # '\t'
            buf.append("\\t")
        elif b == 0x0D:           # '\r'
            buf.append("\\r")
        elif 0x20 <= b <= 0x7E:
            buf.append(chr(b))
        else:
            buf.append("\\x%02x" % b)
            nxt = data[i + 1] if i + 1 < n else None
            if nxt is not None and nxt in HEX_DIGITS:
                flush_part()

    if buf or parts:
        flush_line()
    if not lines:
        lines = ['""']
    return "\n".join(lines)


def emit_asset(name: str, data: bytes) -> str:
    body = c_escape_bytes(data)
    indented = textwrap.indent(body, "    ")
    return (
        "const char %s[] =\n%s\n;\n"
        "const size_t %s_LEN = sizeof(%s) - 1;\n\n"
        % (name, indented, name, name)
    )


def read_required(path: Path) -> bytes:
    if not path.is_file():
        sys.stderr.write(
            "gen_ide_assets: missing input file '%s'\n"
            "  (see the module docstring in tools/gen_ide_assets.py for "
            "where each input comes from -- AGENTS.md / README.md)\n" % path
        )
        sys.exit(1)
    return path.read_bytes()


BODY_CLOSE_RE = re.compile(rb"</body>", re.IGNORECASE)


def inject_before_body_close(html: bytes, snippet: bytes) -> bytes:
    """Insert `snippet` immediately before the LAST </body> in `html`
    (there should be exactly one in a well-formed page; using the last
    occurrence is defensive against any incidental literal "</body>" text
    appearing earlier, e.g. inside a documentation code sample)."""
    matches = list(BODY_CLOSE_RE.finditer(html))
    if not matches:
        sys.stderr.write("gen_ide_assets: vendored HTML has no </body> to inject before\n")
        sys.exit(1)
    idx = matches[-1].start()
    return html[:idx] + snippet + html[idx:]


def main() -> int:
    portal_html = read_required(PICOSCRIPT_DOCS / "index.html")
    bridge_js = read_required(SCRIPT_DIR / "ide_server_bridge.js")
    picowal_html = read_required(SCRIPT_DIR / "ide_picowal_workspace.html")
    pico_hooks_js = read_required(PICOSCRIPT_VM / "pico_hooks.js")
    picoc_js = read_required(PICOSCRIPT_VM / "picoc.js")
    picovm_js = read_required(PICOSCRIPT_VM / "picovm.js")
    baremetal_binary_js = read_required(BAREMETALJSTOOLS_SRC / "BareMetal.Binary.js")

    ide_html = inject_before_body_close(
        portal_html,
        b"<script>\n" + bridge_js + b"\n</script>\n",
    )

    out_path = REPO_ROOT / "src" / "ide_assets.c"
    with out_path.open("w", encoding="utf-8", newline="\n") as f:
        f.write(
            "/* ide_assets.c -- GENERATED by tools/gen_ide_assets.py. DO NOT EDIT BY HAND.\n"
            " * Regenerate with `make gen-ide-assets` (requires ../picoscript and\n"
            " * ../baremetaljstools checked out next to this repo). See src/ide_assets.h\n"
            " * for the declarations and src/ide.c for how these are served.\n"
            " *\n"
            " * IDE_HTML is the ACTUAL upstream PicoScript WebIDE portal\n"
            " * (../picoscript/docs/index.html, built by that repo's gen_site.py) with\n"
            " * tools/ide_server_bridge.js injected right before </body> -- never a\n"
            " * hand-rolled substitute. IDE_PICOWAL_HTML is this repo's own PicoWAL\n"
            " * workspace page (tools/ide_picowal_workspace.html), served separately at\n"
            " * {ide_prefix}picowal.html and opened from the portal's top-level PicoWAL\n"
            " * tab via an iframe for CSS isolation. */\n\n"
            '#include "ide_assets.h"\n\n'
        )
        f.write(emit_asset("IDE_HTML", ide_html))
        f.write(emit_asset("IDE_PICOWAL_HTML", picowal_html))
        f.write(emit_asset("IDE_PICO_HOOKS_JS", pico_hooks_js))
        f.write(emit_asset("IDE_PICOC_JS", picoc_js))
        f.write(emit_asset("IDE_PICOVM_JS", picovm_js))
        f.write(emit_asset("IDE_BAREMETAL_BINARY_JS", baremetal_binary_js))

    sizes = {
        "IDE_HTML (portal + bridge)": len(ide_html),
        "IDE_PICOWAL_HTML": len(picowal_html),
        "IDE_PICO_HOOKS_JS": len(pico_hooks_js),
        "IDE_PICOC_JS": len(picoc_js),
        "IDE_PICOVM_JS": len(picovm_js),
        "IDE_BAREMETAL_BINARY_JS": len(baremetal_binary_js),
    }
    total = sum(sizes.values())
    print("gen_ide_assets: wrote %s (%d bytes total)" % (out_path, total))
    for k, v in sizes.items():
        print("  %-28s %8d bytes" % (k, v))
    return 0


if __name__ == "__main__":
    sys.exit(main())
