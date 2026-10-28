#!/usr/bin/env python3
"""
extractforms.py — print every <form> (action/method/enctype) and its named
fields from local HTML files. stdlib-only, offline.

Made for reverse-engineering REPORTING forms (e.g., abuse-report pages you
save with `fetch`): shows what a programmatic POST would need to carry.
Never use it to auto-submit forms of a fraud kit — that stays forbidden.

usage:
  python extractforms.py page.html [more.html ...]
"""
import re
import sys

FORM_RE = re.compile(r"<form\b[^>]*>", re.I)
CLOSE_RE = re.compile(r"</form\s*>", re.I)
FIELD_RE = re.compile(
    r"<(input|select|textarea|button)\b[^>]*>", re.I)


def attrs(tag):
    out = {}
    for k, v in re.findall(r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*"([^"]*)"',
                           tag, re.I):
        out[k.lower()] = v
    return out


def main(paths):
    for path in paths:
        try:
            html = open(path, "r", encoding="utf-8", errors="replace").read()
        except OSError as exc:
            print("== {}: cannot read ({})".format(path, exc))
            continue
        print("== {} ==".format(path))
        for m in FORM_RE.finditer(html):
            fa = attrs(m.group(0))
            end = CLOSE_RE.search(html, m.end())
            block = html[m.end():end.start() if end else len(html)]
            print("  FORM action={!r} method={!r} enctype={!r}".format(
                fa.get("action"), (fa.get("method") or "GET").upper(),
                fa.get("enctype")))
            for f in FIELD_RE.finditer(block):
                a = attrs(f.group(0))
                if f.group(1).lower() == "button":
                    label = "text={!r}".format(a.get("text"))
                else:
                    label = "value={!r}".format(a.get("value")) if "value" in a else ""
                print("    {:<9} name={!r} type={!r} {}".format(
                    f.group(1).lower(), a.get("name"), a.get("type"), label))
        if not FORM_RE.search(html):
            print("  (no <form> tags found)")
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
