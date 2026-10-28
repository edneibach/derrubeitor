#!/usr/bin/env python3
"""
gmaillink.py — build a pre-typed Gmail (or mailto:) compose link.

stdlib-only; no network; GET nothing. Reads subject/body from text files so
reports stay reviewable before sending.

usage:
  python gmaillink.py --to abuse@example.com --subject-file assunto.txt --body-file corpo.txt
  python gmaillink.py --to abuse@example.com --subject "Subject line" --body-file corpo.txt \
                      [--marker "===== CORPO ====="] [--mailto] [--open] [--max-chars 1900]

--marker: if the body file contains this line, everything AFTER it becomes the
body (lets one EMAIL.txt hold Para/Assunto + the message text).
--mailto: emit a mailto: link instead of the Gmail web compose link.
--open:   open the link in the default browser (webbrowser, local call only).

Caveat printed as WARN: some clients truncate Gmail compose links past
~1900-2000 encoded body chars. For long reports, open the link (recipient +
subject land fine), then paste the body from the file / clipboard.
"""
import argparse
import sys
import urllib.parse
import webbrowser


def read_text(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def body_after_marker(text, marker):
    if marker and marker in text:
        idx = text.index(marker)
        nl = text.find("\n", idx)
        return text[nl + 1:] if nl >= 0 else ""
    return text


def main():
    ap = argparse.ArgumentParser(description="Pre-typed Gmail/mailto compose link builder")
    ap.add_argument("--to", required=True, help="recipient address")
    ap.add_argument("--subject", help="subject as inline text")
    ap.add_argument("--subject-file", help="file with the subject line")
    ap.add_argument("--body-file", required=True, help="file with the body text")
    ap.add_argument("--marker", dest="marker",
                    help="use only the text AFTER this marker line in --body-file")
    ap.add_argument("--mailto", action="store_true", help="emit mailto: instead of Gmail web")
    ap.add_argument("--open", dest="open_link", action="store_true",
                    help="open the link in the default browser")
    ap.add_argument("--max-chars", type=int, default=1900,
                    help="encoded-body soft limit before the truncation WARN (default 1900)")
    args = ap.parse_args()

    if args.subject:
        subject = args.subject
    elif args.subject_file:
        subject = read_text(args.subject_file).strip()
    else:
        subject = ""

    body = body_after_marker(read_text(args.body_file), args.marker).strip()

    su = urllib.parse.quote(subject, safe="")
    bd = urllib.parse.quote(body, safe="")

    if args.mailto:
        url = "mailto:{}?subject={}&body={}".format(args.to, su, bd)
    else:
        to_q = urllib.parse.quote(args.to, safe="@")
        url = "https://mail.google.com/mail/?view=cm&fs=1&to={}&su={}&body={}".format(to_q, su, bd)

    print(url)

    if len(bd) > args.max_chars:
        sys.stderr.write(
            "WARN: encoded body is {} chars (limit {}). Gmail compose links may be "
            "truncated by some clients. Prefer: open the link for To/Subject, then "
            "paste the body from the file (or attach it) — e.g. PowerShell: "
            "Get-Content <body-file> -Raw | Set-Clipboard\n".format(len(bd), args.max_chars)
        )

    if args.open_link:
        webbrowser.open(url)


if __name__ == "__main__":
    main()
