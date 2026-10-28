#!/usr/bin/env python3
"""autoreport_forms.py — OPTIONAL browser-assisted abuse-report submission.

CONSENT-FIRST (this is an AI-skill tool): the agent must NEVER run a real
submission without asking the user in the conversation first:
  1. "Evidence is compiled — may I file the reports now?" (list targets)
  2. If a form needs reporter identity, ask "Which name/email should the
     forms use? (required by the provider; never stored)" — identity is
     passed per-run via --name/--email or typed interactively.
  3. Only then submit. One submission per invocation. Receipts land in
     receipts/ with the captured XHR evidence.

Providers (matrix — headless, camoufox v0.5.8, tested 2026-10-28):
  cloudflare   AUTOMATABLE — no challenge even headless; needs reporter
               name+email; Turnstile renders at submit (auto or 1 click).
  gsb          AUTOMATABLE — Safe Browsing JS form; reCAPTCHA-Enterprise is
               invisible/score-based (token ready, no click needed); the app
               submits via XHR and silently resets the form (verdict comes
               from the captured XHR, not from a "thank you" page).
               One URL per report; one report per hostname is enough.
  smartscreen  MANUAL — guest form has a character CAPTCHA (HIP); signed-in
               needs a Microsoft account. Prints paste instructions.
  googleads    MANUAL — support harness requires a Google login. Prints
               paste instructions.
  OTHER        EXTENSIBLE — run `map <form-url>`: dumps the form structure
               (labels, inputs, buttons, selects+options, frames) so an LLM
               can write a new adapter by following the gsb/cf examples
               below. Copy an adapter block, adjust selectors, done.

usage:
  python scripts/autoreport_forms.py status
  python scripts/autoreport_forms.py map <form-url>
  python scripts/autoreport_forms.py gsb <url> [--comment TEXT]
                                        [--dry-run | --assist]
  python scripts/autoreport_forms.py cf <urls...> [--name N] [--email E]
              [--evidence-text FILE] [--brand B] [--country C]
              [--dry-run | --assist]
  python scripts/autoreport_forms.py smartscreen <url>   (manual fallback)
  python scripts/autoreport_forms.py googleads           (manual fallback)

modes:
  --dry-run  types nothing: prints the exact fill plan + receipt.
  --assist   opens a VISIBLE browser with everything pre-filled and waits
             for the human to click captcha/submit — automation prepares,
             the human sends. Best for captcha-gated or review-before-send.

install (OPTIONAL feature — the rest of the skill works without it):
  pip install "camoufox[geoip]" && python -m camoufox fetch

receipts: every real submission writes receipts/<provider>-<utc>.txt (+ .html
snapshot) with what was sent and the captured submit XHR (url + status).
"""
import argparse
import datetime
import hashlib
import sys
from urllib.parse import urlparse

try:
    from camoufox.sync_api import Camoufox
except ImportError:
    Camoufox = None

CF_FORM = "https://abuse.cloudflare.com/phishing"
GSB_FORM = "https://safebrowsing.google.com/safebrowsing/report_phish/"

PASTE_MANUAL = {
    "smartscreen": (
        "SmartScreen: manual only (guest form has a character CAPTCHA; "
        "signed-in needs a Microsoft account).\n"
        "1. Open https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site\n"
        "2. 'Continue as a guest' -> paste the URL -> Phishing -> language -> "
        "solve the CAPTCHA -> Submit."
    ),
    "googleads": (
        "Google Ads: manual only (support harness requires a Google login).\n"
        "1. Open https://support.google.com/google-ads/contact/rumors_or_fraud\n"
        "2. Sign in -> paste the report from the case's google-ads FORM.txt."
    ),
}


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def receipt(provider, lines, dom=""):
    import os
    os.makedirs("receipts", exist_ok=True)
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    sha = hashlib.sha256(dom.encode("utf-8", "replace")).hexdigest() if dom else "-"
    path = f"receipts/{provider}-{stamp}.txt"
    domfile = None
    if dom:
        domfile = f"receipts/{provider}-{stamp}.html"
        with open(domfile, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(dom)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# receipt {provider} {stamp} UTC\n")
        fh.write(f"# dom-sha256 {sha}\n")
        if domfile:
            fh.write(f"# dom-snapshot {domfile}\n")
        fh.write("\n".join(lines) + "\n")
    print(f"[receipt] {path} (dom sha256 {sha[:16]}...)")
    return path


def group_by_host(urls):
    out = {}
    for u in urls:
        out.setdefault(urlparse(u).netloc, []).append(u)
    return out


def log_state(page, tag):
    try:
        print(f"[state {tag}] title={page.title()!r} len={len(page.content())}")
    except Exception as e:  # noqa: BLE001
        print(f"[state {tag}] err {e}")


class XhrWatch:
    """Records POST/submit XHRs so receipts prove what was actually sent."""

    KEY: str = ""  # substring of the XHR url that identifies a submission

    def __init__(self, page):
        self.hits = []
        page.on("response", self._on_response)

    def _on_response(self, response):
        try:
            if (not self.KEY or self.KEY in response.url) and \
                    response.request.method == "POST":
                self.hits.append(f"{response.request.method} {response.url} "
                                 f"-> {response.status}")
        except Exception:  # noqa: BLE001
            pass

    def evidence(self):
        return list(self.hits)


# ----------------------------------------------------------------- gsb ----
# ADAPTER EXAMPLE (add new providers by copying this pattern):
#   1. run `map <form-url>` and read the dump: ids, labels, submit button
#   2. write a fill_<provider>(page, payload) + submit detection
#   3. register it in main() with the consent-first rules honored.

GSB_THREAT_LABELS = ("engenharia social", "social engineering")
GSB_CATEGORY_EXACT = ("phishing",)
GSB_CATEGORY_HINTS = ("phishing", "phish")
GSB_THANKS = ("thank you", "obrigado", "obrigada", "gratid",
              "recebemos sua", "your report", "sua denúncia", "sua denuncia",
              "has been recorded", "foi registrada", "foi enviada",
              "report is submitted", "denúncia foi")


def gsb_fill(page, url, comment):
    page.locator("#mat-select-1").click()
    page.wait_for_timeout(1200)
    picked = None
    for o in page.locator("mat-option, [role=option]").all():
        t = (o.inner_text() or "").strip().lower()
        if any(lbl in t for lbl in GSB_THREAT_LABELS):
            o.click()
            picked = t
            break
    if picked is None:
        opts = page.locator("mat-option, [role=option]").all()
        if opts:
            opts[0].click()
            picked = "(first option)"
    print(f"[gsb] threat type -> {picked}")
    page.wait_for_timeout(1500)

    page.locator("#mat-select-2").click(timeout=20000)
    page.wait_for_timeout(1200)
    picked_cat = None
    opts = page.locator("mat-option, [role=option]").all()
    for o in opts:
        t = (o.inner_text() or "").strip().lower()
        if t in GSB_CATEGORY_EXACT:
            o.click()
            picked_cat = t
            break
    if picked_cat is None:
        for o in opts:
            t = (o.inner_text() or "").strip().lower()
            if any(h in t for h in GSB_CATEGORY_HINTS):
                o.click()
                picked_cat = t
                break
    if picked_cat is None and opts:
        opts[0].click()
        picked_cat = "(first option)"
    print(f"[gsb] threat category -> {picked_cat}")
    page.wait_for_timeout(1200)

    page.locator("#mat-input-0").fill(url)
    if comment:
        page.locator("#mat-input-1").fill(comment[:800])
    print(f"[gsb] filled url={url}")
    return picked, picked_cat


def gsb_captcha_token(page):
    """reCAPTCHA-Enterprise here is invisible/score-based: the anchor frame
    holds a ready token. Some variants show a checkbox — click it."""
    for _ in range(30):
        page.wait_for_timeout(1000)
        for f in page.frames:
            if "recaptcha" not in f.url:
                continue
            try:
                tok = f.locator("#recaptcha-token").input_value()
                if tok:
                    return tok
                box = f.locator("#recaptcha-anchor, [role=checkbox]")
                if box.count():
                    box.first.click(timeout=10000)
                    print("[gsb] captcha checkbox clicked (fallback)")
            except Exception:  # noqa: BLE001
                pass
    return ""


def gsb_submit(url, comment, dry_run, assist):
    if dry_run:
        print("[dry-run] would fill: threat='social engineering', "
              "category='phishing', "
              f"url={url}, comment={comment!r}; then submit (captcha is "
              "invisible/score-based). NOTHING is typed.")
        receipt("gsb-dryrun", [f"planned url: {url}"])
        return
    with Camoufox(headless=not assist, humanize=True, geoip=True) as browser:
        page = browser.new_page()
        watch = XhrWatch(page)
        watch.KEY = "SafebrowsingSubmission"
        page.goto(GSB_FORM, timeout=90000)
        page.wait_for_load_state("load")
        page.wait_for_timeout(5000)
        log_state(page, "loaded")
        threat, cat = gsb_fill(page, url, comment)

        token = gsb_captcha_token(page)
        print(f"[gsb] recaptcha token: "
              f"{'OK (invisible/score-based)' if token else 'MISSING'}")

        if assist:
            print("[gsb] ASSIST MODE: form is pre-filled in the open window — "
                  "please verify, then click ENVIAR yourself. "
                  "Waiting up to 10 min...")
            ok = _wait_human_confirm(page, GSB_THANKS)
            receipt("gsb", [f"verdict: {'human-confirmed' if ok else 'timeout/unknown'}",
                            f"url: {url}", f"threat: {threat} / {cat}",
                            "xhr: " + "; ".join(watch.evidence()) or "-"],
                    page.content())
            return

        if not token:
            print("[gsb] VERDICT: RECAPTCHA_CHALLENGE — honest stop; rerun "
                  "with --assist to finish with one human click")
            receipt("gsb", ["recaptcha not passed", f"url: {url}"],
                    page.content())
            return

        for b in page.get_by_role("button").all():
            try:
                t = (b.inner_text() or "").strip().lower()
            except Exception:  # noqa: BLE001
                continue
            if t in ("enviar", "submit"):
                b.click()
                print(f"[gsb] clicked submit button {t!r}")
                break

        body, ok = "", False
        for _ in range(15):
            page.wait_for_timeout(1000)
            body = page.inner_text("body") or ""
            if any(m in body.lower() for m in GSB_THANKS):
                ok = True
                break
        # silent-reset detection: the app clears the form after submit
        reset = False
        try:
            reset = (page.locator("#mat-input-0").input_value() == ""
                     and "ng-pristine" in (page.content() or ""))
        except Exception:  # noqa: BLE001
            pass
        xhr = watch.evidence()
        verdict = ("SUBMITTED (xhr captured)" if xhr else
                   "SUBMITTED (form silently reset — Google shows no "
                   "confirmation)" if reset or ok else "UNKNOWN — inspect "
                   "dom-snapshot; rerun with --assist")
        print(f"[gsb] VERDICT: {verdict}")
        receipt("gsb", [f"verdict: {verdict}", f"url: {url}",
                        f"threat: {threat} / {cat}",
                        "xhr: " + ("; ".join(xhr) if xhr else "(none captured)"),
                        f"post-submit text: {body[:300]}"], page.content())


def _wait_human_confirm(page, thanks_markers, minutes=10):
    import time
    deadline = time.time() + minutes * 60
    while time.time() < deadline:
        page.wait_for_timeout(2000)
        try:
            body = (page.inner_text("body") or "").lower()
            if any(m in body for m in thanks_markers):
                print("[assist] confirmation text detected — thank you!")
                return True
        except Exception:  # noqa: BLE001
            pass
    print("[assist] timeout waiting for human confirmation")
    return False


# ------------------------------------------------------------------ cf ----

def cf_submit(urls, name, email, evidence_text, brand, country, dry_run,
             assist):
    groups = group_by_host(urls)
    print(f"[cf] {len(groups)} hostname group(s): "
          f"{ {h: len(v) for h, v in groups.items()} }")
    for host, host_urls in groups.items():
        print(f"[cf] === {host} ===")
        if dry_run:
            lines = [
                "DRY-RUN — nothing typed, nothing submitted",
                f"hostname: {host}",
                f"urls ({len(host_urls)}): " + "\n  ".join(host_urls),
                f"name: {name or '(will prompt interactively)'}",
                f"email: {email or '(will prompt interactively)'}",
                f"targeted brand: {brand}",
                f"country: {country}",
                "checkboxes: forward-to-provider=yes(include contact), "
                "forward-to-owner=NO, DSA bona fide=yes",
                f"evidence text: {'(file)' if evidence_text else '(basic)'}",
            ]
            receipt("cf-dryrun", lines)
            print("\n".join(lines))
            continue
        if not name or not email:
            print("[cf] identity required — type it (never hardcoded):")
            name = name or input("  Full name: ").strip()
            email = email or input("  Email: ").strip()
            confirm = input("  Confirm email: ").strip()
            if email != confirm:
                print("email mismatch — aborting this group")
                continue
        with Camoufox(headless=not assist, humanize=True, geoip=True) as browser:
            page = browser.new_page()
            watch = XhrWatch(page)
            watch.KEY = ""  # record any POST from the page
            page.goto(CF_FORM, timeout=90000)
            page.wait_for_load_state("load")
            page.wait_for_timeout(5000)
            log_state(page, "loaded")
            try:
                _cf_fill(page, host_urls, name, email, evidence_text, brand,
                         country)
            except Exception as e:  # noqa: BLE001
                print(f"[cf] fill error: {e}")
                receipt("cf", [f"fill error: {e}", f"hostname: {host}"],
                        page.content())
                continue
            if assist:
                print("[cf] ASSIST MODE: form pre-filled in the open window — "
                      "verify, solve Turnstile if shown, click Submit "
                      "yourself. Waiting up to 10 min...")
                ok = _cf_turnstile_and_submit(page, human=True)
                receipt("cf", [f"verdict: "
                                f"{'human-confirmed' if ok else 'TIMEOUT-not-confirmed'}",
                                f"hostname: {host}",
                                f"urls: {host_urls}",
                                "xhr: " + ("; ".join(watch.evidence()) or "-")],
                        page.content())
                continue
            submitted = _cf_turnstile_and_submit(page, human=False)
            body = (page.inner_text("body") or "").lower()
            ok = submitted and any(
                m in body for m in ("thank you", "report has been", "submitted"))
            verdict = "SUBMITTED" if ok else "UNKNOWN — rerun with --assist"
            print(f"[cf] VERDICT: {verdict}")
            receipt("cf", [f"verdict: {'submitted' if ok else 'unknown'}",
                           f"hostname: {host}",
                           f"urls: {host_urls}",
                           "xhr: " + ("; ".join(watch.evidence()) or "-")],
                    page.content())


def _cf_fill(page, urls, name, email, evidence_text, brand, country):
    page.get_by_label("Your full name", exact=False).fill(name)
    page.get_by_label("Your email address", exact=False).fill(email)
    page.get_by_label("Confirm email address", exact=False).fill(email)
    page.get_by_label("Evidence URLs", exact=False).fill("\n".join(urls))
    if evidence_text:
        page.get_by_label("Logs or other evidence of abuse",
                          exact=False).fill(evidence_text[:4000])
    if brand:
        page.get_by_label("Targeted Brand", exact=False).fill(brand)
    try:
        page.locator("[role=combobox]").nth(2).click()
        page.wait_for_timeout(1000)
        page.get_by_role("option", name=country, exact=False).first.click()
    except Exception as e:  # noqa: BLE001
        print(f"[cf] country select skipped: {e}")
    _cf_check(page, "Please forward my report to the website hosting provider")
    _cf_check(page, "Include my name and contact information with the report "
                    "to the website hosting provider")
    _cf_check(page, "DSA certification of bona fide belief")
    print("[cf] form filled")


def _cf_check(page, text):
    """Check a Cloudflare abuse-form checkbox by its label text.

    Skips when already checked or locked (disabled): the 2026-10 form ships
    'forward my report to provider/owner' pre-checked AND disabled (locked
    ON), so clicking them is impossible and unnecessary. Returns silently so
    a locked checkbox never aborts the fill."""
    info = page.evaluate(
        """(t) => {
            for (const inp of document.querySelectorAll('input[type=checkbox]')) {
                const lab = inp.labels && inp.labels[0];
                if (lab && lab.textContent.replace(/\\s+/g, ' ').includes(t)) {
                    return {id: inp.id, checked: inp.checked,
                            disabled: inp.disabled};
                }
            }
            return null;
        }""", text)
    short = text[:60]
    if info is None:
        print(f"[cf] checkbox not found (skip): {short}")
        return
    if info["checked"]:
        print(f"[cf] checkbox already checked (skip): {short}")
        return
    if info["disabled"]:
        print(f"[cf] checkbox locked off, cannot check (skip): {short}")
        return
    page.locator(f"label[for='{info['id']}']").click()
    page.wait_for_timeout(400)
    after = page.evaluate(
        """(id) => {
            const inp = document.getElementById(id);
            return inp ? inp.checked : null;
        }""", info["id"])
    print(f"[cf] checked: {short} -> {after}")


def _cf_turnstile_and_submit(page, human=False):
    if not human:
        print("[cf] submit + turnstile")
        try:
            page.get_by_role("button", name="Submit").first.click()
        except Exception as e:  # noqa: BLE001
            print(f"[cf] submit click err: {e}")
            return False
    if human:
        # assist mode: the HUMAN clicks Turnstile + Submit. Automation only
        # waits and watches for the confirmation copy (up to 10 minutes);
        # it never touches the page — automation prepares, the human sends.
        done_markers = ("thank you", "has been submitted", "report received",
                        "we have received", "report submitted")
        for i in range(300):
            page.wait_for_timeout(2000)
            try:
                body = (page.inner_text("body") or "").lower()
                if any(m in body for m in done_markers):
                    print(f"[cf] confirmation detected after "
                          f"~{(i + 1) * 2}s of waiting")
                    return True
            except Exception:  # noqa: BLE001
                pass
            if (i + 1) % 75 == 0:
                print(f"[cf] still waiting for your Submit... "
                      f"({(i + 1) * 2}s elapsed)")
        print("[cf] no confirmation within 10 min — treat as NOT submitted")
        return False
    # unattended: if a turnstile checkbox appears, click it once (what a user
    # would do)
    for _ in range(15):
        page.wait_for_timeout(1000)
        for f in page.frames:
            if "challenges.cloudflare.com" in f.url:
                try:
                    box = f.locator("input[type=checkbox], .ctp-checkbox-label")
                    if box.count():
                        box.first.click(timeout=3000)
                        print("[cf] turnstile checkbox clicked")
                except Exception:  # noqa: BLE001
                    pass
        try:
            body = (page.inner_text("body") or "").lower()
            if "thank you" in body or "has been submitted" in body:
                return True
        except Exception:  # noqa: BLE001
            pass
    return not human


# ----------------------------------------------------------------- map ----
# LLM extensibility: dump any provider's form so an adapter can be written.

def map_form(url):
    if Camoufox is None:
        sys.exit("camoufox not installed — pip install 'camoufox[geoip]' "
                 "&& python -m camoufox fetch")
    from urllib.parse import urlparse as up
    host = up(url).netloc.replace(":", "_")
    with Camoufox(headless=True, humanize=True, geoip=True) as browser:
        page = browser.new_page()
        page.goto(url, timeout=90000)
        page.wait_for_load_state("load")
        page.wait_for_timeout(5000)
        html = page.content()
        out = f"map-{host}.html"
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(html)
        print(f"[map] {len(html)} chars -> {out}")
        print("== visible text ==")
        print(page.inner_text("body")[:2000])
        print("== fields ==")
        for sel in ("form", "input", "textarea", "select", "button",
                    "[role=radio]", "[role=combobox]"):
            els = page.locator(sel).all()
            print(f"-- {sel}: {len(els)}")
            for el in els[:15]:
                try:
                    print("   id=", el.get_attribute("id"),
                          "name=", el.get_attribute("name"),
                          "type=", el.get_attribute("type"),
                          "placeholder=", el.get_attribute("placeholder"),
                          "text=", repr((el.inner_text() or "").strip()[:40]))
                except Exception:  # noqa: BLE001
                    pass
        print("== frames ==")
        for f in page.frames:
            print("   ", f.url[:120])
        print("[map] to add this provider: copy the gsb adapter block in "
              "scripts/autoreport_forms.py, adjust selectors from this dump, "
              "register in main(). Keep consent-first rules.")


# ---------------------------------------------------------------- main ----

def main():
    ap = argparse.ArgumentParser(
        description="OPTIONAL browser-assisted abuse-report submission "
                    "(consent-first — see module docstring)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status")

    p = sub.add_parser("map")
    p.add_argument("url")

    p = sub.add_parser("gsb")
    p.add_argument("url")
    p.add_argument("--comment", default="")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--assist", action="store_true",
                   help="headful: pre-fill, human clicks submit")

    p = sub.add_parser("cf")
    p.add_argument("urls", nargs="+")
    p.add_argument("--name")
    p.add_argument("--email")
    p.add_argument("--evidence-text")
    p.add_argument("--brand", default="")
    p.add_argument("--country", default="Brazil")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--assist", action="store_true",
                   help="headful: pre-fill, human clicks submit")

    p = sub.add_parser("smartscreen")
    p.add_argument("url")
    p = sub.add_parser("googleads")

    args = ap.parse_args()

    if args.cmd == "status":
        print(__doc__)
        return
    if args.cmd == "map":
        map_form(args.url)
        return
    if args.cmd in PASTE_MANUAL:
        print(PASTE_MANUAL[args.cmd])
        return
    if Camoufox is None:
        sys.exit("camoufox not installed — pip install 'camoufox[geoip]' "
                 "&& python -m camoufox fetch")

    if args.cmd == "gsb":
        gsb_submit(args.url, args.comment, args.dry_run, args.assist)
    elif args.cmd == "cf":
        ev = None
        if args.evidence_text:
            with open(args.evidence_text, encoding="utf-8") as fh:
                ev = fh.read()
        cf_submit(args.urls, args.name, args.email, ev, args.brand,
                  args.country, args.dry_run, args.assist)


if __name__ == "__main__":
    main()
