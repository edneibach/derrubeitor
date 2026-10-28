#!/usr/bin/env python3
"""
fraudtriage.py - stdlib-only OSINT triage for scam and phishing sites of
any kind, with extra smarts for Brazilian fraud kits (fake gov.br / Receita
Federal, PIX extortion).

Model-agnostic: works anywhere Python 3.8+ runs. No third-party packages.
No API keys (public keyless sources only: RDAP, crt.sh, urlscan.io public
search, Wayback availability API, BrasilAPI CNPJ, plain HTTP GETs).

Safety contract baked into the design:
  - GET-only. Never submits forms, never generates PIX/payment transactions.
  - Never queries a real person's CPF/CNPJ against a data-broker endpoint.
    (Querying the FRAUD KIT'S OWN lookup endpoint with a checksum-valid DUMMY
    CPF is allowed — it documents the kit's behavior, not a third party's.)
  - Classifies everything it prints as [HARD] (provable infrastructure) or
    [LEAD] (unverified identity claim displayed on a page). LEADS are for the
    law-enforcement annex only — never assert them as attribution in a
    third-party abuse report.

Commands:
  recon <host>          DNS + RDAP + CT logs + urlscan + Wayback + live header
                        fingerprint of https://<host>/
  fetch <url>           GET with mobile UA (default), print status + headers +
                        provider fingerprint, save body to a file (+sha256)
  analyze <file> ...    Extract IOCs and kit fingerprints from saved HTML
                        (--csv FILE to write an IOC table)
  cnpj <number>         Checksum + public registry lookup (BrasilAPI)
  validate-cpf <n>      Offline checksum validation
  validate-cnpj <n>     Offline checksum validation
  selftest              Offline checks, no network

Examples:
  python fraudtriage.py recon processo.limpar-divida.com
  python fraudtriage.py fetch "https://host/gvgconsulta?cpf=00000000000" --save stage3.html
  python fraudtriage.py analyze stage3.html --csv iocs.csv
  python fraudtriage.py cnpj 64.453.674/0001-24
"""

import argparse
import hashlib
import json
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

try:
    _reconfigure = getattr(sys.stdout, "reconfigure", None)
    if _reconfigure:
        _reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

UA_MOBILE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1")
UA_DESKTOP = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
UA_TOOL = "fraudtriage/1.0 (osint; stdlib; GET-only)"
MAX_BODY = 3 * 1024 * 1024

# ---------------------------------------------------------------------------
# Provider fingerprint table. The reliable way to attribute hosting/CDN behind
# a proxy: headers unique to a provider. The receiving provider can verify
# these in its own systems, which is what makes them [HARD] evidence.
# (header-name lowercase, value regex, provider, hard-or-soft)
FINGERPRINTS = [
    ("cf-ray", r".", "Cloudflare", "hard"),
    ("cf-cache-status", r".", "Cloudflare", "hard"),
    ("server", r"(?i)^cloudflare\b", "Cloudflare", "hard"),
    ("report-to", r"(?i)cloudflare", "Cloudflare", "hard"),
    ("nel", r"(?i)cf-nel", "Cloudflare", "hard"),
    ("set-cookie", r"__cf_bm|__cfduid|cf_clearance", "Cloudflare", "hard"),
    ("x-nf-request-id", r".", "Netlify", "hard"),
    ("netlify-vary", r".", "Netlify", "hard"),
    ("cache-status", r"(?i)netlify", "Netlify", "hard"),
    ("x-vercel-id", r".", "Vercel", "hard"),
    ("x-vercel-cache", r".", "Vercel", "hard"),
    ("server", r"(?i)^vercel\b", "Vercel", "hard"),
    ("x-github-request-id", r".", "GitHub Pages", "hard"),
    ("server", r"(?i)^github\.com\b", "GitHub Pages", "hard"),
    ("x-render-origin-server", r".", "Render", "hard"),
    ("fly-request-id", r".", "Fly.io", "hard"),
    ("x-amz-cf-id", r".", "AWS CloudFront", "hard"),
    ("via", r"(?i)cloudfront", "AWS CloudFront", "hard"),
    ("server", r"(?i)^amazons3\b", "AWS S3", "hard"),
    ("x-amz-request-id", r".", "AWS", "hard"),
    ("x-azure-ref", r".", "Azure Front Door", "hard"),
    ("x-served-by", r"(?i)^cache-", "Fastly", "hard"),
    ("via", r"(?i)varnish", "Fastly", "soft"),
    ("x-shopify-stage", r".", "Shopify", "hard"),
    ("x-wix-request-id", r".", "Wix", "hard"),
    ("x-iinfo", r".", "Imperva", "hard"),
    ("server", r"(?i)^nginx", None, "generic"),
    ("server", r"(?i)^apache", None, "generic"),
    ("x-powered-by", r"(?i)^express", None, "generic"),
]
REQUEST_ID_HEADERS = ("x-nf-request-id", "x-vercel-id", "x-github-request-id",
                      "fly-request-id", "x-render-origin-server")

# ---------------------------------------------------------------------------
# Brazil fraud-kit markers (corroboration tier: same kit family, not identity).
KIT_MARKERS = [
    ("HTTrack mirror comment (kit copied from source site)", r"Mirrored from \S+?\s+by HTTrack"),
    ("gvg kit path family (gvg/gvgconsulta/gvgchat/gvgpix)", r"/gvg(?:consulta|chat|pix)?\b"),
    ("fake reCAPTCHA (client-side-only checkbox)", r"[Nn][ãa]o sou um rob[ôo]|captcha-box"),
    ("anti-desktop gating (about:blank redirect)", r"about:blank"),
    ("mother-name verification quiz", r"NOME_MAE|showMaeVerification|nome da sua?\s*<b>m[ãa]e"),
    ("fake gov.br / Receita Federal impersonation",
     r"Receita Federal|gov\.br|INTIMA[ÇC][ÃA]O|Minist[ée]rio da Fazenda"),
    ("DARF / tax-document forgery", r"\bDARF\b|VLibras|e-CAC"),
    ("Desenrola Brasil lure", r"Desenrola"),
    ("device fingerprinting (FingerprintJS)", r"fingerprintjs"),
    ("Cloudflare Web Analytics beacon", r"cloudflareinsights\.com/beacon"),
    ("known scam value script (R$ 419,55 -> R$ 138,45)", r"419,55|138,45"),
    ("generic 'client with restriction' fallback persona", r"Cliente Com Restri[çc][ãa]o"),
]

# Common CDN dependencies that are NOT IOCs — filtered from the third-party URL list.
CDN_WHITELIST = (
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "fonts.googleapis.com",
    "fonts.gstatic.com", "fonts.cdnfonts.com", "cdn.tailwindcss.com",
    "unpkg.com", "ajax.googleapis.com", "www.google-analytics.com",
    "www.googletagmanager.com", "google.com/recaptcha", "gstatic.com",
    "cdn.lineicons.com",
)


# ============================== HTTP helpers ===============================

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class FetchResult(object):
    def __init__(self, final_url, status, headers, body, chain, ssl_ok, error=None):
        self.final_url = final_url
        self.status = status
        self.headers = headers          # list[(name, value)]
        self.body = body                # bytes (capped)
        self.chain = chain              # list[(url, code, location)]
        self.ssl_ok = ssl_ok
        self.error = error


def _open_once(url, ua, timeout, verify):
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={
        "User-Agent": ua, "Accept": "*/*", "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8"})
    return opener.open(req, timeout=timeout)


def http_fetch(url, ua=UA_MOBILE, timeout=25, verify=True, max_redirects=10):
    """Single GET with manual redirect tracking. Returns FetchResult."""
    chain, cur = [], url
    for _ in range(max_redirects + 1):
        try:
            r = _open_once(cur, ua, timeout, verify)
            body = r.read(MAX_BODY + 1)
            return FetchResult(cur, r.status, list(r.headers.items()), body, chain, verify)
        except urllib.error.HTTPError as e:
            loc = None
            for n, v in (e.headers.items() if e.headers else []):
                if n.lower() == "location":
                    loc = v
                    break
            if e.code in (301, 302, 303, 307, 308) and loc:
                chain.append((cur, e.code, loc))
                cur = urllib.parse.urljoin(cur, loc)
                continue
            body = b""
            try:
                body = e.read(MAX_BODY + 1)
            except Exception:
                pass
            return FetchResult(cur, e.code, list(e.headers.items()) if e.headers else [],
                               body, chain, verify)
        except ssl.SSLCertVerificationError:
            if verify:
                res = http_fetch(url, ua=ua, timeout=timeout, verify=False,
                                 max_redirects=max_redirects)
                res.ssl_ok = False
                return res
            return FetchResult(cur, 0, [], b"", chain, False,
                               error="TLS cert not valid even unverified")
        except Exception as e:                       # DNS, timeout, refused...
            return FetchResult(cur, 0, [], b"", chain, True, error=str(e))
    return FetchResult(cur, 0, [], b"", chain, True, error="too many redirects")


def http_json(url, timeout=45, retries=2, backoff=3):
    last = None
    for i in range(retries + 1):
        try:
            res = http_fetch(url, ua=UA_TOOL, timeout=timeout)
            if 200 <= res.status < 300 and res.body:
                return json.loads(res.body.decode("utf-8", "replace"))
            last = "HTTP %s" % res.status
        except Exception as e:
            last = str(e)
        if i < retries:
            time.sleep(backoff)
    raise RuntimeError("%s -> %s" % (url, last))


# ============================ Fingerprinting ===============================

def fingerprint(headers):
    hits, generic = {}, []
    for name, value in headers:
        ln, val = name.lower(), value or ""
        for hname, pat, provider, kind in FINGERPRINTS:
            if ln == hname and re.search(pat, val[:300]):
                if provider:
                    hits.setdefault((provider, kind), set()).add("%s: %s" % (name, val[:100]))
                else:
                    generic.append("%s: %s" % (name, val[:60]))
                break
    return hits, generic


def print_fingerprint(headers):
    hits, generic = fingerprint(headers)
    print("--- PROVIDER FINGERPRINT (from response headers) ---")
    if not hits:
        print("  [!!] No provider-unique header found. Only the REGISTRAR and the")
        print("       public blocklists are hard targets for this site.")
    for (provider, kind), evid in sorted(hits.items()):
        tag = "[HARD]" if kind == "hard" else "[SOFT]"
        print("  %s %-18s %s" % (tag, provider, " | ".join(sorted(evid))[:200]))
        blob = " ".join(sorted(evid)).lower()
        if any(h in blob for h in REQUEST_ID_HEADERS):
            print("       >>> attach this request-ID + the UTC fetch time to the abuse report")
    for g in sorted(set(generic)):
        print("  [----] %s  (generic, NOT attribution)" % g)
    print()


# ============================ Validators ===================================

def digits(s):
    return re.sub(r"\D", "", s or "")


def cpf_valid(cpf):
    d = digits(cpf)
    if len(d) != 11 or d == d[0] * 11:
        return False

    def dig(n):
        s = sum(int(d[i]) * (n + 1 - i) for i in range(n))
        r = (s * 10) % 11
        return 0 if r == 10 else r
    return dig(9) == int(d[9]) and dig(10) == int(d[10])


def cnpj_valid(cnpj):
    d = digits(cnpj)
    if len(d) != 14 or d == d[0] * 14:
        return False
    w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    w2 = [6] + w1

    def dig(ws):
        s = sum(int(d[i]) * ws[i] for i in range(len(ws)))
        r = s % 11
        return 0 if r < 2 else 11 - r
    return dig(w1) == int(d[12]) and dig(w2) == int(d[13])


def homoglyph_name_flag(name):
    """Digits embedded inside alphabetic words — e.g. 'REGULARIZAND0 PAGAMENT0'."""
    for t in re.split(r"\s+", name or ""):
        if re.search(r"\d", t) and re.search(r"[A-Za-zÀ-ÿ]", t):
            return True
    return False


# ============================ RDAP =========================================

def vcard_props(entity):
    out = {}
    va = entity.get("vcardArray")
    if isinstance(va, list) and len(va) > 1 and isinstance(va[1], list):
        for prop in va[1]:
            if isinstance(prop, list) and len(prop) >= 4:
                val = prop[3]
                if isinstance(val, list):
                    val = " ".join(str(x) for x in val if x)
                if val:
                    out.setdefault(prop[0], []).append(str(val))
    return out


def rdap_lookup(name):
    d = http_json("https://rdap.org/domain/" + name)
    events = {}
    for e in d.get("events") or []:
        events[e.get("eventAction")] = e.get("eventDate")
    nss = [n.get("ldhName", "").lower() for n in d.get("nameservers") or []]
    info = {"name": (d.get("ldhName") or name).lower(), "handle": d.get("handle"),
            "status": d.get("status") or [], "registrar": None, "abuse": [],
            "events": events, "nameservers": nss}

    def walk(ents):
        for e in ents or []:
            roles = e.get("roles") or []
            props = vcard_props(e)
            if "registrar" in roles and not info["registrar"]:
                iana = None
                for p in e.get("publicIds") or []:
                    if str(p.get("type", "")).startswith("IANA"):
                        iana = p.get("identifier")
                links = [l.get("href") for l in e.get("links") or [] if l.get("href")]
                info["registrar"] = {"name": (props.get("fn") or ["(unnamed)"])[0],
                                     "iana_id": iana, "links": links}
            if "abuse" in roles:
                info["abuse"].append({
                    "fn": (props.get("fn") or [""])[0],
                    "email": (props.get("email") or ["n/a"])[0],
                    "tel": (props.get("tel") or ["n/a"])[0]})
            walk(e.get("entities"))
    walk(d.get("entities"))
    return info


def print_rdap(info):
    print("--- RDAP / REGISTRAR [HARD target: the registrar] ---")
    print("  domain       : %s (handle %s)" % (info["name"], info.get("handle")))
    print("  status       : %s" % ", ".join(info["status"]))
    for action in ("registration", "last changed", "expiration"):
        if info["events"].get(action):
            print("  %-13s: %s" % (action, info["events"][action]))
    reg = info["registrar"]
    if reg:
        print("  registrar    : %s (IANA ID %s)" % (reg["name"], reg["iana_id"]))
        for l in reg["links"][:2]:
            print("  registrar ref: %s" % l)
    else:
        print("  registrar    : not exposed via RDAP (check the registry's web WHOIS)")
    if info["abuse"]:
        for a in info["abuse"]:
            print("  abuse contact: %s %s %s" % (a["fn"], a["email"], a["tel"]))
    else:
        print("  abuse contact: not in RDAP -> find it on the registrar's website")
    print("  nameservers  : %s" % ", ".join(info["nameservers"]))
    if any("cloudflare" in n for n in info["nameservers"]):
        print("  [HARD] DNS is on Cloudflare (DNS service; reportable via Cloudflare)")
    print()


# ============================ DNS ==========================================

def dns_a(host):
    try:
        return sorted({str(x[4][0]) for x in socket.getaddrinfo(host, 443, socket.AF_INET)})
    except Exception:
        return []


def dns_subprocess(host, rtype):
    for cmd in (["nslookup", "-type=" + rtype, host], ["dig", "+short", rtype, host]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            txt = (out.stdout or "") + (out.stderr or "")
            if out.returncode == 0 and txt.strip():
                return cmd[0], txt.strip()[:1500]
        except Exception:
            continue
    return None, "lookup unavailable (install dig or run from another host)"


def print_dns(host):
    print("--- DNS ---")
    ips = dns_a(host)
    print("  A     : %s" % (", ".join(ips) if ips else "resolution failed"))
    for rtype in ("NS", "MX", "TXT"):
        tool, out = dns_subprocess(host, rtype)
        keep = [l for l in out.splitlines() if l.strip()][:8] if out else []
        print("  %-5s : (%s) %s" % (rtype, tool or "?",
                                   " / ".join(keep)[:400] if keep else out[:120]))
    if ips:
        try:
            print("  rDNS  : %s -> %s" % (ips[0], socket.gethostbyaddr(str(ips[0]))[0]))
        except Exception:
            pass
    print()


# ============================ CT logs / urlscan / wayback ===================

def print_ct(apex):
    print("--- CERTIFICATE TRANSPARENCY (crt.sh) [corroboration: age + churn] ---")
    rows = []
    for q in (apex, "%." + apex):
        url = "https://crt.sh/?q=%s&output=json" % urllib.parse.quote(q, safe="")
        try:
            rows.extend(http_json(url, timeout=90, retries=1))
        except Exception as e:
            print("  [!] crt.sh failed for %s (%s)" % (q, e))
    if not rows:
        print("  no rows returned (crt.sh can be flaky — rerun recon)\n")
        return
    names = sorted({n.strip().lower() for r in rows
                    for n in re.split(r"[\n]", r.get("name_value", "")) if n.strip()})
    issuers = sorted({(r.get("issuer_name") or "")[:70] for r in rows})
    timeline = sorted({(r.get("not_before", "")[:10], (r.get("issuer_name") or "")[:40])
                       for r in rows})
    if timeline:
        print("  first cert  : %s" % timeline[0][0])
    print("  cert rows   : %d | distinct names: %d" % (len(rows), len(names)))
    print("  SAN names   : %s" % ", ".join(names[:12])[:400])
    print("  issuers     : %s" % " | ".join(issuers)[:300])
    print("  timeline (frequent re-issuance = rehosting churn):")
    for nb, iss in timeline[:30]:
        print("    %s  %s" % (nb, iss))
    print()


def print_urlscan(apex):
    print("--- URLSCAN.IO public scans [corroboration] ---")
    try:
        d = http_json("https://urlscan.io/api/v1/search/?q=domain:%s&size=20" % apex,
                      timeout=30, retries=0)
    except Exception as e:
        print("  search failed: %s\n" % e)
        return
    print("  total: %s (free tier searches ~30 days back)" % d.get("total"))
    for r in (d.get("results") or [])[:10]:
        pg, tk = r.get("page", {}), r.get("task", {})
        print("  %s | %s | %s %s | title=%r" % (
            tk.get("time", "?")[:19], tk.get("url", "?")[:90],
            pg.get("asn", ""), pg.get("ip", ""), pg.get("title", "")[:40]))
        print("    result: %s   screenshot: %s" % (r.get("result", ""), r.get("screenshot", "")))
    print()


def print_wayback(host, apex):
    print("--- WAYBACK MACHINE ---")
    for name in (host, apex):
        try:
            d = http_json("https://archive.org/wayback/available?url=" + name,
                          timeout=20, retries=0)
            snap = (d.get("archived_snapshots") or {}).get("closest") or {}
            print("  %-42s %s" % (name, snap.get("url", "no snapshot")))
        except Exception as e:
            print("  %-42s lookup failed (%s)" % (name, e))
    print()


# ============================ recon command ================================

def derive_apex(host):
    """Try RDAP on the host; strip the leftmost label on 404 until it resolves."""
    name, tried = host, 0
    while tried < 4:
        try:
            return name, rdap_lookup(name)
        except Exception as e:
            if "404" in str(e):
                if name.count(".") <= 1:
                    return name, None
                name = name.split(".", 1)[1]
                tried += 1
                continue
            return name, None
    return name, None


def cmd_recon(args):
    host = args.host.strip().rstrip(".")
    now = datetime.now(timezone.utc).isoformat()[:19]
    print("== recon: %s   (%s UTC) ==\n" % (host, now))
    print_dns(host)
    apex, info = derive_apex(host)
    if apex != host:
        print("  (RDAP resolved registered domain: %s)\n" % apex)
    if info:
        print_rdap(info)
    else:
        print("--- RDAP: no data for %s (unregistered or RDAP unreachable) ---\n" % apex)
    print_ct(apex)
    print_urlscan(apex)
    print_wayback(host, apex)
    if args.no_fetch:
        return
    res = None
    for scheme in ("https", "http"):
        res = http_fetch("%s://%s/" % (scheme, host))
        if res.status:
            print("--- LIVE HEADER PROBE: %s://%s/ ---" % (scheme, host))
            print("  status %s | body %d bytes | ssl_ok=%s"
                  % (res.status, len(res.body), res.ssl_ok))
            if res.error:
                print("  probe error: %s" % res.error)
            for n, v in res.headers:
                if n.lower() == "date" or n.lower().startswith("x-"):
                    print("  %s: %s" % (n, v[:120]))
            print_fingerprint(res.headers)
            break
    print("== HARD TARGET SUMMARY ==")
    if info and info["registrar"]:
        print("  registrar : %s (IANA %s)" % (info["registrar"]["name"],
                                               info["registrar"]["iana_id"]))
    if res and res.status:
        hits, _ = fingerprint(res.headers)
        providers = sorted({p for (p, k) in hits if k == "hard"})
        print("  serving   : %s" % (", ".join(providers) if providers
                                   else "no provider fingerprint (registrar+blocklists only)"))
    print("  next      : fetch the entry URL (mobile UA), follow the kit chain,")
    print("              then run analyze on each saved page.")


# ============================ fetch command ================================

def cmd_fetch(args):
    ua = UA_MOBILE if args.ua == "mobile" else UA_DESKTOP
    res = http_fetch(args.url, ua=ua)
    now = datetime.now(timezone.utc).isoformat()[:19]
    print("== fetch: %s ==" % args.url)
    for (u, code, loc) in res.chain:
        print("  redirect  : %s -> %s (%s)" % (u[:100], loc[:100], code))
    print("  final     : %s" % res.final_url)
    print("  status    : %s | %d bytes | ssl_ok=%s | fetched_at=%s UTC"
          % (res.status, len(res.body), res.ssl_ok, now))
    if res.error:
        print("  error     : %s" % res.error)
    print("  sha256    : %s" % hashlib.sha256(res.body).hexdigest())
    print("--- RESPONSE HEADERS (full — include in evidence file) ---")
    for n, v in res.headers:
        print("  %s: %s" % (n, v[:200]))
    print()
    print_fingerprint(res.headers)
    if args.save == "-":
        return
    path = args.save or ("fetched_%s.html" % re.sub(
        r"[^A-Za-z0-9]+", "_",
        urllib.parse.urlparse(args.url).netloc + urllib.parse.urlparse(args.url).path)[:80])
    with open(path, "wb") as f:
        f.write(res.body)
    print("  body saved to: %s" % path)


# ============================ analyze command ==============================

RE_CNPJ_FMT = re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b")
RE_CNPJ_CTX = re.compile(r"\bCNPJ\b[^0-9]{0,20}(\d{14})\b", re.I)
RE_CPF_FMT = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")
RE_CPF_CTX = re.compile(r"\bCPF\b[^0-9]{0,10}(\d{11})\b", re.I)
RE_MONEY = re.compile(r"R\$\s?[\d][\d.,]*")
RE_PIX = re.compile(r"\b000201[0-9A-Za-z.\-]{60,}")
RE_BEACON_TOKEN = re.compile(r"\"token\"\s*:\s*\"([0-9a-f]{32})\"")
RE_TELEGRAM = re.compile(r"\b(\d{8,10}):([A-Za-z0-9_-]{35})\b")
RE_RECAPTCHA = re.compile(r"(?:data-sitekey=[\"']|[?&]sitekey=)([0-9A-Za-z_-]{20,60})")
RE_WHATSAPP = re.compile(r"https?://(?:chat\.whatsapp\.com/[A-Za-z0-9_-]{10,}|wa\.me/\d+)")
RE_HTTRACK = re.compile(r"Mirrored from (\S+?)\s+by HTTrack[^>]*?,\s+([^<\"]+?GMT)")
RE_ENDPOINT_FETCH = re.compile(r"(?:fetch|\.open)\(\s*[`'\"]([^`'\"]+)[`'\"]")
RE_ENDPOINT_ACTION = re.compile(r"action=[\"']([^\"']+)[\"']")
RE_LOCALSTORAGE = re.compile(r"localStorage\.(?:get|set)Item\(\s*[\"']([^\"']+)[\"']")
RE_ABS_URL = re.compile(r"https?://([A-Za-z0-9.\-]+[A-Za-z0-9])")


def cmd_analyze(args):
    all_iocs = []
    for path in args.files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                html = f.read()
        except Exception as e:
            print("[!] cannot read %s: %s" % (path, e))
            continue
        print("== analyze: %s (%d chars) ==\n" % (path, len(html)))

        print("[1] KIT FAMILY MARKERS (corroboration — same-kit lineage, NOT identity)")
        for label, pat in KIT_MARKERS:
            found = re.findall(pat, html)
            if found:
                print("  [x] %-58s (%d hits)" % (label, len(found)))
        m = RE_HTTRACK.search(html)
        if m:
            print("  [x] HTTrack source: %s mirrored %s" % (m.group(1), m.group(2)))

        print("\n[2] ENDPOINTS (the kit's own attack surface)")
        seen = set()
        for pat in (RE_ENDPOINT_FETCH, RE_ENDPOINT_ACTION):
            for e in pat.findall(html):
                e = e.strip()
                if e and e not in seen and not e.startswith(("http://", "https://")):
                    seen.add(e)
        for e in sorted(seen):
            print("  endpoint: %s" % e[:140])
            all_iocs.append(("endpoint", e[:140], "kit endpoint", "corroboration"))
        ext = {h for h in RE_ABS_URL.findall(html)
               if not any(w in h for w in CDN_WHITELIST)}
        for h in sorted(ext)[:25]:
            print("  3p-host : %s" % h)
            all_iocs.append(("3p-host", h, "third-party reference", "corroboration"))

        print("\n[3] TRACKING / OPERATOR TOKENS [LEADS]")
        bt = RE_BEACON_TOKEN.search(html)
        if bt:
            print("  [LEAD] cloudflare-analytics token: %s" % bt.group(1))
            all_iocs.append(("cf-beacon-token", bt.group(1), "operator analytics", "lead"))
        if re.search(r"cloudflareinsights", html):
            print("  [LEAD] cloudflareinsights beacon present (operator's CF analytics)")
        for tk in RE_TELEGRAM.findall(html)[:5]:
            print("  [LEAD] telegram bot token: %s:%s" % tk)
            all_iocs.append(("telegram-token", "%s:%s" % tk, "operator exfil channel", "lead"))
        for sk in RE_RECAPTCHA.findall(html)[:5]:
            print("  [LEAD] recaptcha sitekey: %s" % sk)
        for wa in RE_WHATSAPP.findall(html)[:5]:
            print("  [LEAD] whatsapp link: %s" % wa)
        for k in sorted(set(RE_LOCALSTORAGE.findall(html)))[:15]:
            print("  [LEAD] localStorage key: %s" % k)

        print("\n[4] IDENTITY CLAIMS DISPLAYED ON PAGE [LEADS — NEVER assert ownership]")
        cn = sorted(set(RE_CNPJ_FMT.findall(html)) | set(RE_CNPJ_CTX.findall(html)))
        for c in cn:
            v = "VALID" if cnpj_valid(c) else "INVALID"
            print("  [LEAD] CNPJ %s (checksum %s)" % (c, v))
            all_iocs.append(("cnpj", c, "displayed on page; checksum %s" % v.lower(), "lead"))
        cp = sorted(set(RE_CPF_FMT.findall(html)) | set(RE_CPF_CTX.findall(html)))
        for c in cp:
            v = "VALID" if cpf_valid(c) else "INVALID"
            print("  [LEAD] CPF %s (checksum %s) — could be victim, operator default, or dummy"
                  % (c, v))
            all_iocs.append(("cpf", c, "displayed on page; checksum %s" % v.lower(), "lead"))
        for ben in re.findall(r"Benefici[áa]rio[^A-Za-z]{0,4}([A-Z_][A-Z_' ]{4,60})", html)[:5]:
            print("  [LEAD] PIX beneficiary string: %r" % ben.strip())
            all_iocs.append(("pix-beneficiary", ben.strip(), "displayed on page", "lead"))
        for px in RE_PIX.findall(html)[:3]:
            print("  [LEAD] PIX BR-code payload present (%d chars) — decode for law"
                  " enforcement only" % len(px))
            all_iocs.append(("pix-code", "len=%d" % len(px), "in page source", "lead"))
        for mv in sorted(set(RE_MONEY.findall(html)))[:15]:
            print("  [LEAD] money amount: %s" % mv)
        print()
    if args.csv:
        import csv as _csv
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = _csv.writer(f)
            w.writerow(["ioc_type", "value", "note", "tier"])
            for row in all_iocs:
                w.writerow(row)
        print("IOCs written to %s (%d rows)" % (args.csv, len(all_iocs)))


# ============================ cnpj command =================================

def cmd_cnpj(args):
    n = digits(args.number)
    print("== cnpj: %s ==" % args.number)
    print("  checksum: %s" % ("VALID" if cnpj_valid(n) else "INVALID"))
    if not cnpj_valid(n):
        print("  not a real-looking CNPJ — registry lookup skipped")
        return
    try:
        d = http_json("https://brasilapi.com.br/api/cnpj/v1/%s" % n, timeout=30, retries=1)
    except Exception as e:
        print("  registry lookup failed: %s" % e)
        return
    print("  [LEAD] razao social : %s" % d.get("razao_social"))
    print("  [LEAD] nome fantasia: %s" % d.get("nome_fantasia"))
    print("  opened     : %s" % d.get("data_inicio_atividade"))
    print("  situation  : %s / %s (%s)" % (d.get("descricao_situacao_cadastral"),
                                           d.get("data_situacao_cadastral"),
                                           d.get("descricao_motivo_situacao_cadastral")))
    print("  address    : %s, %s - %s/%s, CEP %s" % (d.get("logradouro"), d.get("numero"),
                                                     d.get("municipio"), d.get("uf"), d.get("cep")))
    print("  phone      : %s" % (d.get("ddd_telefone_1") or "-"))
    print("  capital    : %s" % d.get("capital_social"))
    print("  FLAGS:")
    if d.get("descricao_situacao_cadastral") in ("SUSPENSA", "BAIXADA", "INAPTA", "NULA"):
        print("    [x] registry status is %s (%s) — consistent with fraud shells"
              % (d.get("descricao_situacao_cadastral"),
                 d.get("descricao_motivo_situacao_cadastral")))
    if homoglyph_name_flag(d.get("razao_social")):
        print("    [x] digit-in-word name trick (e.g. SERVIC0S, REGULARIZAND0)")
    opened = str(d.get("data_inicio_atividade") or "")
    if opened:
        try:
            started = datetime.strptime(opened, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - started).days
            print("    company age: %d days%s" % (age, "  [x] FRESH (<180d)" if age < 180 else ""))
        except Exception:
            pass
    for socio in d.get("qsa") or []:
        print("  [LEAD] owner: %s (%s, since %s)"
              % (socio.get("nome_socio"), socio.get("qualificacao_socio"),
                 socio.get("data_entrada_sociedade")))
    print("\n  Reminder: registry data identifies the REGISTERED owner, not the actor.")
    print("  Fraud kits display stolen/dummy identifiers. Everything above is a")
    print("  law-enforcement lead — never an attribution in a third-party report.")


# ============================ validators / selftest ========================

def cmd_validate_cpf(args):
    print("CPF %s -> checksum %s" % (args.number, "VALID" if cpf_valid(args.number) else "INVALID"))


def cmd_validate_cnpj(args):
    print("CNPJ %s -> checksum %s" % (args.number, "VALID" if cnpj_valid(args.number) else "INVALID"))


def cmd_selftest(_args):
    ok = True

    def check(name, cond):
        nonlocal ok
        print("  [%s] %s" % ("PASS" if cond else "FAIL", name))
        ok = ok and bool(cond)

    print("== selftest (offline) ==")
    check("cpf 529.982.247-25 valid", cpf_valid("529.982.247-25"))
    check("cpf 111.111.111-11 invalid", not cpf_valid("111.111.111-11"))
    check("cpf 00000000000 invalid", not cpf_valid("00000000000"))
    check("cnpj 64.453.674/0001-24 valid", cnpj_valid("64.453.674/0001-24"))
    check("cnpj 11.222.333/0001-81 valid", cnpj_valid("11.222.333/0001-81"))
    check("cnpj 64.453.674/0001-25 invalid", not cnpj_valid("64.453.674/0001-25"))
    sample = ("<!-- Mirrored from regularizadebitos.click/gov/ by HTTrack Website Copier/3.x"
              " [XR&CO'2014], Sun, 07 Jun 2026 01:21:40 GMT -->"
              " data-cf-beacon='{\"token\":\"3b7e4700fd74406bbfabeeaa99024733\"}'"
              " fetch('api/gerar_pix.php') R$ 419,55 R$138,45 64.453.674/0001-24"
              " 052.182.791-45 NOME_MAE /gvgconsulta about:blank"
              " 1234567890:" + "A" * 35 +
              ' data-sitekey="' + "6" * 40 + '"'
              " Beneficiario PRIME_SOLUCOES_CORPORATIV"
              " 00020126580014BR.GOV.BCB.PIX0136123e4567e89b12d3a4567e89b12d3a4567e89b12d3a4567e89")
    check("httrack regex", bool(RE_HTTRACK.search(sample)))
    mb = RE_BEACON_TOKEN.search(sample)
    check("beacon token regex",
          bool(mb) and mb.group(1) == "3b7e4700fd74406bbfabeeaa99024733")
    check("telegram regex", bool(RE_TELEGRAM.search(sample)))
    check("recaptcha regex", bool(RE_RECAPTCHA.search(sample)))
    check("pix code regex", bool(RE_PIX.search(sample)))
    check("money regex", len(set(RE_MONEY.findall(sample))) >= 1)
    check("cnpj-format regex", "64.453.674/0001-24" in RE_CNPJ_FMT.findall(sample))
    check("cpf-format regex", "052.182.791-45" in RE_CPF_FMT.findall(sample))
    check("endpoint regex", "api/gerar_pix.php" in RE_ENDPOINT_FETCH.findall(sample))
    check("homoglyph flag", homoglyph_name_flag("REGULARIZAND0 PAGAMENT0 LTDA"))
    check("homoglyph clean name ok", not homoglyph_name_flag("SERVICOS DIGITAIS LTDA"))
    print("selftest %s" % ("OK" if ok else "FAILED"))
    sys.exit(0 if ok else 1)


# ============================ main ==========================================

def main():
    p = argparse.ArgumentParser(prog="fraudtriage",
                                description="Brazil fraud OSINT triage (GET-only, keyless)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("recon", help="DNS+RDAP+CT+urlscan+wayback+header fingerprint")
    sp.add_argument("host")
    sp.add_argument("--no-fetch", action="store_true")
    sp.set_defaults(func=cmd_recon)

    sp = sub.add_parser("fetch", help="GET a URL, capture headers, fingerprint provider")
    sp.add_argument("url")
    sp.add_argument("--ua", choices=["mobile", "desktop"], default="mobile")
    sp.add_argument("--save", default=None, help="output file, or '-' to not save")
    sp.set_defaults(func=cmd_fetch)

    sp = sub.add_parser("analyze", help="extract IOCs from saved HTML files")
    sp.add_argument("files", nargs="+")
    sp.add_argument("--csv", default=None)
    sp.set_defaults(func=cmd_analyze)

    sp = sub.add_parser("cnpj", help="validate + public registry lookup (LEAD tier)")
    sp.add_argument("number")
    sp.set_defaults(func=cmd_cnpj)

    sp = sub.add_parser("validate-cpf", help="offline CPF checksum")
    sp.add_argument("number")
    sp.set_defaults(func=cmd_validate_cpf)

    sp = sub.add_parser("validate-cnpj", help="offline CNPJ checksum")
    sp.add_argument("number")
    sp.set_defaults(func=cmd_validate_cnpj)

    sub.add_parser("selftest", help="offline checks").set_defaults(func=cmd_selftest)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
