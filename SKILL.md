---
name: derrubeitor
description: DERRUBEITOR - investigate and take down scam and phishing sites of any kind (golpe, phishing, bank/government/brand impersonation, PIX or card payment extortion, any country) by building evidence and filing abuse reports with the parties who can act: CDN, origin host, registrar, Safe Browsing, national CSIRT (CERT.br in Brazil), police. Extra smarts for Brazilian fraud: CPF/CNPJ checks, CERT.br/ANPD/Receita Federal channels, known BR kit families. Bundles a keyless, stdlib-only Python triage toolkit (DNS, RDAP, CT logs, urlscan, CNPJ registry lookup, kit IOC extraction). Use when the user reports a scam site, suspicious link, or lure message and wants analysis, evidence, or a takedown.
---

# DERRUBEITOR - Scam/Phishing Takedown (OSINT → Abuse Reports)

**Languages:** this file is the English reference (auto-loaded by opencode).
`SKILL.pt-BR.md` is the full Portuguese version, and `README.md` is the
bilingual overview. File reports in Portuguese (templates in
`SKILL.pt-BR.md` §4) to Brazilian recipients (CERT.br, Receita Federal,
ANPD, police); use the English templates below (§4) for international
providers (Netlify, Vercel, GitHub, Cloudflare, foreign registrars).

Model-agnostic workflow. It only assumes the executing agent can (1) run shell
commands with Python 3.8+, (2) fetch URLs, (3) write files. The bundled
`scripts/fraudtriage.py` is stdlib-only, needs no API keys, is GET-only, and
can be copied standalone into any other agent environment or machine.

## 0. Golden rule — evidence tiers (read before doing anything)

**Tier 1 — HARD. State as fact, and report TO that party:**
- CDN/proxy in the serving path (provider-unique response headers: `cf-ray`,
  `x-amz-cf-id`, `x-served-by: cache-`, …)
- Origin host (provider-unique request IDs: `x-nf-request-id` → Netlify,
  `x-vercel-id` → Vercel, `x-github-request-id` → GitHub Pages,
  `fly-request-id` → Fly.io, …)
- Registrar (RDAP entity with IANA ID)

These are hard **because the receiving provider can verify the claim in its
own systems.** Everything else cannot be verified by the party you're talking
to, so it must be softened or omitted.

**Tier 2 — CORROBORATION. State as "observed on <date>", never as accusation:**
kit fingerprints, HTTrack mirror lineage, cert issuance timeline, urlscan
history, domain age. Used to link cases into a series, not to accuse anyone.

**Tier 3 — LEADS. NEVER assert. NEVER put in third-party reports.**
Names, CNPJs, CPFs, phone numbers, PIX beneficiary strings, fake process
numbers, hardcoded fallback CPFs. They go ONLY in the law-enforcement annex,
phrased exactly as "displayed on the page (unverified)". Rationale: fraud
kits paste stolen or dummy identifiers — a documented case showed the same
fake document displaying two different CNPJs. Only police (subpoena /
BACENJUD) can connect a bank account to an actor.

- Wrong: "the scammer's CNPJ is 64.453.674/0001-24."
- Right: "the fake DARF displays beneficiary CNPJ 64.453.674/0001-24
  (checksum valid, registry status SUSPENSA — unverified ownership)."

## 1. Workflow

**Step 0 — case directory.** Create `case-<domain>-<yyyymmdd>/` with this
canonical layout (working reference: `case-limpar-divida.com-20261028/`):

```
case-<domain>-<yyyymmdd>/
├── dossier.txt            # the ONLY dossier file — tiered facts, IOCs, hashes
├── evidence/              # recon/fetch/analyze/cnpj console output saved as .txt,
│                          #   raw stage*.html, *.json, iocs.csv, sha256-manifest.txt
└── send/                  # one folder PER RECIPIENT, numbered in §3 filing order
    ├── 1-<origin-host>/   # EMAIL.txt + gmail-link.txt + attachments/ (no Tier 3)
    ├── 2-cloudflare/      # FORM.txt for web-form channels
    ├── ...
    └── 6-policia/         # ANEXO-POLICIAL.txt + attachments/ (full case incl. Tier 3)
```

Save everything with UTC timestamps (headers, HTML bodies, sha256 — the tool
prints them). Chain of custody starts here.

**Case-file rules (HARD, no exceptions):**
- **NEVER create .md files in a case — .txt ONLY.** Dossier, reports,
  annexes, read-me files, evidence-log captures: all `.txt`. A single
  monolithic "reports-bundle" file is equally forbidden — reports live ONLY
  in their per-recipient folders. Raw evidence keeps its native extension
  (`.html`, `.json`, `.csv`) — the rule targets every document the agent
  writes.
- **One folder per provider to email**, under `send/`, numbered in the §3
  order (`1-netlify/`, `2-cloudflare/`, `4-certbr/`, `6-policia/`, …), each
  holding `EMAIL.txt` (+ `gmail-link.txt`) or `FORM.txt` for web forms, plus
  a curated `attachments/` (Tier-3-free for every non-police recipient).
  `makepackage.py case.json` builds this tree automatically; when writing by
  hand, reproduce it exactly.

**Step 1 — recon.**
```
python scripts/fraudtriage.py recon <host>
```
One pass: DNS (A/NS/MX/TXT/rDNS), RDAP (registrar, IANA ID, abuse contact,
registration date), CT-log timeline (age + rehosting churn), urlscan public
history, Wayback, and a live header probe of `https://<host>/` with the
[HARD] provider fingerprint.

Fraud kits usually live on a subdomain (`processo.example.com`). Recon THAT
hostname — the script auto-derives the registered apex for RDAP/CT/urlscan.

**Step 2 — walk the kit chain with `fetch`.** Mobile UA is the default
because Brazilian kits commonly gate desktops to `about:blank`. Save each
stage. Typical chain: entry link → fake gov.br login → fake tax
summons/consultation → fake auditor chat → PIX/DARF page. Fetch every URL
the previous page points to; note query-parameter propagation (`cpf`, `cd`).
```
python scripts/fraudtriage.py fetch "<url>" --save stage1.html
```

**Step 3 — analyze every saved stage.**
```
python scripts/fraudtriage.py analyze stage*.html --csv iocs.csv
```
Extracts: kit-family markers, endpoints, operator tokens (Cloudflare
analytics token, Telegram bot tokens, reCAPTCHA sitekeys), identity claims
(labeled LEADS), PIX payloads, money amounts.

**Step 4 — financial endpoints (strict rules).**
- ALLOWED: GET the kit's own CPF-lookup endpoint once with a checksum-valid
  dummy CPF (e.g. `52998224725`) to document whether it returns real personal
  data. If it does, that is an objective, observed LGPD violation → ANPD
  report material.
- NEVER: query with a real person's CPF; generate a PIX; POST to any payment
  API; submit any form; download or run payloads.

**Step 5 — CNPJ registry check** for every CNPJ displayed on the pages
(still Tier 3):
```
python scripts/fraudtriage.py cnpj 64.453.674/0001-24
```
Auto-flags: SUSPENSA/BAIXADA + "inconsistência cadastral", digit-in-word
name tricks (`SERVIC0S`, `REGULARIZAND0`), fresh registration (<180 days).

**Step 6 — assemble the dossier** (`dossier.txt` — NEVER `.md`): tiered facts,
IOC table, timeline, screenshots/HTML hashes. The §4 reports go ONLY into the
per-recipient folders of Step 0 (`send/NN-<provider>/EMAIL.txt` or `FORM.txt`)
— never one combined reports file. Build them with
`python scripts/makepackage.py case.json` (schema: `templates/case.example.json`).

**Step 7 — file the reports same-day** in the priority order of §3.

**Step 8 — monitor daily** (rerun `recon`) until NXDOMAIN/404. Kits rotate
domains; when a new domain appears, repeat and link the cases via kit
markers (beacon token, HTTrack source, value script) — recidivism is what
gets police attention.

## 2. Command cheat sheet

| Command | Yields |
|---|---|
| `recon <host>` | Registrar [HARD], DNS/NS provider, cert timeline, urlscan history, provider fingerprint [HARD] |
| `fetch <url>` | Full response headers, request IDs [HARD], redirect chain, saved HTML + sha256, UTC timestamp |
| `analyze <file>` | Kit markers [CORROBORATION], endpoints, operator tokens, identity claims [LEADS] |
| `cnpj <n>` | Registry status, homoglyph/freshness flags, owners [LEADS] |
| `validate-cpf/-cnpj` | Offline checksum — no network |
| `extractforms.py <saved.html>` | Form action/method + named fields of a saved page (recon of reporting forms) |
| `gmaillink.py --to … --body-file …` | Pre-typed Gmail compose link (see §4 T-GMAIL) |
| `makepackage.py case.json` | Generates the zero-script send/ package for a case (EMAIL.txt + gmail-link.txt + attachments per destination; schema: templates/case.example.json) |
| `selftest` | Offline sanity checks of validators + regexes |

## 3. Abuse-report matrix (hard targets + officials, in filing order)

1. **Origin host** — from request-ID headers; the single most effective
   takedown. Attach the request-ID + UTC time (lets support locate the exact
   account server-side).
   - Netlify → `support@netlify.com` (subject includes `X-Nf-Request-Id`)
   - Vercel → `abuse@vercel.com` (include `x-vercel-id`)
   - GitHub Pages → https://github.com/contact/report-abuse (include
     `x-github-request-id`)
   - Any other fingerprinted provider → the abuse contact published on that
     provider's own site; the request-ID headers are your proof.
   - Finding the abuse address: `recon` already prints the registrar's RDAP
     abuse contact automatically; for hosts/CDNs/registrars without a listed
     address, search the provider's own site ("report abuse" / "abuse policy")
     or its published `abuse@`/`support@` page — never a contact found inside
     the kit. If nothing is published, the RDAP registrar abuse contact and
     ICANN RDDS are the fallback.
   - Sending via Gmail: pre-typed compose links — §4 T-GMAIL +
     `scripts/gmaillink.py`.
2. **CDN** — Cloudflare: https://abuse.cloudflare.com/phishing (choose
   "phishing"; `cf-ray` proves Cloudflare is in the serving path; they relay
   to the host and feed their phishing blocklist).
3. **Registrar** (from RDAP IANA ID) — the registrar's published abuse
   contact. Include RDAP facts + all URLs. Effect: possible domain
   suspension. If registrar data is stale/wrong → ICANN RDDS inaccuracy
   form: https://icann.org/wicf (URL is printed in RDAP notices).
4. **Google Safe Browsing** — https://safebrowsing.google.com/safebrowsing/report_phish/
   (every stage URL). Protects Chrome/Android/Firefox users within hours.
5. **Microsoft SmartScreen** — https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site
6. **CERT.br** (national CSIRT; English or Portuguese accepted) — email the
   full dossier to `cert@cert.br`. If the TLD is .br, say so — they loop in
   registro.br.
7. **PhishTank / APWG** — https://phishtank.org (add phish);
   forward the lure message to `reportphishing@apwg.org`.
8. **Meta/WhatsApp** (when the lure arrived on WhatsApp) — report the message
   and sender in-app.
9. **Brazil officials** (same day, after the technical reports):
   - Receita Federal impersonation → the official denúncia channel reached
     from https://www.gov.br/receitafederal (never via third-party links).
   - ANPD → https://www.gov.br/anpd when a live endpoint returns personal
     data (observed LGPD violation).
   - Police → file a B.O. (state Delegacia Eletrônica or the federal
     cybercrime channel). The B.O. is what unlocks BACENJUD (PIX account
     freezing). Attach the LEADS annex.

## 4. Report templates (fill the `<VARS>`)

### T-ORIGIN — to the host provider (the workhorse)
```
Subject: Phishing impersonating <ENTITY (e.g. Receita Federal / a bank / a
delivery brand)> — <DOMAIN> — <REQUEST-ID-HEADER> <ID>

At <UTC-TIMESTAMP> I retrieved <URL> via HTTP GET. The response carried
your header <REQUEST-ID-HEADER>: <VALUE>, so the site is served by your
platform. It is a phishing kit impersonating <ENTITY> to extort payments
via <PAYMENT METHOD (e.g. PIX)>.

URLs: <ALL STAGE URLS>
Evidence: full response headers, saved HTML (sha256 <HASH>), screenshots.

Please remove the site for AUP violation (phishing/fraud) and preserve the
account records for law enforcement (Brazilian police report pending:
<BO-NUMBER or "being filed">).
```

### T-CLOUDFLARE — https://abuse.cloudflare.com/phishing
```
Reporting URL(s): <STAGE URLS>
Type: Phishing. The sites at these URLs (served via Cloudflare, cf-ray
<VALUE> at <UTC>) impersonate <ENTITY> to extort payments via
<PAYMENT, e.g. PIX>. Attached: headers, HTML, screenshots.
Please relay to the origin host and add to the phishing blocklist.
```

### T-REGISTRAR
```
Domain <DOMAIN> (registered <DATE>, RDAP handle <HANDLE>) is being used
exclusively for phishing impersonating <ENTITY> with payment extortion
(e.g. PIX). URLs: <LIST>. Evidence attached. Please
enforce your AUP and consider suspension.
```

### T-CERTBR — email to cert@cert.br
Full dossier: URLs, UTC timestamps, headers, kit description, IOC list,
screenshot links. State plainly: active phishing against <COUNTRY> users,
impersonating <ENTITY>; infra: registrar <NAME>, CDN
<CLOUDFLARE?>, origin <PROVIDER IF FINGERPRINTED>. Mention .br TLD if
applicable.

### T-POLICE-ANNEX — the ONLY place Tier-3 LEADS go
Structure:
1. HARD facts: registrar, DNS/CDN, origin host + request IDs, URLs, dates.
2. Observed kit behavior (chain, endpoints, PII-returning API, values).
3. LEADS — each phrased "displayed on the page (unverified)": beneficiary
   strings, CNPJs (+ registry status), names, phones, hardcoded CPFs, token
   IDs.
4. Request: BACENJUD on the PIX-receiving accounts; provider log requests
   via the request IDs; kit-series linkage if ≥3 family markers match §5.

### T-GMAIL — pre-typed Gmail compose link (scripts/gmaillink.py)

For email reports, build a link that opens Gmail with recipient, subject and
body already typed:

```
https://mail.google.com/mail/?view=cm&fs=1&to=<to>&su=<urlencoded-subject>&body=<urlencoded-body>
```

```
python scripts/gmaillink.py --to support@netlify.com \
  --subject-file assunto.txt --body-file corpo.txt > gmail-link.txt
# EMAIL.txt holding Para/Assunto + body in one file:
python scripts/gmaillink.py --to cert@cert.br --body-file EMAIL.txt \
  --marker "===== CORPO =====" --subject "..." > gmail-link.txt
```

Caveats: some clients truncate the body past ~1900 encoded chars (the script
WARNs) — then open the link for To/Subject and copy the body text from the
EMAIL.txt file (everything below the `===== CORPO =====` line). Always
re-read the pre-typed draft before hitting send; the link opens the user's
own Gmail, it does not send anything by itself.

Case packaging (script-free, generated by `scripts/makepackage.py case.json`):
per destination a folder with `EMAIL.txt`, `gmail-link.txt`, and
`attachments/` (curated evidence, Tier-3-free for providers). Text files and
links ONLY — nothing executes on the reporter's machine, by design: users
should never have to run scripts to send an abuse report.

### T-AUTO — submission channels (zero credentials, zero scripts)

Design rule: the whole pipeline runs with NO accounts, NO API keys, NO
logins, and the send package contains NO executable files — only text and
links. Anyone can copy the skill folder and use it; that is what keeps the
evidence reproducible and the tool redistributable and trustworthy.

- **Email channel (Netlify, Vercel, GitHub, registrars, CERT.br, APWG)**:
  `makepackage.py case.json` generates, per destination, `EMAIL.txt` +
  `gmail-link.txt` (opens the reporter's own Gmail pre-typed) +
  `attachments/`. Fallback for truncated bodies: copy from EMAIL.txt.
- **Web forms (Cloudflare, Safe Browsing, SmartScreen)**: manual paste —
  `FORM.txt` + `urls-kit.txt` are generated for it. Cloudflare's form is
  bot-protected (403 to plain GET) — do not script it.
- **PhishTank**: requires a login — optional; the APWG email covers the same
  ground without credentials.
- Deliberately OUT of the redistributable core, though they exist: the
  official Cloudflare Abuse Reports API (needs account + token) and any
  channel requiring registration. Not needed for effective takedowns —
  email + forms do the job.
- Human review before every send — automation prepares, the user sends.

## 5. Known kit families (Brazil) — for case linkage

**gvg / "pendência tributária" family** (active since 2025 on rotating
throwaway domains; confirmed case 2026-10-28 on `processo.limpar-divida.com`):
- Path family: `/gvg` → `/gvgconsulta` → `/gvgchat` → `/gvgpix` (also `/gov/`)
- Value script: R$ 419,55 → R$ 138,45 ("67% discount"); threat values
  R$ 1.985,00 / R$ 985,00; fake 10-minute deadline; double-charge pattern
  (first payment hits an "error" screen and re-charges)
- Personae: fake auditor "Tereza Alencar"; forged signature of the real IRS
  secretary; fallback persona "Cliente Com Restrição"
- Mechanics: client-only fake reCAPTCHA checkbox ("Não sou um robô");
  mother-name quiz; phone harvest; `about:blank` desktop gate; FingerprintJS;
  Cloudflare Web Analytics beacon; HTTrack-mirrored lineage
  (`Mirrored from <source-site> by HTTrack … <date>`)
- Lures: "Desenrola Brasil", fake "INTIMAÇÃO FISCAL", fake DARF, WhatsApp
  blasts with the victim CPF pre-filled in the URL

≥3 markers → treat as the same kit lineage; put the series/recidivism
argument in the CERT.br and police reports.

## 6. Safety & conduct (non-negotiable)

- GET-only, one request per stage. You are collecting evidence, not attacking.
- Never generate a PIX, submit a form, complete a "verification", or
  run/download anything the kit offers.
- Never query a real person's CPF/CNPJ against any lookup endpoint.
- Tier-3 data is never asserted as attribution anywhere except the police
  annex — and even there, "displayed".
- Redact third-party (victim) PII in anything shared publicly; full data
  only goes to police.
- If a chain requires an account/OTP to proceed, stop and report what you
  already have.
- Always UTC timestamps; keep raw headers + HTML + sha256 (`fetch` prints
  them automatically).

## 7. curl fallback (no Python available)

```
curl -sSL -A "<any iPhone UA>" -D headers.txt "<URL>" -o page.html   # headers+body
curl -s https://rdap.org/domain/<domain>                             # registrar
curl -s "https://crt.sh/?q=%25.<domain>&output=json"                 # CT logs (%25 = wildcard)
curl -s "https://urlscan.io/api/v1/search/?q=domain:<domain>"       # prior scans
curl -s https://brasilapi.com.br/api/cnpj/v1/<14digits>              # CNPJ registry
curl -s "https://archive.org/wayback/available?url=<domain>"         # wayback
```
Then grep the saved HTML for the §5 markers (HTTrack comment, `/gvg`,
`NOME_MAE`, `about:blank`, `000201` PIX prefix, `R$`, CNPJ/CPF patterns).

## 8. Limits — be honest in the dossier

- Behind a CDN the origin IP is invisible; provider request-ID headers are
  the ONLY reliable origin attribution. No fingerprint → hard targets are
  registrar + blocklists + CERT.br only.
- urlscan free search covers ~30 days. Wayback rarely has fresh fraud
  domains. crt.sh is flaky — rerun recon.
- No creds, no API keys, no accounts anywhere, by design: every lookup stays
  reproducible by third parties (which is what makes the evidence credible)
  and every report channel works from the reporter's own browser/email
  session — the skill folder is copy-and-run redistributable. The send
  package is text files and links only; nothing executes on the reporter's
  machine.
