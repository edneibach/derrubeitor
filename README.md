# DERRUBEITOR

> Portuguese version: [README.pt-BR.md](README.pt-BR.md).
> Full agent instructions: [SKILL.md](SKILL.md) — the README is the human overview.

A free tool for taking down scam and phishing sites. It works with any kind of scam: a fake link received on WhatsApp, a site that copies a bank, a bill, a delivery company, a streaming service, a government program, a promotion, a crypto investment. If the page exists to trick someone out of money, it qualifies.

You give it the scam link. It gathers the evidence and builds the reports for you to review and send.

There is extra support for Brazilian scams: CNPJ lookup, CPF validation, CERT.br and police contacts, and detection of known kit families, such as the ones copying Receita Federal and Desenrola Brasil. Those extras are optional. The main path works for scams from any country.

No sign-up, no API keys, no cost. The report package generated at the end is made of text files and links. Nothing runs on your machine when you send.

## Who is it for

- You received a scam via WhatsApp, SMS or email and want the site down.
- Not technical: start with the "Quick path" section, which lets you report in ten minutes without installing anything.
- If you can use a terminal, the full path generates the evidence dossier and the reports with the Gmail message already typed.
- The SKILL.md files also let you use the project as a skill in the opencode agent.

## How it works

Scams usually live on throwaway domains, but they are served by real providers: hosting, CDN, registrar. Those providers take the site down when the report carries facts they can check in their own systems. The `x-nf-request-id` header proves the site is on Netlify. The `cf-ray` header proves the response passed through Cloudflare. RDAP shows who registered the domain.

With that in mind, the tool:

1. Investigates the domain: registrar, hosting, CDN, age and history.
2. Saves the scam pages as evidence, with UTC time and sha256 hash.
3. Looks for markers of known scam kits.
4. Builds the dossier and the report package: one folder per recipient, with the right attachments and a pre-typed Gmail link.
5. You review and send. The tool never sends anything by itself.

## What it does not do

- It never asks for an account, password or API key.
- It never sends anything by itself. Every send is manual, after your review.
- It never interacts with the scam site beyond opening each page once. It never generates payments, never fills forms, never completes "verifications", never queries a real person's CPF.
- Installing it is just downloading this folder.
- The final report package contains only text files and links.

## Setup (5 minutes)

1. Install Python 3.8 or newer from https://www.python.org/downloads/ (on Windows, check "Add Python to PATH" during installation).
2. Download or clone this folder.
3. Open a terminal inside the folder and run:

   ```
   python scripts/fraudtriage.py selftest
   ```

   It must end with `selftest OK`. On Windows the command may be `py` instead of `python`.

## Using it as an AI-agent skill (opencode, Claude, others)

This project is a skill: the instructions (`SKILL.md`) teach the agent to
run the whole case — recon, evidence, dossier, reports — asking for your
confirmation before anything is sent.

- **opencode (project level — automatic in this repo):** keep the folder at
  `.opencode/skills/derrubeitor/` in the project root. `SKILL.md` is loaded
  at session start.
- **opencode (global, all projects):**
  ```powershell
  robocopy "<project>\.opencode\skills\derrubeitor" "$env:USERPROFILE\.config\opencode\skill\derrubeitor" /E
  ```
  then restart opencode (skills load at session start).
- **Claude Code:** copy the folder to `.claude/skills/derrubeitor/` in the
  project, or `~/.cla/skills/derrubeitor/` for all projects.
- **Any other agent (Claude/GPT/Gemini via UI, scripts, CI):** attach or
  point the agent at `SKILL.md` and give it a shell with Python 3.8+. The
  pipeline is stdlib-only, GET-only, keyless — anything that can run
  `python scripts/fraudtriage.py selftest` can run the rest.

### OPTIONAL assisted submission of web forms (camoufox)

By default, web forms (Cloudflare, Safe Browsing, SmartScreen, Google Ads)
are pasted manually — the tool only prepares the texts. There is an
OPTIONAL path, off by default, where a free stealth browser (camoufox)
fills the form for you; the AI agent ALWAYS asks first ("may I file the
reports now?" and, when the form requires it, "which name and email should
the forms use?"):

```
pip install "camoufox[geoip]" && python -m camoufox fetch   # ~2 GB, no keys
python scripts/autoreport_forms.py status                    # capability matrix
python scripts/autoreport_forms.py cf <urls> --dry-run      # plan, nothing typed
python scripts/autoreport_forms.py cf <urls> --assist       # open window: you click Submit
```

Works headless for Cloudflare and Google Safe Browsing (invisible
reCAPTCHA); SmartScreen (character CAPTCHA) and Google Ads (login) stay
manual by design — the tool prints the instructions. Email reports always
stay manual (pre-typed Gmail). For a NEW provider:
`autoreport_forms.py map <url>` dumps the form, and the AI agent writes the
adapter itself following the examples in the script.

## Quick path: report without the tool (10 minutes)

If you just want to report it now, without installing anything:

1. Google Safe Browsing, which protects Chrome, Android and Firefox users within hours: https://safebrowsing.google.com/safebrowsing/report_phish/ . Paste the scam URL, one at a time.
2. Cloudflare, if the site runs through their CDN: https://abuse.cloudflare.com/phishing . Pick "Phishing" and paste the URL.
3. Microsoft SmartScreen: https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site . Report the main URL.
4. APWG: forward the scam message to reportphishing@apwg.org.
5. In the app where the lure arrived (WhatsApp, SMS, email), report the message and the sender.
6. In Brazil, send the message and link to CERT.br (cert@cert.br). Elsewhere, look up your national CSIRT.
7. If you paid, file a police report. In Brazil, your state's online police station accepts it. The report is what lets police freeze the account that received the money.

## Full path: dossier and report package

Open a terminal inside the folder. In the examples, replace `processo.example.com` with the real scam domain.

### 1) Investigate the domain

```
python scripts/fraudtriage.py recon processo.example.com
```

Shows the registrar (a verifiable fact), DNS, domain age and history, and most importantly the hosting and CDN fingerprint hidden in the response headers. Everything is saved to a text file.

### 2) Save the scam pages

```
python scripts/fraudtriage.py fetch "https://processo.example.com/gvg" --save stage1.html
```

Saves the page, the full headers, the UTC time and the sha256 hash. Then open the saved HTML, find which page the scam points to next, and repeat the fetch for it. One request per page, nothing more.

### 3) Analyze what you saved

```
python scripts/fraudtriage.py analyze stage1.html stage2.html --csv iocs.csv
```

Lists kit-family markers, endpoints and identity claims. Claims are labeled as LEADS, never as accusations.

### 4) Check a CNPJ displayed by the scam (optional, Brazilian scams)

```
python scripts/fraudtriage.py cnpj 00.000.000/0000-00
```

Shows the registry status (active, suspended, closed). It is only a lead: scam kits display shell-company or stolen documents. For other countries this command does not apply; the rest of the flow stays the same.

### 5) Build the dossier and the report package

1. Gather the facts into a `dossier.txt` (**hard rule: never .md — .txt only**; reports live exclusively in `send/NN-<recipient>/` folders, one per provider — never in one combined file). The detailed structure is in SKILL.md and SKILL.pt-BR.md.
2. Fill a `case.json` following the model in `templates/case.example.json`.
3. Run:

   ```
   python scripts/makepackage.py case.json
   ```

This creates the `send/` folder, with one subfolder per recipient. Each subfolder has `EMAIL.txt` (the report text), `gmail-link.txt` (the pre-typed Gmail link) and `attachments/` (the right evidence for that recipient).

## How to send the reports

For each folder inside `send/`:

1. Open `gmail-link.txt`, copy the URL and paste it in your browser. Gmail opens with recipient, subject and body already typed.
2. If the body arrives cut off, due to link size limits in some browsers, open `EMAIL.txt` and copy everything below the `===== CORPO =====` line.
3. Attach the files in `attachments/`.
4. Read it all again and send.

Filing false reports is a crime. Only report scam sites you actually received or examined.

## Safety rules

- The tool only opens pages, with GET. It never interacts with the scam.
- Never generate a payment, fill a form, complete a "verification" or run anything the scam offers.
- Never query a real person's CPF on any endpoint. For testing, the checksum-valid dummy CPF 52998224725 is safe.
- Victim data and documents displayed by the scam go only to the police. Never in reports sent to providers.
- If a page asks for an account, password or OTP to continue, stop and report what you already have.

## Project structure

```
derrubeitor/
├── README.md                <- you are here (English)
├── README.pt-BR.md          <- Portuguese overview
├── SKILL.md                 <- full reference (English)
├── SKILL.pt-BR.md           <- full reference (Portuguese)
├── scripts/
│   ├── fraudtriage.py       <- main tool (recon, fetch, analyze, cnpj)
│   ├── gmaillink.py         <- builds the pre-typed Gmail link
│   ├── makepackage.py       <- builds the send/ report package
│   ├── autoreport_forms.py  <- OPTIONAL assisted form submission (camoufox)
│   ├── extractforms.py      <- extracts forms from saved HTML
│   └── sample-kit.html      <- synthetic page to test analyze
└── templates/
    └── case.example.json   <- model for building case.json
```

## Limits

- Behind a CDN, the real server IP is invisible. Hosting attribution depends on provider request-ID headers. Without that header, the targets are the registrar, the blocklists and the country's CSIRT.
- The free urlscan search covers about 30 days. crt.sh is flaky at times; rerun it.
- The tool prepares everything, but the provider does the takedown. That usually happens within hours or days.
- No tool replaces a police report when money was lost. Only the police can freeze the account that received the payment.

## Legal notice

Free to use under the MIT license, for reporting and education. Use at your own risk. The authors are not liable for misuse. Reports must contain only verifiable facts. The tool explicitly separates FACTS from LEADS to protect you and the victims.
