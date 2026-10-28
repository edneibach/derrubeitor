# DERRUBEITOR

> Portuguese version: [README.pt-BR.md](README.pt-BR.md).
> Full agent instructions: [SKILL.md](SKILL.md) — the README is the human overview.
> Manual use without an AI agent: [MANUAL.md](MANUAL.md).

A free, model-agnostic toolkit for taking down scam and phishing sites, designed to be used as a **skill in whatever AI you have** — opencode, Claude Code, or any other agent. It works with any kind of scam: a fake link received on WhatsApp, a site that copies a bank, a bill, a delivery company, a streaming service, a government program, a promotion, a crypto investment. If the page exists to trick someone out of money, it qualifies.

You give the scam link. The agent runs the whole case — investigation, evidence, dossier, and ready-to-send reports — always asking for your confirmation before anything is sent. A fully manual mode exists too, for when you would rather drive the tools yourself: [MANUAL.md](MANUAL.md).

There is extra support for Brazilian scams: CNPJ lookup, CPF validation, CERT.br and police contacts, and detection of known kit families, such as the ones copying Receita Federal and Desenrola Brasil. Those extras are optional. The main path works for scams from any country.

No sign-up, no API keys, no cost. The report package generated at the end is made of text files and links. Nothing runs on your machine when you send.

## Use it as an AI-agent skill (opencode, Claude Code, any agent)

**This is the main way to use the project.** It is a slash skill: the instructions in `SKILL.md` teach any capable agent to run the entire workflow — recon, evidence collection, dossier, report package, and the optional assisted form submission — asking for your confirmation before anything is sent. It is model-agnostic: any agent that can read a file and run shell commands with Python 3.8+ can run it.

- **opencode (project level — automatic in this repo):** keep the folder at `.opencode/skills/derrubeitor/` in the project root. `SKILL.md` is loaded at session start — the skill appears as "derrubeitor".
- **opencode (global, all projects):**
  ```powershell
  robocopy "<project>\.opencode\skills\derrubeitor" "$env:USERPROFILE\.config\opencode\skill\derrubeitor" /E
  ```
  then restart opencode (skills load at session start).
- **Claude Code:** copy the folder to `.claude/skills/derrubeitor/` in the project, or `~/.cla/skills/derrubeitor/` for all projects.
- **Any other agent (Claude/GPT/Gemini via UI, scripts, CI):** attach or point the agent at `SKILL.md` and give it a shell with Python 3.8+. The pipeline is stdlib-only, GET-only, keyless — anything that can run `python scripts/fraudtriage.py selftest` can run the rest.

### OPTIONAL assisted submission of web forms (camoufox)

By default, web forms (Cloudflare, Safe Browsing, SmartScreen, Google Ads) are pasted manually — the tool only prepares the texts. There is an OPTIONAL path, off by default, where a free stealth browser (camoufox) fills the form for you; the AI agent ALWAYS asks first ("may I file the reports now?" and, when the form requires it, "which name and email should the forms use?"):

```
pip install "camoufox[geoip]" && python -m camoufox fetch   # ~2 GB, no keys
python scripts/autoreport_forms.py status                    # capability matrix
python scripts/autoreport_forms.py cf <urls> --dry-run      # plan, nothing typed
python scripts/autoreport_forms.py cf <urls> --assist       # open window: you click Submit
```

Works headless for Cloudflare and Google Safe Browsing (invisible reCAPTCHA); SmartScreen (character CAPTCHA) and Google Ads (login) stay manual by design — the tool prints the instructions. Email reports always stay manual (pre-typed Gmail). For a NEW provider: `autoreport_forms.py map <url>` dumps the form, and the AI agent writes the adapter itself following the examples in the script.

## Manual use (no AI agent)

Everything the agent does can also be done by hand in a terminal — the scripts are plain, keyless CLI tools:

1. Install Python 3.8 or newer from https://www.python.org/downloads/ (on Windows, check "Add Python to PATH" during installation).
2. Download or clone this folder.
3. Open a terminal inside the folder and run:

   ```
   python scripts/fraudtriage.py selftest
   ```

   It must end with `selftest OK`. On Windows the command may be `py` instead of `python`.

The complete manual walkthrough — investigating the domain, saving pages as evidence, building the dossier and the report package, sending the reports, and reporting with no tooling at all — lives in [MANUAL.md](MANUAL.md).

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
├── MANUAL.md                <- manual use, no AI agent
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
    └── case.example.json    <- model for building case.json
```

## Limits

- Behind a CDN, the real server IP is invisible. Hosting attribution depends on provider request-ID headers. Without that header, the targets are the registrar, the blocklists and the country's CSIRT.
- The free urlscan search covers about 30 days. crt.sh is flaky at times; rerun it.
- The tool prepares everything, but the provider does the takedown. That usually happens within hours or days.
- No tool replaces a police report when money was lost. Only the police can freeze the account that received the payment.

## Legal notice

Free to use under the MIT license, for reporting and education. Use at your own risk. The authors are not liable for misuse. Reports must contain only verifiable facts. The tool explicitly separates FACTS from LEADS to protect you and the victims.
