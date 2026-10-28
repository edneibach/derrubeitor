# DERRUBEITOR — Manual use (no AI agent)

For the AI-agent path (the main way to use the project), see the main
[README.md](README.md). This guide covers the same workflow by hand, in a
terminal. The scripts are plain, keyless, GET-only CLI tools — nothing here
requires an account, an API key or a login.

## Setup (5 minutes)

1. Install Python 3.8 or newer from https://www.python.org/downloads/ (on Windows, check "Add Python to PATH" during installation).
2. Download or clone this folder.
3. Open a terminal inside the folder and run:

   ```
   python scripts/fraudtriage.py selftest
   ```

   It must end with `selftest OK`. On Windows the command may be `py` instead of `python`.

## Quick path: report without any tooling (10 minutes)

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
