#!/usr/bin/env python3
"""
makepackage.py — assemble the zero-credential, zero-script send/ package for
a fraud case. stdlib-only; no network; no creds; no API keys.

Output is TEXT AND LINKS ONLY: EMAIL.txt, gmail-link.txt, FORM.txt,
urls-kit.txt, INSTRUCOES.txt, LEIA-ME.txt and copies of evidence files.
Nothing it writes executes on the reporter's machine, by design (trust:
users should never have to run scripts to send an abuse report).

Reads case.json (schema + filled example: templates/case.example.json) and
writes, by default, into send/ next to the case.json:

  send/LEIA-ME.txt                      master flow + table
  send/<n>-<dest>/EMAIL.txt             Para/Assunto + '===== CORPO =====' + body
  send/<n>-<dest>/gmail-link.txt       one URL -> Gmail opens pre-typed
  send/<n>-<dest>/attachments/...      evidence (glob-copied; curate so that
                                       provider folders stay Tier-3-free)
  send/<n>-<form>/FORM.txt              text to paste into a web form
  send/5-blocklists/urls-kit.txt       one URL per line
  send/5-blocklists/INSTRUCOES.txt      default or instructions_file
  send/<police>/<annex> + attachments/  full case incl. Tier-3 (police only)

usage:
  python makepackage.py case.json [--out send]
"""
import argparse
import glob
import json
import os
import shutil
import sys
import urllib.parse

WARN_LIMIT = 1900

DEFAULT_INSTRUCOES = """# BLOCKLISTS E CANAIS WEB (sem e-mail — colagem manual)

## URLs do kit (uma por linha em urls-kit.txt)

## Google Safe Browsing (protege Chrome/Android/Firefox em horas)
https://safebrowsing.google.com/safebrowsing/report_phish/
-> reportar CADA URL do fluxo (uma submissao por URL)

## Microsoft SmartScreen
https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site
-> reportar a URL principal e citar as demais

## PhishTank (exige login gratuito; opcional — o APWG por e-mail cobre o mesmo terreno)
https://phishtank.org -> "Add phish"

## APWG
Enviar a mensagem-isca para reportphishing@apwg.org (pasta apwg/, se houver)

## Meta/WhatsApp (no app que recebeu a isca)
Segurar a mensagem -> Denunciar -> "Golpe ou fraude"; denunciar tambem o
contato. Registrar o numero no B.O.

## Autoridades do pais-alvo (Brasil)
- Receita Federal (impersonacao): https://www.gov.br/receitafederal
  (canal oficial de denuncias; nunca por link de terceiro)
- ANPD (tratamento de dados pessoais sob falsa pretensa): https://www.gov.br/anpd
"""


def uq(text):
    return urllib.parse.quote(text, safe="")


def gmail_link(to, subject, body):
    return ("https://mail.google.com/mail/?view=cm&fs=1&to={}&su={}&body={}"
            .format(urllib.parse.quote(to, safe="@"), uq(subject), uq(body)))


def wfile(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def expand(base, patterns):
    hits = []
    for pat in patterns or []:
        hits.extend(sorted(glob.glob(os.path.join(base, pat))))
    return hits


def read_text(base, entry, key_file, key_inline):
    if entry.get(key_file):
        with open(os.path.join(base, entry[key_file]), encoding="utf-8") as fh:
            return fh.read().strip()
    return (entry.get(key_inline) or "").strip()


def copy_attachments(base, dest, patterns):
    os.makedirs(dest, exist_ok=True)
    names = []
    for src in expand(base, patterns):
        dst = os.path.join(dest, os.path.basename(src))
        shutil.copy2(src, dst)
        names.append(os.path.basename(src))
    return names


def main():
    ap = argparse.ArgumentParser(description="Assemble the zero-script send/ package")
    ap.add_argument("case_json", help="path to case.json (see templates/case.example.json)")
    ap.add_argument("--out", default="send", help="output dir next to case.json (default: send)")
    args = ap.parse_args()

    with open(args.case_json, encoding="utf-8") as fh:
        case = json.load(fh)
    base = os.path.dirname(os.path.abspath(args.case_json))
    out = os.path.join(base, args.out)
    os.makedirs(out, exist_ok=True)
    rows = []

    for entry in case.get("emails", []):
        name = entry["name"]
        to = entry["to"]
        subject = entry["subject"]
        order = entry.get("order", "")
        body = read_text(base, entry, "body_file", "body")
        d = os.path.join(out, name)
        os.makedirs(d, exist_ok=True)
        n_att = len(copy_attachments(base, os.path.join(d, "attachments"),
                                     entry.get("attachments")))
        email_md = (
            "# DENUNCIA {o} - {n}\n"
            "**Para:** {to}\n"
            "**Assunto:** {s}\n"
            "**Anexos:** tudo em `attachments/` desta pasta ({k} arquivos)\n"
            "===== CORPO (copie daqui para baixo) =====\n"
            "{body}\n"
        ).format(o=order, n=name, to=to, s=subject, k=n_att, body=body)
        wfile(os.path.join(d, "EMAIL.txt"), email_md)
        link = gmail_link(to, subject, body)
        if len(uq(body)) > WARN_LIMIT:
            sys.stderr.write(
                "WARN [{}]: corpo codificado tem {} chars (> {}) - alguns clientes"
                " truncam o link do Gmail; EMAIL.txt e a copia segura do corpo\n"
                .format(name, len(uq(body)), WARN_LIMIT))
        wfile(os.path.join(d, "gmail-link.txt"), link + "\n")
        rows.append("| {o} | `{n}` | {to} | gmail-link.txt (ou copiar de EMAIL.txt) | {k} anexos |"
                    .format(o=order, n=name, to=to, k=n_att))

    for entry in case.get("forms", []):
        name = entry["name"]
        order = entry.get("order", "")
        d = os.path.join(out, name)
        os.makedirs(d, exist_ok=True)
        text = read_text(base, entry, "text_file", "text")
        form_md = (
            "# FORMULARIO {o} - {n}\n"
            "**Pagina:** {u}\n"
            "===== TEXTO PARA COLAR =====\n"
            "{t}\n"
        ).format(o=order, n=name, u=entry.get("form_url", ""), t=text)
        wfile(os.path.join(d, "FORM.txt"), form_md)
        rows.append("| {o} | `{n}` | formulario web | colar texto do FORM.txt | - |"
                    .format(o=order, n=name))

    if case.get("blocklist_urls"):
        d = os.path.join(out, "5-blocklists")
        os.makedirs(d, exist_ok=True)
        wfile(os.path.join(d, "urls-kit.txt"), "\n".join(case["blocklist_urls"]) + "\n")
        instr = case.get("instructions_file")
        if instr:
            shutil.copy2(os.path.join(base, instr), os.path.join(d, "INSTRUCOES.txt"))
        else:
            wfile(os.path.join(d, "INSTRUCOES.txt"), DEFAULT_INSTRUCOES)
        rows.append("| 5 | `5-blocklists` | Safe Browsing / SmartScreen / PhishTank / WhatsApp / oficiais | INSTRUCOES.txt + urls-kit.txt | - |")

    police = case.get("police")
    if police:
        d = os.path.join(out, police.get("name", "6-policia"))
        os.makedirs(d, exist_ok=True)
        annex = police.get("annex_file")
        if annex:
            dst_name = os.path.basename(annex)
            if dst_name.lower().endswith(".md"):
                dst_name = dst_name[:-3] + ".txt"
            shutil.copy2(os.path.join(base, annex), os.path.join(d, dst_name))
        n_att = len(copy_attachments(base, os.path.join(d, "attachments"),
                                      police.get("attachments")))
        rows.append("| 6 | `{n}` | B.O. / autoridade policial | anexo + attachments (TUDO, incl. camada 3) | {k} anexos |"
                    .format(n=police.get("name", "6-policia"), k=n_att))

    leia_me = (
        "# LEIA-ME - PACOTE DE ENVIO (zero scripts: so texto e links)\n\n"
        "Este pacote contem apenas arquivos de texto - nada executa na sua maquina.\n\n"
        "Fluxo por e-mail:\n"
        "1. Abra `gmail-link.txt` e cole a URL no navegador - o Gmail abre com"
        " destinatario+assunto+corpo pre-digitados.\n"
        "2. Se o corpo vier cortado, abra `EMAIL.txt` e copie o texto abaixo da linha"
        " `===== CORPO =====`.\n"
        "3. Anexe os arquivos de `attachments/` e envie (releia antes de enviar).\n\n"
        "Formularios web: cole o texto de `FORM.txt`. Blocklists: `urls-kit.txt`.\n"
        "Camada 3 (PISTAS) fica APENAS na pasta da policia - nunca em pastas de provedores.\n\n"
        "| Ordem | Pasta | Destino | Como | Anexos |\n"
        "|---|---|---|---|---|\n"
        "{rows}\n"
    ).format(rows="\n".join(rows))
    wfile(os.path.join(out, "LEIA-ME.txt"), leia_me)

    print("package written to: " + out)
    for row in rows:
        print("  " + row)


if __name__ == "__main__":
    main()
