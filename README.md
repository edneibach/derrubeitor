# DERRUBEITOR — Derrube sites de golpe que imitam a Receita Federal

Ferramenta gratuita e de código aberto para combater golpes que se passam
pela Receita Federal, pelo gov.br e por programas como o Desenrola Brasil.
Você recebeu uma mensagem de golpe com um link? Esta ferramenta junta as
provas e monta as denúncias prontas para você enviar aos provedores.

**Sem cadastro. Sem chave de API. Sem custo. O pacote de denúncias é só
texto e links — nada executa na sua máquina na hora de enviar.**

---

## Para quem é

- Você recebeu um golpe por WhatsApp, SMS ou e-mail e quer o site derrubado
- Sem conhecimento técnico? Comece pela seção "Caminho rápido" — dá para
  denunciar em 10 minutos sem instalar nada
- Sabe usar um terminal? O caminho completo gera o dossiê de evidências e
  o pacote de denúncias com o Gmail pré-digitado
- Também funciona como skill para o agente opencode (arquivos SKILL.md)

## Como funciona

Golpes assim vivem em domínios descartáveis, mas são servidos por provedores
de verdade — hospedagem, CDN, registrador. Esses provedores derrubam o site
quando recebem uma denúncia com FATOS que eles mesmos podem verificar nos
próprios sistemas:

- o header `x-nf-request-id` prova que o site está hospedado na Netlify
- o header `cf-ray` prova que a Cloudflare está no caminho de resposta
- o RDAP mostra quem registrou o domínio

A ferramenta, em ordem:

1. **Investiga** o domínio: registrador, hospedagem, CDN, idade, histórico
2. **Salva as páginas** do golpe como prova, com hora UTC e hash sha256
3. **Identifica a família** do kit de golpe (marcadores conhecidos)
4. **Monta** o dossiê e o pacote de denúncias: uma pasta por destinatário,
   com anexos corretos e link do Gmail pré-digitado
5. **Você revisa e envia** — a ferramenta nunca envia nada sozinha

## O que ela NÃO faz (leia isto)

- Não pede conta, senha ou chave de API em lugar nenhum
- Não envia nada sozinha: todo envio é manual, depois da sua revisão
- Não interage com o site do golpe além de ABRIR as páginas (uma vez por
  página) — nunca gera PIX, nunca preenche formulário, nunca completa
  "verificação", nunca consulta CPF de pessoa real
- Não instala nada além de baixar esta pasta
- O pacote final de denúncias contém apenas arquivos de texto e links

## Preparação (5 minutos)

1. Instale o Python 3.8 ou mais novo: https://www.python.org/downloads/
   (no Windows, marque "Add Python to PATH" durante a instalação)
2. Baixe ou clone esta pasta
3. Teste — abra o terminal dentro da pasta e rode:

   ```
   python scripts/fraudtriage.py selftest
   ```

   Deve terminar com `selftest OK`. No Windows o comando pode ser `py` em
   vez de `python`.

---

## Caminho rápido: denunciar SEM a ferramenta (10 minutos)

Se você só quer denunciar agora, sem instalar nada:

1. **Google Safe Browsing** — protege usuários de Chrome/Android/Firefox
   em poucas horas:
   https://safebrowsing.google.com/safebrowsing/report_phish/
   Cole a URL do golpe. Uma por vez.
2. **Cloudflare** (se o site passar pela Cloudflare):
   https://abuse.cloudflare.com/phishing — escolha "Phishing" e cole a URL
3. **APWG**: encaminhe a mensagem de golpe (print ou texto) para
   reportphishing@apwg.org
4. **CERT.br** (CSIRT nacional): envie a mensagem + link para
   cert@cert.br
5. **WhatsApp**: segure a mensagem → Denunciar → "Golpe ou fraude";
   denuncie também o remetente
6. **Se você pagou**: registre Boletim de Ocorrência na Delegacia
   Eletrônica do seu estado — é o B.O. que permite à polícia congelar a
   conta PIX que recebeu o dinheiro (via BACENJUD)

## Caminho completo: dossiê + pacote de denúncias

Abra o terminal dentro da pasta. Nos exemplos, troque
`processo.exemplo.com` pelo domínio real do golpe.

### 1) Investigar o domínio

```
python scripts/fraudtriage.py recon processo.exemplo.com
```

Mostra o registrador (fato verificável), DNS, idade e histórico do domínio,
e o mais importante: a impressão digital da hospedagem/CDN escondida nos
headers da resposta. Tudo fica salvo em um arquivo de texto.

### 2) Salvar as páginas do golpe (prova)

```
python scripts/fraudtriage.py fetch "https://processo.exemplo.com/gvg" --save stage1.html
```

Salva a página + headers completos + hora UTC + hash sha256. Depois abra o
HTML salvo, veja para qual página o golpe aponta em seguida, e repita o
fetch para ela. Uma requisição por página, só isso.

### 3) Analisar o que foi salvo

```
python scripts/fraudtriage.py analyze stage1.html stage2.html --csv iocs.csv
```

Lista marcadores da família do kit, endpoints e alegações de identidade
(marcadas como PISTAS — nunca como acusação).

### 4) Conferir CNPJ exibido no golpe (opcional)

```
python scripts/fraudtriage.py cnpj 00.000.000/0000-00
```

Mostra a situação cadastral (ativa, suspensa, baixada). É só PISTA: kits
de golpe exibem documentos de empresas-laranja ou roubados.

### 5) Montar o dossiê e o pacote de denúncias

1. Junte os fatos em um `dossier.txt` (estrutura detalhada no SKILL.md/SKILL.pt-BR.md)
2. Preencha um `case.json` seguindo o modelo `templates/case.example.json`
3. Rode:

   ```
   python scripts/makepackage.py case.json
   ```

Isso cria a pasta `send/` com uma subpasta por destinatário, cada uma com
`EMAIL.txt` (o texto da denúncia), `gmail-link.txt` (link do Gmail
pré-digitado) e `attachments/` (os anexos certos para aquele destinatário).

## Como enviar as denúncias

Para cada pasta dentro de `send/`:

1. Abra `gmail-link.txt`, copie a URL e cole no navegador — o Gmail abre
   com destinatário, assunto e corpo já digitados
2. Se o corpo vier cortado (limite de tamanho do link em alguns
   navegadores), abra `EMAIL.txt` e copie o texto abaixo da linha
   `===== CORPO =====`
3. Anexe os arquivos da pasta `attachments/`
4. Releia tudo e envie

Atenção: denúncia falsa é crime. Só relate sites de golpe que você
realmente recebeu ou examinou.

## Regras de segurança (inegociáveis)

- A ferramenta só ABRE páginas (GET). Ela nunca interage com o golpe
- Nunca gere PIX, preencha formulário, complete uma "verificação" ou rode
  qualquer coisa que o golpe oferecer
- Nunca consulte CPF de pessoa real em endpoint nenhum (para testes, o
  CPF fictício de soma válida `52998224725` é seguro)
- Dados de vítimas e documentos exibidos no golpe vão APENAS para a
  polícia — nunca nos relatórios enviados a provedores
- Se uma página pedir conta, senha ou código OTP para continuar: pare e
  denuncie o que já tem

## Estrutura do projeto

```
derrubeitor/
├── README.md               <- você está aqui
├── SKILL.md                <- referência completa (inglês)
├── SKILL.pt-BR.md          <- referência completa (português)
├── scripts/
│   ├── fraudtriage.py      <- ferramenta principal (recon/fetch/analyze/cnpj)
│   ├── gmaillink.py        <- gera o link do Gmail pré-digitado
│   ├── makepackage.py      <- gera a pasta send/ com as denúncias
│   ├── extractforms.py     <- extrai formulários de um HTML salvo
│   └── sample-kit.html     <- página sintética para testar o analyze
└── templates/
    └── case.example.json   <- modelo para montar o case.json
```

## Limites (honestidade)

- Atrás de uma CDN, o IP real do servidor é invisível; a identificação da
  hospedagem depende dos headers de request-ID do provedor. Sem esse
  header, os alvos são: registrador + blocklists + CERT.br
- O urlscan gratuito cobre ~30 dias; o crt.sh às vezes falha (rode de novo)
- A ferramenta prepara tudo, mas quem derruba é o provedor — e isso
  costuma funcionar em horas ou dias
- Nenhuma ferramenta substitui o Boletim de Ocorrência quando há dinheiro
  perdido: só a polícia consegue congelar a conta que recebeu o PIX

## Aviso legal

Ferramenta de uso livre (licença MIT), com fins de denúncia e educação.
Use por sua conta e risco. Os autores não se responsabilizam por uso
indevido. Denúncias devem conter apenas fatos verificáveis — a ferramenta
separa explicitamente FATOS de PISTAS para proteger você e as vítimas.

---

# DERRUBEITOR — Take down scams impersonating the Brazilian Revenue Service

A free, open-source tool to fight scams that impersonate Receita Federal,
gov.br and programs like Desenrola Brasil. Got a scam message with a link?
This tool gathers the evidence and builds the abuse reports for you to send.

**No sign-up. No API keys. No cost. The report package is text and links
only — nothing runs on your machine when sending.**

---

## Who is it for

- You received a scam via WhatsApp, SMS or email and want the site down
- Not technical? Start with the "Quick path" — you can report in 10
  minutes without installing anything
- Comfortable with a terminal? The full path generates the evidence
  dossier and a ready-to-send report package with a pre-typed Gmail link
- It also works as a skill for the opencode agent (SKILL.md files)

## How it works

These scams live on throwaway domains, but they are served by real
providers — hosting, CDN, registrar. Those providers take the site down
when they receive a report containing FACTS they can verify in their own
systems:

- the `x-nf-request-id` header proves the site is hosted on Netlify
- the `cf-ray` header proves Cloudflare is in the serving path
- RDAP shows who registered the domain

The tool, in order:

1. **Investigates** the domain: registrar, hosting, CDN, age, history
2. **Saves** the scam pages as evidence, with UTC timestamp and sha256
3. **Identifies** the scam-kit family (known markers)
4. **Builds** the dossier and the report package: one folder per
   recipient, with the right attachments and a pre-typed Gmail link
5. **You review and send** — the tool never sends anything by itself

## What it does NOT do (read this)

- It never asks for an account, password or API key
- It never sends anything by itself: every send is manual, after your review
- It never interacts with the scam site beyond OPENING pages (once per
  page) — it never generates PIX payments, never fills forms, never
  completes "verifications", never queries a real person's CPF
- Installing it is just downloading this folder
- The final report package contains only text files and links

## Setup (5 minutes)

1. Install Python 3.8 or newer: https://www.python.org/downloads/
   (on Windows, check "Add Python to PATH" during installation)
2. Download or clone this folder
3. Test — open a terminal inside the folder and run:

   ```
   python scripts/fraudtriage.py selftest
   ```

   It must end with `selftest OK`. On Windows the command may be `py`
   instead of `python`.

---

## Quick path: report WITHOUT the tool (10 minutes)

If you just want to report it now, without installing anything:

1. **Google Safe Browsing** — protects Chrome/Android/Firefox users within
   hours: https://safebrowsing.google.com/safebrowsing/report_phish/
   Paste the scam URL. One at a time.
2. **Cloudflare** (if the site goes through Cloudflare):
   https://abuse.cloudflare.com/phishing — pick "Phishing", paste the URL
3. **APWG**: forward the scam message (screenshot or text) to
   reportphishing@apwg.org
4. **CERT.br** (Brazil's national CSIRT): send the message + link to
   cert@cert.br
5. **WhatsApp**: hold the message → Report → "Scam or fraud"; report the
   sender too
6. **If you paid**: file a police report (B.O.) at your state's online
   police station — the B.O. is what lets police freeze the PIX account
   that received the money (via BACENJUD)

## Full path: dossier + report package

Open a terminal inside the folder. In the examples, replace
`processo.example.com` with the real scam domain.

### 1) Investigate the domain

```
python scripts/fraudtriage.py recon processo.exemplo.com
```

Shows the registrar (hard, verifiable fact), DNS, domain age and history,
and most importantly: the hosting/CDN fingerprint hidden in the response
headers. Everything is saved to a text file.

### 2) Save the scam pages (evidence)

```
python scripts/fraudtriage.py fetch "https://processo.exemplo.com/gvg" --save stage1.html
```

Saves the page + full headers + UTC time + sha256 hash. Then open the saved
HTML, find which page the scam points to next, and repeat the fetch for it.
One request per page, nothing more.

### 3) Analyze what you saved

```
python scripts/fraudtriage.py analyze stage1.html stage2.html --csv iocs.csv
```

Lists kit-family markers, endpoints and identity claims (labeled as LEADS —
never as accusations).

### 4) Check a CNPJ displayed by the scam (optional)

```
python scripts/fraudtriage.py cnpj 00.000.000/0000-00
```

Shows the registry status (active, suspended, closed). It is only a LEAD:
scam kits display shell-company or stolen documents.

### 5) Build the dossier and the report package

1. Gather the facts into a `dossier.txt` (structure detailed in SKILL.md)
2. Fill a `case.json` following the model `templates/case.example.json`
3. Run:

   ```
   python scripts/makepackage.py case.json
   ```

This creates the `send/` folder with one subfolder per recipient, each with
`EMAIL.txt` (the report text), `gmail-link.txt` (pre-typed Gmail link) and
`attachments/` (the right evidence for that recipient).

## How to send the reports

For each folder inside `send/`:

1. Open `gmail-link.txt`, copy the URL and paste it in your browser — Gmail
   opens with recipient, subject and body already typed
2. If the body arrives cut off (link size limit in some browsers), open
   `EMAIL.txt` and copy everything below the `===== CORPO =====` line
3. Attach the files in `attachments/`
4. Read it all again and send

Warning: filing false reports is a crime. Only report scam sites you
actually received or examined.

## Safety rules (non-negotiable)

- The tool only OPENS pages (HTTP GET). It never interacts with the scam
- Never generate a PIX payment, fill a form, complete a "verification" or
  run anything the scam offers
- Never query a real person's CPF on any endpoint (for testing, the
  checksum-valid dummy CPF `52998224725` is safe)
- Victim data and documents displayed by the scam go ONLY to the police —
  never in reports sent to providers
- If a page asks for an account, password or OTP to continue: stop and
  report what you already have

## Project structure

```
derrubeitor/
├── README.md               <- you are here
├── SKILL.md                <- full reference (English)
├── SKILL.pt-BR.md          <- full reference (Portuguese)
├── scripts/
│   ├── fraudtriage.py      <- main tool (recon/fetch/analyze/cnpj)
│   ├── gmaillink.py        <- builds the pre-typed Gmail link
│   ├── makepackage.py      <- builds the send/ report package
│   ├── extractforms.py     <- extracts forms from saved HTML
│   └── sample-kit.html     <- synthetic page to test analyze
└── templates/
    └── case.example.json   <- model for building case.json
```

## Limits (honesty)

- Behind a CDN the real server IP is invisible; hosting attribution
  depends on provider request-ID headers. Without that header, the targets
  are: registrar + blocklists + CERT.br
- The free urlscan search covers ~30 days; crt.sh is flaky at times (rerun)
- The tool prepares everything, but the provider does the takedown — which
  usually works within hours or days
- No tool replaces a police report when money was lost: only the police
  can freeze the PIX account that received the payment

## Legal notice

Free-to-use tool (MIT license), for reporting and education purposes. Use
at your own risk. The authors are not liable for misuse. Reports must
contain only verifiable facts — the tool explicitly separates FACTS from
LEADS to protect you and the victims.
