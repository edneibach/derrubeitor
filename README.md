# DERRUBEITOR

Ferramenta gratuita para derrubar sites de golpe e phishing. Funciona com qualquer tipo de golpe: link falso recebido no WhatsApp, site que imita um banco, um boleto, uma entrega, uma empresa, um programa de governo, uma promoção, um investimento em criptomoeda. Se a página existe para enganar alguém e tirar dinheiro dela, serve.

Você fornece o link do golpe. A ferramenta reúne as provas e monta as denúncias prontas para você revisar e enviar.

Há suporte extra para golpes brasileiros: consulta de CNPJ, validação de CPF, contatos da CERT.br e da polícia, e reconhecimento de famílias de kit já conhecidas, como as que imitam a Receita Federal e o Desenrola Brasil. Esses recursos são opcionais. O caminho principal funciona para golpe de qualquer país.

Sem cadastro, sem chave de API, sem custo. O pacote de denúncias gerado no final é feito de arquivos de texto e links. Nada executa na sua máquina na hora de enviar.

## Para quem é

- Você recebeu um golpe por WhatsApp, SMS ou e-mail e quer o site derrubado.
- Sem conhecimento técnico: comece pela seção "Caminho rápido", que permite denunciar em dez minutos sem instalar nada.
- Quem sabe usar um terminal pode ir até o final do caminho completo, que gera o dossiê de evidências e as denúncias com o Gmail já digitado.
- Os arquivos SKILL.md também permitem usar o projeto como skill no agente opencode.

## Como funciona

Golpes costumam viver em domínios descartáveis, mas são servidos por provedores de verdade: hospedagem, CDN, registrador. Esses provedores derrubam o site quando a denúncia traz fatos que eles mesmos podem conferir em seus sistemas. O header `x-nf-request-id` prova que o site está na Netlify. O header `cf-ray` prova que a resposta passou pela Cloudflare. O RDAP mostra quem registrou o domínio.

Com isso em mente, a ferramenta:

1. Investiga o domínio: registrador, hospedagem, CDN, idade e histórico.
2. Salva as páginas do golpe como prova, com hora UTC e hash sha256.
3. Procura marcadores de kits de golpe conhecidos.
4. Monta o dossiê e o pacote de denúncias: uma pasta por destinatário, com os anexos corretos e um link do Gmail já digitado.
5. Você revisa e envia. A ferramenta nunca envia nada sozinha.

## O que ela não faz

- Não pede conta, senha ou chave de API em lugar nenhum.
- Não envia nada sozinha. Todo envio é manual, depois da sua revisão.
- Não interage com o site do golpe além de abrir as páginas, uma vez cada. Nunca gera PIX, nunca preenche formulário, nunca completa "verificação", nunca consulta CPF de pessoa real.
- Não instala nada além de baixar esta pasta.
- O pacote de denúncias final contém apenas arquivos de texto e links.

## Preparação (5 minutos)

1. Instale o Python 3.8 ou mais novo em https://www.python.org/downloads/ (no Windows, marque "Add Python to PATH" durante a instalação).
2. Baixe ou clone esta pasta.
3. Abra o terminal dentro da pasta e rode:

   ```
   python scripts/fraudtriage.py selftest
   ```

   Deve terminar com `selftest OK`. No Windows o comando pode ser `py` em vez de `python`.

## Caminho rápido: denuncar sem a ferramenta (10 minutos)

Se você só quer denunciar agora, sem instalar nada:

1. Google Safe Browsing, que protege usuários de Chrome, Android e Firefox em poucas horas: https://safebrowsing.google.com/safebrowsing/report_phish/ . Cole a URL do golpe, uma por vez.
2. Cloudflare, se o site passar pela CDN deles: https://abuse.cloudflare.com/phishing . Escolha "Phishing" e cole a URL.
3. Microsoft SmartScreen: https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site . Reporte a URL principal.
4. APWG: encaminhe a mensagem de golpe para reportphishing@apwg.org.
5. No aplicativo onde a isca chegou (WhatsApp, SMS, e-mail), denuncie a mensagem e o remetente.
6. No Brasil, envie a mensagem e o link para a CERT.br (cert@cert.br). Em outros países, procure o CSIRT nacional.
7. Se você pagou, registre um Boletim de Ocorrência. No Brasil, a Delegacia Eletrônica do seu estado aceita online. O B.O. é o que permite à polícia congelar a conta que recebeu a dinheiro, no caso de PIX via BACENJUD.

## Caminho completo: dossiê e pacote de denúncias

Abra o terminal dentro da pasta. Nos exemplos, troque `processo.exemplo.com` pelo domínio real do golpe.

### 1) Investigar o domínio

```
python scripts/fraudtriage.py recon processo.exemplo.com
```

Mostra o registrador (fato verificável), DNS, idade e histórico do domínio, e o mais importante: a impressão digital da hospedagem e da CDN escondida nos headers da resposta. Tudo fica salvo em um arquivo de texto.

### 2) Salvar as páginas do golpe

```
python scripts/fraudtriage.py fetch "https://processo.exemplo.com/gvg" --save stage1.html
```

Salva a página, os headers completos, a hora UTC e o hash sha256. Depois abra o HTML salvo, veja para qual página o golpe aponta em seguida, e repita o fetch para ela. Uma requisição por página, só isso.

### 3) Analisar o que foi salvo

```
python scripts/fraudtriage.py analyze stage1.html stage2.html --csv iocs.csv
```

Lista marcadores da família do kit, endpoints e alegações de identidade. As alegações são marcadas como PISTAS e nunca como acusação.

### 4) Conferir um CNPJ exibido no golpe (opcional, golpes brasileiros)

```
python scripts/fraudtriage.py cnpj 00.000.000/0000-00
```

Mostra a situação cadastral (ativa, suspensa, baixada). É apenas uma pista: kits de golpe exibem documentos de empresas-laranja ou roubados. Para outros países, esse comando não se aplica; o resto do fluxo continua igual.

### 5) Montar o dossiê e o pacote de denúncias

1. Reúna os fatos em um `dossier.txt` (**regra dura: nunca .md — só .txt**; as denúncias ficam exclusivamente nas pastas `send/NN-<destinatário>/`, uma por provedor — nunca num arquivo único combinado). A estrutura detalhada está em SKILL.md e SKILL.pt-BR.md.
2. Preencha um `case.json` seguindo o modelo `templates/case.example.json`.
3. Rode:

   ```
   python scripts/makepackage.py case.json
   ```

Isso cria a pasta `send/`, com uma subpasta por destinatário. Cada subpasta tem `EMAIL.txt` (o texto da denúncia), `gmail-link.txt` (link do Gmail já digitado) e `attachments/` (os anexos certos para aquele destinatário).

## Como enviar as denúncias

Para cada pasta dentro de `send/`:

1. Abra `gmail-link.txt`, copie a URL e cole no navegador. O Gmail abre com destinatário, assunto e corpo já digitados.
2. Se o corpo vier cortado, por limite de tamanho do link em alguns navegadores, abra `EMAIL.txt` e copie o texto abaixo da linha `===== CORPO =====`.
3. Anexe os arquivos da pasta `attachments/`.
4. Releia tudo e envie.

Denúncia falsa é crime. Só relate sites de golpe que você realmente recebeu ou examinou.

## Regras de segurança

- A ferramenta só abre páginas, com GET. Ela nunca interage com o golpe.
- Nunca gere PIX, preencha formulário, complete uma "verificação" ou rode qualquer coisa que o golpe oferecer.
- Nunca consulte CPF de pessoa real em endpoint nenhum. Para testes, o CPF fictício de soma válida 52998224725 é seguro.
- Dados de vítimas e documentos exibidos no golpe vão apenas para a polícia. Nunca nos relatórios enviados a provedores.
- Se uma página pedir conta, senha ou código OTP para continuar, pare e denuncie o que já tem.

## Estrutura do projeto

```
derrubeitor/
├── README.md               <- você está aqui
├── SKILL.md                <- referência completa (inglês)
├── SKILL.pt-BR.md          <- referência completa (português)
├── scripts/
│   ├── fraudtriage.py      <- ferramenta principal (recon, fetch, analyze, cnpj)
│   ├── gmaillink.py        <- gera o link do Gmail já digitado
│   ├── makepackage.py      <- gera a pasta send/ com as denúncias
│   ├── extractforms.py     <- extrai formulários de um HTML salvo
│   └── sample-kit.html     <- página sintética para testar o analyze
└── templates/
    └── case.example.json   <- modelo para montar o case.json
```

## Limites

- Atrás de uma CDN, o IP real do servidor é invisível. A identificação da hospedagem depende dos headers de request-ID do provedor. Sem esse header, os alvos são o registrador, as blocklists e o CSIRT do país.
- O urlscan gratuito cobre cerca de 30 dias. O crt.sh às vezes falha; rode de novo.
- A ferramenta prepara tudo, mas quem derruba é o provedor. Isso costuma acontecer em horas ou dias.
- Nenhuma ferramenta substitui o Boletim de Ocorrência quando há dinheiro perdido. Só a polícia consegue congelar a conta que recebeu o pagamento.

## Aviso legal

Uso livre sob a licença MIT, com fins de denúncia e educação. Use por sua conta e risco. Os autores não se responsabilizam por uso indevido. Denúncias devem conter apenas fatos verificáveis. A ferramenta separa explicitamente FATOS de PISTAS para proteger você e as vítimas.

---

# DERRUBEITOR (English)

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
├── README.md               <- you are here
├── SKILL.md                <- full reference (English)
├── SKILL.pt-BR.md          <- full reference (Portuguese)
├── scripts/
│   ├── fraudtriage.py      <- main tool (recon, fetch, analyze, cnpj)
│   ├── gmaillink.py        <- builds the pre-typed Gmail link
│   ├── makepackage.py      <- builds the send/ report package
│   ├── extractforms.py     <- extracts forms from saved HTML
│   └── sample-kit.html     <- synthetic page to test analyze
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
