# DERRUBEITOR (português)

> Versão em português do README. English version: [README.md](README.md).
> Uso manual sem agente de IA: [MANUAL.md](MANUAL.md) (em inglês).

Ferramenta gratuita para derrubar sites de golpe e phishing. Funciona com qualquer tipo de golpe: link falso recebido no WhatsApp, site que imita um banco, um boleto, uma entrega, uma empresa, um programa de governo, uma promoção, um investimento em criptomoeda. Se a página existe para enganar alguém e tirar dinheiro dela, serve.

Você fornece o link do golpe. O agente de IA conduz o caso inteiro — investigação, evidência, dossiê e denúncias prontas para revisar e enviar — sempre pedindo sua confirmação antes de qualquer envio. Também dá para conduzir tudo manualmente (seção "Preparação" abaixo e o MANUAL.md).

Há suporte extra para golpes brasileiros: consulta de CNPJ, validação de CPF, contatos da CERT.br e da polícia, e reconhecimento de famílias de kit já conhecidas, como as que imitam a Receita Federal e o Desenrola Brasil. Esses recursos são opcionais. O caminho principal funciona para golpe de qualquer país.

Sem cadastro, sem chave de API, sem custo. O pacote de denúncias gerado no final é feito de arquivos de texto e links. Nada executa na sua máquina na hora de enviar.

## Como funciona

O mecanismo é a **denúncia de abuso** — um canal legítimo e lícito. Todo
provedor de quem o golpe depende (hospedagem, CDN, registrador) publica um
contato de abuso e derruba sites quando a denúncia traz fatos que ele
mesmo consegue verificar nos próprios sistemas. Este projeto faz bem a
parte lícita: reúne fatos verificáveis, embala-os nos formatos de denúncia
dos próprios provedores e coloca-os na frente de quem pode agir. Nada aqui
ataca, explora ou burla ninguém — a evidência é coletada com requisições
GET comuns, uma por página, exatamente como abrir a página num navegador,
e as denúncias só são enviadas depois da sua revisão.

Por que funciona: golpes costumam viver em domínios descartáveis, mas são
servidos por provedores de verdade. O header `x-nf-request-id` prova que o
site está na Netlify. O header `cf-ray` prova que a resposta passou pela
Cloudflare. O RDAP mostra quem registrou o domínio.

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

## Para quem é

- **Uso principal: como skill no seu agente de IA** — opencode, Claude Code ou qualquer outro (veja a seção abaixo).
- Você recebeu um golpe por WhatsApp, SMS ou e-mail e quer o site derrubado.
- Sem conhecimento técnico: peça ao seu agente de IA, ou comece pela seção "Caminho rápido", que permite denunciar em dez minutos sem instalar nada.
- Quem sabe usar um terminal pode ir até o final do caminho completo, que gera o dossiê de evidências e as denúncias com o Gmail já digitado.

## Como usar como skill de agente de IA (opencode, Claude, outros)

**Este é o uso principal do projeto.** É uma skill: as instruções do `SKILL.md`
ensinam qualquer agente capaz a conduzir o fluxo inteiro — recon, evidência,
dossiê, pacote de denúncias e o envio assistido opcional — pedindo sua
confirmação antes de qualquer envio. É agnóstica de modelo: qualquer agente
que leia um arquivo e rode comandos shell com Python 3.8+ consegue.

- **opencode (nível projeto — já fica automático neste repositório):**
  mantenha a pasta em `.opencode/skills/derrubeitor/` na raiz do projeto.
  O `SKILL.md` é carregado no início da sessão.
- **opencode (global, todos os projetos):**
  ```powershell
  robocopy "<projeto>\.opencode\skills\derrubeitor" "$env:USERPROFILE\.config\opencode\skill\derrubeitor" /E
  ```
  e reinicie o opencode (skills são carregadas no início da sessão).
- **Claude Code:** copie a pasta para `.claude/skills/derrubeitor/` no
  projeto, ou para `~/.cla/skills/derrubeitor/` para todos os projetos.
  A skill aparece como "derrubeitor".
- **Outros agentes (Claude/GPT/Gemini via UI, scripts, CI):** anexe ou
  aponte o `SKILL.md` como instrução e dê ao agente acesso a shell com
  Python 3.8+. Todo o pipeline é stdlib, GET-only e sem chaves — qualquer
  ambiente que rode `python scripts/fraudtriage.py selftest` consegue
  executar o resto.

### Envio assistido OPCIONAL dos formulários web (camoufox)

Por padrão, formulários web (Cloudflare, Safe Browsing, SmartScreen,
Google Ads) são colados manualmente — a ferramenta só prepara os textos.
Há um caminho OPCIONAL, desligado por padrão, em que um navegador furtivo
gratuito (camoufox) preenche o formulário por você; o agente de IA SEMPRE
pergunta antes de usar ("posso enviar as denúncias agora?" e, se o
formulário exigir, "qual nome e e-mail usar?"):

```
pip install "camoufox[geoip]" && python -m camoufox fetch   # ~2 GB, sem chaves
python scripts/autoreport_forms.py status                    # o que é possível
python scripts/autoreport_forms.py cf <urls> --dry-run      # plano, nada digitado
python scripts/autoreport_forms.py cf <urls> --assist       # janela aberta: você clica em Enviar
```

Funciona headless para Cloudflare e Google Safe Browsing (reCAPTCHA
invisível); SmartScreen (captcha de caracteres) e Google Ads (login) são
manuais por design — a ferramenta imprime as instruções. E-mails seguem
sempre manuais (Gmail pré-digitado). Para um provedor novo:
`autoreport_forms.py map <url>` despeja o formulário e o próprio agente de
IA escreve o adaptador seguindo os exemplos no script.

## Preparação (5 minutos)

1. Instale o Python 3.8 ou mais novo em https://www.python.org/downloads/ (no Windows, marque "Add Python to PATH" durante a instalação).
2. Baixe ou clone esta pasta.
3. Abra o terminal dentro da pasta e rode:

   ```
   python scripts/fraudtriage.py selftest
   ```

   Deve terminar com `selftest OK`. No Windows o comando pode ser `py` em vez de `python`.

## Caminho rápido: denunciar sem a ferramenta (10 minutos)

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

1. Reúna os fatos em um `dossier.txt` (**regra dura: nunca .md — só .txt**; as denúncias ficam exclusivamente nas pastas `send/email/NN-<destinatário>/` e `send/form/NN-<destinatário>/`, uma por provedor — nunca num arquivo único combinado). A estrutura detalhada está em SKILL.md e SKILL.pt-BR.md.
2. Preencha um `case.json` seguindo o modelo `templates/case.example.json`.
3. Rode:

   ```
   python scripts/makepackage.py case.json
   ```

Isso cria a pasta `send/` dividida por tipo de envio — `send/email/` (tudo que se envia por e-mail) e `send/form/` (tudo que se cola em formulário web) — com uma subpasta numerada por destinatário dentro de cada. Subpastas de e-mail têm `EMAIL.txt` (o texto da denúncia), `gmail-link.txt` (link do Gmail já digitado) e `attachments/` (os anexos certos); subpastas de formulário têm `FORM.txt` (o texto para colar).

## Como enviar as denúncias

Para cada pasta de destinatário dentro de `send/email/` e `send/form/`:

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
├── README.pt-BR.md          <- você está aqui
├── README.md                <- visão geral em inglês
├── MANUAL.md                <- uso manual sem IA (inglês)
├── SKILL.md                 <- referência completa (inglês)
├── SKILL.pt-BR.md           <- referência completa (português)
├── scripts/
│   ├── fraudtriage.py       <- ferramenta principal (recon, fetch, analyze, cnpj)
│   ├── gmaillink.py         <- gera o link do Gmail já digitado
│   ├── makepackage.py       <- gera a pasta send/ (email/ + form/) com as denúncias
│   ├── autoreport_forms.py  <- OPCIONAL: envio assistido de formulários (camoufox)
│   ├── extractforms.py      <- extrai formulários de um HTML salvo
│   └── sample-kit.html      <- página sintética para testar o analyze
└── templates/
    └── case.example.json    <- modelo para montar o case.json
```

## Limites

- Atrás de uma CDN, o IP real do servidor é invisível. A identificação da hospedagem depende dos headers de request-ID do provedor. Sem esse header, os alvos são o registrador, as blocklists e o CSIRT do país.
- O urlscan gratuito cobre cerca de 30 dias. O crt.sh às vezes falha; rode de novo.
- A ferramenta prepara tudo, mas quem derruba é o provedor. Isso costuma acontecer em horas ou dias.
- Nenhuma ferramenta substitui o Boletim de Ocorrência quando há dinheiro perdido. Só a polícia consegue congelar a conta que recebeu o pagamento.

## Aviso legal

Uso livre sob a licença MIT, com fins de denúncia e educação. Use por sua conta e risco. Os autores não se responsabilizam por uso indevido. Denúncias devem conter apenas fatos verificáveis. A ferramenta separa explicitamente FATOS de PISTAS para proteger você e as vítimas.
