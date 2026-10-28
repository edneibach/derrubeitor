# DERRUBEITOR — Derrubada de golpes e phishing (OSINT → Denúncias)

> Versão em português do `SKILL.md`. As duas versões dizem a mesma coisa — mantenha-as em sincronia. Os templates de denúncia em **português** (§4) são para os destinatários brasileiros: CERT.br, Receita Federal, ANPD, polícia. Para provedores internacionais (Netlify, Vercel, GitHub, Cloudflare, registrador), use os templates em inglês do `SKILL.md` §4.

Fluxo agnóstico de modelo. Só assume que o agente executor consegue (1) rodar comandos shell com Python 3.8+, (2) buscar URLs, (3) escrever arquivos. O `scripts/fraudtriage.py` incluído usa só a biblioteca padrão, não precisa de chave de API, é somente-GET e pode ser copiado sozinho para qualquer outro ambiente de agente ou máquina.

## 0. Regra de ouro — camadas de evidência (leia antes de fazer qualquer coisa)

**Camada 1 — FATO. Afirme como fato e denuncie PARA essa parte:**
- CDN/proxy no caminho de resposta (headers exclusivos de provedor: `cf-ray`,
  `x-amz-cf-id`, `x-served-by: cache-`, …)
- Hospedagem de origem (request-IDs exclusivos de provedor: `x-nf-request-id` →
  Netlify, `x-vercel-id` → Vercel, `x-github-request-id` → GitHub Pages,
  `fly-request-id` → Fly.io, …)
- Registrador (entidade RDAP com ID IANA)

São fatos **porque o provedor que recebe a denúncia consegue verificar a
alegação nos próprios sistemas dele.** Todo o resto não pode ser verificado
por quem está lendo — então precisa ser suavizado ou omitido.

**Camada 2 — CORROBORAÇÃO. Declare como "observado em <data>", nunca como acusação:**
impressões digitais do kit, linhagem de espelhamento HTTrack, linha do tempo
de emissão de certificados, histórico no urlscan, idade do domínio. Serve
para ligar casos numa série, não para acusar ninguém.

**Camada 3 — PISTA (lead). NUNCA afirme. NUNCA coloque em relatório de terceiros.**
Nomes, CNPJs, CPFs, telefones, beneficiários PIX, números de processo falsos,
CPFs padrão fixados no código. Vão **SOMENTE** no anexo para a polícia, com a
frase exata "exibido na página (não verificado)". Motivo: kits de golpe
colam identificadores roubados ou falsos — um caso documentado mostrou o
mesmo documento falso exibindo dois CNPJs diferentes. Só a polícia
(requisição / BACENJUD) conecta uma conta bancária a um autor.

- Errado: "o CNPJ do golpista é 64.453.674/0001-24."
- Certo: "o DARF falso exibe o beneficiário CNPJ 64.453.674/0001-24
  (soma verificável válida, situação cadastral SUSPENSA — propriedade não
  verificada)."

## 1. Fluxo de trabalho

**Passo 0 — diretório do caso.** Crie `case-<dominio>-<aaaammdd>/` com este
layout canônico (referência de trabalho: `case-limpar-divida.com-20261028/`):

```
case-<dominio>-<aaaammdd>/
├── dossier.txt            # o ÚNICO arquivo de dossiê — fatos por camada, IOCs, hashes
├── evidence/              # saída de recon/fetch/analyze/cnpj salva como .txt,
│                          #   stage*.html brutos, *.json, iocs.csv, sha256-manifest.txt
└── send/                  # uma pasta POR DESTINATÁRIO, numerada na ordem do §3
    ├── 1-<hospedagem>/    # EMAIL.txt + gmail-link.txt + attachments/ (sem camada 3)
    ├── 2-cloudflare/      # FORM.txt para canais de formulário web
    ├── ...
    └── 6-policia/         # ANEXO-POLICIAL.txt + attachments/ (caso completo, com camada 3)
```

Salve tudo com horário UTC (headers, corpos HTML, sha256 — a ferramenta
imprime). A cadeia de custódia começa aqui.

**Regras de arquivo do caso (DURAS, sem exceção):**
- **NUNCA crie arquivos .md num caso — SOMENTE .txt.** Dossiê, denúncias,
  anexos, leia-me, capturas de log de evidência: tudo `.txt`. Igualmente
  proibido um único arquivo "bundle de relatórios" — as denúncias vivem
  SOMENTE nas pastas por destinatário. Evidência bruta mantém a extensão
  nativa (`.html`, `.json`, `.csv`) — a regra vale para todo documento que
  o agente escreve.
- **Uma pasta por provedor a contatar por e-mail**, dentro de `send/`,
  numerada na ordem do §3 (`1-netlify/`, `2-cloudflare/`, `4-certbr/`,
  `6-policia/`, …), cada uma com `EMAIL.txt` (+ `gmail-link.txt`) ou
  `FORM.txt` para formulários web, e `attachments/` curado (sem camada 3
  para todo destinatário que não seja a polícia).
  O `makepackage.py case.json` monta essa árvore automaticamente; se for
  escrever à mão, reproduza-a exatamente.

**Passo 1 — reconhecimento.**
```
python scripts/fraudtriage.py recon <host>
```
Uma passada: DNS (A/NS/MX/TXT/rDNS), RDAP (registrador, ID IANA, contato de
abuso, data de registro), linha do tempo de CT-logs (idade + churn de
rehospedagem), histórico público do urlscan, Wayback, e uma sonda ao vivo
de `https://<host>/` com o fingerprint [HARD] de provedor.

Kits de golpe geralmente ficam num subdomínio (`processo.exemplo.com`).
Rode o recon **NESSE** hostname — o script deriva automaticamente o domínio
registrado (apex) para RDAP/CT/urlscan.

**Passo 2 — percorra o fluxo do kit com `fetch`.** O User-Agent mobile é o
padrão porque kits brasileiros comumente bloqueiam desktop com `about:blank`.
Salve cada etapa. Fluxo típico: link de entrada → login falso do gov.br →
intimação/consulta fiscal falsa → chat com falsa auditora → página PIX/DARF.
Busque cada URL que a página anterior aponta; note a propagação de parâmetros
(`cpf`, `cd`).
```
python scripts/fraudtriage.py fetch "<url>" --save etapa1.html
```

**Passo 3 — analise cada etapa salva.**
```
python scripts/fraudtriage.py analyze etapa*.html --csv iocs.csv
```
Extrai: marcadores da família do kit, endpoints, tokens do operador (token
de analytics da Cloudflare, tokens de bot do Telegram, sitekeys de
reCAPTCHA), alegações de identidade (etiquetadas PISTA), payloads PIX,
valores em reais.

**Passo 4 — endpoints financeiros (regras estritas).**
- PERMITIDO: um GET ao endpoint de consulta de CPF do próprio kit com um
  CPF fictício de soma válida (ex.: `52998224725`) para documentar se ele
  devolve dados pessoais reais. Se devolver, é uma violação de LGPD
  observada e objetiva → matéria para denúncia à ANPD.
- NUNCA: consultar com CPF de pessoa real; gerar PIX; POST em qualquer API
  de pagamento; enviar formulário; baixar ou executar payloads.

**Passo 5 — checagem de CNPJ na Receita Federal** para cada CNPJ exibido nas
páginas (ainda camada 3):
```
python scripts/fraudtriage.py cnpj 64.453.674/0001-24
```
Marca automaticamente: SUSPENSA/BAIXADA + "inconsistência cadastral", truque
de dígito-no-nome (`SERVIC0S`, `REGULARIZAND0`), abertura recente (<180 dias).

**Passo 6 — monte o dossiê** (`dossier.txt` — NUNCA `.md`): fatos por camada,
tabela de IOCs, linha do tempo, hashes das capturas/HTML. As denúncias do §4
vão SOMENTE para as pastas por destinatário do Passo 0
(`send/NN-<provedor>/EMAIL.txt` ou `FORM.txt`) — nunca um arquivo único
combinado. Monte com
`python scripts/makepackage.py case.json` (schema: `templates/case.example.json`).

**Passo 7 — envie as denúncias no mesmo dia**, na ordem de prioridade do §3.

**Passo 8 — monitore diariamente** (rerode `recon`) até NXDOMAIN/404. Kits
trocam de domínio; quando aparecer um domínio novo, repita e ligue os casos
pelos marcadores do kit (token de beacon, fonte HTTrack, roteiro de valores)
— reincidente é o que chama a atenção da polícia.

## 2. Cola de comandos

| Comando | Entrega |
|---|---|
| `recon <host>` | Registrador [FATO], provedor DNS/NS, linha do tempo de certificados, histórico urlscan, fingerprint de provedor [FATO] |
| `fetch <url>` | Headers completos da resposta, request-IDs [FATO], cadeia de redirecionamento, HTML salvo + sha256, horário UTC |
| `analyze <arquivo>` | Marcadores do kit [CORROBORAÇÃO], endpoints, tokens do operador, alegações de identidade [PISTA] |
| `cnpj <n>` | Situação cadastral, marcas de homoglifo/recência, sócios [PISTA] |
| `validate-cpf/-cnpj` | Soma verificável offline — sem rede |
| `extractforms.py <html-salvo>` | Action/método do form + campos nomeados de uma página salva (recon de formulários de denúncia) |
| `gmaillink.py --to … --body-file …` | Link do Gmail pré-digitado (ver §4 T-GMAIL) |
| `makepackage.py case.json` | Gera o pacote send/ sem scripts para o caso (EMAIL.txt + gmail-link.txt + attachments por destino; schema: templates/case.example.json) |
| `selftest` | Checagem offline de validadores + regexes |

## 3. Matriz de denúncia (alvos duros + autoridades, na ordem de envio)

1. **Hospedagem de origem** — via headers de request-ID; o single mais
   eficaz de derrubada. Anexe o request-ID + horário UTC (permite que o
   suporte localize a conta exata do lado do servidor).
   - Netlify → `support@netlify.com` (assunto inclui `X-Nf-Request-Id`)
   - Vercel → `abuse@vercel.com` (inclua o `x-vercel-id`)
   - GitHub Pages → https://github.com/contact/report-abuse (inclua o
     `x-github-request-id`)
    - Qualquer outro provedor fingerprintado → o contato de abuso publicado
      no site oficial daquele provedor; os headers de request-ID são a sua
      prova.
    - Como achar o e-mail de abuso: o `recon` já imprime o contato de abuso do
      registrador (RDAP) automaticamente; para hospedagens/CDNs/registradores
      sem endereço listado, procure no site oficial do provedor ("report
      abuse" / política de abuso / `abuse@`) — nunca um contato encontrado
      dentro do kit. Sem nada publicado, o fallback é o contato RDAP do
      registrador e o RDDS da ICANN.
    - Envio pelo Gmail: links de composição pré-digitados — §4 T-GMAIL +
      `scripts/gmaillink.py`.
2. **CDN** — Cloudflare: https://abuse.cloudflare.com/phishing (escolha
   "phishing"; o `cf-ray` prova que a Cloudflare está no caminho de resposta;
   eles repassam à hospedagem e alimentam a blocklist de phishing).
3. **Registrador** (ID IANA do RDAP) — o contato de abuso publicado pelo
   registrador. Inclua os fatos do RDAP + todas as URLs. Efeito: possível
   suspensão do domínio. Se os dados do registrador estiverem errados/atrasados
   → formulário de inexatidão RDDS da ICANN: https://icann.org/wicf (a URL
   aparece nos avisos do RDAP).
4. **Google Safe Browsing** — https://safebrowsing.google.com/safebrowsing/report_phish/
   (todas as URLs do fluxo). Protege usuários de Chrome/Android/Firefox em
   horas.
5. **Microsoft SmartScreen** — https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site
6. **CERT.br** (CSIRT nacional; aceita português ou inglês) — envie o
   dossiê completo por e-mail para `cert@cert.br`. Se o TLD for .br, diga —
   eles acionam o registro.br.
7. **PhishTank / APWG** — https://phishtank.org (adicionar phish);
   encaminhe a mensagem-isca para `reportphishing@apwg.org`.
8. **Meta/WhatsApp** (quando a isca chegou por WhatsApp) — denuncie a
   mensagem e o remetente dentro do aplicativo.
9. **Autoridades brasileiras** (no mesmo dia, depois dos relatórios
   técnicos):
   - Impersonação da Receita Federal → o canal de denúncias oficial,
     alcançado a partir de https://www.gov.br/receitafederal (nunca por
     links de terceiros).
   - ANPD → https://www.gov.br/anpd quando um endpoint ativo devolve dados
     pessoais (violação de LGPD observada).
   - Polícia → registre um **Boletim de Ocorrência** (Delegacia Eletrônica
     do estado ou o canal federal de crimes cibernéticos). O B.O. é o que
     destrava o **BACENJUD** (congelamento de contas PIX). Anexe o
     **ANEXO-POLÍCIA** (pistas) ao B.O.

## 4. Templates de denúncia em português (preencha as `<VARIÁVEIS>`)

> Para provedores internacionais (Netlify/Vercel/GitHub/Cloudflare/
> registrador estrangeiro), use as versões em inglês no `SKILL.md` §4 —
> em geral processam mais rápido. Os abaixo são para os destinatários
> brasileiros.

### T-ORIGEM — para a hospedagem de origem (a mais eficaz)
```
Assunto: Phishing que imita <ENTIDADE (ex.: Receita Federal / um banco / uma
entregadora)> — <DOMINIO> — <REQUEST-ID-HEADER> <ID>

Às <UTC> fiz uma requisição HTTP GET a <URL>. A resposta trouxe o header de
vocês <REQUEST-ID-HEADER>: <VALUE>, ou seja, o site é servido pela sua
plataforma. Trata-se de um kit de phishing que se passa por <ENTIDADE>
para extorquir pagamentos via <MEIO (ex.: PIX)>.

URLs do fluxo: <TODAS AS URLS>
Evidências anexadas: headers completos da resposta, HTML salvo
(sha256 <HASH>), capturas de tela.

Solicito a remoção do site por violação da política de uso aceitável
(phishing/fraude) e a preservação dos registros da conta para as
autoridades policiais (Boletim de Ocorrência nº <Nº OU "em tramitação">).
```

### T-CLOUDFLARE — https://abuse.cloudflare.com/phishing
```
URLs denunciadas: <URLS DO FLUXO>
Tipo: Phishing. Os sites nessas URLs (servidos via Cloudflare, cf-ray
<VALOR> em <UTC>) se passam por <ENTIDADE> para extorquir pagamentos via
<MEIO (ex.: PIX)>. Anexos: headers, HTML,
capturas. Por favor reencaminhem à hospedagem de origem e incluam os
domínios na blocklist de phishing.
```

### T-REGISTRADOR (em português se o registrador for brasileiro; senão use o template em inglês)
```
O domínio <DOMINIO> (registrado em <DATA>, handle RDAP <HANDLE>) está sendo
usado exclusivamente para phishing que imita <ENTIDADE> com extorsão via
<MEIO (ex.: PIX)>. URLs: <LISTA>.
Evidências anexadas. Solicito a aplicação da política de uso aceitável e a
avaliação de suspensão do domínio.
```

### T-CERTBR — e-mail para cert@cert.br
Dossiê completo: URLs, horários UTC, headers, descrição do kit, lista de
IOCs, links de capturas de tela. Afirme com clareza: phishing ativo contra
usuários do <PAÍS>, impersonando <ENTIDADE>; infraestrutura:
registrador <NOME>, CDN <CLOUDFLARE?>, hospedagem de origem <PROVEDOR SE
FINGERPRINTADA>. Mencione o TLD .br se for o caso.

### T-ANEXO-POLÍCIA — o ÚNICO lugar onde as PISTAS (camada 3) entram
Estrutura:
1. **Fatos** (camadas 1–2): registrador, DNS/CDN, hospedagem de origem +
   request-IDs, URLs, datas UTC.
2. **Comportamento observado do kit**: fluxo completo, endpoints, API que
   devolve dados pessoais reais, valores cobrados, prazo falso,
   dupla cobrança (primeiro pagamento leva a uma tela de "erro" e cobra de
   novo).
3. **Pistas** — cada uma com a frase "exibido na página (não verificado)":
   beneficiários PIX, CNPJs (+ situação cadastral), nomes, telefones, CPFs
   fixados no código, tokens de analytics.
4. **Pedidos**: BACENJUD sobre as contas que receberam os PIX; requisição de
   logs aos provedores via request-IDs; ligação com a série do kit se ≥3
   marcadores da família baterem com o §5.

### T-GMAIL — link do Gmail pré-digitado (scripts/gmaillink.py)

Para denúncias por e-mail, monte um link que abre o Gmail com destinatário,
assunto e corpo já digitados:

```
https://mail.google.com/mail/?view=cm&fs=1&to=<para>&su=<assunto-urlencode>&body=<corpo-urlencode>
```

```
python scripts/gmaillink.py --to support@netlify.com \
  --subject-file assunto.txt --body-file corpo.txt > gmail-link.txt
# EMAIL.txt com Para/Assunto + corpo num arquivo só:
python scripts/gmaillink.py --to cert@cert.br --body-file EMAIL.txt \
  --marker "===== CORPO =====" --subject "..." > gmail-link.txt
```

Ressalvas: alguns clientes truncam o corpo acima de ~1900 caracteres
codificados (o script avisa com WARN) — nesse caso abra o link (Para/Assunto
caem certos) e copie o corpo do arquivo EMAIL.txt (tudo abaixo da linha
`===== CORPO =====`). Releia sempre o rascunho antes de enviar; o link abre
o Gmail do usuário — não envia nada sozinho.

Pacote do caso (sem scripts, gerado por `scripts/makepackage.py case.json`):
por destino, uma pasta com `EMAIL.txt`, `gmail-link.txt` e `attachments/`
(evidência curada, sem camada 3 para provedores). SÓ arquivos de texto e
links — nada executa na máquina de quem envia, por projeto: usuário nenhum
deveria ter que rodar script para enviar uma denúncia.

### T-AUTO — canais de envio (zero credenciais, zero scripts)

Regra de design: todo o pipeline roda SEM contas, SEM chaves de API, SEM
logins, e o pacote de envio NÃO contém nada executável — só texto e links.
Qualquer pessoa pode copiar a pasta do skill e usar; é isso que mantém a
evidência reproduzível e a ferramenta redistribuível e confiável.

- **Canal e-mail (Netlify, Vercel, GitHub, registradores, CERT.br, APWG)**:
  o `makepackage.py case.json` gera, por destino, `EMAIL.txt` +
  `gmail-link.txt` (abre o Gmail do próprio denunciante pré-digitado) +
  `attachments/`. Fallback para corpo truncado: copiar do EMAIL.txt.
- **Formulários web (Cloudflare, Safe Browsing, SmartScreen)**: colagem
  manual — `FORM.txt` + `urls-kit.txt` são gerados para isso. O formulário
  da Cloudflare é protegido contra bots (403 ao GET simples) — não scripte.
- **PhishTank**: exige login — opcional; o APWG por e-mail cobre o mesmo
  terreno sem credenciais.
- Fora do núcleo redistribuível de propósito (existem, mas exigem conta):
  a API oficial de Abuse Reports da Cloudflare (conta + token) e qualquer
  canal com cadastro. Não são necessários para derrubada eficaz — e-mail +
  formulários resolvem.
- Revisão humana antes de cada envio — a automação prepara, o usuário envia.

## 5. Famílias de kit conhecidas (Brasil) — para ligação de casos

**Família gvg / "pendência tributária"** (ativa desde 2025 em domínios
descartáveis rotativos; caso confirmado em 28/10/2026 em
`processo.limpar-divida.com`):
- Família de caminhos: `/gvg` → `/gvgconsulta` → `/gvgchat` → `/gvgpix`
  (também `/gov/`)
- Roteiro de valores: R$ 419,55 → R$ 138,45 ("desconto de 67%"); ameaças de
  R$ 1.985,00 / R$ 985,00; prazo falso de 10 minutos; padrão de dupla
  cobrança (primeiro pagamento leva a uma tela de "erro" e cobra de novo)
- Personas: falsa auditora "Tereza Alencar"; assinatura falsificada do
  secretário real da Receita Federal; persona de fallback "Cliente Com
  Restrição"
- Mecânicas: checkbox falso de reCAPTCHA só no cliente ("Não sou um robô");
  quiz do nome da mãe; coleta de telefone; bloqueio de desktop com
  `about:blank`; FingerprintJS; beacon da Cloudflare Web Analytics;
  linhagem espelhada com HTTrack (`Mirrored from <site-fonte> by HTTrack
  … <data>`)
- Iscas: "Desenrola Brasil", "INTIMAÇÃO FISCAL" falsa, DARF falso, disparos
  em massa por WhatsApp com o CPF da vítima pré-preenchido na URL

≥3 marcadores → trate como a mesma linhagem de kit; coloque o argumento de
série/reincidência nas denúncias ao CERT.br e à polícia.

## 6. Segurança e conduta (inegociável)

- Somente GET, uma requisição por etapa. Você está coletando evidência, não
  atacando.
- Nunca gere PIX, envie formulário, complete uma "verificação", ou
  execute/baixe qualquer coisa que o kit oferecer.
- Nunca consulte CPF/CNPJ de pessoa real em nenhum endpoint.
- Dados da camada 3 nunca são afirmados como atribuição em lugar nenhum
  além do anexo da polícia — e mesmo lá, "exibido na página".
- Redija PII de terceiros (vítimas) em qualquer coisa compartilhada
  publicamente; dados completos só para a polícia.
- Se o fluxo exigir conta/OTP para avançar, pare e denuncie o que já tem.
- Sempre horários UTC; guarde headers brutos + HTML + sha256 (o `fetch`
  imprime automaticamente).

## 7. Fallback com curl (sem Python disponível)

```
curl -sSL -A "<qualquer UA de iPhone>" -D headers.txt "<URL>" -o page.html   # headers+corpo
curl -s https://rdap.org/domain/<dominio>                                    # registrador
curl -s "https://crt.sh/?q=%25.<dominio>&output=json"                        # CT logs (%25 = curinga)
curl -s "https://urlscan.io/api/v1/search/?q=domain:<dominio>"              # exames anteriores
curl -s https://brasilapi.com.br/api/cnpj/v1/<14digitos>                     # CNPJ na Receita
curl -s "https://archive.org/wayback/available?url=<dominio>"                # wayback
```
Depois faça grep no HTML salvo pelos marcadores do §5 (comentário HTTrack,
`/gvg`, `NOME_MAE`, `about:blank`, prefixo PIX `000201`, `R$`, padrões de
CNPJ/CPF).

## 8. Limites — seja honesto no dossiê

- Atrás de uma CDN o IP de origem é invisível; headers de request-ID do
  provedor são a ÚNICA atribuição confiável de origem. Sem fingerprint →
  os alvos duros são só registrador + blocklists + CERT.br.
- A busca pública do urlscan cobre ~30 dias. O Wayback raramente tem
  domínios de fraude recém-criados. O crt.sh é instável — rerode o recon.
- Nenhuma credencial, chave de API ou conta em lugar nenhum, por projeto:
  toda busca permanece reproduzível por terceiros (é isso que torna a
  evidência crível) e todo canal de denúncia funciona a partir da sessão
  normal de navegador/e-mail do denunciante — a pasta do skill é
  copiar-e-usar, redistribuível. O pacote de envio é só texto e links; nada
  executa na máquina de quem envia.
