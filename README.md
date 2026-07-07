# llm-redact-proxy

A tiny **local** proxy that strips secrets out of LLM API requests before they reach
a third-party endpoint. Use a cheap/reseller LLM API without leaking your API keys,
DB passwords, SSH creds, or tokens to them.

```
LLM CLI  →  http://127.0.0.1:PORT  (this proxy: redact)  →  vendor
```

- **Local only** (a remote redactor would see the secret first).
- Redacts the **request** body: known secret values (+ their base64 / url-encoded /
  json-escaped variants) and common secret shapes (JWT, PEM keys, `Bearer`, `sk-…`,
  cookies) via regex for dynamic tokens.
- **Fails closed** — on any redaction/parse error it blocks the request, never
  forwards raw.
- Streams responses through untouched.

See `CLAUDE.md` for the full spec, threat model, and pitfalls. Copy `.env.example` →
`.env` and `secrets.local.example` → `secrets.local` (both gitignored) to configure.

Point your LLM CLI at it:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8788
```

## MCP mode (recommended)

Run everything as an MCP server: the CLI boots it automatically and the
embedded proxy starts with it. Copy `.mcp.json.example` to `.mcp.json` (or add
the entry to your existing one) and restart the CLI.

Tools exposed to the model:

- **`run`** - execute a command locally with `{{NAME}}` placeholders (or
  `$NAME` env vars) resolved to the real secret values. Output comes back
  redacted; the literal value never enters the model context at all. This is
  the 1st line of defense - the proxy is the safety net.
- **`secret_add`** - register a new secret (redacted from then on, usable in
  `run`). The value is never echoed back.
- **`secret_list`** - names only.
- **`redaction_stats`** - counters, never values.

- **`redact_mode`** - read or change how aggressively *unregistered* secrets
  are redacted, at runtime (see below).

There is intentionally no `secret_get`: returning a value into the context
would defeat the whole system.

## Redaction modes (tuning the false-positive / coverage tradeoff)

Registered secrets (`secrets.local`) are **always** redacted. The mode only
controls how the shape/entropy layer treats *unregistered* values, so you can
stop it masking things you don't care about (an internal test cookie, a
generated cert, a random high-entropy id):

| Mode | Redacts | Use when |
| --- | --- | --- |
| `named-only` | only your registered secrets | internal/test work; leaking a random token is fine |
| `balanced` | named + shapes (JWT, PEM, `Bearer`, API keys, cookies), **no** entropy | you want the obvious credentials caught without entropy false-positives |
| `strict` (default) | everything, including entropy-gated blobs | maximum safety |

Set the default with `REDACT_MODE`; change it live with the `redact_mode`
tool (e.g. "this project is internal, use named-only"). `REDACT_MODE_FLOOR`
is a hard minimum the tool cannot go below — set it to `balanced`/`strict` so
a prompt-injected model can't loosen its own protection. `REDACT_DISABLE`
turns off individual rules; `REDACT_IGNORE` marks specific values or `/regex/`
patterns as known-safe.

Note the proxy only touches the **request**, never the response — a freshly
generated artifact is visible the turn it's created; redaction only affects it
on later turns once it's part of the uploaded context.

Without `UPSTREAM_URL` the MCP tools still work (proxy disabled) - useful
while you are still on the official API and only want the runner + secret
management.

**Never commit a real secret value.** Real values live only in the gitignored
`secrets.local` / `.env`.
