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

**Never commit a real secret value.** Real values live only in the gitignored
`secrets.local` / `.env`.
