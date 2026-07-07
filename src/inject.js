// Redaction notice injection. When a request had redactions, we append a
// note to the system prompt teaching the model to work WITH the censorship:
// reference secrets by NAME (env var / secrets file resolved at runtime on
// the user's machine) instead of needing the literal value. The notice is
// static text and is only injected when something was actually redacted.
export const NOTICE_SENTINEL = '[NOTE FROM LOCAL REDACTION PROXY';

export function buildNotice(names = []) {
  const list = names.length ? `\nRedacted in this request: ${names.join(', ')}.` : '';
  return `${NOTICE_SENTINEL} - NOT FROM THE USER]
Secrets (API keys, passwords, tokens) were removed from this conversation before it left the user's machine. Each removal is marked [REDACTED:<NAME>].${list}
The real values exist locally and work normally. Only what YOU see is censored; commands and code run locally with the real values.
Rules:
1. NEVER ask the user to paste a secret, and never try to reconstruct one.
2. Reference secrets indirectly, by name:
   - Preferred: if an MCP tool named "run" (from llm-redact-proxy) is available, call it with {{<NAME>}} placeholders - it substitutes the real value locally and returns redacted output.
   - Shell: use the environment variable "$<NAME>", or read it at runtime, e.g. "$(grep '^<NAME>=' secrets.local | cut -d= -f2-)". The value resolves locally when the command executes; you never need to see it.
   - Code: read process.env.<NAME> / os.environ["<NAME>"] or a gitignored config file. Never hardcode a literal secret.
3. If a tool output contains [REDACTED:...], the command DID run with the real value; treat the masking as cosmetic. Judge success by exit codes and surrounding output, not by the masked text.
4. Do not print, echo, or log secrets to "check" them - the output would just be masked again. To verify a credential works, run a command that USES it and check the result.`;
}

// Mutates the parsed body in place. Returns true when a notice was added.
// pathHint disambiguates Anthropic (/v1/messages: "system" top-level field)
// from OpenAI-compatible (/chat/completions: system role message) shapes.
export function injectNotice(body, names = [], { pathHint = '' } = {}) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return false;

  try {
    if (JSON.stringify(body).includes(NOTICE_SENTINEL)) return false;
  } catch {
    return false;
  }

  const notice = buildNotice(names);

  if (typeof body.system === 'string') {
    body.system = `${body.system}\n\n${notice}`;
    return true;
  }
  if (Array.isArray(body.system)) {
    body.system.push({ type: 'text', text: notice });
    return true;
  }
  if (Array.isArray(body.messages)) {
    // Anthropic messages API rejects role:"system" messages; use the
    // top-level system field instead when the path says Anthropic.
    if (/\/v1\/messages/.test(pathHint)) {
      body.system = notice;
      return true;
    }
    const sys = body.messages.find((m) => m && m.role === 'system' && typeof m.content === 'string');
    if (sys) {
      sys.content = `${sys.content}\n\n${notice}`;
      return true;
    }
    body.messages.unshift({ role: 'system', content: notice });
    return true;
  }
  return false;
}
