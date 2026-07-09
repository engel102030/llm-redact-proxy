// Redaction notice injection. When a request had redactions, we append a
// note to the system prompt teaching the model to work WITH the censorship:
// reference secrets by NAME (env var / secrets file resolved at runtime on
// the user's machine) instead of needing the literal value. The notice is
// static text and is only injected when something was actually redacted.
export const NOTICE_SENTINEL = '[NOTE FROM LOCAL REDACTION PROXY';

export function buildNotice(names = [], { restore = false } = {}) {
  const list = names.length ? `\nRedacted in this request: ${names.join(', ')}.` : '';
  const restoreRule = restore
    ? `
5. RESPONSE RESTORE IS ON - you can DIRECTLY GIVE the user any redacted value. Wherever you write {{<NAME>}} (exact registered name, double braces), the user reading your reply receives the REAL value: the proxy swaps it back on their local machine BEFORE they see it. To the user, {{<NAME>}} is not a placeholder - it IS the value. So when the user asks for a secret's value (an IP, a key, a password), just ANSWER, e.g. "The iPhone IP is {{IP_IPHONE}}." Do NOT say it is redacted or that you do not have it, and do NOT offer to search files or ask the user for it - writing {{<NAME>}} IS how you deliver the real value to them. It works the same inside shell/tool commands (curl -H "x-api-key: {{<NAME>}}") and by passing a [REDACTED:<NAME>] line through verbatim. Only the vendor ever saw the redaction; never write the literal value yourself.`
    : '';
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
4. Do not print, echo, or log secrets to "check" them - the output would just be masked again. To verify a credential works, run a command that USES it and check the result.${restoreRule}`;
}

// Mutates the parsed body in place. Returns true when a notice was added.
// pathHint disambiguates Anthropic (/v1/messages: "system" top-level field)
// from OpenAI-compatible (/chat/completions: system role message) shapes.
export function injectNotice(body, names = [], { pathHint = '', restore = false } = {}) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return false;

  try {
    if (JSON.stringify(body).includes(NOTICE_SENTINEL)) return false;
  } catch {
    return false;
  }

  const notice = buildNotice(names, { restore });

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
