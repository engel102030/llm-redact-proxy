# Codex (ChatGPT subscription) Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Claude Code / Overclock (Anthropic Messages format) use the GPT models of a ChatGPT subscription through the local redaction proxy, with login from the dashboard, one provider per account.

**Architecture:** A new provider auth mode `codex-oauth`. The dashboard runs the PKCE login (callback listener on `localhost:1455`), tokens live in `providers.json`. Per request, the proxy redacts the Anthropic body exactly as today, then a dedicated handler translates it to the OpenAI Responses dialect, POSTs to `chatgpt.com/backend-api/codex/responses`, and translates the Responses SSE back to Anthropic SSE (thinking blocks carry the encrypted reasoning in `signature` so the next turn can replay it).

**Tech Stack:** Node >= 22, ESM, zero dependencies (`node:http`, `node:https`, `node:crypto`), `node --test`.

**Spec:** `docs/superpowers/specs/2026-09-24-codex-provider-design.md`

## Global Constraints

- Zero external dependencies. Node >= 22 (`package.json` engines).
- Code, comments, commits, docs: English. Test files: no emojis.
- Never log, return in a public view, or store in stats/inspector a token value. Never commit a real secret (`providers.json` is gitignored via `~/.config`, tests use temp dirs).
- Fail closed: an untranslatable request is answered locally (400/502) and never forwarded raw.
- The ChatGPT token is only ever sent to `chatgpt.com` / `*.chatgpt.com` or a loopback host (tests).
- Fixed OAuth values: client id `app_EMoamEEZ73f0CkXaXp7hrann`, redirect `http://localhost:1455/auth/callback`, scope `openid profile email offline_access`, issuer `https://auth.openai.com`.
- Fixed request fields: `store:false`, `stream:true`, `include:["reasoning.encrypted_content"]`, `parallel_tool_calls:true`, `reasoning.summary:"auto"`. `max_tokens` is DROPPED (backend answers 400 on `max_output_tokens`).
- Default effort map: `{ low:"low", medium:"medium", high:"xhigh", max:"max" }`, clamped to the model's supported levels. No effort from the client: the model's default level, else `medium` (this replaces the spec's "omitted": a request without `reasoning.effort` is not verified against the backend, `medium` is supported by every Codex model).
- Every commit message ends with:
  ```
  Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_016B5pssw9PR5KXtxnP2w9u3
  ```
- Run the whole suite (`npm test`) before every commit; it must stay green (195 tests at the start).

## Review Focus

1. A `tool_result` block with no `content` (Claude Code sends this for tools that print nothing): must become `function_call_output` with `output:""`, not throw. Test in Task 1.
2. Backend SSE with `\r\n` line endings or a final frame without a trailing blank line: the decoder must still yield every event. Test in Task 2.
3. A provider URL that already ends in `/responses`: the upstream path must not become `/responses/responses`. Test in Task 7.
4. Stored tokens without a known expiry (`expiresAt:null`): treated as fresh, refreshed only on a backend 401. Test in Task 3.
5. A 200 answer that is not an SSE stream (e.g. an HTML/JSON page): the client must get an `error` event / 502, never an invented `message_stop`. Test in Task 7.

Not testable here, watch in the first real use: conversation history that started on an Anthropic provider carries `toolu_...` tool ids; the backend may reject those as `call_id`. If it does, start a fresh conversation after switching providers.

## File Structure

- Create `src/codex-translate.js` - request translation (Anthropic Messages -> Responses), SSE decoder, stream reducer (Responses events -> Anthropic SSE event objects), serializer, non-stream accumulator, local token estimate. Pure functions/classes, no I/O.
- Create `src/codex-auth.js` - OAuth constants, PKCE, authorize URL, code exchange, refresh, JWT claim parsing, host guard, backend request headers, model-list fetch. Tiny HTTPS transport, injectable.
- Create `src/codex-login.js` - the one-shot callback listener on `127.0.0.1:1455` that drives a login from authorize URL to stored tokens.
- Create `src/codex-upstream.js` - `handleCodexUpstream()`: the per-request path (host guard, local `/v1/models` + `count_tokens`, translate, POST, 401 refresh+replay, 429 passthrough, stream/non-stream translation back).
- Modify `src/providers.js` - `codex-oauth` auth, default URL, `effortMap`, sanitized `codex` record, `setCodexAuth` / `clearCodexAuth`, public view.
- Modify `src/runtime.js` - auth list + host guard, `codexAdapter()`, `codexLogin()`, `codexLogout()`, injectable `codexDeps`.
- Modify `src/proxy.js` - dispatch to the handler after redaction; `codexAdapter` option.
- Modify `src/stats.js` - optional `note` on `finish()` for the `codex model=... effort=...` log line.
- Modify `src/dashboard.js` - login/logout routes, auth option, login button + status in the provider editor.
- Modify `README.md` - a short section.
- Tests: `test/codex-translate.test.js`, `test/codex-auth.test.js`, `test/codex-login.test.js`, `test/codex.proxy.test.js`, `test/codex-dashboard.test.js`, additions to `test/providers.test.js` and `test/runtime.test.js`, fixtures in `test/helpers/codex-fixtures.js`.

Existing pieces you will reuse (do not rewrite): `modelsEnvelope()` in `src/models.js`; `createMockUpstream()` in `test/helpers/mock-upstream.js` (records requests, can stream SSE frames); `startProxy()` in `test/helpers/start-proxy.js` (boots the proxy on a random port, `serverOptions` are spread into `createProxyServer`); the `readJson` / `json` / `panelGuard` helpers inside `handleDashboard()` in `src/dashboard.js`.

---

### Task 1: Request translation (Anthropic Messages -> Responses)

**Files:**
- Create: `src/codex-translate.js`
- Test: `test/codex-translate.test.js`
- Modify: `docs/superpowers/specs/2026-09-24-codex-provider-design.md` (one line, see step 5)

**Interfaces:**
- Consumes: `ONE_M_SUFFIX` from `src/models.js`.
- Produces: `anthropicToCodex(req, { models, effortMap }) -> object` (the Responses request body), `mapEffort(effort, { effortMap, levels }) -> string|null`, `findModel(models, slug)`, constants `DEFAULT_EFFORT_MAP`, `DEFAULT_INSTRUCTIONS`, `CODEX_DEFAULT_MODELS` (array of `{ slug, displayName, visibility, defaultLevel, levels }`).

- [ ] **Step 1: Write the failing tests**

Create `test/codex-translate.test.js`:

```js
// Request translation: Anthropic Messages -> the Responses dialect the Codex
// backend speaks. Translation runs AFTER redaction, so strictness here is
// about correctness (fail closed on anything unknown), not about leaks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  anthropicToCodex,
  mapEffort,
  findModel,
  DEFAULT_EFFORT_MAP,
  DEFAULT_INSTRUCTIONS,
  CODEX_DEFAULT_MODELS,
} from '../src/codex-translate.js';

const base = { model: 'gpt-5.6-sol', messages: [{ role: 'user', content: 'hi' }] };

test('minimal request: fixed Codex fields, default instructions, dropped Anthropic-only fields', () => {
  const out = anthropicToCodex({
    ...base,
    max_tokens: 64000,
    temperature: 0.2,
    top_p: 1,
    stop_sequences: ['x'],
    metadata: { user_id: 'user-1' },
    thinking: { type: 'adaptive', display: 'omitted' },
    context_management: { edits: [] },
    service_tier: 'auto',
  });
  assert.equal(out.model, 'gpt-5.6-sol');
  assert.equal(out.instructions, DEFAULT_INSTRUCTIONS);
  assert.deepEqual(out.input, [{ type: 'message', role: 'user', content: [{ type: 'input_text', text: 'hi' }] }]);
  assert.equal(out.store, false);
  assert.equal(out.stream, true);
  assert.deepEqual(out.include, ['reasoning.encrypted_content']);
  assert.equal(out.parallel_tool_calls, true);
  assert.equal(out.tool_choice, 'auto');
  assert.deepEqual(out.tools, []);
  assert.equal(out.prompt_cache_key.length, 64); // sha256 hex of metadata.user_id
  assert.equal(out.prompt_cache_key.includes('user-1'), false);
  for (const k of ['max_output_tokens', 'max_tokens', 'temperature', 'top_p', 'stop_sequences', 'metadata', 'thinking', 'context_management', 'service_tier']) {
    assert.equal(k in out, false, `${k} must not be forwarded`);
  }
  assert.equal('prompt_cache_key' in anthropicToCodex(base), false);
});

test('[1m] suffix is stripped from the model id', () => {
  assert.equal(anthropicToCodex({ ...base, model: 'gpt-5.5[1m]' }).model, 'gpt-5.5');
});

test('system string and text blocks become instructions joined by a blank line', () => {
  assert.equal(anthropicToCodex({ ...base, system: '  Be terse.  ' }).instructions, 'Be terse.');
  const out = anthropicToCodex({ ...base, system: [{ type: 'text', text: 'A', cache_control: { type: 'ephemeral' } }, { type: 'text', text: '' }, { type: 'text', text: 'B' }] });
  assert.equal(out.instructions, 'A\n\nB');
  assert.equal(anthropicToCodex({ ...base, system: [] }).instructions, DEFAULT_INSTRUCTIONS);
});

test('effort: default map, provider map, clamp to the model levels', () => {
  assert.equal(mapEffort('high'), 'xhigh');
  assert.equal(mapEffort('low'), 'low');
  assert.equal(mapEffort('max', { levels: ['low', 'medium', 'high', 'xhigh'] }), 'xhigh');
  assert.equal(mapEffort('low', { levels: ['medium', 'high'] }), 'medium');
  assert.equal(mapEffort('medium', { effortMap: { ...DEFAULT_EFFORT_MAP, medium: 'high' } }), 'high');
  assert.equal(mapEffort('weird', { levels: ['low', 'medium'] }), 'weird'); // unknown: let the backend reject it
  assert.equal(mapEffort(undefined), null);
  const out = anthropicToCodex({ ...base, model: 'gpt-5.5', output_config: { effort: 'max' } }, { models: CODEX_DEFAULT_MODELS });
  assert.deepEqual(out.reasoning, { effort: 'xhigh', summary: 'auto' });
  assert.deepEqual(anthropicToCodex({ ...base, output_config: { effort: 'high' } }).reasoning, { effort: 'xhigh', summary: 'auto' });
});

test('no effort from the client: the model default level, else medium', () => {
  assert.equal(anthropicToCodex(base, { models: CODEX_DEFAULT_MODELS }).reasoning.effort, 'low'); // gpt-5.6-sol default
  assert.equal(anthropicToCodex({ ...base, model: 'unknown-model' }).reasoning.effort, 'medium');
  assert.equal(findModel(CODEX_DEFAULT_MODELS, 'gpt-5.5').defaultLevel, 'medium');
  assert.equal(findModel(null, 'gpt-5.5'), null);
});

test('tool loop: tool_use -> function_call, tool_result -> function_call_output, order kept', () => {
  const out = anthropicToCodex({
    ...base,
    messages: [
      { role: 'user', content: 'weather?' },
      { role: 'assistant', content: [{ type: 'text', text: 'checking' }, { type: 'tool_use', id: 'call_1', name: 'get_weather', input: { city: 'Paris' } }] },
      {
        role: 'user',
        content: [
          { type: 'tool_result', tool_use_id: 'call_1', is_error: true, content: [{ type: 'text', text: '18C' }, { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AA==' } }] },
          { type: 'text', text: 'and now?' },
        ],
      },
    ],
  });
  assert.deepEqual(out.input, [
    { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'weather?' }] },
    { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'checking' }] },
    { type: 'function_call', call_id: 'call_1', name: 'get_weather', arguments: '{"city":"Paris"}' },
    { type: 'function_call_output', call_id: 'call_1', output: 'ERROR: 18C\n[image omitted]' },
    { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'and now?' }] },
  ]);
});

test('tool_result with a string or no content', () => {
  const out = anthropicToCodex({
    ...base,
    messages: [
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'c1', content: 'plain' }, { type: 'tool_result', tool_use_id: 'c2' }] },
    ],
  });
  assert.deepEqual(out.input, [
    { type: 'function_call_output', call_id: 'c1', output: 'plain' },
    { type: 'function_call_output', call_id: 'c2', output: '' },
  ]);
});

test('thinking with a signature replays as a reasoning item; without one it is dropped', () => {
  const out = anthropicToCodex({
    ...base,
    messages: [
      { role: 'user', content: 'q' },
      {
        role: 'assistant',
        content: [
          { type: 'thinking', thinking: 'plan', signature: 'ENC' },
          { type: 'thinking', thinking: 'no sig', signature: '' },
          { type: 'redacted_thinking', data: 'zzz' },
          { type: 'text', text: 'answer' },
        ],
      },
    ],
  });
  assert.deepEqual(out.input, [
    { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'q' }] },
    { type: 'reasoning', summary: [{ type: 'summary_text', text: 'plan' }], encrypted_content: 'ENC' },
    { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'answer' }] },
  ]);
  const empty = anthropicToCodex({ ...base, messages: [{ role: 'assistant', content: [{ type: 'thinking', thinking: '', signature: 'ENC2' }] }] });
  assert.deepEqual(empty.input, [{ type: 'reasoning', summary: [], encrypted_content: 'ENC2' }]);
});

test('user image becomes an input_image data URL; url sources pass through', () => {
  const out = anthropicToCodex({
    ...base,
    messages: [
      { role: 'user', content: [{ type: 'text', text: 'look' }, { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: 'QUJD' } }, { type: 'image', source: { type: 'url', url: 'https://x/y.png' } }] },
    ],
  });
  assert.deepEqual(out.input, [
    { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'look' }, { type: 'input_image', image_url: 'data:image/jpeg;base64,QUJD' }, { type: 'input_image', image_url: 'https://x/y.png' }] },
  ]);
});

test('tools: function tools mapped, defer_loading ignored, server tools dropped, tool_choice mapped', () => {
  const out = anthropicToCodex({
    ...base,
    tools: [
      { name: 'Read', description: 'read a file', input_schema: { type: 'object' }, defer_loading: true },
      { type: 'web_search_20250305', name: 'web_search' },
      { type: 'custom', name: 'Grep', input_schema: { type: 'object', properties: {} } },
    ],
    tool_choice: { type: 'any', disable_parallel_tool_use: true },
  });
  assert.deepEqual(out.tools, [
    { type: 'function', name: 'Read', description: 'read a file', parameters: { type: 'object' }, strict: false },
    { type: 'function', name: 'Grep', parameters: { type: 'object', properties: {} }, strict: false },
  ]);
  assert.equal(out.tool_choice, 'required');
  assert.equal(out.parallel_tool_calls, false);
  assert.deepEqual(anthropicToCodex({ ...base, tools: [{ name: 'x', input_schema: {} }], tool_choice: { type: 'tool', name: 'x' } }).tool_choice, { type: 'function', name: 'x' });
  assert.equal(anthropicToCodex({ ...base, tool_choice: { type: 'none' } }).tool_choice, 'none');
  assert.equal(anthropicToCodex({ ...base, tool_choice: { type: 'any' } }).tool_choice, 'auto'); // no tools: required would be rejected
});

test('unknown content block or malformed request throws (fail closed)', () => {
  assert.throws(() => anthropicToCodex({ ...base, messages: [{ role: 'user', content: [{ type: 'document', source: {} }] }] }), /unsupported content block type: document/);
  assert.throws(() => anthropicToCodex({ ...base, messages: [{ role: 'system', content: 'x' }] }), /unsupported message role/);
  assert.throws(() => anthropicToCodex({ ...base, messages: 'nope' }), /messages must be an array/);
  assert.throws(() => anthropicToCodex({ messages: [] }), /model is required/);
  assert.throws(() => anthropicToCodex({ ...base, system: [{ type: 'image' }] }), /text blocks/);
  assert.throws(() => anthropicToCodex({ ...base, tools: [{ name: '', input_schema: {} }] }), /tool has no name/);
  assert.throws(() => anthropicToCodex({ ...base, tool_choice: { type: 'tool' } }), /needs a name/);
  assert.throws(() => anthropicToCodex('not an object'), /JSON object/);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test test/codex-translate.test.js`
Expected: FAIL - `Cannot find module '.../src/codex-translate.js'`.

- [ ] **Step 3: Write the implementation**

Create `src/codex-translate.js`:

```js
// Protocol translation between the Anthropic Messages API (what the client
// speaks) and the OpenAI Responses dialect served by the ChatGPT Codex
// backend (chatgpt.com/backend-api/codex). Translation runs AFTER redaction:
// every string that reaches this module has already been scrubbed, so the
// strictness here is about correctness, never about leaks.
//
// Request side: anthropicToCodex(). Response side (Task 2): SseDecoder,
// CodexReducer, serializeSse(), accumulateMessage(), estimateTokens().
import { createHash } from 'node:crypto';
import { ONE_M_SUFFIX } from './models.js';

// Claude Code sends output_config.effort = low|medium|high|max. The backend
// speaks low|medium|high|xhigh|max|ultra (per model). Claude Code's default
// ("high") lands on xhigh, the level the user runs the Codex CLI at.
export const DEFAULT_EFFORT_MAP = Object.freeze({ low: 'low', medium: 'medium', high: 'xhigh', max: 'max' });
export const DEFAULT_INSTRUCTIONS = 'You are a helpful coding assistant.';

// Fallback when a provider has no fetched model list (visibility "list" only).
// Levels as served by GET /backend-api/codex/models on 2026-09-24.
export const CODEX_DEFAULT_MODELS = [
  { slug: 'gpt-5.6-sol', displayName: 'GPT-5.6-Sol', visibility: 'list', defaultLevel: 'low', levels: ['low', 'medium', 'high', 'xhigh', 'max', 'ultra'] },
  { slug: 'gpt-5.6-terra', displayName: 'GPT-5.6-Terra', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium', 'high', 'xhigh', 'max', 'ultra'] },
  { slug: 'gpt-5.6-luna', displayName: 'GPT-5.6-Luna', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium', 'high', 'xhigh', 'max'] },
  { slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium', 'high', 'xhigh'] },
];

const LEVEL_ORDER = ['none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max', 'ultra'];

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

export function findModel(models, slug) {
  if (!Array.isArray(models)) return null;
  return models.find((m) => m && m.slug === slug) ?? null;
}

// Claude effort -> Codex level through the provider map, clamped to the
// highest level the model supports (or its lowest when mapped below it).
// A level outside the known order is passed through so the backend rejects
// it explicitly instead of us guessing.
export function mapEffort(effort, { effortMap = DEFAULT_EFFORT_MAP, levels = null } = {}) {
  if (typeof effort !== 'string' || !effort) return null;
  const map = effortMap || DEFAULT_EFFORT_MAP;
  const mapped = map[effort] ?? effort;
  if (!Array.isArray(levels) || levels.length === 0 || levels.includes(mapped)) return mapped;
  const rank = (l) => LEVEL_ORDER.indexOf(l);
  if (rank(mapped) < 0) return mapped;
  const known = levels.filter((l) => rank(l) >= 0).sort((a, b) => rank(a) - rank(b));
  if (known.length === 0) return mapped;
  const below = known.filter((l) => rank(l) <= rank(mapped));
  return below.length ? below[below.length - 1] : known[0];
}

function systemToInstructions(system) {
  if (system === undefined || system === null) return DEFAULT_INSTRUCTIONS;
  if (typeof system === 'string') return system.trim() || DEFAULT_INSTRUCTIONS;
  if (!Array.isArray(system)) throw new Error('system must be a string or an array of text blocks');
  const parts = [];
  for (const block of system) {
    if (!isPlainObject(block) || block.type !== 'text' || typeof block.text !== 'string') {
      throw new Error('system blocks must be text blocks');
    }
    if (block.text) parts.push(block.text);
  }
  return parts.join('\n\n') || DEFAULT_INSTRUCTIONS;
}

function imagePart(block) {
  const src = block.source;
  if (!isPlainObject(src)) throw new Error('image block has no source');
  if (src.type === 'base64' && typeof src.media_type === 'string' && typeof src.data === 'string') {
    return { type: 'input_image', image_url: `data:${src.media_type};base64,${src.data}` };
  }
  if (src.type === 'url' && typeof src.url === 'string') return { type: 'input_image', image_url: src.url };
  throw new Error(`unsupported image source: ${String(src.type)}`);
}

// function_call_output.output is a string: text parts joined, an image inside
// a tool result becomes a literal placeholder, is_error becomes a prefix.
function toolResultText(block) {
  const c = block.content;
  let text = '';
  if (typeof c === 'string') {
    text = c;
  } else if (Array.isArray(c)) {
    const parts = [];
    for (const part of c) {
      if (!isPlainObject(part)) throw new Error('tool_result content parts must be objects');
      if (part.type === 'text' && typeof part.text === 'string') parts.push(part.text);
      else if (part.type === 'image') parts.push('[image omitted]');
      else throw new Error(`unsupported tool_result part: ${String(part.type)}`);
    }
    text = parts.join('\n');
  } else if (c !== undefined && c !== null) {
    throw new Error('tool_result content must be a string or an array');
  }
  return block.is_error === true ? `ERROR: ${text}` : text;
}

function pushMessage(message, input) {
  if (!isPlainObject(message)) throw new Error('messages entries must be objects');
  const role = message.role;
  if (role !== 'user' && role !== 'assistant') throw new Error(`unsupported message role: ${String(role)}`);
  const blocks = typeof message.content === 'string' ? [{ type: 'text', text: message.content }] : message.content;
  if (!Array.isArray(blocks)) throw new Error('message content must be a string or an array of blocks');
  let parts = [];
  const flush = () => {
    if (parts.length === 0) return;
    input.push({ type: 'message', role, content: parts });
    parts = [];
  };
  for (const block of blocks) {
    if (!isPlainObject(block) || typeof block.type !== 'string') throw new Error('content blocks must have a type');
    switch (block.type) {
      case 'text':
        if (typeof block.text !== 'string') throw new Error('text block has no text');
        parts.push({ type: role === 'assistant' ? 'output_text' : 'input_text', text: block.text });
        break;
      case 'image':
        if (role !== 'user') throw new Error('image blocks are only supported in user messages');
        parts.push(imagePart(block));
        break;
      case 'tool_result':
        if (typeof block.tool_use_id !== 'string' || !block.tool_use_id) throw new Error('tool_result has no tool_use_id');
        flush();
        input.push({ type: 'function_call_output', call_id: block.tool_use_id, output: toolResultText(block) });
        break;
      case 'tool_use':
        if (typeof block.id !== 'string' || typeof block.name !== 'string') throw new Error('tool_use needs id and name');
        flush();
        input.push({ type: 'function_call', call_id: block.id, name: block.name, arguments: JSON.stringify(block.input ?? {}) });
        break;
      case 'thinking': {
        // The signature carries the backend's encrypted_content (see the
        // reducer). Without it there is nothing the backend can replay.
        const sig = typeof block.signature === 'string' ? block.signature : '';
        if (!sig) break;
        flush();
        const text = typeof block.thinking === 'string' ? block.thinking : '';
        input.push({ type: 'reasoning', summary: text ? [{ type: 'summary_text', text }] : [], encrypted_content: sig });
        break;
      }
      case 'redacted_thinking':
        break;
      default:
        throw new Error(`unsupported content block type: ${block.type}`);
    }
  }
  flush();
}

// Only function tools (those with an input_schema) can run on the client.
// Server-side tools (web_search_..., tool_search_...) carry a `type` and no
// schema: nothing on the Codex side can run them, so they are dropped.
// defer_loading is a Claude-only hint: every tool is sent.
function toolsToFunctions(tools) {
  if (tools === undefined || tools === null) return [];
  if (!Array.isArray(tools)) throw new Error('tools must be an array');
  const out = [];
  for (const t of tools) {
    if (!isPlainObject(t)) throw new Error('tools entries must be objects');
    if (!isPlainObject(t.input_schema)) continue;
    if (typeof t.name !== 'string' || !t.name) throw new Error('tool has no name');
    const fn = { type: 'function', name: t.name };
    if (typeof t.description === 'string') fn.description = t.description;
    fn.parameters = t.input_schema;
    fn.strict = false;
    out.push(fn);
  }
  return out;
}

function mapToolChoice(choice, toolCount) {
  if (choice === undefined || choice === null) return { choice: 'auto', parallel: true };
  if (!isPlainObject(choice) || typeof choice.type !== 'string') throw new Error('tool_choice must be an object with a type');
  const parallel = choice.disable_parallel_tool_use !== true;
  switch (choice.type) {
    case 'auto':
      return { choice: 'auto', parallel };
    case 'any':
      return { choice: toolCount > 0 ? 'required' : 'auto', parallel };
    case 'none':
      return { choice: 'none', parallel };
    case 'tool':
      if (typeof choice.name !== 'string' || !choice.name) throw new Error('tool_choice.tool needs a name');
      return { choice: { type: 'function', name: choice.name }, parallel };
    default:
      throw new Error(`unsupported tool_choice type: ${choice.type}`);
  }
}

// Anthropic Messages request -> Responses request for the Codex backend.
// `models` is the provider's fetched list (for level clamping and defaults),
// `effortMap` the provider's Claude->Codex effort map. Throws on anything it
// does not understand; the caller answers 400 and forwards nothing.
export function anthropicToCodex(req, { models = null, effortMap = DEFAULT_EFFORT_MAP } = {}) {
  if (!isPlainObject(req)) throw new Error('request body must be a JSON object');
  if (typeof req.model !== 'string' || !req.model) throw new Error('model is required');
  if (!Array.isArray(req.messages)) throw new Error('messages must be an array');
  const model = req.model.endsWith(ONE_M_SUFFIX) ? req.model.slice(0, -ONE_M_SUFFIX.length) : req.model;

  const input = [];
  for (const message of req.messages) pushMessage(message, input);
  const tools = toolsToFunctions(req.tools);
  const { choice, parallel } = mapToolChoice(req.tool_choice, tools.length);

  const known = findModel(models, model);
  const requested = isPlainObject(req.output_config) ? req.output_config.effort : undefined;
  const effort = mapEffort(requested, { effortMap, levels: known?.levels ?? null }) ?? known?.defaultLevel ?? 'medium';

  const out = {
    model,
    instructions: systemToInstructions(req.system),
    input,
    tools,
    tool_choice: choice,
    parallel_tool_calls: parallel,
    reasoning: { effort, summary: 'auto' },
    store: false,
    stream: true,
    include: ['reasoning.encrypted_content'],
  };
  const userId = isPlainObject(req.metadata) ? req.metadata.user_id : undefined;
  if (typeof userId === 'string' && userId) {
    // Stable per-session cache key without sending the client's own id.
    out.prompt_cache_key = createHash('sha256').update(userId).digest('hex');
  }
  return out;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test test/codex-translate.test.js`
Expected: all tests PASS (11 tests). Then `npm test` - everything green.

- [ ] **Step 5: Align the spec with the effort default**

In `docs/superpowers/specs/2026-09-24-codex-provider-design.md`, section 3, replace the line

```
  unknown model → sent as mapped). Absent → `reasoning.effort` omitted.
```

with

```
  unknown model → sent as mapped). Absent → the model's default level from the
  fetched list, else `medium` (every Codex model supports it).
```

- [ ] **Step 6: Commit**

```bash
git add src/codex-translate.js test/codex-translate.test.js docs/superpowers/specs/2026-09-24-codex-provider-design.md
git commit -F - <<'EOF'
feat(codex): translate Anthropic Messages requests to the Codex Responses dialect

system -> instructions, messages -> input items (text, images, tool_use ->
function_call, tool_result -> function_call_output, signed thinking ->
reasoning with encrypted_content), function tools only, tool_choice mapped,
Claude effort mapped and clamped per model. Drops max_tokens (the backend
rejects max_output_tokens) and every Anthropic-only field. Unknown blocks
throw so the proxy fails closed.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B5pssw9PR5KXtxnP2w9u3
EOF
```

---

### Task 2: Response translation (Responses SSE -> Anthropic SSE)

**Files:**
- Modify: `src/codex-translate.js` (append)
- Create: `test/helpers/codex-fixtures.js`
- Modify: `test/codex-translate.test.js` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: `class SseDecoder { push(chunk: Buffer|string): object[]; flush(): object[] }`, `class CodexReducer { constructor({ messageId, model }); push(event: object): AnthropicEvent[]; get done(): boolean }` where `AnthropicEvent = { event: string, data: object }`, `serializeSse(events: AnthropicEvent[]): string`, `errorSse(message: string): string`, `accumulateMessage(events: AnthropicEvent[]): object` (a Messages-API message), `estimateTokens(translated): number`, `MAX_SSE_FRAME_BYTES`. Fixtures: `TEXT_TURN`, `TOOL_TURN` (Responses event arrays), `sseFrames(events) -> string[]`.

- [ ] **Step 1: Write the fixtures**

Create `test/helpers/codex-fixtures.js`:

```js
// Shared fixtures for the Codex provider tests. The event sequences mirror
// what the live backend streamed on 2026-09-24 (shapes only, no real ids).
export const sseFrames = (events) => events.map((e) => `data: ${JSON.stringify(e)}\n\n`);

// One text answer preceded by a reasoning item with an EMPTY summary (what a
// low-effort trivial turn looks like) - the thinking block must still be
// emitted, with the encrypted content as its signature.
export const TEXT_TURN = [
  { type: 'response.created', response: { id: 'resp_1' } },
  { type: 'response.in_progress', response: { id: 'resp_1' } },
  { type: 'response.output_item.added', output_index: 0, item: { id: 'rs_1', type: 'reasoning', summary: [] } },
  { type: 'response.output_item.done', output_index: 0, item: { id: 'rs_1', type: 'reasoning', summary: [], content: [], encrypted_content: 'ENC1' } },
  { type: 'response.output_item.added', output_index: 1, item: { id: 'msg_a', type: 'message', role: 'assistant', content: [] } },
  { type: 'response.content_part.added', output_index: 1, content_index: 0, part: { type: 'output_text', text: '' } },
  { type: 'response.output_text.delta', output_index: 1, content_index: 0, delta: 'Hi' },
  { type: 'response.output_text.delta', output_index: 1, content_index: 0, delta: '.' },
  { type: 'response.output_text.done', output_index: 1, content_index: 0, text: 'Hi.' },
  { type: 'response.content_part.done', output_index: 1, content_index: 0, part: { type: 'output_text', text: 'Hi.' } },
  { type: 'response.output_item.done', output_index: 1, item: { id: 'msg_a', type: 'message', role: 'assistant', phase: 'final_answer', content: [{ type: 'output_text', text: 'Hi.' }] } },
  { type: 'response.completed', response: { id: 'resp_1', status: 'completed', output: [], usage: { input_tokens: 24, output_tokens: 18, input_tokens_details: { cached_tokens: 5 }, output_tokens_details: { reasoning_tokens: 10 }, total_tokens: 42 } } },
];

// One function call, arguments streamed in deltas.
export const TOOL_TURN = [
  { type: 'response.created', response: { id: 'resp_2' } },
  { type: 'response.in_progress', response: { id: 'resp_2' } },
  { type: 'response.output_item.added', output_index: 0, item: { id: 'fc_1', type: 'function_call', status: 'in_progress', call_id: 'call_1', name: 'get_weather', arguments: '' } },
  { type: 'response.function_call_arguments.delta', output_index: 0, item_id: 'fc_1', delta: '{"city":' },
  { type: 'response.function_call_arguments.delta', output_index: 0, item_id: 'fc_1', delta: '"Paris"}' },
  { type: 'response.function_call_arguments.done', output_index: 0, item_id: 'fc_1', arguments: '{"city":"Paris"}' },
  { type: 'response.output_item.done', output_index: 0, item: { id: 'fc_1', type: 'function_call', status: 'completed', call_id: 'call_1', name: 'get_weather', arguments: '{"city":"Paris"}' } },
  { type: 'response.completed', response: { id: 'resp_2', status: 'completed', output: [], usage: { input_tokens: 10, output_tokens: 6 } } },
];
```

- [ ] **Step 2: Write the failing tests**

Append to `test/codex-translate.test.js`:

```js
import { SseDecoder, CodexReducer, serializeSse, errorSse, accumulateMessage, estimateTokens } from '../src/codex-translate.js';
import { TEXT_TURN, TOOL_TURN } from './helpers/codex-fixtures.js';

function run(events) {
  const r = new CodexReducer({ messageId: 'msg_1', model: 'gpt-5.6-sol' });
  const out = [];
  for (const e of events) out.push(...r.push(e));
  return { out, r };
}

test('text turn: reasoning (empty summary) -> thinking block with signature, text block, end_turn + usage', () => {
  const { out, r } = run(TEXT_TURN);
  assert.deepEqual(
    out.map((e) => e.event),
    ['message_start', 'content_block_start', 'content_block_delta', 'content_block_stop', 'content_block_start', 'content_block_delta', 'content_block_delta', 'content_block_stop', 'message_delta', 'message_stop'],
  );
  assert.deepEqual(out[0].data.message, { id: 'msg_1', type: 'message', role: 'assistant', model: 'gpt-5.6-sol', content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } });
  assert.deepEqual(out[1].data, { type: 'content_block_start', index: 0, content_block: { type: 'thinking', thinking: '', signature: '' } });
  assert.deepEqual(out[2].data.delta, { type: 'signature_delta', signature: 'ENC1' });
  assert.deepEqual(out[4].data, { type: 'content_block_start', index: 1, content_block: { type: 'text', text: '' } });
  assert.deepEqual(out[5].data.delta, { type: 'text_delta', text: 'Hi' });
  assert.deepEqual(out[8].data, { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { input_tokens: 24, output_tokens: 18, cache_read_input_tokens: 5 } });
  assert.equal(r.done, true);
  assert.deepEqual(r.push({ type: 'response.output_text.delta', output_index: 9, delta: 'late' }), []); // after done: ignored
});

test('tool turn: function_call -> tool_use block with input_json deltas, stop_reason tool_use', () => {
  const { out } = run(TOOL_TURN);
  assert.deepEqual(out[1].data, { type: 'content_block_start', index: 0, content_block: { type: 'tool_use', id: 'call_1', name: 'get_weather', input: {} } });
  assert.deepEqual(out[2].data.delta, { type: 'input_json_delta', partial_json: '{"city":' });
  assert.deepEqual(out[3].data.delta, { type: 'input_json_delta', partial_json: '"Paris"}' });
  assert.equal(out[4].event, 'content_block_stop');
  assert.equal(out[5].data.delta.stop_reason, 'tool_use');
  assert.deepEqual(out[5].data.usage, { input_tokens: 10, output_tokens: 6, cache_read_input_tokens: 0 });
});

test('function_call whose arguments never streamed: the final arguments become one delta', () => {
  const { out } = run([
    { type: 'response.created', response: {} },
    { type: 'response.output_item.added', output_index: 0, item: { id: 'fc', type: 'function_call', call_id: 'c9', name: 'ls', arguments: '' } },
    { type: 'response.output_item.done', output_index: 0, item: { id: 'fc', type: 'function_call', call_id: 'c9', name: 'ls', arguments: '{"path":"."}' } },
    { type: 'response.completed', response: { usage: {} } },
  ]);
  assert.deepEqual(out[2].data.delta, { type: 'input_json_delta', partial_json: '{"path":"."}' });
});

test('reasoning summary deltas stream as thinking_delta; a second part gets a blank-line separator', () => {
  const { out } = run([
    { type: 'response.created', response: {} },
    { type: 'response.output_item.added', output_index: 0, item: { id: 'rs', type: 'reasoning', summary: [] } },
    { type: 'response.reasoning_summary_part.added', output_index: 0, summary_index: 0, part: { type: 'summary_text', text: '' } },
    { type: 'response.reasoning_summary_text.delta', output_index: 0, summary_index: 0, delta: 'Think A' },
    { type: 'response.reasoning_summary_part.done', output_index: 0, summary_index: 0 },
    { type: 'response.reasoning_summary_part.added', output_index: 0, summary_index: 1, part: { type: 'summary_text', text: '' } },
    { type: 'response.reasoning_summary_text.delta', output_index: 0, summary_index: 1, delta: 'Think B' },
    { type: 'response.output_item.done', output_index: 0, item: { id: 'rs', type: 'reasoning', summary: [{ type: 'summary_text', text: 'Think A' }, { type: 'summary_text', text: 'Think B' }], encrypted_content: 'ENC' } },
    { type: 'response.completed', response: { usage: {} } },
  ]);
  const thinking = out.filter((e) => e.data.delta?.type === 'thinking_delta').map((e) => e.data.delta.thinking).join('');
  assert.equal(thinking, 'Think A\n\nThink B');
  assert.equal(out.filter((e) => e.data.delta?.type === 'signature_delta').length, 1);
});

test('summary present only in the done item is emitted once', () => {
  const { out } = run([
    { type: 'response.created', response: {} },
    { type: 'response.output_item.added', output_index: 0, item: { id: 'rs', type: 'reasoning', summary: [] } },
    { type: 'response.output_item.done', output_index: 0, item: { id: 'rs', type: 'reasoning', summary: [{ type: 'summary_text', text: 'Only here' }], encrypted_content: 'E' } },
    { type: 'response.completed', response: { usage: {} } },
  ]);
  const thinking = out.filter((e) => e.data.delta?.type === 'thinking_delta').map((e) => e.data.delta.thinking);
  assert.deepEqual(thinking, ['Only here']);
});

test('out-of-order delta, duplicate created, wrong block kind, failed and error events throw', () => {
  assert.throws(() => run([{ type: 'response.created' }, { type: 'response.output_text.delta', output_index: 3, delta: 'x' }]), /not open/);
  assert.throws(() => run([{ type: 'response.created' }, { type: 'response.created' }]), /duplicate/);
  assert.throws(() => run([{ type: 'response.output_text.delta', output_index: 0, delta: 'x' }]), /before response.created/);
  assert.throws(
    () => run([{ type: 'response.created' }, { type: 'response.output_item.added', output_index: 0, item: { type: 'message' } }, { type: 'response.reasoning_summary_text.delta', output_index: 0, delta: 'x' }]),
    /for a text block/,
  );
  assert.throws(() => run([{ type: 'response.created' }, { type: 'response.failed', response: { error: { message: 'quota exhausted' } } }]), /quota exhausted/);
  assert.throws(() => run([{ type: 'response.created' }, { type: 'error', message: 'boom' }]), /boom/);
  assert.throws(() => run([{ nope: true }]), /no type/);
});

test('unknown item types and unknown events are ignored; incomplete -> max_tokens and open blocks are closed', () => {
  const { out, r } = run([
    { type: 'response.created', response: {} },
    { type: 'response.output_item.added', output_index: 0, item: { id: 'ws', type: 'web_search_call' } },
    { type: 'response.web_search_call.searching', output_index: 0 },
    { type: 'response.output_item.done', output_index: 0, item: { id: 'ws', type: 'web_search_call' } },
    { type: 'response.output_item.added', output_index: 1, item: { id: 'm', type: 'message', content: [] } },
    { type: 'response.output_text.delta', output_index: 1, delta: 'partial' },
    { type: 'response.incomplete', response: { usage: { input_tokens: 1, output_tokens: 2 } } },
  ]);
  assert.deepEqual(out.map((e) => e.event), ['message_start', 'content_block_start', 'content_block_delta', 'content_block_stop', 'message_delta', 'message_stop']);
  assert.equal(out[1].data.index, 0); // the ignored item consumed no index
  assert.equal(out[4].data.delta.stop_reason, 'max_tokens');
  assert.equal(r.done, true);
});

test('SseDecoder: frames split across chunks, CRLF, [DONE], comments, a final frame without blank line, size cap', () => {
  const d = new SseDecoder();
  const text = ': keepalive\nevent: x\ndata: {"a":1}\n\ndata: {"b":\ndata: 2}\r\n\r\ndata: [DONE]\n\ndata: {"c":3}';
  const all = [...d.push(Buffer.from(text.slice(0, 20))), ...d.push(Buffer.from(text.slice(20, 50))), ...d.push(text.slice(50)), ...d.flush()];
  assert.deepEqual(all, [{ a: 1 }, { b: 2 }, { c: 3 }]);
  assert.deepEqual(new SseDecoder().flush(), []);
  assert.throws(() => new SseDecoder().push('data: not-json\n\n'), /not valid JSON/);
  assert.throws(() => new SseDecoder().push(`data: {"x":"${'y'.repeat(1024 * 1024 + 16)}`), /size limit/);
});

test('serializeSse and errorSse produce Anthropic SSE frames', () => {
  const s = serializeSse([{ event: 'message_stop', data: { type: 'message_stop' } }]);
  assert.equal(s, 'event: message_stop\ndata: {"type":"message_stop"}\n\n');
  assert.equal(errorSse('bad'), 'event: error\ndata: {"type":"error","error":{"type":"api_error","message":"bad"}}\n\n');
});

test('accumulateMessage folds a stream into one Messages-API body', () => {
  const tool = accumulateMessage(run(TOOL_TURN).out);
  assert.equal(tool.type, 'message');
  assert.equal(tool.id, 'msg_1');
  assert.equal(tool.stop_reason, 'tool_use');
  assert.deepEqual(tool.content, [{ type: 'tool_use', id: 'call_1', name: 'get_weather', input: { city: 'Paris' } }]);
  assert.deepEqual(tool.usage, { input_tokens: 10, output_tokens: 6, cache_read_input_tokens: 0 });
  const text = accumulateMessage(run(TEXT_TURN).out);
  assert.deepEqual(text.content, [{ type: 'thinking', thinking: '', signature: 'ENC1' }, { type: 'text', text: 'Hi.' }]);
  assert.throws(() => accumulateMessage([]), /before message_start/);
});

test('estimateTokens is a deterministic bytes/4 estimate over what is sent', () => {
  assert.equal(estimateTokens({ instructions: 'abcd', input: [], tools: [] }), Math.ceil((4 + 2 + 2) / 4));
});
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `node --test test/codex-translate.test.js`
Expected: FAIL - `SseDecoder`/`CodexReducer` are not exported (SyntaxError on the named import).

- [ ] **Step 4: Write the implementation**

Append to `src/codex-translate.js` (add `import { StringDecoder } from 'node:string_decoder';` next to the other imports at the top):

```js
// ---------------------------------------------------------------------------
// Response side
// ---------------------------------------------------------------------------

export const MAX_SSE_FRAME_BYTES = 1024 * 1024;

// Incremental SSE decoder: bytes -> the parsed `data:` JSON of each complete
// frame. Frames end at a blank line (LF or CRLF); `[DONE]` and frames without
// data lines are skipped. Throws on non-JSON data or an oversized frame.
export class SseDecoder {
  #buf = '';
  #dec = new StringDecoder('utf8');

  push(chunk) {
    this.#buf += Buffer.isBuffer(chunk) ? this.#dec.write(chunk) : String(chunk);
    const out = [];
    for (;;) {
      const m = /\r?\n\r?\n/.exec(this.#buf);
      if (!m) break;
      const frame = this.#buf.slice(0, m.index);
      this.#buf = this.#buf.slice(m.index + m[0].length);
      const data = parseFrame(frame);
      if (data !== null) out.push(data);
    }
    if (this.#buf.length > MAX_SSE_FRAME_BYTES) throw new Error('SSE frame exceeds the size limit');
    return out;
  }

  // End of stream: a last frame may lack its trailing blank line.
  flush() {
    const rest = (this.#buf + this.#dec.end()).trim();
    this.#buf = '';
    if (!rest) return [];
    const data = parseFrame(rest);
    return data === null ? [] : [data];
  }
}

function parseFrame(frame) {
  const lines = frame
    .split(/\r?\n/)
    .filter((l) => l.startsWith('data:'))
    .map((l) => l.slice(5).replace(/^ /, ''));
  if (lines.length === 0) return null;
  const text = lines.join('\n');
  if (text === '[DONE]') return null;
  try {
    return JSON.parse(text);
  } catch {
    throw new Error('SSE data is not valid JSON');
  }
}

function num(v) {
  return Number.isFinite(v) ? v : 0;
}

// Responses stream events -> Anthropic SSE event objects ({ event, data }).
// One instance per response. STRICT: a delta for a block that is not open, a
// delta of the wrong kind, or a second response.created throws - the caller
// aborts the stream with an error event instead of inventing content.
// Block indexes are assigned sequentially per message, as Anthropic does;
// items the client cannot represent (web_search_call...) consume no index.
export class CodexReducer {
  #messageId;
  #model;
  #started = false;
  #done = false;
  #nextIndex = 0;
  #open = new Map(); // output_index -> { index, kind, parts, argsSeen }
  #sawToolCall = false;

  constructor({ messageId, model }) {
    this.#messageId = messageId;
    this.#model = model;
  }

  get done() {
    return this.#done;
  }

  push(ev) {
    if (!ev || typeof ev.type !== 'string') throw new Error('stream event has no type');
    if (this.#done) return [];
    switch (ev.type) {
      case 'response.created':
        if (this.#started) throw new Error('duplicate response.created');
        this.#started = true;
        return [
          {
            event: 'message_start',
            data: {
              type: 'message_start',
              message: { id: this.#messageId, type: 'message', role: 'assistant', model: this.#model, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } },
            },
          },
        ];
      case 'response.output_item.added':
        return this.#itemAdded(ev);
      case 'response.reasoning_summary_part.added':
        return this.#summaryPart(ev);
      case 'response.reasoning_summary_text.delta':
      case 'response.reasoning_text.delta':
        return this.#delta(ev, 'thinking', 'thinking_delta', 'thinking');
      case 'response.output_text.delta':
      case 'response.refusal.delta':
        return this.#delta(ev, 'text', 'text_delta', 'text');
      case 'response.function_call_arguments.delta':
        return this.#delta(ev, 'tool_use', 'input_json_delta', 'partial_json');
      case 'response.output_item.done':
        return this.#itemDone(ev);
      case 'response.completed':
        return this.#finish(ev, false);
      case 'response.incomplete':
        return this.#finish(ev, true);
      case 'response.failed':
        throw new Error(ev.response?.error?.message ?? 'upstream response failed');
      case 'error':
        throw new Error(ev.message ?? ev.error?.message ?? 'upstream error');
      default:
        return []; // in_progress, queued, content_part.*, *.done, unknown
    }
  }

  #requireStarted() {
    if (!this.#started) throw new Error('stream event before response.created');
  }

  #itemAdded(ev) {
    this.#requireStarted();
    const item = ev.item;
    const key = ev.output_index;
    if (!item || typeof item.type !== 'string' || typeof key !== 'number') throw new Error('output_item.added is malformed');
    if (this.#open.has(key)) throw new Error('output item added twice');
    let kind = 'ignored';
    let start = null;
    if (item.type === 'reasoning') {
      kind = 'thinking';
      start = { type: 'thinking', thinking: '', signature: '' };
    } else if (item.type === 'message') {
      kind = 'text';
      start = { type: 'text', text: '' };
    } else if (item.type === 'function_call') {
      if (typeof item.call_id !== 'string' || typeof item.name !== 'string') throw new Error('function_call item is malformed');
      kind = 'tool_use';
      this.#sawToolCall = true;
      start = { type: 'tool_use', id: item.call_id, name: item.name, input: {} };
    }
    if (!start) {
      this.#open.set(key, { index: -1, kind, parts: 0, argsSeen: false });
      return [];
    }
    const index = this.#nextIndex;
    this.#nextIndex += 1;
    this.#open.set(key, { index, kind, parts: 0, argsSeen: false });
    return [{ event: 'content_block_start', data: { type: 'content_block_start', index, content_block: start } }];
  }

  #block(ev, kind) {
    this.#requireStarted();
    const b = this.#open.get(ev.output_index);
    if (!b) throw new Error(`${ev.type} for a block that is not open`);
    if (b.kind === 'ignored') return null;
    if (b.kind !== kind) throw new Error(`${ev.type} for a ${b.kind} block`);
    return b;
  }

  #summaryPart(ev) {
    const b = this.#block(ev, 'thinking');
    if (!b) return [];
    b.parts += 1;
    if (b.parts === 1) return [];
    return [{ event: 'content_block_delta', data: { type: 'content_block_delta', index: b.index, delta: { type: 'thinking_delta', thinking: '\n\n' } } }];
  }

  #delta(ev, kind, deltaType, field) {
    const b = this.#block(ev, kind);
    if (!b) return [];
    if (typeof ev.delta !== 'string') throw new Error(`${ev.type} has no delta`);
    if (kind === 'tool_use') b.argsSeen = true;
    if (kind === 'thinking') b.parts = Math.max(b.parts, 1);
    return [{ event: 'content_block_delta', data: { type: 'content_block_delta', index: b.index, delta: { type: deltaType, [field]: ev.delta } } }];
  }

  #itemDone(ev) {
    this.#requireStarted();
    const b = this.#open.get(ev.output_index);
    if (!b) throw new Error('output_item.done for a block that is not open');
    this.#open.delete(ev.output_index);
    if (b.kind === 'ignored') return [];
    const item = ev.item ?? {};
    const out = [];
    const delta = (d) => out.push({ event: 'content_block_delta', data: { type: 'content_block_delta', index: b.index, delta: d } });
    if (b.kind === 'thinking') {
      if (b.parts === 0 && Array.isArray(item.summary)) {
        const text = item.summary.filter((s) => s && typeof s.text === 'string').map((s) => s.text).join('\n\n');
        if (text) delta({ type: 'thinking_delta', thinking: text });
      }
      // The encrypted reasoning rides in the signature so the client sends it
      // back verbatim next turn and the translator replays it (Task 1).
      delta({ type: 'signature_delta', signature: typeof item.encrypted_content === 'string' ? item.encrypted_content : '' });
    } else if (b.kind === 'tool_use' && !b.argsSeen && typeof item.arguments === 'string' && item.arguments) {
      delta({ type: 'input_json_delta', partial_json: item.arguments });
    }
    out.push({ event: 'content_block_stop', data: { type: 'content_block_stop', index: b.index } });
    return out;
  }

  #finish(ev, incomplete) {
    this.#requireStarted();
    const out = [];
    // Defensive: close blocks the upstream never finished.
    for (const [key, b] of [...this.#open.entries()]) {
      this.#open.delete(key);
      if (b.kind === 'ignored') continue;
      if (b.kind === 'thinking') {
        out.push({ event: 'content_block_delta', data: { type: 'content_block_delta', index: b.index, delta: { type: 'signature_delta', signature: '' } } });
      }
      out.push({ event: 'content_block_stop', data: { type: 'content_block_stop', index: b.index } });
    }
    const u = ev.response?.usage ?? {};
    const usage = { input_tokens: num(u.input_tokens), output_tokens: num(u.output_tokens), cache_read_input_tokens: num(u.input_tokens_details?.cached_tokens) };
    const stop_reason = incomplete ? 'max_tokens' : this.#sawToolCall ? 'tool_use' : 'end_turn';
    out.push({ event: 'message_delta', data: { type: 'message_delta', delta: { stop_reason, stop_sequence: null }, usage } });
    out.push({ event: 'message_stop', data: { type: 'message_stop' } });
    this.#done = true;
    return out;
  }
}

export function serializeSse(events) {
  let s = '';
  for (const e of events) s += `event: ${e.event}\ndata: ${JSON.stringify(e.data)}\n\n`;
  return s;
}

export function errorSse(message) {
  return `event: error\ndata: ${JSON.stringify({ type: 'error', error: { type: 'api_error', message } })}\n\n`;
}

// Fold Anthropic SSE event objects into one Messages-API body (stream:false).
export function accumulateMessage(events) {
  let message = null;
  const blocks = [];
  for (const { data } of events) {
    switch (data.type) {
      case 'message_start':
        message = { ...data.message, content: [] };
        break;
      case 'content_block_start':
        blocks[data.index] = { ...data.content_block };
        if (blocks[data.index].type === 'tool_use') blocks[data.index]._json = '';
        break;
      case 'content_block_delta': {
        const b = blocks[data.index];
        if (!b) throw new Error('delta for an unknown block');
        const d = data.delta;
        if (d.type === 'text_delta') b.text += d.text;
        else if (d.type === 'thinking_delta') b.thinking += d.thinking;
        else if (d.type === 'signature_delta') b.signature = d.signature;
        else if (d.type === 'input_json_delta') b._json += d.partial_json;
        break;
      }
      case 'message_delta':
        if (message) {
          message.stop_reason = data.delta.stop_reason;
          message.stop_sequence = data.delta.stop_sequence ?? null;
          message.usage = { ...message.usage, ...data.usage };
        }
        break;
      default:
        break;
    }
  }
  if (!message) throw new Error('stream ended before message_start');
  message.content = blocks.filter(Boolean).map((b) => {
    if (b.type !== 'tool_use') return b;
    const { _json, ...rest } = b;
    let input = {};
    if (_json) {
      try {
        input = JSON.parse(_json);
      } catch {
        throw new Error('tool_use arguments are not valid JSON');
      }
    }
    return { ...rest, input };
  });
  return message;
}

// Local, deterministic estimate for /v1/messages/count_tokens (the backend
// has no such endpoint and nothing may leave the machine for it).
export function estimateTokens(translated) {
  const text = String(translated.instructions ?? '') + JSON.stringify(translated.input ?? []) + JSON.stringify(translated.tools ?? []);
  return Math.ceil(Buffer.byteLength(text, 'utf8') / 4);
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `node --test test/codex-translate.test.js`
Expected: PASS (22 tests). Then `npm test` green.

- [ ] **Step 6: Commit**

```bash
git add src/codex-translate.js test/codex-translate.test.js test/helpers/codex-fixtures.js
git commit -F - <<'EOF'
feat(codex): translate Responses SSE back to Anthropic SSE

Incremental SSE decoder plus a strict reducer: reasoning items become
thinking blocks whose signature carries encrypted_content, messages become
text blocks, function calls become tool_use blocks with input_json deltas,
completed/incomplete become message_delta (tool_use | end_turn | max_tokens)
with usage. Out-of-order or failed streams throw. Accumulator for
stream:false clients and a local token estimate.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B5pssw9PR5KXtxnP2w9u3
EOF
```

---

### Task 3: OAuth helpers and the backend wire contract (`codex-auth.js`)

**Files:**
- Create: `src/codex-auth.js`
- Modify: `test/helpers/codex-fixtures.js` (append fake JWT helpers)
- Test: `test/codex-auth.test.js`

**Interfaces:**
- Consumes: nothing from the project.
- Produces: constants `CODEX_OAUTH_ISSUER`, `CODEX_CLIENT_ID`, `CODEX_REDIRECT_PORT`, `CODEX_REDIRECT_URI`, `CODEX_SCOPE`, `CODEX_DEFAULT_BASE_URL`, `CODEX_ORIGINATOR`, `CODEX_CLIENT_VERSION`, `CODEX_HOST`, `REFRESH_SKEW_MS`; `createPkce() -> { verifier, challenge, state }`; `buildAuthorizeUrl({ state, challenge, issuer? }) -> string`; `httpRequest(url, { method, headers, body, timeoutMs }) -> Promise<{ status, body }>` (the injectable transport, every other function takes `request = httpRequest`); `exchangeCode({ code, verifier, issuer?, request? }) -> Promise<{ access, refresh, idToken }>` (throws); `refreshTokens({ refreshToken, issuer?, request? }) -> Promise<{ access, refresh, idToken } | null>`; `decodeJwtClaims(token) -> object|null`; `accountFromTokens({ access, idToken }) -> { accountId, email, plan, expiresAt }`; `tokensFresh(tokens, nowMs) -> boolean`; `isCodexHost(url)`, `isLoopbackHost(url)`; `codexRequestHeaders({ access, accountId, sessionId, clientVersion? }) -> object`; `fetchCodexModels({ baseUrl?, access, accountId, clientVersion?, request? }) -> Promise<Model[] | null>`; `normalizeCodexModels(body) -> Model[] | null` with `Model = { slug, displayName, visibility, defaultLevel, levels }`. Fixtures: `fakeJwt(claims)`, `fakeAccessToken({ accountId, plan, expSec })`, `fakeIdToken({ email })`.

- [ ] **Step 1: Add the JWT fixtures**

Append to `test/helpers/codex-fixtures.js`:

```js
// Unsigned JWT-shaped tokens carrying the claims the real ones carry. Only
// the payload is read by the code under test.
const b64url = (s) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export function fakeJwt(claims) {
  return `${b64url('{"alg":"none","typ":"JWT"}')}.${b64url(JSON.stringify(claims))}.sig`;
}
// expSec 4102444800 = 2100-01-01T00:00:00Z
export function fakeAccessToken({ accountId = 'acc-1', plan = 'plus', expSec = 4102444800 } = {}) {
  return fakeJwt({ exp: expSec, 'https://api.openai.com/auth': { chatgpt_account_id: accountId, chatgpt_plan_type: plan } });
}
export function fakeIdToken({ email = 'me@example.com' } = {}) {
  return fakeJwt({ 'https://api.openai.com/profile': { email } });
}
```

- [ ] **Step 2: Write the failing tests**

Create `test/codex-auth.test.js`:

```js
// OAuth helpers for the ChatGPT Codex backend: PKCE, authorize URL, code
// exchange, refresh, claim parsing, host guard, request headers, model list.
// Every network call is injected; no test touches the network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  createPkce,
  buildAuthorizeUrl,
  exchangeCode,
  refreshTokens,
  decodeJwtClaims,
  accountFromTokens,
  tokensFresh,
  isCodexHost,
  isLoopbackHost,
  codexRequestHeaders,
  fetchCodexModels,
  normalizeCodexModels,
  CODEX_CLIENT_ID,
  CODEX_REDIRECT_URI,
  CODEX_DEFAULT_BASE_URL,
  REFRESH_SKEW_MS,
} from '../src/codex-auth.js';
import { fakeJwt, fakeAccessToken, fakeIdToken } from './helpers/codex-fixtures.js';

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

test('PKCE: S256 challenge of the verifier, fresh state each time', () => {
  const a = createPkce();
  const b = createPkce();
  assert.equal(a.challenge, b64url(createHash('sha256').update(a.verifier).digest()));
  assert.ok(a.verifier.length >= 43 && /^[A-Za-z0-9_-]+$/.test(a.verifier));
  assert.notEqual(a.state, b.state);
  assert.notEqual(a.verifier, b.verifier);
});

test('authorize URL carries the Codex client id, fixed redirect, scope, PKCE and state', () => {
  const u = new URL(buildAuthorizeUrl({ state: 'st', challenge: 'ch' }));
  assert.equal(`${u.origin}${u.pathname}`, 'https://auth.openai.com/oauth/authorize');
  const p = u.searchParams;
  assert.equal(p.get('response_type'), 'code');
  assert.equal(p.get('client_id'), CODEX_CLIENT_ID);
  assert.equal(p.get('redirect_uri'), CODEX_REDIRECT_URI);
  assert.equal(CODEX_REDIRECT_URI, 'http://localhost:1455/auth/callback');
  assert.equal(p.get('scope'), 'openid profile email offline_access');
  assert.equal(p.get('code_challenge'), 'ch');
  assert.equal(p.get('code_challenge_method'), 'S256');
  assert.equal(p.get('state'), 'st');
  assert.equal(p.get('id_token_add_organizations'), 'true');
  assert.equal(p.get('codex_cli_simplified_flow'), 'true');
  assert.equal(p.get('originator'), 'codex_cli_rs');
});

test('exchangeCode posts the form grant and parses tokens; failures throw without the code in the message', async () => {
  const calls = [];
  const request = async (url, opts) => {
    calls.push({ url, opts });
    return { status: 200, body: JSON.stringify({ access_token: 'A', refresh_token: 'R', id_token: 'I' }) };
  };
  const t = await exchangeCode({ code: 'c0de', verifier: 'v', request });
  assert.deepEqual(t, { access: 'A', refresh: 'R', idToken: 'I' });
  assert.equal(calls[0].url, 'https://auth.openai.com/oauth/token');
  assert.equal(calls[0].opts.method, 'POST');
  assert.equal(calls[0].opts.headers['content-type'], 'application/x-www-form-urlencoded');
  const form = new URLSearchParams(calls[0].opts.body);
  assert.equal(form.get('grant_type'), 'authorization_code');
  assert.equal(form.get('code'), 'c0de');
  assert.equal(form.get('code_verifier'), 'v');
  assert.equal(form.get('client_id'), CODEX_CLIENT_ID);
  assert.equal(form.get('redirect_uri'), CODEX_REDIRECT_URI);
  await assert.rejects(exchangeCode({ code: 'c0de', verifier: 'v', request: async () => ({ status: 400, body: '{}' }) }), (e) => /HTTP 400/.test(e.message) && !e.message.includes('c0de'));
  await assert.rejects(exchangeCode({ code: 'c0de', verifier: 'v', request: async () => ({ status: 200, body: '{"nope":1}' }) }), /no access token/);
});

test('refreshTokens: JSON grant, keeps the old refresh token when none is rotated, form fallback on 400, null on failure', async () => {
  const calls = [];
  const ok = async (url, opts) => {
    calls.push(opts);
    return { status: 200, body: JSON.stringify({ access_token: 'A2', id_token: 'I2' }) };
  };
  assert.deepEqual(await refreshTokens({ refreshToken: 'R1', request: ok }), { access: 'A2', refresh: 'R1', idToken: 'I2' });
  assert.equal(calls[0].headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(calls[0].body), { client_id: CODEX_CLIENT_ID, grant_type: 'refresh_token', refresh_token: 'R1', scope: 'openid profile email' });

  const fallback = [];
  const rejectsJson = async (url, opts) => {
    fallback.push(opts.headers['content-type']);
    if (opts.headers['content-type'] === 'application/json') return { status: 400, body: 'unsupported' };
    return { status: 200, body: JSON.stringify({ access_token: 'A3', refresh_token: 'R3' }) };
  };
  assert.deepEqual(await refreshTokens({ refreshToken: 'R1', request: rejectsJson }), { access: 'A3', refresh: 'R3', idToken: '' });
  assert.deepEqual(fallback, ['application/json', 'application/x-www-form-urlencoded']);

  assert.equal(await refreshTokens({ refreshToken: 'R1', request: async () => ({ status: 401, body: '{}' }) }), null);
  assert.equal(await refreshTokens({ refreshToken: 'R1', request: async () => { throw new Error('net'); } }), null);
  assert.equal(await refreshTokens({ refreshToken: '', request: ok }), null);
});

test('accountFromTokens reads account id, plan, email and expiry from the claims', () => {
  const access = fakeAccessToken({ accountId: 'acc-9', plan: 'pro', expSec: 1800000000 });
  const idToken = fakeIdToken({ email: 'me@example.com' });
  assert.deepEqual(accountFromTokens({ access, idToken }), { accountId: 'acc-9', email: 'me@example.com', plan: 'pro', expiresAt: 1800000000000 });
  assert.deepEqual(accountFromTokens({ access: 'garbage', idToken: '' }), { accountId: null, email: null, plan: null, expiresAt: null });
  assert.equal(decodeJwtClaims('garbage'), null);
  assert.deepEqual(decodeJwtClaims(fakeJwt({ a: 1 })), { a: 1 });
});

test('tokensFresh applies the 5 minute skew and trusts an unknown expiry', () => {
  const now = 1_000_000_000_000;
  assert.equal(tokensFresh({ access: 'A', expiresAt: now + REFRESH_SKEW_MS + 1 }, now), true);
  assert.equal(tokensFresh({ access: 'A', expiresAt: now + REFRESH_SKEW_MS - 1 }, now), false);
  assert.equal(tokensFresh({ access: 'A', expiresAt: null }, now), true);
  assert.equal(tokensFresh({ access: '', expiresAt: null }, now), false);
  assert.equal(tokensFresh(null, now), false);
});

test('host guard: chatgpt.com and its subdomains, loopback for tests, nothing else', () => {
  assert.equal(isCodexHost(new URL('https://chatgpt.com/backend-api/codex')), true);
  assert.equal(isCodexHost(new URL('https://api.chatgpt.com/x')), true);
  assert.equal(isCodexHost(new URL('https://chatgpt.com.evil.example/')), false);
  assert.equal(isCodexHost(new URL('https://api.openai.com/')), false);
  assert.equal(isLoopbackHost(new URL('http://127.0.0.1:1234')), true);
  assert.equal(isLoopbackHost(new URL('http://localhost:1234')), true);
  assert.equal(isLoopbackHost(new URL('https://chatgpt.com')), false);
  assert.equal(CODEX_DEFAULT_BASE_URL, 'https://chatgpt.com/backend-api/codex');
});

test('request headers carry the exact backend contract', () => {
  const h = codexRequestHeaders({ access: 'TOK', accountId: 'acc-1', sessionId: 'sess', clientVersion: '0.145.0' });
  assert.equal(h.authorization, 'Bearer TOK');
  assert.equal(h['chatgpt-account-id'], 'acc-1');
  assert.equal(h['openai-beta'], 'responses=experimental');
  assert.equal(h.originator, 'codex_cli_rs');
  assert.match(h['user-agent'], /^codex_cli_rs\/0\.145\.0 \(.+; .+\) unknown$/);
  assert.equal(h.accept, 'text/event-stream');
  assert.equal(h['content-type'], 'application/json');
  assert.equal(h.session_id, 'sess');
});

test('fetchCodexModels normalizes the backend list; any failure yields null', async () => {
  const body = {
    models: [
      { slug: 'gpt-5.5', display_name: 'GPT-5.5', visibility: 'list', default_reasoning_level: 'medium', supported_reasoning_levels: [{ effort: 'low' }, { effort: 'medium' }] },
      { slug: 'gpt-reserve', visibility: 'hide', supported_reasoning_levels: ['low'] },
      { nope: true },
    ],
  };
  const calls = [];
  const request = async (url, opts) => {
    calls.push({ url, opts });
    return { status: 200, body: JSON.stringify(body) };
  };
  const models = await fetchCodexModels({ access: 'TOK', accountId: 'acc-1', request });
  assert.deepEqual(models, [
    { slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium'] },
    { slug: 'gpt-reserve', displayName: 'gpt-reserve', visibility: 'hide', defaultLevel: null, levels: ['low'] },
  ]);
  assert.equal(calls[0].url, 'https://chatgpt.com/backend-api/codex/models?client_version=0.145.0');
  assert.equal(calls[0].opts.method, 'GET');
  assert.equal(calls[0].opts.headers.authorization, 'Bearer TOK');
  assert.equal(calls[0].opts.headers['chatgpt-account-id'], 'acc-1');
  assert.equal(calls[0].opts.headers.accept, 'application/json');
  assert.equal(await fetchCodexModels({ access: 'TOK', accountId: 'acc-1', request: async () => ({ status: 500, body: '' }) }), null);
  assert.equal(await fetchCodexModels({ access: 'TOK', accountId: 'acc-1', request: async () => { throw new Error('net'); } }), null);
  assert.equal(normalizeCodexModels('not json'), null);
  assert.equal(normalizeCodexModels({ data: [] }), null);
});
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `node --test test/codex-auth.test.js`
Expected: FAIL - `Cannot find module '.../src/codex-auth.js'`.

- [ ] **Step 4: Write the implementation**

Create `src/codex-auth.js`:

```js
// OAuth + wire contract for the ChatGPT Codex backend. The user logs in from
// the dashboard with the same PKCE flow, client id and fixed redirect the
// Codex CLI uses; the resulting tokens live in providers.json (chmod 600) and
// are ONLY ever sent to chatgpt.com (or a loopback test upstream - enforced
// in runtime + the upstream handler). Tokens are never logged; no error
// message built here ever contains one.
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import { createHash, randomBytes } from 'node:crypto';

export const CODEX_OAUTH_ISSUER = 'https://auth.openai.com';
export const CODEX_CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';
export const CODEX_REDIRECT_PORT = 1455;
export const CODEX_REDIRECT_URI = `http://localhost:${CODEX_REDIRECT_PORT}/auth/callback`;
export const CODEX_SCOPE = 'openid profile email offline_access';
export const CODEX_DEFAULT_BASE_URL = 'https://chatgpt.com/backend-api/codex';
export const CODEX_HOST = 'chatgpt.com';
export const CODEX_ORIGINATOR = 'codex_cli_rs';
// Version the backend currently accepts; override with CODEX_CLIENT_VERSION.
export const CODEX_CLIENT_VERSION = process.env.CODEX_CLIENT_VERSION || '0.145.0';
export const REFRESH_SKEW_MS = 5 * 60 * 1000;

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export function createPkce() {
  const verifier = b64url(randomBytes(64));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  const state = b64url(randomBytes(32));
  return { verifier, challenge, state };
}

export function buildAuthorizeUrl({ state, challenge, issuer = CODEX_OAUTH_ISSUER }) {
  const u = new URL('/oauth/authorize', issuer);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', CODEX_CLIENT_ID);
  u.searchParams.set('redirect_uri', CODEX_REDIRECT_URI);
  u.searchParams.set('scope', CODEX_SCOPE);
  u.searchParams.set('code_challenge', challenge);
  u.searchParams.set('code_challenge_method', 'S256');
  u.searchParams.set('id_token_add_organizations', 'true');
  u.searchParams.set('codex_cli_simplified_flow', 'true');
  u.searchParams.set('state', state);
  u.searchParams.set('originator', CODEX_ORIGINATOR);
  return u.toString();
}

// Minimal transport: resolves { status, body }. Every caller takes it as an
// injectable `request` so tests never touch the network.
export function httpRequest(url, { method = 'GET', headers = {}, body = null, timeoutMs = 20_000 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const transport = u.protocol === 'https:' ? https : http;
    const data = body === null || body === undefined ? null : Buffer.from(body);
    const h = { accept: 'application/json', ...headers };
    if (data) h['content-length'] = String(data.length);
    const req = transport.request(
      {
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: `${u.pathname}${u.search}`,
        method,
        headers: h,
        timeout: timeoutMs,
      },
      (res) => {
        let acc = '';
        res.setEncoding('utf8');
        res.on('data', (c) => {
          acc += c;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: acc }));
        res.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    req.end(data ?? undefined);
  });
}

function parseTokens(body) {
  let j;
  try {
    j = JSON.parse(body);
  } catch {
    return null;
  }
  if (!j || typeof j.access_token !== 'string' || !j.access_token) return null;
  return {
    access: j.access_token,
    refresh: typeof j.refresh_token === 'string' ? j.refresh_token : '',
    idToken: typeof j.id_token === 'string' ? j.id_token : '',
  };
}

// Authorization code -> tokens (form-encoded, as the Codex CLI does).
export async function exchangeCode({ code, verifier, issuer = CODEX_OAUTH_ISSUER, request = httpRequest }) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: CODEX_REDIRECT_URI,
    client_id: CODEX_CLIENT_ID,
    code_verifier: verifier,
  }).toString();
  const res = await request(`${issuer}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (res.status !== 200) throw new Error(`token exchange failed (HTTP ${res.status})`);
  const tokens = parseTokens(res.body);
  if (!tokens) throw new Error('token exchange returned no access token');
  return tokens;
}

// refresh_token grant. JSON body first (the Codex CLI's form); a 4xx other
// than 401/403 is retried form-encoded in case the endpoint wants that.
// Returns null when no token can be obtained - the fix is logging in again
// from the dashboard. The old refresh token is kept when none is rotated.
export async function refreshTokens({ refreshToken, issuer = CODEX_OAUTH_ISSUER, request = httpRequest }) {
  if (!refreshToken) return null;
  const url = `${issuer}/oauth/token`;
  const params = { client_id: CODEX_CLIENT_ID, grant_type: 'refresh_token', refresh_token: refreshToken, scope: 'openid profile email' };
  let res;
  try {
    res = await request(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(params) });
    if (res.status >= 400 && res.status < 500 && res.status !== 401 && res.status !== 403) {
      res = await request(url, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(params).toString(),
      });
    }
  } catch {
    return null;
  }
  if (!res || res.status !== 200) return null;
  const tokens = parseTokens(res.body);
  if (!tokens) return null;
  return { ...tokens, refresh: tokens.refresh || refreshToken };
}

export function decodeJwtClaims(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const json = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const claims = JSON.parse(json);
    return claims && typeof claims === 'object' ? claims : null;
  } catch {
    return null;
  }
}

const AUTH_CLAIM = 'https://api.openai.com/auth';
const PROFILE_CLAIM = 'https://api.openai.com/profile';

// Account identity + expiry from the token claims. accountId is REQUIRED by
// the backend (chatgpt-account-id header); expiresAt drives the refresh.
export function accountFromTokens({ access, idToken }) {
  const a = decodeJwtClaims(access) ?? {};
  const i = decodeJwtClaims(idToken) ?? {};
  const auth = (a[AUTH_CLAIM] && typeof a[AUTH_CLAIM] === 'object' ? a[AUTH_CLAIM] : i[AUTH_CLAIM]) ?? {};
  const profile = (i[PROFILE_CLAIM] && typeof i[PROFILE_CLAIM] === 'object' ? i[PROFILE_CLAIM] : a[PROFILE_CLAIM]) ?? {};
  return {
    accountId: typeof auth.chatgpt_account_id === 'string' ? auth.chatgpt_account_id : null,
    email: typeof profile.email === 'string' ? profile.email : typeof i.email === 'string' ? i.email : null,
    plan: typeof auth.chatgpt_plan_type === 'string' ? auth.chatgpt_plan_type : null,
    expiresAt: Number.isFinite(a.exp) ? a.exp * 1000 : null,
  };
}

export function tokensFresh(tokens, nowMs = Date.now()) {
  if (!tokens || !tokens.access) return false;
  // Unknown expiry: trust the token until the backend answers 401.
  if (!Number.isFinite(tokens.expiresAt)) return true;
  return tokens.expiresAt - REFRESH_SKEW_MS > nowMs;
}

export function isCodexHost(url) {
  const host = url?.hostname ?? '';
  return host === CODEX_HOST || host.endsWith(`.${CODEX_HOST}`);
}

// A process on the user's own machine is inside the trust boundary (it is
// how the test suite proves the canary round-trip).
export function isLoopbackHost(url) {
  const host = url?.hostname ?? '';
  return host === '127.0.0.1' || host === 'localhost' || host === '[::1]' || host === '::1';
}

// The exact header contract of the Codex backend. Built clean-room: the
// caller's own headers are NOT forwarded on this path.
export function codexRequestHeaders({ access, accountId, sessionId, clientVersion = CODEX_CLIENT_VERSION }) {
  const platform = process.platform === 'darwin' ? 'Mac OS' : process.platform;
  return {
    authorization: `Bearer ${access}`,
    'chatgpt-account-id': accountId,
    'openai-beta': 'responses=experimental',
    originator: CODEX_ORIGINATOR,
    'user-agent': `${CODEX_ORIGINATOR}/${clientVersion} (${platform} ${os.release()}; ${process.arch}) unknown`,
    accept: 'text/event-stream',
    'content-type': 'application/json',
    session_id: sessionId,
  };
}

// GET <base>/models?client_version=... -> normalized list, or null on any
// failure (callers fall back to the static list). Never throws.
export async function fetchCodexModels({ baseUrl = CODEX_DEFAULT_BASE_URL, access, accountId, clientVersion = CODEX_CLIENT_VERSION, request = httpRequest }) {
  const url = `${String(baseUrl).replace(/\/$/, '')}/models?client_version=${encodeURIComponent(clientVersion)}`;
  let res;
  try {
    const headers = codexRequestHeaders({ access, accountId, sessionId: 'models', clientVersion });
    headers.accept = 'application/json';
    delete headers['content-type'];
    res = await request(url, { method: 'GET', headers });
  } catch {
    return null;
  }
  if (!res || res.status !== 200) return null;
  return normalizeCodexModels(res.body);
}

export function normalizeCodexModels(body) {
  let j;
  try {
    j = typeof body === 'string' ? JSON.parse(body) : body;
  } catch {
    return null;
  }
  if (!j || !Array.isArray(j.models)) return null;
  const out = [];
  for (const m of j.models) {
    if (!m || typeof m.slug !== 'string' || !m.slug) continue;
    const raw = Array.isArray(m.supported_reasoning_levels) ? m.supported_reasoning_levels : [];
    const levels = raw.map((l) => (typeof l === 'string' ? l : l?.effort)).filter((l) => typeof l === 'string');
    out.push({
      slug: m.slug,
      displayName: typeof m.display_name === 'string' ? m.display_name : m.slug,
      visibility: m.visibility === 'hide' ? 'hide' : 'list',
      defaultLevel: typeof m.default_reasoning_level === 'string' ? m.default_reasoning_level : null,
      levels,
    });
  }
  return out;
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `node --test test/codex-auth.test.js`
Expected: PASS (9 tests). Then `npm test` green.

- [ ] **Step 6: Commit**

```bash
git add src/codex-auth.js test/codex-auth.test.js test/helpers/codex-fixtures.js
git commit -F - <<'EOF'
feat(codex): OAuth helpers and backend wire contract

PKCE + authorize URL (Codex client id, fixed localhost:1455 redirect), code
exchange, refresh with form fallback, JWT claim parsing (account id, plan,
email, expiry), host guard (chatgpt.com or loopback only), backend request
headers, model-list fetch. All network calls injectable; no token ever ends
up in an error message.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B5pssw9PR5KXtxnP2w9u3
EOF
```

---

### Task 4: Provider registry: `codex-oauth` records

**Files:**
- Modify: `src/providers.js` (`AUTH`, `normalizeProvider`, `upsertProvider`, `publicRegistry`; add `setCodexAuth`, `clearCodexAuth`)
- Modify: `test/providers.test.js` (append)

**Interfaces:**
- Consumes: `CODEX_DEFAULT_BASE_URL` from `src/codex-auth.js`, `DEFAULT_EFFORT_MAP` from `src/codex-translate.js`.
- Produces: provider records gain `effortMap: { low, medium, high, max } | null` and `codex: { tokens: { access, refresh, idToken, accountId, expiresAt } | null, account: { email, plan }, models: Model[] | null, fetchedAt: number | null } | null` (both non-null only for `auth === 'codex-oauth'`); `setCodexAuth(reg, id, { tokens?, account?, models?, fetchedAt? })` (merges over the stored record, throws on unknown/non-codex provider); `clearCodexAuth(reg, id)`; `publicRegistry()` entries gain `effortMap` and `codex: { loggedIn, email, plan, expiresAt, models: string[] } | null` - never a token.

- [ ] **Step 1: Write the failing tests**

Append to `test/providers.test.js` (add `setCodexAuth, clearCodexAuth` to the existing import list from `../src/providers.js`):

```js
import { fakeAccessToken, fakeIdToken } from './helpers/codex-fixtures.js';

const LOGIN = {
  tokens: { access: fakeAccessToken({ accountId: 'acc-1' }), refresh: 'R', idToken: fakeIdToken(), accountId: 'acc-1', expiresAt: 4102444800000 },
  account: { email: 'me@example.com', plan: 'plus' },
  models: [{ slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium'] }, { slug: 'gpt-reserve', visibility: 'hide', levels: [] }],
  fetchedAt: 1234,
};

test('codex-oauth provider: default url, effort map, sanitized login record', () => {
  const p = normalizeProvider({ auth: 'codex-oauth' });
  assert.equal(p.url, 'https://chatgpt.com/backend-api/codex');
  assert.deepEqual(p.effortMap, { low: 'low', medium: 'medium', high: 'xhigh', max: 'max' });
  assert.equal(p.codex, null);
  assert.equal(p.key, null);

  const q = normalizeProvider({ auth: 'codex-oauth', url: 'http://127.0.0.1:9', effortMap: { high: 'max', bogus: 'x', low: 7 }, codex: { ...LOGIN, extra: true, tokens: { ...LOGIN.tokens, junk: 1 } } });
  assert.equal(q.url, 'http://127.0.0.1:9');
  assert.deepEqual(q.effortMap, { low: 'low', medium: 'medium', high: 'max', max: 'max' });
  assert.deepEqual(Object.keys(q.codex).sort(), ['account', 'fetchedAt', 'models', 'tokens']);
  assert.deepEqual(Object.keys(q.codex.tokens).sort(), ['access', 'accountId', 'expiresAt', 'idToken', 'refresh']);
  assert.equal(q.codex.models.length, 2);
  assert.equal(q.codex.models[1].displayName, 'gpt-reserve');

  // other auth modes carry neither field
  const r = normalizeProvider({ auth: 'replace', key: 'k', url: 'https://x.y', codex: LOGIN, effortMap: { high: 'max' } });
  assert.equal(r.codex, null);
  assert.equal(r.effortMap, null);
});

test('upsert keeps the stored login when the form omits it; setCodexAuth merges; clearCodexAuth wipes', () => {
  const reg = emptyRegistry();
  upsertProvider(reg, 'codex', { auth: 'codex-oauth' });
  setCodexAuth(reg, 'codex', LOGIN);
  assert.equal(reg.providers.codex.codex.tokens.accountId, 'acc-1');
  // the dashboard form re-saves without a codex field (and a blank url)
  upsertProvider(reg, 'codex', { label: 'Codex', auth: 'codex-oauth', url: '' });
  assert.equal(reg.providers.codex.codex.tokens.accountId, 'acc-1');
  assert.equal(reg.providers.codex.url, 'https://chatgpt.com/backend-api/codex');
  assert.equal(reg.providers.codex.effortMap.high, 'xhigh');
  // a token refresh only touches tokens
  setCodexAuth(reg, 'codex', { tokens: { ...LOGIN.tokens, access: 'A2' } });
  assert.equal(reg.providers.codex.codex.tokens.access, 'A2');
  assert.equal(reg.providers.codex.codex.account.email, 'me@example.com');
  assert.equal(reg.providers.codex.codex.models.length, 2);
  assert.throws(() => setCodexAuth(reg, 'nope', LOGIN), /unknown provider/);
  upsertProvider(reg, 'plain', { auth: 'replace', key: 'k', url: 'https://x.y' });
  assert.throws(() => setCodexAuth(reg, 'plain', LOGIN), /not codex-oauth/);
  clearCodexAuth(reg, 'codex');
  assert.equal(reg.providers.codex.codex, null);
});

test('public view exposes login state and model slugs, never a token; round-trips through the file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'prov-codex-'));
  const file = path.join(dir, 'providers.json');
  const reg = emptyRegistry();
  upsertProvider(reg, 'codex', { auth: 'codex-oauth' });
  setCodexAuth(reg, 'codex', LOGIN);
  const pub = publicRegistry(reg);
  const view = pub.providers[0];
  assert.deepEqual(view.codex, { loggedIn: true, email: 'me@example.com', plan: 'plus', expiresAt: 4102444800000, models: ['gpt-5.5'] });
  assert.deepEqual(view.effortMap, { low: 'low', medium: 'medium', high: 'xhigh', max: 'max' });
  const text = JSON.stringify(pub);
  assert.equal(text.includes(LOGIN.tokens.access), false);
  assert.equal(text.includes('"refresh"'), false);
  assert.equal(text.includes('"R"'), false);
  saveProviders(file, reg);
  const back = loadProviders(file);
  assert.equal(back.providers.codex.codex.tokens.refresh, 'R');
  assert.equal(back.providers.codex.codex.models[0].slug, 'gpt-5.5');
  assert.equal(publicRegistry(emptyRegistry()).providers.length, 0);
  const off = emptyRegistry();
  upsertProvider(off, 'codex', { auth: 'codex-oauth' });
  assert.deepEqual(publicRegistry(off).providers[0].codex, { loggedIn: false, email: null, plan: null, expiresAt: null, models: [] });
  fs.rmSync(dir, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test test/providers.test.js`
Expected: FAIL - `setCodexAuth` is not exported / `auth must be one of passthrough|replace|oauth`.

- [ ] **Step 3: Write the implementation**

In `src/providers.js`:

Replace the imports and the `AUTH` line at the top with:

```js
import fs from 'node:fs';
import path from 'node:path';
import { CODEX_DEFAULT_BASE_URL } from './codex-auth.js';
import { DEFAULT_EFFORT_MAP } from './codex-translate.js';

const AUTH = ['passthrough', 'replace', 'oauth', 'codex-oauth'];
const EFFORT_KEYS = ['low', 'medium', 'high', 'max'];

// Claude effort -> Codex level. Every key present; unknown keys dropped.
function normalizeEffortMap(input) {
  const map = { ...DEFAULT_EFFORT_MAP };
  if (input && typeof input === 'object') {
    for (const k of EFFORT_KEYS) {
      if (typeof input[k] === 'string' && input[k].trim()) map[k] = input[k].trim();
    }
  }
  return map;
}

// The stored ChatGPT login: tokens + account + fetched models. A sanitized
// copy - unknown fields are dropped. null when not logged in.
function normalizeCodex(input) {
  if (!input || typeof input !== 'object') return null;
  const t = input.tokens && typeof input.tokens === 'object' ? input.tokens : null;
  const tokens =
    t && typeof t.access === 'string' && t.access
      ? {
          access: t.access,
          refresh: typeof t.refresh === 'string' ? t.refresh : '',
          idToken: typeof t.idToken === 'string' ? t.idToken : '',
          accountId: typeof t.accountId === 'string' ? t.accountId : null,
          expiresAt: Number.isFinite(t.expiresAt) ? t.expiresAt : null,
        }
      : null;
  const a = input.account && typeof input.account === 'object' ? input.account : {};
  const account = { email: typeof a.email === 'string' ? a.email : null, plan: typeof a.plan === 'string' ? a.plan : null };
  const models = Array.isArray(input.models)
    ? input.models
        .filter((m) => m && typeof m.slug === 'string' && m.slug)
        .map((m) => ({
          slug: m.slug,
          displayName: typeof m.displayName === 'string' ? m.displayName : m.slug,
          visibility: m.visibility === 'hide' ? 'hide' : 'list',
          defaultLevel: typeof m.defaultLevel === 'string' ? m.defaultLevel : null,
          levels: Array.isArray(m.levels) ? m.levels.filter((l) => typeof l === 'string') : [],
        }))
    : null;
  return { tokens, account, models, fetchedAt: Number.isFinite(input.fetchedAt) ? input.fetchedAt : null };
}
```

Replace the whole `normalizeProvider` function with:

```js
// Normalize + validate one provider record. Throws on invalid url/auth.
export function normalizeProvider(input = {}) {
  const p = {};
  p.label = typeof input.label === 'string' && input.label.trim() ? input.label.trim() : null;

  const auth = input.auth ?? 'replace';
  if (!AUTH.includes(auth)) throw new Error(`auth must be one of ${AUTH.join('|')}`);
  p.auth = auth;

  let url = typeof input.url === 'string' ? input.url.trim() : '';
  // A ChatGPT login talks to the Codex backend unless told otherwise.
  if (!url && auth === 'codex-oauth') url = CODEX_DEFAULT_BASE_URL;
  if (url) {
    const u = new URL(url); // throws on malformed
    if (u.protocol !== 'https:' && u.protocol !== 'http:') {
      throw new Error(`provider url must be http(s), got "${u.protocol}"`);
    }
    p.url = url;
  } else {
    p.url = null;
  }

  p.key = typeof input.key === 'string' && input.key ? input.key : null;

  // Custom headers sent upstream (lowercased keys). Used e.g. for a browser
  // User-Agent that clears Cloudflare, or a vendor-specific header.
  p.headers = {};
  if (input.headers && typeof input.headers === 'object') {
    for (const [k, v] of Object.entries(input.headers)) {
      if (typeof v === 'string' && v) p.headers[String(k).toLowerCase().trim()] = v;
    }
  }

  // Alias map: custom-name -> real upstream model id.
  p.aliases = {};
  if (input.aliases && typeof input.aliases === 'object') {
    for (const [alias, real] of Object.entries(input.aliases)) {
      const a = String(alias).trim();
      if (a && typeof real === 'string' && real.trim()) p.aliases[a] = real.trim();
    }
  }

  // Codex-only state: the Claude->Codex effort map and the stored login.
  p.effortMap = auth === 'codex-oauth' ? normalizeEffortMap(input.effortMap) : null;
  p.codex = auth === 'codex-oauth' ? normalizeCodex(input.codex) : null;
  return p;
}
```

In `upsertProvider`, after the line `if ((merged.key === undefined || merged.key === '') && existing) merged.key = existing.key;` add:

```js
  // The dashboard form never carries the login or the effort map: keep them.
  if (merged.codex === undefined && existing) merged.codex = existing.codex;
  if (merged.effortMap === undefined && existing) merged.effortMap = existing.effortMap;
```

After `setActive`, add:

```js
// Store (or merge) the ChatGPT login of a codex-oauth provider. A refresh
// passes only { tokens }; a login passes tokens + account + models.
export function setCodexAuth(reg, id, { tokens, account, models, fetchedAt } = {}) {
  const p = reg.providers[id];
  if (!p) throw new Error(`unknown provider "${id}"`);
  if (p.auth !== 'codex-oauth') throw new Error(`provider "${id}" is not codex-oauth`);
  const prev = p.codex ?? {};
  p.codex = normalizeCodex({
    tokens: tokens === undefined ? prev.tokens : tokens,
    account: account === undefined ? prev.account : account,
    models: models === undefined ? prev.models : models,
    fetchedAt: fetchedAt === undefined ? prev.fetchedAt : fetchedAt,
  });
  return reg;
}

export function clearCodexAuth(reg, id) {
  const p = reg.providers[id];
  if (!p) throw new Error(`unknown provider "${id}"`);
  p.codex = null;
  return reg;
}
```

In `publicRegistry`, replace the object inside `.map(([id, p]) => ({ ... }))` with:

```js
    providers: Object.entries(reg.providers).map(([id, p]) => ({
      id,
      label: p.label,
      url: p.url,
      auth: p.auth,
      hasKey: !!p.key,
      headers: p.headers,
      aliases: p.aliases,
      effortMap: p.effortMap ?? null,
      // Login STATE only - never a token.
      codex:
        p.auth === 'codex-oauth'
          ? {
              loggedIn: !!(p.codex && p.codex.tokens),
              email: p.codex?.account?.email ?? null,
              plan: p.codex?.account?.plan ?? null,
              expiresAt: p.codex?.tokens?.expiresAt ?? null,
              models: (p.codex?.models ?? []).filter((m) => m.visibility === 'list').map((m) => m.slug),
            }
          : null,
    })),
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test test/providers.test.js`
Expected: PASS (all, including the 3 new). Then `npm test` green (the existing `publicRegistry` assertions only check absence of `key`).

- [ ] **Step 5: Commit**

```bash
git add src/providers.js test/providers.test.js
git commit -F - <<'EOF'
feat(codex): codex-oauth provider records in the registry

New auth mode with a default backend url, a Claude->Codex effort map and a
sanitized stored login (tokens, account, fetched models). Form re-saves
keep the login; setCodexAuth/clearCodexAuth manage it; the public view
exposes login state and model slugs, never a token.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B5pssw9PR5KXtxnP2w9u3
EOF
```

---

### Task 5: The login listener (`codex-login.js`)

**Files:**
- Create: `src/codex-login.js`
- Test: `test/codex-login.test.js`

**Interfaces:**
- Consumes: `createPkce`, `buildAuthorizeUrl`, `exchangeCode`, `accountFromTokens`, `fetchCodexModels`, `CODEX_REDIRECT_PORT`, `CODEX_DEFAULT_BASE_URL` from `src/codex-auth.js`.
- Produces: `startCodexLogin({ port?, host?, timeoutMs?, baseUrl?, exchange?, fetchModels?, request?, onResult, nowMs? }) -> Promise<{ url, port, close }>`; resolves once the listener is bound; rejects with `err.code === 'LOGIN_IN_PROGRESS'` when one is already running, or with the bind error (`EADDRINUSE`). `onResult({ tokens: { access, refresh, idToken, accountId, expiresAt }, account: { email, plan }, models: Model[] | null, fetchedAt })` is called once on success. `loginInProgress() -> boolean`.

- [ ] **Step 1: Write the failing tests**

Create `test/codex-login.test.js`:

```js
// The one-shot OAuth callback listener: builds the authorize URL, validates
// the state, exchanges the code, stores tokens + account + models through
// onResult, then closes. Only one login at a time. No network: exchange and
// model fetch are injected.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startCodexLogin, loginInProgress } from '../src/codex-login.js';
import { fakeAccessToken, fakeIdToken } from './helpers/codex-fixtures.js';

const MODELS = [{ slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium'] }];

function deps(results, { fail = false } = {}) {
  return {
    port: 0,
    exchange: async ({ code, verifier }) => {
      assert.equal(typeof verifier, 'string');
      if (fail) throw new Error('exchange exploded');
      results.exchanged.push(code);
      return { access: fakeAccessToken({ accountId: 'acc-7', plan: 'plus', expSec: 1900000000 }), refresh: 'R7', idToken: fakeIdToken({ email: 'a@b.c' }) };
    },
    fetchModels: async ({ access, accountId }) => {
      assert.equal(accountId, 'acc-7');
      assert.ok(access);
      return MODELS;
    },
    onResult: (r) => results.stored.push(r),
    nowMs: () => 1234,
  };
}

test('authorize URL, wrong state rejected without storing, then a good callback stores the login and closes', async () => {
  const results = { exchanged: [], stored: [] };
  const login = await startCodexLogin(deps(results));
  assert.equal(loginInProgress(), true);
  const u = new URL(login.url);
  assert.equal(u.hostname, 'auth.openai.com');
  assert.equal(u.searchParams.get('redirect_uri'), 'http://localhost:1455/auth/callback');
  const state = u.searchParams.get('state');
  assert.ok(state);

  const bad = await fetch(`http://127.0.0.1:${login.port}/auth/callback?code=x&state=wrong`);
  assert.equal(bad.status, 400);
  assert.equal(results.stored.length, 0);
  assert.equal(results.exchanged.length, 0);
  assert.equal(loginInProgress(), false); // closed after the first callback

  const again = await startCodexLogin(deps(results));
  const state2 = new URL(again.url).searchParams.get('state');
  assert.notEqual(state2, state);
  const ok = await fetch(`http://127.0.0.1:${again.port}/auth/callback?code=abc&state=${encodeURIComponent(state2)}`);
  assert.equal(ok.status, 200);
  assert.match(await ok.text(), /Logged in/);
  assert.deepEqual(results.exchanged, ['abc']);
  assert.equal(results.stored.length, 1);
  const r = results.stored[0];
  assert.equal(r.tokens.accountId, 'acc-7');
  assert.equal(r.tokens.refresh, 'R7');
  assert.equal(r.tokens.expiresAt, 1900000000000);
  assert.deepEqual(r.account, { email: 'a@b.c', plan: 'plus' });
  assert.deepEqual(r.models, MODELS);
  assert.equal(r.fetchedAt, 1234);
  assert.equal(loginInProgress(), false);
});

test('an exchange failure answers an error page and stores nothing', async () => {
  const results = { exchanged: [], stored: [] };
  const login = await startCodexLogin(deps(results, { fail: true }));
  const state = new URL(login.url).searchParams.get('state');
  const res = await fetch(`http://127.0.0.1:${login.port}/auth/callback?code=abc&state=${encodeURIComponent(state)}`);
  assert.equal(res.status, 500);
  assert.match(await res.text(), /exchange exploded/);
  assert.equal(results.stored.length, 0);
  assert.equal(loginInProgress(), false);
});

test('only one login at a time; close() frees it; other paths are 404', async () => {
  const results = { exchanged: [], stored: [] };
  const login = await startCodexLogin(deps(results));
  await assert.rejects(startCodexLogin(deps(results)), (e) => e.code === 'LOGIN_IN_PROGRESS');
  const other = await fetch(`http://127.0.0.1:${login.port}/nope`);
  assert.equal(other.status, 404);
  login.close();
  assert.equal(loginInProgress(), false);
  const next = await startCodexLogin(deps(results));
  next.close();
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test test/codex-login.test.js`
Expected: FAIL - `Cannot find module '.../src/codex-login.js'`.

- [ ] **Step 3: Write the implementation**

Create `src/codex-login.js`:

```js
// One-shot local listener for the OAuth callback. The redirect URI is fixed
// by OpenAI's registered client (http://localhost:1455/auth/callback - the
// same port the Codex CLI uses), so the listener binds 127.0.0.1:1455 for
// the duration of ONE login: started from the dashboard, alive for at most
// timeoutMs, closed after the first callback. One login per process at a
// time. Everything that touches the network is injectable for tests.
import http from 'node:http';
import {
  createPkce,
  buildAuthorizeUrl,
  exchangeCode,
  accountFromTokens,
  fetchCodexModels,
  CODEX_REDIRECT_PORT,
  CODEX_DEFAULT_BASE_URL,
} from './codex-auth.js';

let active = null; // { server, close } while a login is in flight

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const page = (title, body) =>
  `<!doctype html><meta charset="utf-8"><title>${escapeHtml(title)}</title>` +
  `<body style="font-family:system-ui;padding:40px;max-width:640px"><h2>${escapeHtml(title)}</h2><p>${body}</p></body>`;

export function loginInProgress() {
  return active !== null;
}

export function startCodexLogin({
  port = CODEX_REDIRECT_PORT,
  host = '127.0.0.1',
  timeoutMs = 5 * 60 * 1000,
  baseUrl = CODEX_DEFAULT_BASE_URL,
  exchange = exchangeCode,
  fetchModels = fetchCodexModels,
  request,
  onResult,
  nowMs = Date.now,
} = {}) {
  if (active) {
    const err = new Error('a ChatGPT login is already in progress');
    err.code = 'LOGIN_IN_PROGRESS';
    return Promise.reject(err);
  }
  const pkce = createPkce();
  const url = buildAuthorizeUrl({ state: pkce.state, challenge: pkce.challenge });

  return new Promise((resolve, reject) => {
    let timer = null;
    let server = null;
    const close = () => {
      if (timer) clearTimeout(timer);
      timer = null;
      if (active && active.server === server) active = null;
      if (server) {
        server.close();
        if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
      }
    };

    server = http.createServer(async (req, res) => {
      const u = new URL(req.url ?? '/', 'http://localhost');
      if (u.pathname !== '/auth/callback') {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('not found');
        return;
      }
      const send = (code, html) => {
        res.writeHead(code, { 'content-type': 'text/html; charset=utf-8' });
        res.end(html);
      };
      const code = u.searchParams.get('code');
      if (u.searchParams.get('state') !== pkce.state || !code) {
        send(400, page('Login failed', 'State mismatch or missing code. Start the login again from the dashboard.'));
        close();
        return;
      }
      try {
        const tokens = await exchange({ code, verifier: pkce.verifier, request });
        const account = accountFromTokens(tokens);
        if (!account.accountId) throw new Error('the token carries no ChatGPT account id');
        const models = await fetchModels({ baseUrl, access: tokens.access, accountId: account.accountId, request });
        onResult({
          tokens: { access: tokens.access, refresh: tokens.refresh, idToken: tokens.idToken, accountId: account.accountId, expiresAt: account.expiresAt },
          account: { email: account.email, plan: account.plan },
          models,
          fetchedAt: nowMs(),
        });
        send(200, page('Logged in', `Signed in as ${escapeHtml(account.email ?? 'your ChatGPT account')}. You can close this tab.`));
      } catch (err) {
        send(500, page('Login failed', escapeHtml(err.message)));
      }
      close();
    });

    server.on('error', (err) => {
      if (active && active.server === server) active = null;
      reject(err);
    });
    server.listen(port, host, () => {
      active = { server, close };
      timer = setTimeout(close, timeoutMs);
      if (typeof timer.unref === 'function') timer.unref();
      resolve({ url, port: server.address().port, close });
    });
  });
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test test/codex-login.test.js`
Expected: PASS (3 tests). Then `npm test` green.

- [ ] **Step 5: Commit**

```bash
git add src/codex-login.js test/codex-login.test.js
git commit -F - <<'EOF'
feat(codex): one-shot OAuth callback listener on localhost:1455

Builds the PKCE authorize URL, validates the state, exchanges the code,
reads the account from the claims, fetches the plan's model list and hands
everything to onResult, then closes. One login per process at a time, five
minute timeout, injectable exchange/model fetch for tests.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B5pssw9PR5KXtxnP2w9u3
EOF
```

---

### Task 6: Runtime: guard, adapter, login/logout

**Files:**
- Modify: `src/runtime.js` (imports, `createRuntime` signature, `apply` auth list + guard, new functions, return object)
- Modify: `test/runtime.test.js` (append)

**Interfaces:**
- Consumes: `isCodexHost`, `isLoopbackHost`, `refreshTokens`, `accountFromTokens`, `tokensFresh` from `src/codex-auth.js`; `startCodexLogin` from `src/codex-login.js`; `setCodexAuth`, `clearCodexAuth` from `src/providers.js`.
- Produces: `createRuntime({ config, secrets, codexDeps })` where `codexDeps = { request?, port?, loginTimeoutMs?, exchange?, fetchModels?, now? }` (all optional; tests inject); runtime gains `codexAdapter() -> { profile(): { models, effortMap }, credentials(): Promise<{ access, accountId } | null>, refresh(): Promise<{ access, accountId } | null> } | null` (null unless the ACTIVE provider is `codex-oauth`); `codexLogin(id) -> Promise<{ url, port }>`; `codexLogout(id) -> publicRegistry`.

- [ ] **Step 1: Write the failing tests**

Append to `test/runtime.test.js`:

```js
import { loadProviders } from '../src/providers.js';
import { fakeAccessToken, fakeIdToken } from './helpers/codex-fixtures.js';

function codexConfig(providers) {
  const config = baseConfig({ upstreamAuth: 'replace', upstreamKey: null });
  config.providersFile = path.join(path.dirname(config.configFile), 'providers.json');
  config.redactDisable = [];
  config.redactIgnore = [];
  if (providers) fs.writeFileSync(config.providersFile, JSON.stringify(providers));
  return config;
}

const NOW = 1_700_000_000_000;
const login = (expSec) => ({
  tokens: { access: fakeAccessToken({ accountId: 'acc-1', expSec }), refresh: 'R1', idToken: fakeIdToken(), accountId: 'acc-1', expiresAt: expSec * 1000 },
  account: { email: 'me@example.com', plan: 'plus' },
  models: [{ slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium'] }],
  fetchedAt: 1,
});

test('codex-oauth is only accepted against chatgpt.com or loopback', () => {
  const rt = createRuntime({ config: baseConfig(), secrets: [] });
  assert.throws(() => rt.apply({ upstreamUrl: 'https://api.openai.com/v1', upstreamAuth: 'codex-oauth' }), /chatgpt\.com/);
  rt.apply({ upstreamUrl: 'https://chatgpt.com/backend-api/codex', upstreamAuth: 'codex-oauth' });
  assert.equal(rt.upstream.auth, 'codex-oauth');
  rt.apply({ upstreamUrl: 'http://127.0.0.1:1', upstreamAuth: 'codex-oauth' });
  assert.equal(rt.codexAdapter(), null); // no active codex provider in the registry
});

test('codexAdapter: fresh stored token is returned as-is; an expired one is refreshed and persisted', async () => {
  const config = codexConfig({ active: 'codex', providers: { codex: { auth: 'codex-oauth', codex: login(NOW / 1000 + 3600) } } });
  const calls = [];
  const request = async (url, opts) => {
    calls.push({ url, opts });
    return { status: 200, body: JSON.stringify({ access_token: fakeAccessToken({ accountId: 'acc-1', expSec: NOW / 1000 + 7200 }), refresh_token: 'R2' }) };
  };
  const rt = createRuntime({ config, secrets: [], codexDeps: { request, now: () => NOW } });
  assert.equal(rt.upstream.auth, 'codex-oauth');
  assert.equal(rt.upstream.url.href, 'https://chatgpt.com/backend-api/codex');
  const a = rt.codexAdapter();
  assert.deepEqual(a.profile().models.map((m) => m.slug), ['gpt-5.5']);
  assert.equal(a.profile().effortMap.high, 'xhigh');
  const c = await a.credentials();
  assert.equal(c.accountId, 'acc-1');
  assert.equal(calls.length, 0); // fresh: no refresh

  // expire it: credentials() refreshes and the file carries the rotated tokens
  fs.writeFileSync(config.providersFile, JSON.stringify({ active: 'codex', providers: { codex: { auth: 'codex-oauth', codex: login(NOW / 1000 - 10) } } }));
  const rt2 = createRuntime({ config, secrets: [], codexDeps: { request, now: () => NOW } });
  const c2 = await rt2.codexAdapter().credentials();
  assert.equal(calls.length, 1);
  assert.equal(JSON.parse(calls[0].opts.body).refresh_token, 'R1');
  assert.equal(c2.accountId, 'acc-1');
  const saved = loadProviders(config.providersFile);
  assert.equal(saved.providers.codex.codex.tokens.refresh, 'R2');
  assert.equal(saved.providers.codex.codex.tokens.expiresAt, (NOW / 1000 + 7200) * 1000);
  assert.equal(saved.providers.codex.codex.account.email, 'me@example.com'); // untouched by a refresh
  // forced refresh (after a backend 401) goes through the same path
  const c3 = await rt2.codexAdapter().refresh();
  assert.equal(calls.length, 2);
  assert.equal(c3.accountId, 'acc-1');
  // refresh failure -> null
  const rt3 = createRuntime({ config: codexConfig({ active: 'codex', providers: { codex: { auth: 'codex-oauth', codex: login(NOW / 1000 - 10) } } }), secrets: [], codexDeps: { request: async () => ({ status: 401, body: '' }), now: () => NOW } });
  assert.equal(await rt3.codexAdapter().credentials(), null);
  // not logged in -> null credentials, adapter still answers profile()
  const rt4 = createRuntime({ config: codexConfig({ active: 'codex', providers: { codex: { auth: 'codex-oauth' } } }), secrets: [] });
  assert.equal(await rt4.codexAdapter().credentials(), null);
  assert.equal(rt4.codexAdapter().profile().models, null);
});

test('codexLogin starts the listener and stores the result; codexLogout wipes it', async () => {
  const config = codexConfig({ active: 'codex', providers: { codex: { auth: 'codex-oauth' } } });
  const rt = createRuntime({
    config,
    secrets: [],
    codexDeps: {
      port: 0,
      now: () => NOW,
      exchange: async () => ({ access: fakeAccessToken({ accountId: 'acc-2' }), refresh: 'R9', idToken: fakeIdToken({ email: 'x@y.z' }) }),
      fetchModels: async () => [{ slug: 'gpt-5.6-sol', displayName: 'GPT-5.6-Sol', visibility: 'list', defaultLevel: 'low', levels: ['low'] }],
    },
  });
  await assert.rejects(rt.codexLogin('nope'), /unknown provider/);
  const { url, port } = await rt.codexLogin('codex');
  const state = new URL(url).searchParams.get('state');
  const res = await fetch(`http://127.0.0.1:${port}/auth/callback?code=c&state=${encodeURIComponent(state)}`);
  assert.equal(res.status, 200);
  let pub = rt.providers().providers[0];
  assert.deepEqual(pub.codex, { loggedIn: true, email: 'x@y.z', plan: 'plus', expiresAt: 4102444800000, models: ['gpt-5.6-sol'] });
  assert.equal(loadProviders(config.providersFile).providers.codex.codex.tokens.refresh, 'R9');
  pub = rt.codexLogout('codex').providers[0];
  assert.equal(pub.codex.loggedIn, false);
  assert.equal(loadProviders(config.providersFile).providers.codex.codex, null);
  rt.upsertProvider('plain', { auth: 'replace', key: 'k', url: 'https://x.y' });
  await assert.rejects(rt.codexLogin('plain'), /codex-oauth/);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test test/runtime.test.js`
Expected: FAIL - `upstreamAuth must be passthrough, replace or oauth` / `rt.codexAdapter is not a function`.

- [ ] **Step 3: Write the implementation**

In `src/runtime.js`:

Add to the imports (after the `providers.js` import block; also add `setCodexAuth, clearCodexAuth` to that block):

```js
import { isCodexHost, isLoopbackHost, refreshTokens, accountFromTokens, tokensFresh } from './codex-auth.js';
import { startCodexLogin } from './codex-login.js';
```

Change the signature to `export function createRuntime({ config, secrets = [], codexDeps = {} }) {`.

In `apply`, replace the auth validation with:

```js
    if (patch.upstreamAuth !== undefined) {
      if (!['passthrough', 'replace', 'oauth', 'codex-oauth'].includes(patch.upstreamAuth)) {
        throw new Error('upstreamAuth must be passthrough, replace, oauth or codex-oauth');
      }
      upstream.auth = patch.upstreamAuth;
    }
```

and after the `oauth` host guard (the `isAnthropicHost` check) add:

```js
    // Same rule for a ChatGPT login: only the Codex backend host (or a
    // loopback process on this machine, which is inside the trust boundary).
    if (
      upstream.auth === 'codex-oauth' &&
      upstream.url &&
      !isCodexHost(upstream.url) &&
      !isLoopbackHost(upstream.url)
    ) {
      throw new Error('upstreamAuth=codex-oauth is only allowed with chatgpt.com');
    }
```

After `resolveModel` (before the `try { syncActiveProvider(); }` block) add:

```js
  // ---- Codex (ChatGPT subscription) provider ----
  const codexNow = codexDeps.now ?? Date.now;

  // What the upstream handler needs from the ACTIVE provider, or null when it
  // is not codex-oauth. credentials() refreshes proactively (5 min skew);
  // refresh() is the forced path after a backend 401. Rotated tokens are
  // persisted so the next boot starts from them.
  function codexAdapter() {
    const id = registry.active;
    const p = regActive(registry);
    if (!p || p.auth !== 'codex-oauth') return null;
    const current = () => registry.providers[id]?.codex?.tokens ?? null;
    const refresh = async () => {
      const t = current();
      if (!t || !t.refresh) return null;
      const next = await refreshTokens({ refreshToken: t.refresh, request: codexDeps.request });
      if (!next) return null;
      const account = accountFromTokens(next);
      setCodexAuth(registry, id, {
        tokens: { access: next.access, refresh: next.refresh, idToken: next.idToken, accountId: account.accountId ?? t.accountId, expiresAt: account.expiresAt },
      });
      persistRegistry();
      const fresh = current();
      return fresh ? { access: fresh.access, accountId: fresh.accountId } : null;
    };
    return {
      profile: () => ({ models: registry.providers[id]?.codex?.models ?? null, effortMap: registry.providers[id]?.effortMap ?? null }),
      credentials: async () => {
        const t = current();
        if (!t || !t.access) return null;
        if (tokensFresh(t, codexNow())) return { access: t.access, accountId: t.accountId };
        return refresh();
      },
      refresh,
    };
  }

  // Start a ChatGPT login for a codex-oauth provider: resolves with the URL
  // the panel opens. The callback listener stores the result in the registry.
  async function codexLogin(id) {
    const p = registry.providers[id];
    if (!p) throw new Error(`unknown provider "${id}"`);
    if (p.auth !== 'codex-oauth') throw new Error('provider auth must be codex-oauth to log in');
    const { url, port } = await startCodexLogin({
      port: codexDeps.port,
      timeoutMs: codexDeps.loginTimeoutMs,
      baseUrl: p.url,
      exchange: codexDeps.exchange,
      fetchModels: codexDeps.fetchModels,
      request: codexDeps.request,
      nowMs: codexNow,
      onResult: (r) => {
        setCodexAuth(registry, id, r);
        persistRegistry();
      },
    });
    return { url, port };
  }

  function codexLogout(id) {
    clearCodexAuth(registry, id);
    persistRegistry();
    return publicRegistry(registry);
  }
```

`startCodexLogin` applies its own defaults for every `undefined` option, so passing `codexDeps.port` etc. through unchanged is correct.

Add to the returned object, after `resolveModel,`:

```js
    codexAdapter,
    codexLogin,
    codexLogout,
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test test/runtime.test.js`
Expected: PASS (all, including the 3 new). Then `npm test` green.

- [ ] **Step 5: Commit**

```bash
git add src/runtime.js test/runtime.test.js
git commit -F - <<'EOF'
feat(codex): runtime guard, credential adapter, login/logout

codex-oauth is accepted only against chatgpt.com or loopback. The adapter
hands the upstream handler the active provider's models, effort map and a
fresh token (proactive refresh with a 5 minute skew, forced refresh after a
401), persisting rotated tokens. codexLogin starts the callback listener
and stores the result; codexLogout wipes it.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B5pssw9PR5KXtxnP2w9u3
EOF
```

---

### Task 7: The upstream handler and the proxy dispatch

**Files:**
- Create: `src/codex-upstream.js`
- Modify: `src/proxy.js:83-93` (signature + adapter getter), `src/proxy.js:212-217` (dispatch right after the redaction block)
- Modify: `src/stats.js:93-104` (`finish` gains `note`)
- Test: `test/codex.proxy.test.js`

**Interfaces:**
- Consumes: everything from `src/codex-translate.js` and `src/codex-auth.js` (Tasks 1-3), `modelsEnvelope` from `src/models.js`, the adapter shape from Task 6 (`{ profile, credentials, refresh }`).
- Produces: `handleCodexUpstream({ req, res, up, entry, stats, t0, bodyText, codex, aliases?, timeoutMs? })`; `createProxyServer` gains the option `codexAdapter: () => adapter | null` (default: `controller.codexAdapter()`); `stats.finish(entry, { ..., note })` appends the note to the log line and stores it on the entry.

- [ ] **Step 1: Write the failing tests**

Create `test/codex.proxy.test.js`:

```js
// End-to-end for the codex-oauth upstream path: redaction happens BEFORE
// translation (the canary proof), translation failures fail closed, the
// Responses SSE is translated back to Anthropic SSE, a 401 triggers one
// refresh + replay, 429 passes through, /v1/models and count_tokens are
// answered locally without ever contacting the upstream.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createMockUpstream } from './helpers/mock-upstream.js';
import { startProxy } from './helpers/start-proxy.js';
import { createRedactor } from '../src/redact.js';
import { TEXT_TURN, TOOL_TURN, sseFrames } from './helpers/codex-fixtures.js';

const CANARY = 'CODEX-CANARY-9f2b7e-uniq-value-31337';
const MODELS = [
  { slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium', 'high', 'xhigh'] },
  { slug: 'gpt-reserve', displayName: 'Reserve', visibility: 'hide', defaultLevel: 'medium', levels: ['low'] },
];

function fakeAdapter({ access = 'tok-1', accountId = 'acc-1', models = MODELS, effortMap = null, refreshed = 'tok-2', creds = true } = {}) {
  const calls = { credentials: 0, refresh: 0 };
  return {
    calls,
    profile: () => ({ models, effortMap }),
    credentials: async () => {
      calls.credentials += 1;
      return creds ? { access, accountId } : null;
    },
    refresh: async () => {
      calls.refresh += 1;
      return refreshed ? { access: refreshed, accountId } : null;
    },
  };
}

// An upstream whose answers are scripted per request (the last one repeats).
function scriptedUpstream(responders, { path = '' } = {}) {
  const requests = [];
  let i = 0;
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, headers: { ...req.headers }, body: Buffer.concat(chunks).toString('utf8') });
      const r = responders[Math.min(i, responders.length - 1)];
      i += 1;
      r(req, res);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ url: `http://127.0.0.1:${server.address().port}${path}`, requests, close: () => new Promise((r) => server.close(r)) });
    });
  });
}
const sseResponder = (frames, headers = {}) => (req, res) => {
  res.writeHead(200, headers); // NOTE: no content-type by default, like the real backend
  for (const f of frames) res.write(f);
  res.end();
};
const jsonResponder = (status, obj) => (req, res) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(obj));
};

async function boot(upstreamUrl, adapter, extra = {}) {
  return startProxy({
    upstreamUrl,
    redactor: createRedactor({ secrets: [{ name: 'CODEX_CANARY', value: CANARY }] }),
    configOverrides: { upstreamAuth: 'codex-oauth', injectNotice: false, ...extra },
    serverOptions: { codexAdapter: () => adapter },
  });
}

const post = (url, body, headers = {}) =>
  fetch(`${url}/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': 'client-key-must-not-forward', ...headers }, body: JSON.stringify(body) });

test('canary round-trip: redaction runs before translation, nothing leaks, backend contract honoured', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN), sseDelayMs: 1 });
  const adapter = fakeAdapter();
  const proxy = await boot(upstream.url, adapter);
  try {
    const res = await post(proxy.url, {
      model: 'gpt-5.5[1m]',
      max_tokens: 64000,
      stream: true,
      system: 'You are a test agent.',
      output_config: { effort: 'max' },
      metadata: { user_id: 'session-xyz' },
      messages: [
        { role: 'user', content: `my secret is ${CANARY}` },
        { role: 'user', content: `base64: ${Buffer.from(CANARY).toString('base64')}` },
      ],
    });
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/event-stream/);
    const body = await res.text();
    assert.ok(body.includes('event: message_start'));
    assert.ok(body.includes('"type":"thinking"'));
    assert.ok(body.includes('"signature":"ENC1"'));
    assert.ok(body.includes('"text":"Hi"'));
    assert.ok(body.includes('event: message_stop'));

    assert.equal(upstream.requests.length, 1);
    const sent = upstream.requests[0];
    assert.equal(sent.url, '/responses');
    assert.equal(sent.body.includes(CANARY), false, 'literal canary leaked');
    assert.equal(sent.body.includes(Buffer.from(CANARY).toString('base64')), false, 'base64 canary leaked');
    assert.ok(sent.body.includes('[REDACTED:CODEX_CANARY]'));
    const wire = JSON.parse(sent.body);
    assert.equal(wire.model, 'gpt-5.5');
    assert.equal(wire.store, false);
    assert.equal(wire.stream, true);
    assert.deepEqual(wire.reasoning, { effort: 'xhigh', summary: 'auto' }); // max clamped to gpt-5.5's ceiling
    assert.equal('max_output_tokens' in wire, false);
    assert.equal(wire.instructions, 'You are a test agent.');
    assert.equal(sent.headers.authorization, 'Bearer tok-1');
    assert.equal(sent.headers['chatgpt-account-id'], 'acc-1');
    assert.equal(sent.headers['openai-beta'], 'responses=experimental');
    assert.equal('x-api-key' in sent.headers, false, 'client credential forwarded');
    assert.equal(adapter.calls.refresh, 0);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('the inspector keeps the TRANSLATED body (what actually left)', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN), sseDelayMs: 1 });
  const proxy = await boot(upstream.url, fakeAdapter());
  try {
    await post(proxy.url, { model: 'gpt-5.5', stream: true, messages: [{ role: 'user', content: 'hi' }] });
    const s = await (await fetch(`${proxy.url}/__redact/stats.json`)).json();
    const id = s.recent[0].id;
    const d = await (await fetch(`${proxy.url}/__redact/inspect?id=${id}`, { headers: { 'x-redact-panel': '1' } })).json();
    assert.ok(JSON.parse(d.req).input, 'stored request is the Responses body');
    assert.ok(d.resp.includes('response.completed'), 'raw upstream SSE captured');
    assert.equal(s.recent[0].status, 200);
    assert.equal(s.recent[0].inputTokens, 24);
    assert.equal(s.recent[0].outputTokens, 18);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('fail closed: an untranslatable body is answered 400 and the upstream receives nothing', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN) });
  const proxy = await boot(upstream.url, fakeAdapter());
  try {
    const res = await post(proxy.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: [{ type: 'document', source: {} }] }] });
    assert.equal(res.status, 400);
    const j = await res.json();
    assert.match(j.error.message, /unsupported content block type: document/);
    assert.equal(upstream.requests.length, 0);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('tool call turn streams back as a tool_use block; stream:false folds into one JSON message', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TOOL_TURN), sseDelayMs: 1 });
  const proxy = await boot(upstream.url, fakeAdapter());
  try {
    const streamed = await post(proxy.url, { model: 'gpt-5.5', stream: true, messages: [{ role: 'user', content: 'weather' }], tools: [{ name: 'get_weather', input_schema: { type: 'object' } }] });
    const text = await streamed.text();
    assert.ok(text.includes('"type":"tool_use","id":"call_1","name":"get_weather"'));
    assert.ok(text.includes('"partial_json":"{\\"city\\":"'));
    assert.ok(text.includes('"stop_reason":"tool_use"'));

    const single = await post(proxy.url, { model: 'gpt-5.5', stream: false, messages: [{ role: 'user', content: 'weather' }] });
    assert.equal(single.status, 200);
    assert.match(single.headers.get('content-type'), /application\/json/);
    const m = await single.json();
    assert.equal(m.type, 'message');
    assert.equal(m.model, 'gpt-5.5');
    assert.deepEqual(m.content, [{ type: 'tool_use', id: 'call_1', name: 'get_weather', input: { city: 'Paris' } }]);
    assert.equal(m.stop_reason, 'tool_use');
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('401 -> one refresh + replay with the new token; a second 401 is a 502 no_codex_oauth', async () => {
  const upstream = await scriptedUpstream([jsonResponder(401, { detail: 'expired' }), sseResponder(sseFrames(TEXT_TURN))]);
  const adapter = fakeAdapter();
  const proxy = await boot(upstream.url, adapter);
  try {
    const res = await post(proxy.url, { model: 'gpt-5.5', stream: true, messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 200);
    assert.ok((await res.text()).includes('event: message_stop'));
    assert.equal(upstream.requests.length, 2);
    assert.equal(upstream.requests[0].headers.authorization, 'Bearer tok-1');
    assert.equal(upstream.requests[1].headers.authorization, 'Bearer tok-2');
    assert.equal(adapter.calls.refresh, 1);
  } finally {
    await proxy.close();
    await upstream.close();
  }
  const always401 = await scriptedUpstream([jsonResponder(401, { detail: 'expired' })]);
  const dead = fakeAdapter({ refreshed: null });
  const proxy2 = await boot(always401.url, dead);
  try {
    const res = await post(proxy2.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 502);
    assert.equal((await res.json()).error.type, 'no_codex_oauth');
    assert.equal(always401.requests.length, 1);
  } finally {
    await proxy2.close();
    await always401.close();
  }
});

test('no login -> 502 no_codex_oauth before anything is sent; misconfigured host -> 400', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN) });
  const proxy = await boot(upstream.url, fakeAdapter({ creds: false }));
  try {
    const res = await post(proxy.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 502);
    assert.equal((await res.json()).error.type, 'no_codex_oauth');
    assert.equal(upstream.requests.length, 0);
  } finally {
    await proxy.close();
    await upstream.close();
  }
  const proxy2 = await boot('https://api.openai.com/v1', fakeAdapter());
  try {
    const res = await post(proxy2.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error.type, 'codex_misconfig');
  } finally {
    await proxy2.close();
  }
});

test('429 passes through with the backend detail; other errors become 502 with the detail', async () => {
  const limited = await scriptedUpstream([jsonResponder(429, { detail: 'usage limit reached, resets in 3h' })]);
  const proxy = await boot(limited.url, fakeAdapter());
  try {
    const res = await post(proxy.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 429);
    const j = await res.json();
    assert.equal(j.error.type, 'rate_limit_error');
    assert.match(j.error.message, /usage limit reached/);
  } finally {
    await proxy.close();
    await limited.close();
  }
  const broken = await scriptedUpstream([jsonResponder(400, { detail: 'Unsupported parameter: foo' })]);
  const proxy2 = await boot(broken.url, fakeAdapter());
  try {
    const res = await post(proxy2.url, { model: 'gpt-5.5', messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 502);
    const j = await res.json();
    assert.equal(j.error.type, 'upstream_error');
    assert.match(j.error.message, /HTTP 400.*Unsupported parameter: foo/);
  } finally {
    await proxy2.close();
    await broken.close();
  }
});

test('a 200 that is not a Responses stream never becomes a finished message', async () => {
  const bogus = await scriptedUpstream([jsonResponder(200, { ok: true })]);
  const proxy = await boot(bogus.url, fakeAdapter());
  try {
    const streamed = await post(proxy.url, { model: 'gpt-5.5', stream: true, messages: [{ role: 'user', content: 'hi' }] });
    const text = await streamed.text();
    assert.ok(text.includes('event: error'));
    assert.equal(text.includes('message_stop'), false);
    const single = await post(proxy.url, { model: 'gpt-5.5', stream: false, messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(single.status, 502);
  } finally {
    await proxy.close();
    await bogus.close();
  }
});

test('a provider url already ending in /responses is not doubled', async () => {
  const upstream = await scriptedUpstream([sseResponder(sseFrames(TEXT_TURN))], { path: '/backend-api/codex/responses' });
  const proxy = await boot(upstream.url, fakeAdapter());
  try {
    const res = await post(proxy.url, { model: 'gpt-5.5', stream: true, messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(res.status, 200);
    await res.text();
    assert.equal(upstream.requests[0].url, '/backend-api/codex/responses');
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test('/v1/models and count_tokens are answered locally, never touching the upstream', async () => {
  const upstream = await createMockUpstream({ sse: true, sseEvents: sseFrames(TEXT_TURN) });
  const proxy = await boot(upstream.url, fakeAdapter());
  try {
    const models = await (await fetch(`${proxy.url}/v1/models`)).json();
    assert.deepEqual(models.data.map((m) => m.id), ['gpt-5.5']); // hidden model excluded, no [1m]
    assert.equal(models.data[0].display_name, 'GPT-5.5');
    const count = await (await fetch(`${proxy.url}/v1/messages/count_tokens`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'gpt-5.5', messages: [{ role: 'user', content: 'hello world' }] }) })).json();
    assert.ok(Number.isInteger(count.input_tokens) && count.input_tokens > 0);
    const other = await fetch(`${proxy.url}/v1/complete`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(other.status, 404);
    assert.equal(upstream.requests.length, 0);
  } finally {
    await proxy.close();
    await upstream.close();
  }
  // no fetched list -> the static four
  const proxy2 = await boot('http://127.0.0.1:9', fakeAdapter({ models: null }));
  try {
    const models = await (await fetch(`${proxy2.url}/v1/models`)).json();
    assert.deepEqual(models.data.map((m) => m.id), ['gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-5.6-luna', 'gpt-5.5']);
  } finally {
    await proxy2.close();
  }
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test test/codex.proxy.test.js`
Expected: FAIL - the proxy forwards to the mock as a generic upstream (canary test sees the Anthropic body, `sent.url` is `/v1/messages`) and/or `Cannot find module`.

- [ ] **Step 3: Add `note` to `stats.finish`**

In `src/stats.js`, replace the `finish` function with:

```js
  // Completes a record once the upstream response is done. `note` is a short
  // free-text tag for the log line (e.g. the codex model + effort) - never a
  // value from the body.
  function finish(entry, { status = null, durationMs = null, inputTokens = null, outputTokens = null, respBytes = null, note = null } = {}) {
    if (!entry) return;
    entry.status = status;
    entry.durationMs = durationMs;
    entry.inputTokens = inputTokens;
    entry.outputTokens = outputTokens;
    entry.respBytes = respBytes;
    entry.note = note;
    if (inputTokens) totals.inputTokens += inputTokens;
    if (outputTokens) totals.outputTokens += outputTokens;
    const tok = inputTokens || outputTokens ? ` tok in ${inputTokens ?? 0}/out ${outputTokens ?? 0}` : '';
    log(`[redact] ${entry.method} ${entry.path} -> ${status ?? '-'} ${durationMs ?? '?'}ms${tok}${note ? ` ${note}` : ''}`);
  }
```

- [ ] **Step 4: Write the handler**

Create `src/codex-upstream.js`:

```js
// Codex backend upstream (auth mode "codex-oauth"). The redacted Anthropic
// Messages body is translated to a Responses request, POSTed to
// <base>/responses with the stored ChatGPT token, and the Responses SSE is
// translated back to Anthropic SSE (or folded into one JSON message when the
// client did not ask for a stream). Redaction ALWAYS happened before this
// point; any translation failure blocks the request (fail closed). Model
// discovery and count_tokens are answered locally - no token leaves for them.
import http from 'node:http';
import https from 'node:https';
import { randomUUID } from 'node:crypto';
import { StringDecoder } from 'node:string_decoder';
import { isCodexHost, isLoopbackHost, codexRequestHeaders } from './codex-auth.js';
import {
  anthropicToCodex,
  SseDecoder,
  CodexReducer,
  serializeSse,
  errorSse,
  accumulateMessage,
  estimateTokens,
  CODEX_DEFAULT_MODELS,
} from './codex-translate.js';
import { modelsEnvelope } from './models.js';

export const CODEX_MAX_BUFFERED_RESPONSE_BYTES = 8 * 1024 * 1024;
export const CODEX_MAX_ERROR_BODY_BYTES = 16 * 1024;

const MODEL_EPOCH = '1970-01-01T00:00:00Z';

function readCapped(stream, cap) {
  return new Promise((resolve) => {
    let acc = '';
    stream.setEncoding('utf8');
    stream.on('data', (c) => {
      if (acc.length < cap) acc += c.slice(0, cap - acc.length);
    });
    stream.on('end', () => resolve(acc));
    stream.on('error', () => resolve(acc));
  });
}

function errorDetail(text) {
  try {
    const j = JSON.parse(text);
    if (typeof j.detail === 'string') return j.detail;
    if (typeof j.error?.message === 'string') return j.error.message;
    return JSON.stringify(j.detail ?? j.error ?? j).slice(0, 500);
  } catch {
    return text.slice(0, 500);
  }
}

// `codex` is the adapter from the runtime: { profile(), credentials(), refresh() }.
export async function handleCodexUpstream({ req, res, up, entry, stats, t0, bodyText, codex, aliases = {}, timeoutMs = 10 * 60 * 1000 }) {
  let note = null;
  const finish = (status, extra = {}) => stats.finish(entry, { status, durationMs: Date.now() - t0, note, ...extra });
  const sendJson = (status, obj) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(obj));
    finish(status);
  };

  // Defence in depth: the token must only ever reach the Codex backend or a
  // process on this machine, even if the runtime guard was somehow bypassed.
  if (!isCodexHost(up.url) && !isLoopbackHost(up.url)) {
    sendJson(400, { error: { type: 'codex_misconfig', message: 'codex-oauth auth is only allowed with chatgpt.com' } });
    return;
  }
  if (!codex) {
    sendJson(502, { error: { type: 'no_codex_oauth', message: 'no ChatGPT login for the active provider - log in from the dashboard' } });
    return;
  }

  const pathname = (req.url ?? '/').split('?')[0];
  const profile = codex.profile();
  const models = Array.isArray(profile.models) && profile.models.length > 0 ? profile.models : CODEX_DEFAULT_MODELS;

  // Model discovery: the plan's list (plus alias names), answered locally.
  if (req.method === 'GET' && /^\/v1\/models$/.test(pathname)) {
    const data = models.filter((m) => m.visibility !== 'hide').map((m) => ({ id: m.slug, display_name: m.displayName ?? m.slug, type: 'model', created_at: MODEL_EPOCH }));
    for (const alias of Object.keys(aliases)) {
      if (!data.some((m) => m.id === alias)) data.push({ id: alias, display_name: alias, type: 'model', created_at: MODEL_EPOCH });
    }
    sendJson(200, modelsEnvelope(data));
    return;
  }

  const translate = () => anthropicToCodex(JSON.parse(bodyText), { models, effortMap: profile.effortMap ?? undefined });

  // No count endpoint upstream: a deterministic local estimate.
  if (req.method === 'POST' && pathname.endsWith('/count_tokens')) {
    try {
      sendJson(200, { input_tokens: estimateTokens(translate()) });
    } catch (err) {
      sendJson(400, { error: { type: 'invalid_request_error', message: `codex translation failed: ${err.message}` } });
    }
    return;
  }

  if (req.method !== 'POST' || !pathname.endsWith('/messages')) {
    sendJson(404, { error: { type: 'not_found', message: 'codex-oauth provider serves only /v1/messages, /v1/messages/count_tokens and /v1/models' } });
    return;
  }

  let parsed;
  let translated;
  try {
    parsed = JSON.parse(bodyText);
    translated = anthropicToCodex(parsed, { models, effortMap: profile.effortMap ?? undefined });
  } catch (err) {
    // Fail closed: an untranslatable body is never forwarded raw.
    sendJson(400, { error: { type: 'invalid_request_error', message: `codex translation failed: ${err.message}` } });
    return;
  }
  note = `codex model=${translated.model} effort=${translated.reasoning?.effort ?? '-'}`;
  const clientStream = parsed.stream === true;
  const upstreamBody = Buffer.from(JSON.stringify(translated), 'utf8');
  // Overwrite the inspector copy: THIS is what actually leaves the machine.
  stats.rememberReq(entry?.id, upstreamBody.toString('utf8'));

  let creds;
  try {
    creds = await codex.credentials();
  } catch {
    creds = null;
  }
  if (!creds) {
    sendJson(502, { error: { type: 'no_codex_oauth', message: 'ChatGPT login missing or expired - log in again from the dashboard' } });
    return;
  }

  const transport = up.url.protocol === 'https:' ? https : http;
  const basePath = up.url.pathname.replace(/\/$/, '');
  const upstreamPath = basePath.endsWith('/responses') ? basePath : `${basePath}/responses`;
  const sessionId = randomUUID();
  const attempt = ({ access, accountId }) =>
    new Promise((resolve, reject) => {
      const headers = codexRequestHeaders({ access, accountId, sessionId });
      headers.host = up.url.host;
      headers['content-length'] = String(upstreamBody.length);
      const r = transport.request(
        {
          protocol: up.url.protocol,
          hostname: up.url.hostname,
          port: up.url.port || (up.url.protocol === 'https:' ? 443 : 80),
          method: 'POST',
          path: upstreamPath,
          headers,
          timeout: timeoutMs,
        },
        resolve,
      );
      r.on('timeout', () => r.destroy(new Error('upstream timeout')));
      r.on('error', reject);
      r.end(upstreamBody);
    });

  let upstreamRes;
  try {
    upstreamRes = await attempt(creds);
    if ((upstreamRes.statusCode ?? 0) === 401) {
      // Expired/revoked access token: refresh once and replay.
      upstreamRes.resume();
      let next = null;
      try {
        next = await codex.refresh();
      } catch {
        next = null;
      }
      if (!next) {
        sendJson(502, { error: { type: 'no_codex_oauth', message: 'ChatGPT token refresh failed - log in again from the dashboard' } });
        return;
      }
      upstreamRes = await attempt(next);
      if ((upstreamRes.statusCode ?? 0) === 401) {
        upstreamRes.resume();
        sendJson(502, { error: { type: 'no_codex_oauth', message: 'the Codex backend rejected the refreshed token - log in again from the dashboard' } });
        return;
      }
    }
  } catch (err) {
    sendJson(502, { error: { type: 'upstream_error', message: `codex upstream request failed: ${err.message}` } });
    return;
  }

  const status = upstreamRes.statusCode ?? 0;
  if (status !== 200) {
    const text = await readCapped(upstreamRes, CODEX_MAX_ERROR_BODY_BYTES);
    stats.rememberResp(entry?.id, text);
    const detail = errorDetail(text);
    if (status === 429) {
      // The plan's usage limit: let the client show its own rate-limit UI.
      res.writeHead(429, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: detail || 'rate limited by the Codex backend' } }));
      finish(429);
      return;
    }
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'upstream_error', message: `codex upstream rejected the request (HTTP ${status})${detail ? `: ${detail}` : ''}` } }));
    finish(502);
    return;
  }

  // 200: a Responses SSE stream (the backend sends no content-type - do not
  // depend on it). Translate as it arrives.
  const messageId = `msg_${randomUUID().replace(/-/g, '')}`;
  const reducer = new CodexReducer({ messageId, model: parsed.model });
  const decoder = new SseDecoder();
  const rawDec = new StringDecoder('utf8');
  let respAcc = '';
  let respBytes = 0;
  const usage = { input_tokens: null, output_tokens: null };
  const noteUsage = (events) => {
    for (const e of events) {
      if (e.event === 'message_delta') {
        usage.input_tokens = e.data.usage?.input_tokens ?? null;
        usage.output_tokens = e.data.usage?.output_tokens ?? null;
      }
    }
  };
  const finishStream = (code) => {
    stats.rememberResp(entry?.id, respAcc);
    finish(code, { inputTokens: usage.input_tokens, outputTokens: usage.output_tokens, respBytes });
  };

  if (clientStream) {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
    let ended = false;
    const end = (code) => {
      if (ended) return;
      ended = true;
      res.end();
      finishStream(code);
    };
    const abort = (message) => {
      if (ended) return;
      res.write(errorSse(message));
      upstreamRes.destroy();
      end(502);
    };
    res.on('close', () => {
      if (ended) return;
      ended = true;
      upstreamRes.destroy();
      finishStream(null);
    });
    upstreamRes.on('data', (chunk) => {
      respBytes += chunk.length;
      respAcc += rawDec.write(chunk);
      if (ended) return;
      try {
        for (const ev of decoder.push(chunk)) {
          const out = reducer.push(ev);
          noteUsage(out);
          if (out.length) res.write(serializeSse(out));
        }
      } catch (err) {
        abort(`codex stream translation failed: ${err.message}`);
      }
    });
    upstreamRes.on('end', () => {
      if (ended) return;
      try {
        for (const ev of decoder.flush()) {
          const out = reducer.push(ev);
          noteUsage(out);
          if (out.length) res.write(serializeSse(out));
        }
      } catch (err) {
        abort(`codex stream translation failed: ${err.message}`);
        return;
      }
      if (!reducer.done) {
        res.write(errorSse('codex upstream ended before response.completed'));
        end(502);
        return;
      }
      end(200);
    });
    upstreamRes.on('error', () => abort('codex upstream stream failed'));
    return;
  }

  // Non-streaming client: fold the whole translated stream into one message.
  const events = [];
  let failed = null;
  let concluded = false;
  upstreamRes.on('data', (chunk) => {
    respBytes += chunk.length;
    respAcc += rawDec.write(chunk);
    if (failed) return;
    if (respBytes > CODEX_MAX_BUFFERED_RESPONSE_BYTES) {
      failed = new Error('codex upstream response exceeds the size limit');
      upstreamRes.destroy();
      return;
    }
    try {
      for (const ev of decoder.push(chunk)) events.push(...reducer.push(ev));
    } catch (err) {
      failed = err;
      upstreamRes.destroy();
    }
  });
  const conclude = () => {
    if (concluded) return;
    concluded = true;
    if (!failed) {
      try {
        for (const ev of decoder.flush()) events.push(...reducer.push(ev));
        if (!reducer.done) failed = new Error('codex upstream ended before response.completed');
      } catch (err) {
        failed = err;
      }
    }
    let message = null;
    if (!failed) {
      try {
        message = accumulateMessage(events);
      } catch (err) {
        failed = err;
      }
    }
    if (failed) {
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'api_error', message: `codex response translation failed: ${failed.message}` } }));
      finishStream(502);
      return;
    }
    noteUsage(events);
    const buf = Buffer.from(JSON.stringify(message), 'utf8');
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(buf.length) });
    res.end(buf);
    finishStream(200);
  };
  upstreamRes.on('end', conclude);
  upstreamRes.on('close', conclude);
  upstreamRes.on('error', (err) => {
    failed = failed ?? err;
    conclude();
  });
}
```

- [ ] **Step 5: Dispatch from the proxy**

In `src/proxy.js`:

Add the import after the `rehydrate.js` import:

```js
import { handleCodexUpstream } from './codex-upstream.js';
```

Change the signature and add the adapter getter (replace lines 83-84):

```js
export function createProxyServer({ config, redactor, stats, getUpstream, controller, getOAuth, getRestore, codexAdapter }) {
  const oauthOf = getOAuth ?? (() => readClaudeOAuth());
  // Codex (ChatGPT subscription) credentials for the active provider, resolved
  // per request. Tests inject a fake adapter; the runtime supplies the real one.
  const codexOf = codexAdapter ?? (() => (controller && typeof controller.codexAdapter === 'function' ? controller.codexAdapter() : null));
```

Right after the redaction block ends (after the `} else { entry = stats.record(...); stats.rememberReq(entry?.id, ''); }` block, before `const headers = {};`) insert:

```js
    // Codex backend (ChatGPT subscription): a different wire protocol, so the
    // redacted body is TRANSLATED and the response translated back on a
    // dedicated path. The generic forward below never runs for codex-oauth.
    if (up.auth === 'codex-oauth') {
      await handleCodexUpstream({
        req,
        res,
        up,
        entry,
        stats,
        t0,
        bodyText: outBody ? outBody.toString('utf8') : '',
        codex: codexOf(),
        aliases: controller?.activeAliases ?? {},
        timeoutMs: UPSTREAM_TIMEOUT_MS,
      });
      return;
    }
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `node --test test/codex.proxy.test.js`
Expected: PASS (10 tests). Then `npm test` green (the generic-path tests are untouched: the dispatch only fires for `codex-oauth`).

- [ ] **Step 7: Commit**

```bash
git add src/codex-upstream.js src/proxy.js src/stats.js test/codex.proxy.test.js
git commit -F - <<'EOF'
feat(codex): dedicated upstream path for codex-oauth providers

After redaction the body is translated to the Responses dialect and POSTed
to <base>/responses with the stored ChatGPT token; the stream is translated
back to Anthropic SSE (or folded into one message for stream:false). Host
guard, 401 -> one refresh + replay, 429 passthrough, other errors -> 502
with the backend detail, /v1/models and count_tokens answered locally. The
inspector keeps the translated body; the log line notes model + effort.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B5pssw9PR5KXtxnP2w9u3
EOF
```

---

### Task 8: Dashboard login button, routes, README

**Files:**
- Modify: `src/dashboard.js:140` (routes, insert before the `/__redact/provider/models` block), `:355-356` (top-form auth option), `:397-398` (editor auth option + login box), `:611-614` (provider row), `:654-667` (`openEditor`), `:630-637` (`provPost` gets a sibling `provJson`), after `:682` (handlers)
- Modify: `README.md` (new subsection after "### Response restore")
- Test: `test/codex-dashboard.test.js`

**Interfaces:**
- Consumes: `controller.codexLogin(id) -> Promise<{ url, port }>`, `controller.codexLogout(id) -> publicRegistry`, `controller.providers()` (Task 6).
- Produces: `POST /__redact/providers/codex/login` body `{ id }` -> `{ ok, url, port }` (403 without the panel header, 409 when a login is in progress or port 1455 is busy, 400 otherwise); `POST /__redact/providers/codex/logout` body `{ id }` -> `{ ok, registry }`.

- [ ] **Step 1: Write the failing tests**

Create `test/codex-dashboard.test.js`:

```js
// Dashboard side of the Codex provider: creating a codex-oauth provider from
// the form, the login route (returns the authorize URL and stores the login
// after the callback), the logout route, the CSRF guard, and the panel HTML
// carrying the login controls. The public registry never carries a token.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer } from '../src/proxy.js';
import { createStats } from '../src/stats.js';
import { createRuntime } from '../src/runtime.js';
import { fakeAccessToken, fakeIdToken } from './helpers/codex-fixtures.js';

const panel = { 'content-type': 'application/json', 'x-redact-panel': '1' };

async function boot({ exchange, fetchModels } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codex-dash-'));
  const config = {
    upstreamUrl: null,
    upstreamAuth: 'replace',
    upstreamKey: null,
    configFile: path.join(dir, 'config.json'),
    providersFile: path.join(dir, 'providers.json'),
    redactMode: 'strict',
    redactModeFloor: 'named-only',
    redactDisable: [],
    redactIgnore: [],
    failClosed: true,
    injectNotice: false,
    restoreMarkers: false,
    showRedactedValues: false,
  };
  const runtime = createRuntime({
    config,
    secrets: [],
    codexDeps: {
      port: 0,
      exchange: exchange ?? (async () => ({ access: fakeAccessToken({ accountId: 'acc-5' }), refresh: 'R5', idToken: fakeIdToken({ email: 'dash@example.com' }) })),
      fetchModels: fetchModels ?? (async () => [{ slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low'] }]),
    },
  });
  const server = createProxyServer({
    config,
    redactor: { redactBody: (raw, ct, opts) => runtime.holder.current.redactBody(raw, ct, opts) },
    stats: createStats({ log: () => {} }),
    getUpstream: () => runtime.upstream,
    controller: runtime,
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    runtime,
    providersFile: config.providersFile,
    close: async () => {
      await new Promise((r) => server.close(r));
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

test('create a codex-oauth provider from the form, log in through the route, log out', async () => {
  const app = await boot();
  try {
    let d = await (await fetch(`${app.url}/__redact/providers`, { method: 'POST', headers: panel, body: JSON.stringify({ id: 'codex', auth: 'codex-oauth', url: '', headers: {}, aliases: {} }) })).json();
    assert.ok(d.ok);
    let p = d.registry.providers.find((x) => x.id === 'codex');
    assert.equal(p.url, 'https://chatgpt.com/backend-api/codex');
    assert.equal(p.auth, 'codex-oauth');
    assert.deepEqual(p.codex, { loggedIn: false, email: null, plan: null, expiresAt: null, models: [] });
    assert.equal(app.runtime.upstream.auth, 'codex-oauth'); // first provider becomes active

    const noCsrf = await fetch(`${app.url}/__redact/providers/codex/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 'codex' }) });
    assert.equal(noCsrf.status, 403);

    const bad = await fetch(`${app.url}/__redact/providers/codex/login`, { method: 'POST', headers: panel, body: JSON.stringify({ id: 'missing' }) });
    assert.equal(bad.status, 400);

    d = await (await fetch(`${app.url}/__redact/providers/codex/login`, { method: 'POST', headers: panel, body: JSON.stringify({ id: 'codex' }) })).json();
    assert.ok(d.ok);
    assert.ok(d.url.startsWith('https://auth.openai.com/oauth/authorize?'));
    const state = new URL(d.url).searchParams.get('state');

    const busy = await fetch(`${app.url}/__redact/providers/codex/login`, { method: 'POST', headers: panel, body: JSON.stringify({ id: 'codex' }) });
    assert.equal(busy.status, 409);

    const cb = await fetch(`http://127.0.0.1:${d.port}/auth/callback?code=abc&state=${encodeURIComponent(state)}`);
    assert.equal(cb.status, 200);

    const reg = await (await fetch(`${app.url}/__redact/providers`)).json();
    p = reg.providers.find((x) => x.id === 'codex');
    assert.deepEqual(p.codex, { loggedIn: true, email: 'dash@example.com', plan: 'plus', expiresAt: 4102444800000, models: ['gpt-5.5'] });
    const text = JSON.stringify(reg);
    assert.equal(text.includes('R5'), false);
    assert.equal(text.includes(fakeAccessToken({ accountId: 'acc-5' })), false);
    assert.equal(JSON.parse(fs.readFileSync(app.providersFile, 'utf8')).providers.codex.codex.tokens.refresh, 'R5');

    // the live proxy now serves the plan's models locally
    const models = await (await fetch(`${app.url}/v1/models`)).json();
    assert.deepEqual(models.data.map((m) => m.id), ['gpt-5.5']);

    d = await (await fetch(`${app.url}/__redact/providers/codex/logout`, { method: 'POST', headers: panel, body: JSON.stringify({ id: 'codex' }) })).json();
    assert.ok(d.ok);
    assert.equal(d.registry.providers.find((x) => x.id === 'codex').codex.loggedIn, false);
    const noCsrfOut = await fetch(`${app.url}/__redact/providers/codex/logout`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 'codex' }) });
    assert.equal(noCsrfOut.status, 403);
  } finally {
    await app.close();
  }
});

test('the panel HTML carries the codex-oauth option and the login controls', async () => {
  const app = await boot();
  try {
    const html = await (await fetch(`${app.url}/__redact/`)).text();
    assert.ok(html.includes('id="p_codexlogin"'));
    assert.ok(html.includes('id="p_codexlogout"'));
    assert.ok(html.includes('id="codexstatus"'));
    assert.ok((html.match(/value="codex-oauth"/g) ?? []).length >= 2); // top form + editor
    assert.ok(html.includes("providers/codex/login"));
  } finally {
    await app.close();
  }
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test test/codex-dashboard.test.js`
Expected: FAIL - the login route answers 404 `{"error":"not found"}`; the HTML lacks the controls.

- [ ] **Step 3: Add the routes**

In `src/dashboard.js`, insert before the comment `// Server-side fetch of a provider's real model list` (currently line 141):

```js
  // ---- Codex (ChatGPT subscription) login / logout ----
  // login: starts the PKCE flow (callback listener on localhost:1455) and
  // returns the authorize URL the panel opens in a new tab. The listener
  // stores the tokens in the registry; the panel polls /__redact/providers.
  if (path === '/__redact/providers/codex/login' && method === 'POST') {
    if (!panelGuard()) return json(403, { ok: false, error: 'missing panel header' });
    if (!controller?.codexLogin) return json(404, { error: 'registry not available' });
    return readJson((p) => {
      controller
        .codexLogin(p.id)
        .then((r) => json(200, { ok: true, url: r.url, port: r.port }))
        .catch((err) => {
          const busy = err.code === 'EADDRINUSE' || err.code === 'LOGIN_IN_PROGRESS';
          json(busy ? 409 : 400, { ok: false, error: busy ? `${err.message} (port 1455 busy or a login already open)` : err.message });
        });
    });
  }
  if (path === '/__redact/providers/codex/logout' && method === 'POST') {
    if (!panelGuard()) return json(403, { ok: false, error: 'missing panel header' });
    if (!controller?.codexLogout) return json(404, { error: 'registry not available' });
    return readJson((p) => {
      try {
        json(200, { ok: true, registry: controller.codexLogout(p.id) });
      } catch (err) {
        json(400, { ok: false, error: err.message });
      }
    });
  }
```

- [ ] **Step 4: Add the panel controls**

All edits are inside the `PAGE` template string of `src/dashboard.js`. Use exact string replacement.

(a) Top form auth select - replace

```
          <option value="oauth">oauth &mdash; my Claude subscription (official only)</option>
          </select></div>
```

with

```
          <option value="oauth">oauth &mdash; my Claude subscription (official only)</option>
          <option value="codex-oauth">codex-oauth &mdash; my ChatGPT login (chatgpt.com)</option>
          </select></div>
```

(b) Editor auth select + login box - replace

```
          <select id="p_auth"><option value="replace">replace &mdash; inject key</option><option value="passthrough">passthrough</option><option value="oauth">oauth (official only)</option></select></div>
        <div class="f"><label class="lbl">Key <span class="faint">(replace)</span></label><input id="p_key" type="password" placeholder="blank keeps current"></div>
```

with

```
          <select id="p_auth"><option value="replace">replace &mdash; inject key</option><option value="passthrough">passthrough</option><option value="oauth">oauth (official only)</option><option value="codex-oauth">codex-oauth (ChatGPT login)</option></select></div>
        <div class="f"><label class="lbl">Key <span class="faint">(replace)</span></label><input id="p_key" type="password" placeholder="blank keeps current"></div>
        <div class="f span2 hidec" id="codexbox"><label class="lbl">ChatGPT account</label>
          <div class="caprow"><span id="codexstatus" class="faint">not logged in</span>
            <button class="ghost" id="p_codexlogin" type="button" style="padding:6px 12px;font-size:12px">Login with ChatGPT</button>
            <button class="linkbtn" id="p_codexlogout" type="button" style="color:var(--red)">logout</button></div>
          <div class="hint">Save the provider first. Login opens auth.openai.com in a new tab; the proxy listens on localhost:1455 for the callback (the same port the Codex CLI uses). Tokens are stored in providers.json and never shown here. URL can stay blank (defaults to the Codex backend). Effort map (low/medium/high/max &rarr; Codex level) is edited in providers.json.</div></div>
```

(c) Provider row - replace

```
      +'<td>'+esc(p.auth)+(p.hasKey?' <span class="faint">\\u00b7 key</span>':'')+'</td>'
```

with

```
      +'<td>'+esc(p.auth)+(p.hasKey?' <span class="faint">\\u00b7 key</span>':'')
        +(p.codex&&p.codex.loggedIn?' <span class="faint">\\u00b7 '+esc(p.codex.email||'logged in')+'</span>':(p.codex?' <span class="warn">\\u00b7 not logged in</span>':''))+'</td>'
```

(d) A JSON-returning sibling of `provPost` - insert right after the `provPost` function (after its closing `}` line):

```
async function provJson(pathx,body){
  const r=await fetch(pathx,{method:'POST',headers:{'content-type':'application/json','x-redact-panel':'1'},body:JSON.stringify(body)});
  let d;try{d=await r.json();}catch(e){d={ok:false,error:'bad response '+r.status};}
  if(!('ok' in d))d.ok=r.ok;return d;
}
```

(e) `openEditor` - replace the line

```
  $('modeldl').innerHTML='';$('fetchmsg').textContent='';$('provmsg').textContent='';
```

with

```
  $('modeldl').innerHTML='';$('fetchmsg').textContent='';$('provmsg').textContent='';
  syncCodexBox();
```

(f) Handlers - insert right after the `$('p_fetch').onclick=async()=>{ ... };` block (before `$('p_save').onclick`):

```
// ---------- Codex (ChatGPT subscription) login ----------
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));
function codexStatusText(p){
  const c=p&&p.codex;
  if(!c||!c.loggedIn)return 'not logged in';
  const until=c.expiresAt?new Date(c.expiresAt).toLocaleString():'?';
  return (c.email||'logged in')+' \\u00b7 '+(c.plan||'?')+' \\u00b7 '+c.models.length+' models \\u00b7 token valid until '+until;
}
function syncCodexBox(){
  const on=$('p_auth').value==='codex-oauth';
  $('codexbox').classList.toggle('hidec',!on);
  $('p_key').disabled=on;
  const p=editingId?findProv(editingId):null;
  $('codexstatus').textContent=codexStatusText(p);
  $('codexstatus').className=(p&&p.codex&&p.codex.loggedIn)?'ok':'faint';
}
$('p_auth').addEventListener('change',syncCodexBox);
$('p_codexlogin').onclick=async()=>{
  const id=$('p_id').value.trim();
  if(!id||!findProv(id)){$('provmsg').textContent='save this provider first, then log in';$('provmsg').className='err';return;}
  $('provmsg').textContent='opening ChatGPT login\\u2026';$('provmsg').className='mut';
  const d=await provJson('providers/codex/login',{id});
  if(!d.ok){$('provmsg').textContent='login failed: '+(d.error||'?');$('provmsg').className='err';return;}
  window.open(d.url,'_blank');
  $('provmsg').textContent='waiting for the browser login\\u2026';
  for(let i=0;i<150;i++){
    await sleep(2000);
    await loadProviders();
    const p=findProv(id);
    if(p&&p.codex&&p.codex.loggedIn){syncCodexBox();$('provmsg').textContent='logged in';$('provmsg').className='ok';loadCfg();return;}
  }
  $('provmsg').textContent='login timed out \\u2014 try again';$('provmsg').className='err';
};
$('p_codexlogout').onclick=async()=>{
  const id=$('p_id').value.trim();if(!id)return;
  if(await provPost('providers/codex/logout',{id}))syncCodexBox();
};
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `node --test test/codex-dashboard.test.js`
Expected: PASS (2 tests). Then `npm test` green.

- [ ] **Step 6: Try it by hand (one minute)**

Run `node src/index.js` with a temporary config (`CONFIG_FILE=/tmp/x/config.json PROVIDERS_FILE=/tmp/x/providers.json SECRETS_FILE=/tmp/x/secrets.local LISTEN_ADDR=127.0.0.1:8799`), open `http://127.0.0.1:8799/__redact/`, add a provider with auth `codex-oauth`, save, edit, click **Login with ChatGPT**, complete the browser login. The status line must show the account email, plan and model count. Then point a Claude Code session at it (`ANTHROPIC_BASE_URL=http://127.0.0.1:8799`), pick `gpt-5.6-sol` with `/model`, ask it to run one shell command through a tool. Delete `/tmp/x` afterwards (it holds tokens).

- [ ] **Step 7: README**

In `README.md`, insert after the "### Response restore (`{{NAME}}`) — opt-in" subsection (before "## Dashboard"):

```markdown
### Codex (ChatGPT subscription) provider — `codex-oauth`

Use the GPT models of a ChatGPT Plus/Pro plan from an Anthropic-format client
(Claude Code, Overclock) through the proxy:

1. Dashboard → Providers → **+ New provider**: id `codex`, auth `codex-oauth`
   (the URL can stay blank: it defaults to `https://chatgpt.com/backend-api/codex`). Save.
2. **edit** the provider → **Login with ChatGPT**. A browser tab opens on
   auth.openai.com; the proxy listens on `localhost:1455` for the callback (the
   same port the Codex CLI uses). Tokens are stored in `providers.json` (chmod 600).
3. **activate** it. `/v1/models` now lists the plan's models. `/effort` in Claude
   Code maps low/medium/high/max → low/medium/xhigh/max (edit `effortMap` in
   `providers.json` to change it).

One provider per ChatGPT account; switch with **activate**. Redaction runs on
the Anthropic body before translation, exactly as for every other provider,
and the token only ever goes to chatgpt.com. Reasoning summaries come back as
thinking blocks (the encrypted reasoning rides in the block signature so the
next turn can continue it). `max_tokens`, `temperature` and friends are
dropped: the backend has no equivalent. Using a subscription token outside
the Codex CLI may violate OpenAI's terms — your call.
```

- [ ] **Step 8: Commit**

```bash
git add src/dashboard.js test/codex-dashboard.test.js README.md
git commit -F - <<'EOF'
feat(codex): dashboard login with ChatGPT + docs

codex-oauth auth option in both forms, a login box in the provider editor
(status line, Login with ChatGPT, logout) backed by the new
/__redact/providers/codex/login and /logout routes (CSRF-guarded; 409 when
port 1455 is busy). README section for the provider.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B5pssw9PR5KXtxnP2w9u3
EOF
```

---

## Done criteria

- `npm test` green with every new test file (translate, auth, login, proxy, dashboard, providers/runtime additions).
- The canary test proves the secret (literal and base64) never reaches the mock backend on the codex path.
- A real login from the dashboard stores tokens; a real Claude Code turn with `gpt-5.6-sol` streams text and runs a tool.
- `grep -rn "access\b" src/dashboard.js src/stats.js` shows no token value ever rendered or logged.
