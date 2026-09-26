// Protocol translation between the Anthropic Messages API (what the client
// speaks) and the OpenAI Responses dialect served by the ChatGPT Codex
// backend (chatgpt.com/backend-api/codex). Translation runs AFTER redaction:
// every string that reaches this module has already been scrubbed, so the
// strictness here is about correctness, never about leaks.
//
// Request side: anthropicToCodex(). Response side: SseDecoder,
// CodexReducer, serializeSse(), accumulateMessage(), estimateTokens().
import { createHash } from 'node:crypto';
import { StringDecoder } from 'node:string_decoder';
import { ONE_M_SUFFIX } from './models.js';

// Claude Code sends output_config.effort = low|medium|high|max. The backend
// speaks low|medium|high|xhigh|max|ultra (per model). Claude Code's default
// ("high") lands on xhigh, the level the user runs the Codex CLI at.
export const DEFAULT_EFFORT_MAP = Object.freeze({ low: 'low', medium: 'medium', high: 'xhigh', max: 'max' });
export const DEFAULT_INSTRUCTIONS = 'You are a helpful coding assistant.';

// Fallback when a provider has no fetched model list (visibility "list" only).
// Levels as served by GET /backend-api/codex/models on 2026-09-24 (client 0.156.1).
export const CODEX_DEFAULT_MODELS = [
  { slug: 'gpt-6-astra', displayName: 'GPT-6-Astra', visibility: 'list', defaultLevel: null, levels: ['low', 'medium', 'high', 'xhigh', 'max', 'ultra'] },
  { slug: 'gpt-6-sol', displayName: 'GPT-6-Sol', visibility: 'list', defaultLevel: null, levels: ['low', 'medium', 'high', 'xhigh', 'max', 'ultra'] },
  { slug: 'gpt-6-luna', displayName: 'GPT-6-Luna', visibility: 'list', defaultLevel: null, levels: ['low', 'medium', 'high', 'xhigh', 'max'] },
  { slug: 'gpt-5.6-sol', displayName: 'GPT-5.6-Sol', visibility: 'list', defaultLevel: 'low', levels: ['low', 'medium', 'high', 'xhigh', 'max', 'ultra'] },
  { slug: 'gpt-5.6-terra', displayName: 'GPT-5.6-Terra', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium', 'high', 'xhigh', 'max', 'ultra'] },
  { slug: 'gpt-5.6-luna', displayName: 'GPT-5.6-Luna', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium', 'high', 'xhigh', 'max'] },
  { slug: 'gpt-5.5', displayName: 'GPT-5.5', visibility: 'list', defaultLevel: 'medium', levels: ['low', 'medium', 'high', 'xhigh'] },
];

const LEVEL_ORDER = ['none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max', 'ultra'];

// Proxy-side context pruning. The Codex backend has no equivalent of
// Anthropic's clear_tool_uses edit and Claude Code never prunes on its own,
// so on long sessions every tool call re-sends hundreds of kilotokens of
// stale tool output (measured: 37-59% of a request) plus the encrypted
// reasoning of every past turn (~13%). Pruning only changes what the model
// sees; the client's own transcript is untouched.
//   enabled            master switch
//   triggerTokens      prune only when the request exceeds this (estimate)
//   keepToolUses       the N most recent tool results are never cleared
//   clearAtLeastTokens clear oldest-first until trigger - this, so the
//                      prefix stays cache-stable for many turns afterwards
//   reasoning          "turn": replay only the current tool loop's reasoning;
//                      "all": replay every turn's
export const DEFAULT_PRUNE = Object.freeze({ enabled: true, triggerTokens: 120000, keepToolUses: 8, clearAtLeastTokens: 40000, reasoning: 'turn' });
export const TOOL_RESULT_CLEARED = '[tool result cleared to save context]';

function itemTokens(item) {
  return Math.ceil(Buffer.byteLength(JSON.stringify(item), 'utf8') / 4);
}

// Keep only the reasoning items after the last user message (the current
// tool loop); older turns' encrypted reasoning is dropped.
function scopeReasoningToTurn(input) {
  let lastUser = -1;
  for (let i = 0; i < input.length; i += 1) {
    if (input[i].type === 'message' && input[i].role === 'user') lastUser = i;
  }
  return input.filter((item, i) => item.type !== 'reasoning' || i > lastUser);
}

// Oldest-first clearing of function_call_output items (never the last
// keepToolUses), until the estimate drops to trigger - clearAtLeast.
// Deterministic on the history, so consecutive requests clear the same
// items and the cached prefix only moves when a new batch is cleared.
function clearOldToolResults(input, prune, baseTokens) {
  const positions = [];
  for (let i = 0; i < input.length; i += 1) if (input[i].type === 'function_call_output') positions.push(i);
  const clearable = positions.slice(0, Math.max(0, positions.length - prune.keepToolUses));
  let total = baseTokens;
  for (const item of input) total += itemTokens(item);
  if (total <= prune.triggerTokens || clearable.length === 0) return input;
  const target = prune.triggerTokens - prune.clearAtLeastTokens;
  const out = input.slice();
  for (const i of clearable) {
    if (total <= target) break;
    if (out[i].output === TOOL_RESULT_CLEARED) continue;
    const before = itemTokens(out[i]);
    out[i] = { ...out[i], output: TOOL_RESULT_CLEARED };
    total -= before - itemTokens(out[i]);
  }
  return out;
}

export function normalizePrune(input) {
  const p = { ...DEFAULT_PRUNE };
  if (!isPlainObject(input)) return p;
  if (typeof input.enabled === 'boolean') p.enabled = input.enabled;
  for (const k of ['triggerTokens', 'keepToolUses', 'clearAtLeastTokens']) {
    if (Number.isFinite(input[k]) && input[k] >= 0) p[k] = Math.floor(input[k]);
  }
  if (input.reasoning === 'turn' || input.reasoning === 'all') p.reasoning = input.reasoning;
  return p;
}

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

// function_call_output.output: a plain string when the result is text-only
// (is_error becomes a prefix); a parts array when it carries images, which
// the backend accepts as input_image parts (verified) - screenshots from
// browser tools reach the model.
function toolResultOutput(block) {
  const c = block.content;
  const texts = []; // text runs, merged with newlines
  const parts = []; // { kind: 'text' | 'image', value }
  const pushText = (t) => {
    const last = parts[parts.length - 1];
    if (last && last.kind === 'text') last.value += `\n${t}`;
    else parts.push({ kind: 'text', value: t });
    texts.push(t);
  };
  if (typeof c === 'string') {
    pushText(c);
  } else if (Array.isArray(c)) {
    for (const part of c) {
      if (!isPlainObject(part)) throw new Error('tool_result content parts must be objects');
      if (part.type === 'text' && typeof part.text === 'string') pushText(part.text);
      else if (part.type === 'image') parts.push({ kind: 'image', value: imagePart(part) });
      else if (part.type === 'document') pushText('[document omitted]');
      else if (part.type === 'tool_reference') {
        // Claude Code's ToolSearch result: the tool is already in tools[] on
        // this path (nothing is deferred), so the reference is informational.
        if (typeof part.tool_name !== 'string' || !part.tool_name) throw new Error('tool_reference has no tool_name');
        pushText(`[tool available: ${part.tool_name}]`);
      } else throw new Error(`unsupported tool_result part: ${String(part.type)}`);
    }
  } else if (c !== undefined && c !== null) {
    throw new Error('tool_result content must be a string or an array');
  }
  const prefix = block.is_error === true ? 'ERROR: ' : '';
  if (!parts.some((p) => p.kind === 'image')) return prefix + texts.join('\n');
  if (prefix) {
    if (parts[0].kind === 'text') parts[0].value = prefix + parts[0].value;
    else parts.unshift({ kind: 'text', value: prefix });
  }
  return parts.map((p) => (p.kind === 'text' ? { type: 'input_text', text: p.value } : p.value));
}

// A user-attached document: PDFs (and any base64 payload) become input_file
// (verified against the backend), plain-text sources become text.
function documentPart(block) {
  const src = block.source;
  if (!isPlainObject(src)) throw new Error('document block has no source');
  if (src.type === 'text' && typeof src.data === 'string') return { type: 'input_text', text: src.data };
  if (src.type === 'base64' && typeof src.media_type === 'string' && typeof src.data === 'string') {
    const filename = typeof block.title === 'string' && block.title ? block.title : src.media_type === 'application/pdf' ? 'document.pdf' : 'document';
    return { type: 'input_file', filename, file_data: `data:${src.media_type};base64,${src.data}` };
  }
  throw new Error(`unsupported document source: ${String(src.type)}`);
}

// Claude Code sends its own system prompt as a trailing messages[] entry with
// role "system" when the model id is not a Claude model. The backend rejects
// role "system" input items but accepts "developer", which means the same.
const ROLE_MAP = { user: 'user', assistant: 'assistant', system: 'developer' };

function pushMessage(message, input) {
  if (!isPlainObject(message)) throw new Error('messages entries must be objects');
  const role = ROLE_MAP[message.role];
  if (!role) throw new Error(`unsupported message role: ${String(message.role)}`);
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
      case 'document':
        if (role !== 'user') throw new Error('document blocks are only supported in user messages');
        parts.push(documentPart(block));
        break;
      case 'server_tool_use': {
        // History from an Anthropic provider: the search the model ran there.
        // On this path the hosted web_search tool leaves no such block, so a
        // text note keeps the transcript coherent.
        const query = isPlainObject(block.input) && typeof block.input.query === 'string' ? block.input.query : '';
        parts.push({ type: role === 'assistant' ? 'output_text' : 'input_text', text: block.name === 'web_search' ? `[web search: ${query}]` : `[${String(block.name)}]` });
        break;
      }
      case 'web_search_tool_result':
        break; // the results were already digested into the assistant text
      case 'tool_result':
        if (typeof block.tool_use_id !== 'string' || !block.tool_use_id) throw new Error('tool_result has no tool_use_id');
        flush();
        input.push({ type: 'function_call_output', call_id: block.tool_use_id, output: toolResultOutput(block) });
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
      case 'tool_addition':
        // A system message Claude Code adds after a ToolSearch: the named tool
        // is already in tools[] here, so there is nothing to add.
        break;
      default:
        throw new Error(`unsupported content block type: ${block.type}`);
    }
  }
  flush();
}

// Function tools (those with an input_schema) run on the client and are sent
// as-is; defer_loading is a Claude-only hint, every tool is sent. Server-side
// tools carry a `type` and no schema: Claude's web search maps to the Codex
// hosted web_search tool (verified), every other server tool is dropped.
function toolsToFunctions(tools) {
  if (tools === undefined || tools === null) return [];
  if (!Array.isArray(tools)) throw new Error('tools must be an array');
  const out = [];
  let webSearch = false;
  for (const t of tools) {
    if (!isPlainObject(t)) throw new Error('tools entries must be objects');
    if (!isPlainObject(t.input_schema)) {
      if (typeof t.type === 'string' && t.type.startsWith('web_search')) webSearch = true;
      continue;
    }
    if (typeof t.name !== 'string' || !t.name) throw new Error('tool has no name');
    const fn = { type: 'function', name: t.name };
    if (typeof t.description === 'string') fn.description = t.description;
    fn.parameters = t.input_schema;
    fn.strict = false;
    out.push(fn);
  }
  if (webSearch) out.push({ type: 'web_search' });
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
export function anthropicToCodex(req, { models = null, effortMap = DEFAULT_EFFORT_MAP, prune = DEFAULT_PRUNE } = {}) {
  if (!isPlainObject(req)) throw new Error('request body must be a JSON object');
  if (typeof req.model !== 'string' || !req.model) throw new Error('model is required');
  if (!Array.isArray(req.messages)) throw new Error('messages must be an array');
  const model = req.model.endsWith(ONE_M_SUFFIX) ? req.model.slice(0, -ONE_M_SUFFIX.length) : req.model;

  let input = [];
  for (const message of req.messages) pushMessage(message, input);
  const tools = toolsToFunctions(req.tools);
  const instructions = systemToInstructions(req.system);
  const p = normalizePrune(prune);
  if (p.enabled) {
    if (p.reasoning === 'turn') input = scopeReasoningToTurn(input);
    const baseTokens = Math.ceil((Buffer.byteLength(instructions, 'utf8') + Buffer.byteLength(JSON.stringify(tools), 'utf8')) / 4);
    input = clearOldToolResults(input, p, baseTokens);
  }
  const { choice, parallel } = mapToolChoice(req.tool_choice, tools.length);

  const known = findModel(models, model);
  const requested = isPlainObject(req.output_config) ? req.output_config.effort : undefined;
  const effort = mapEffort(requested, { effortMap, levels: known?.levels ?? null }) ?? known?.defaultLevel ?? 'medium';

  const out = {
    model,
    instructions,
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

// ---------------------------------------------------------------------------
// Response side
// ---------------------------------------------------------------------------

// A tool-call done frame repeats the FULL arguments string (a large Write is
// megabytes), so the cap on an incomplete frame matches the buffered-response cap.
export const MAX_SSE_FRAME_BYTES = 8 * 1024 * 1024;

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
  #inputEstimate;
  #started = false;
  #done = false;
  #nextIndex = 0;
  #open = new Map(); // output_index -> { index, kind, parts, argsSeen }
  #sawToolCall = false;

  // inputEstimate: local estimate of the request size, shown in message_start
  // so the client's context meter does not drop to 0 while streaming (the
  // real numbers only arrive with response.completed).
  constructor({ messageId, model, inputEstimate = 0 }) {
    this.#messageId = messageId;
    this.#model = model;
    this.#inputEstimate = Number.isFinite(inputEstimate) && inputEstimate > 0 ? Math.round(inputEstimate) : 0;
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
              message: { id: this.#messageId, type: 'message', role: 'assistant', model: this.#model, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: this.#inputEstimate, output_tokens: 0 } },
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
      // back verbatim next turn and the translator replays it (request side).
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
    // Anthropic semantics: input_tokens is the UNCACHED input; the client adds
    // cache_read + cache_creation to it for its context meter. The backend
    // reports input_tokens as the total with cached_tokens as a subset.
    const u = ev.response?.usage ?? {};
    const total = num(u.input_tokens);
    const cached = Math.min(total, num(u.input_tokens_details?.cached_tokens));
    const usage = { input_tokens: total - cached, output_tokens: num(u.output_tokens), cache_read_input_tokens: cached, cache_creation_input_tokens: 0 };
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
