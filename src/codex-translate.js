// Protocol translation between the Anthropic Messages API (what the client
// speaks) and the OpenAI Responses dialect served by the ChatGPT Codex
// backend (chatgpt.com/backend-api/codex). Translation runs AFTER redaction:
// every string that reaches this module has already been scrubbed, so the
// strictness here is about correctness, never about leaks.
//
// Request side: anthropicToCodex(). Response side: SseDecoder,
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
