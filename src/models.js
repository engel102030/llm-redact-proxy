// The canonical Claude model list, as the OFFICIAL Anthropic /v1/models returns
// it (captured from api.anthropic.com). Many gateways only proxy /v1/messages
// and answer /v1/models with an error (e.g. 501 "not supported"); a host like
// Overclock builds its model picker from /v1/models and is then left empty. The
// proxy synthesizes THIS list in that case - the models a Claude Code user sees
// are always these, regardless of which gateway relays the message call.
//
// Keep in sync with the official API. Ordered newest-first, matching upstream.
export const CANONICAL_MODELS = [
  { id: 'claude-sonnet-5', display_name: 'Claude Sonnet 5', type: 'model', created_at: '2026-06-29T00:00:00Z' },
  { id: 'claude-fable-5', display_name: 'Claude Fable 5', type: 'model', created_at: '2026-06-07T00:00:00Z' },
  { id: 'claude-opus-4-8', display_name: 'Claude Opus 4.8', type: 'model', created_at: '2026-05-28T00:00:00Z' },
  { id: 'claude-opus-4-7', display_name: 'Claude Opus 4.7', type: 'model', created_at: '2026-04-14T00:00:00Z' },
  { id: 'claude-sonnet-4-6', display_name: 'Claude Sonnet 4.6', type: 'model', created_at: '2026-02-17T00:00:00Z' },
  { id: 'claude-opus-4-6', display_name: 'Claude Opus 4.6', type: 'model', created_at: '2026-02-04T00:00:00Z' },
  { id: 'claude-opus-4-5-20251101', display_name: 'Claude Opus 4.5', type: 'model', created_at: '2025-11-24T00:00:00Z' },
  { id: 'claude-haiku-4-5-20251001', display_name: 'Claude Haiku 4.5', type: 'model', created_at: '2025-10-15T00:00:00Z' },
  { id: 'claude-sonnet-4-5-20250929', display_name: 'Claude Sonnet 4.5', type: 'model', created_at: '2025-09-29T00:00:00Z' },
  { id: 'claude-opus-4-1-20250805', display_name: 'Claude Opus 4.1', type: 'model', created_at: '2025-08-05T00:00:00Z' },
];

// Models that do NOT support a 1M-context window: Haiku (any) and Sonnet below
// 5 (sonnet-4.x). Everything else (Opus, Sonnet 5, Fable 5) gets the "[1m]"
// suffix Claude Code reads to open a 1M local window.
const NO_ONE_M = /haiku|sonnet-4/i;

// The "[1m]" marker the proxy appends to model ids in /v1/models. It is a UI
// signal ("open a 1M local window"), NOT a real model id - no upstream knows a
// model literally called "...[1m]", so it MUST be stripped from an outgoing
// request body (see stripOneMTag) before the message call leaves the machine.
export const ONE_M_SUFFIX = '[1m]';

// Beta flag an upstream needs to accept a >200k-token context window. Added to
// the request only when a "[1m]" tag was stripped (and only on non-oauth paths:
// a Claude subscription is not eligible for the 1M beta - see claude-auth.js).
export const ONE_M_BETA = 'context-1m-2025-08-07';

// Tag each model id with "[1m]" (except the NO_ONE_M families). The display
// name is left clean; nothing is dropped or duplicated. Returns a new array.
export function tagModelIds(models) {
  return models.map((m) => {
    if (m && typeof m.id === 'string' && !NO_ONE_M.test(m.id) && !m.id.endsWith(ONE_M_SUFFIX)) {
      return { ...m, id: `${m.id}${ONE_M_SUFFIX}` };
    }
    return m;
  });
}

// Strip a trailing "[1m]" from the request body's `model` field. The tag is the
// proxy's own /v1/models marker echoed back by the client; upstreams reject the
// literal id ("model ...[1m] is not enabled"). Returns the (possibly rewritten)
// body text and whether a tag was removed. Defensive: any JSON problem leaves
// the body byte-identical (oneM=false), so redaction/forwarding is never broken
// by this cosmetic fix - a non-JSON body simply has no model to rewrite.
export function stripOneMTag(bodyText) {
  try {
    const parsed = JSON.parse(bodyText);
    if (parsed && typeof parsed.model === 'string' && parsed.model.endsWith(ONE_M_SUFFIX)) {
      parsed.model = parsed.model.slice(0, -ONE_M_SUFFIX.length);
      return { body: JSON.stringify(parsed), oneM: true };
    }
  } catch {
    // Not JSON / unparseable - leave the body untouched.
  }
  return { body: bodyText, oneM: false };
}

// Merge the 1M-context beta flag into an existing anthropic-beta header, keeping
// any flags already present and never duplicating. Mutates and returns headers.
export function addOneMBeta(headers) {
  const present = String(headers['anthropic-beta'] ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (!present.includes(ONE_M_BETA)) present.push(ONE_M_BETA);
  headers['anthropic-beta'] = present.join(',');
  return headers;
}

// Wrap a model array in the official /v1/models envelope.
export function modelsEnvelope(data) {
  return {
    data,
    has_more: false,
    first_id: data[0]?.id ?? null,
    last_id: data[data.length - 1]?.id ?? null,
  };
}

// Decide the /v1/models response. Priority:
//  1. The active provider's model ALIASES, when set - exposes the custom names
//     the client will send back (the proxy maps them to the real upstream ids).
//     Alias names are returned CLEAN (no "[1m]"): these reseller gateways serve
//     up to their own window, not 1M, and a "[1m]" tag would balloon context.
//  2. A usable upstream list (status 200 with a data array) - tag its ids.
//  3. Otherwise synthesize the canonical list.
// Always yields a 200 the host can build its picker from.
export function buildModelsResponse(upstreamStatus, rawBody, aliases = null) {
  if (aliases && Object.keys(aliases).length > 0) {
    const data = Object.keys(aliases).map((id) => ({
      id,
      display_name: id,
      type: 'model',
      created_at: '1970-01-01T00:00:00Z',
    }));
    return { status: 200, synthesized: 'aliases', body: modelsEnvelope(data) };
  }
  let parsed = null;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    parsed = null;
  }
  const usable = upstreamStatus === 200 && parsed && Array.isArray(parsed.data);
  if (usable) {
    return { status: 200, synthesized: false, body: { ...parsed, data: tagModelIds(parsed.data) } };
  }
  return { status: 200, synthesized: true, body: modelsEnvelope(tagModelIds(CANONICAL_MODELS)) };
}
