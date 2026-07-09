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

// Tag each model id with "[1m]" (except the NO_ONE_M families). The display
// name is left clean; nothing is dropped or duplicated. Returns a new array.
export function tagModelIds(models) {
  return models.map((m) => {
    if (m && typeof m.id === 'string' && !NO_ONE_M.test(m.id) && !m.id.endsWith('[1m]')) {
      return { ...m, id: `${m.id}[1m]` };
    }
    return m;
  });
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

// Decide the /v1/models response. If the gateway returned a usable list
// (status 200 with a data array), tag its ids. Otherwise synthesize the
// canonical list. Always yields a 200 the host can build its picker from.
export function buildModelsResponse(upstreamStatus, rawBody) {
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
