# Codex (ChatGPT subscription) provider — design

Date: 2026-09-24. Status: approved in conversation, ready for an implementation plan.

## Goal

Let an Anthropic-format client (Claude Code, Overclock) use a ChatGPT
subscription's Codex models (gpt-5.6-*, gpt-5.5) through the local
redaction proxy. The user logs in from the dashboard with their ChatGPT
account; several accounts become several providers, switched manually with
"activate". Redaction is untouched: it runs on the Anthropic body BEFORE any
translation, exactly as for every other provider.

Non-goals: routing the Codex CLI itself through the proxy, automatic
account rotation on rate limits, an effort UI (the map lives in
`providers.json`), Codex "ultra" reasoning (needs Codex's multi-agent
runtime).

## Verified facts (spikes run 2026-09-24 against the live backend)

- Endpoint: `POST https://chatgpt.com/backend-api/codex/responses`, OpenAI
  Responses API dialect, SSE. Required headers: `Authorization: Bearer
  <access>`, `chatgpt-account-id: <account_id>`, `OpenAI-Beta:
  responses=experimental`, `originator: codex_cli_rs`, a Codex-like
  `User-Agent`, `session_id`.
- The SSE response carries NO `content-type` header. Do not depend on it.
- `max_output_tokens` is rejected: `400 {"detail":"Unsupported parameter:
  max_output_tokens"}`. Drop `max_tokens`.
- Arbitrary `instructions` text is accepted.
- With `store:false` + `include:["reasoning.encrypted_content"]`, the
  reasoning item (`response.output_item.done`, `item.type == "reasoning"`)
  carries `encrypted_content` (~1.3 KB for a trivial thought) and `summary`
  (may be an empty array). Replaying `{type:"reasoning", summary,
  encrypted_content}` in the next turn's `input` works.
- Function calls stream as `response.output_item.added` (function_call) →
  `response.function_call_arguments.delta`* → `...arguments.done` →
  `response.output_item.done` (item keys: id, type, status, arguments,
  call_id, name). Replaying `{type:"function_call", call_id, name,
  arguments}` + `{type:"function_call_output", call_id, output}` WITHOUT the
  `fc_...` item id works.
- `response.completed` carries `response.usage` (`input_tokens`,
  `output_tokens`, `output_tokens_details.reasoning_tokens`,
  `input_tokens_details.cached_tokens`) and an empty `output`.
- Model list: `GET https://chatgpt.com/backend-api/codex/models?client_version=0.145.0`
  → `{ models: [{ slug, display_name, visibility: "list"|"hide",
  default_reasoning_level, supported_reasoning_levels: [{effort,
  description}], ... }] }`. Plus plan today: gpt-5.6-sol / gpt-5.6-terra /
  gpt-5.6-luna (low, medium, high, xhigh, max[, ultra]) and gpt-5.5 (low..xhigh).
- OAuth: authorize at `https://auth.openai.com/oauth/authorize` (PKCE S256,
  client_id `app_EMoamEEZ73f0CkXaXp7hrann`, redirect
  `http://localhost:1455/auth/callback`, scope `openid profile email
  offline_access`, `id_token_add_organizations=true`,
  `codex_cli_simplified_flow=true`, `originator=codex_cli_rs`); token
  exchange `POST /oauth/token` (form: `grant_type=authorization_code`,
  `code`, `redirect_uri`, `client_id`, `code_verifier`); refresh `POST
  /oauth/token` (JSON: `client_id`, `grant_type=refresh_token`,
  `refresh_token`, `scope=openid profile email`) → `{id_token, access_token,
  refresh_token}`. `account_id`, email and plan come from the
  `https://api.openai.com/auth` / `profile` claims of the access/id token.
- Claude Code 2.1.281 ALWAYS sends `output_config.effort` (default `high`;
  `low|medium|high|max` pass through from `/effort` or
  `CLAUDE_CODE_EFFORT_LEVEL`), `thinking: {type:"adaptive", display:"omitted"}`,
  `max_tokens`, `metadata.user_id`, `context_management`, tools as
  `{name, description, input_schema[, defer_loading]}`, `system` as an array
  of text blocks.

## 1. Architecture

- New provider auth mode `codex-oauth` in the registry (`src/providers.js`).
  A provider record gains:
  - `url`: defaults to `https://chatgpt.com/backend-api/codex`.
  - `codex.tokens`: `{ access, refresh, idToken, accountId, expiresAt }`.
  - `codex.account`: `{ email, plan }` (display only).
  - `codex.models`: the list fetched at login (slug, display name,
    visibility, default level, supported levels) + `fetchedAt`.
  - `effortMap`: `{ low, medium, high, max }` → Codex level. Default
    `{ low:"low", medium:"medium", high:"xhigh", max:"max" }`.
- Request flow: client (Anthropic Messages) → redaction (unchanged) →
  `up.auth === 'codex-oauth'` → `handleCodexUpstream` in `src/proxy.js`:
  translate → `POST <url>/responses` with the token → Responses SSE →
  translate back → client. The generic forward path never runs for this
  mode.
- Host guard (defence in depth, checked in `runtime.js` when configuring
  and again in the handler): the token is only ever sent to `chatgpt.com`,
  `*.chatgpt.com` or a loopback address (tests). Anything else → 400.
- New files: `src/codex-auth.js` (PKCE URL, code exchange, refresh, claim
  parsing, host guard, request headers), `src/codex-translate.js` (request
  translation, SSE decoder, stream reducer, non-stream accumulation, local
  token estimate). Changed: `providers.js`, `runtime.js`, `proxy.js`,
  `dashboard.js`.
- `publicRegistry()` exposes for a codex provider ONLY: `codex: { loggedIn,
  email, plan, expiresAt, models: [slug...] }`. Never a token.

## 2. Login from the dashboard

- When auth `codex-oauth` is selected the key field is hidden; the form
  shows a **Login with ChatGPT** button, a status line (email, plan, token
  validity, model count) and **Logout**.
- `POST /__redact/providers/<id>/codex/login` (panel CSRF guard): generates
  `state` + PKCE verifier/challenge, starts a one-shot HTTP listener on
  `127.0.0.1:1455` (fixed by OpenAI's registered redirect URI; 5 minute
  timeout; `409` if the port is busy, e.g. the Codex app is mid-login),
  returns `{ url }`. The panel opens it in a new tab and polls the registry.
- Callback `GET /auth/callback?code&state` on the listener: validates
  `state`, exchanges the code, parses claims (accountId, email, plan),
  fetches the model list, stores everything in the provider (saved through
  the existing `saveProviders`, chmod 600), answers a tiny HTML "Logged in
  as <email>, you can close this tab", then closes the listener.
  Any failure answers an HTML error and closes the listener; nothing is
  stored.
- `POST /__redact/providers/<id>/codex/logout` clears `codex.tokens`,
  `codex.account` and `codex.models`.
- Refresh: proactively when `expiresAt - 5 min <= now`, and once on a
  backend `401` (replay the request with the new token). Rotated tokens are
  persisted. Refresh failure → `502 { error: { type: "no_codex_oauth" } }`
  telling the user to log in again from the dashboard.
- Tokens never appear in logs, in the public registry view, in the stats
  feed or in the inspector (which only stores bodies).

## 3. Request translation: Anthropic Messages → Responses

- `model`: alias resolved through the provider map, `[1m]` suffix stripped.
- `system` (string or text blocks) → `instructions` (blocks joined with a
  blank line). Empty → a short default sentence.
- `messages` → `input`:
  - user text → `{type:"message", role:"user", content:[{type:"input_text", text}]}`
  - user image (base64 source) → `{type:"input_image", image_url:"data:<media>;base64,<data>"}`
  - `tool_result` → `{type:"function_call_output", call_id: tool_use_id,
    output}`; `output` is the text content joined; an image inside becomes
    the literal `[image omitted]`; `is_error` is prefixed as `ERROR: `.
  - assistant text → `{type:"message", role:"assistant", content:[{type:"output_text", text}]}`
  - `tool_use` → `{type:"function_call", call_id: id, name, arguments: JSON.stringify(input)}`
  - `thinking` with a non-empty `signature` → `{type:"reasoning",
    summary: text ? [{type:"summary_text", text}] : [], encrypted_content: signature}`
  - `thinking` without signature, `redacted_thinking` → dropped.
- `tools`: only entries with `input_schema` (function tools) →
  `{type:"function", name, description, parameters: input_schema, strict:false}`.
  `defer_loading` is removed (all tools are sent). Server tools (entries
  with a `type`) are dropped.
- `tool_choice`: `auto`→`"auto"`, `any`→`"required"`, `tool`→`{type:"function", name}`,
  `none`→`"none"`. Absent → omitted.
- `output_config.effort` → `reasoning.effort` through `effortMap`, then
  clamped to the highest level the model supports (from `codex.models`;
  unknown model → sent as mapped). Absent → the model's default level from the
  fetched list, else `medium` (every Codex model supports it).
  `reasoning.summary` is always `"auto"`.
- Fixed fields: `store:false`, `stream:true` (always; the client's `stream`
  only decides how the proxy answers), `include:["reasoning.encrypted_content"]`,
  `parallel_tool_calls:true`, `prompt_cache_key: sha256(metadata.user_id)`
  hex (omitted when there is no `metadata.user_id`).
- Dropped: `max_tokens`, `temperature`, `top_p`, `top_k`, `stop_sequences`,
  `metadata`, `thinking`, `context_management`, `service_tier`, every
  `cache_control`.
- Strictness: an unknown content block type or a malformed block throws →
  the proxy answers `400 invalid_request_error` and nothing is forwarded
  (fail closed). Unknown top-level fields are dropped (redaction already ran
  on the whole body, so this is a correctness rule, not a leak rule).

## 4. Response translation: Responses SSE → Anthropic SSE

- Incremental SSE decoder over the byte stream (frames split on blank
  lines, `data:` lines joined, 1 MB frame cap, `[DONE]` ignored).
- Reducer (one instance per request) emits Anthropic events:
  - `response.created` → `message_start` (id `msg_<random>`, `model` = the
    id the client asked for, `role: assistant`, `content: []`, zero usage).
  - reasoning item added → `content_block_start {type:"thinking", thinking:"", signature:""}`;
    `response.reasoning_summary_text.delta` → `thinking_delta`; a new
    summary part after the first is prefixed with `\n\n`; item done →
    `signature_delta` with `encrypted_content` (empty string when absent)
    then `content_block_stop`. An empty summary still yields the block
    (empty text + signature) so the next turn can replay it.
  - message item + `content_part.added` (output_text) → `content_block_start {type:"text"}`;
    `response.output_text.delta` → `text_delta`; `content_part.done` → `content_block_stop`.
  - function_call item added → `content_block_start {type:"tool_use", id: call_id, name, input:{}}`;
    `response.function_call_arguments.delta` → `input_json_delta`; item done →
    `content_block_stop` (if no delta was seen, the final `arguments` string
    is emitted as one `input_json_delta` first).
  - `response.completed` → `message_delta { stop_reason: tool_use if any
    function_call else end_turn, usage: { input_tokens, output_tokens,
    cache_read_input_tokens } }` then `message_stop`.
  - `response.incomplete` → same, with `stop_reason: "max_tokens"`.
  - `response.failed` / `error` → an Anthropic `error` SSE event, then the
    stream ends; if nothing was written yet → `502` JSON instead.
  - Unknown event types are ignored; a delta for a block that is not open,
    or a second `response.created`, throws → the stream is aborted with an
    `error` event (fail closed; the proxy never invents content).
- Non-streaming client (`stream:false`): the same reducer feeds an
  accumulator that returns one Anthropic message JSON (8 MB cap).
- The backend's missing `content-type` is ignored: HTTP 200 is treated as
  SSE.
- Block indexes are assigned sequentially per message, as Anthropic does.

## 5. Locally answered endpoints (no token leaves, no network)

- `GET /v1/models` → the provider's stored models with visibility `list`
  (plus alias names), `display_name` from the backend, NO `[1m]` tag. No
  stored models → the fixed four (gpt-5.6-sol, gpt-5.6-terra, gpt-5.6-luna, gpt-5.5).
- `POST /v1/messages/count_tokens` → `{ input_tokens }` estimated locally
  (UTF-8 bytes / 4 of the translated request).
- `POST /v1/messages` → the translated path. Everything else → 404.

## 6. Errors, limits, observability

- Backend `401` → refresh + one replay; still `401` → `502 no_codex_oauth`.
- Backend `429` → forwarded as `429` with the backend's `detail` text
  (Claude Code shows its rate-limit message). No account rotation.
- Other `4xx/5xx` → `502 upstream_error` with the `detail` text (16 KB cap).
- Upstream timeout: the existing 10 minutes. Non-stream buffer cap 8 MB.
- Stats: `rememberReq` stores the TRANSLATED body (what actually left);
  redaction counters unchanged. Per-request log line:
  `codex model=<slug> effort=<level> status=<n>`. Never a token.

## 7. Tests (written first)

- `test/codex-translate.test.js`: request mapping (system, every block
  type, tool_use/tool_result pairing, thinking→reasoning, tools with
  `defer_loading`, server tools dropped, tool_choice, effort map + clamp,
  dropped fields, `[1m]` strip, unknown block throws); reducer fed with the
  real event sequences captured in the spikes (text, reasoning with empty
  summary, function_call with argument deltas), out-of-order delta throws,
  `incomplete`, `failed`, non-stream accumulation.
- `test/codex-auth.test.js`: authorize URL (PKCE S256, state, fixed
  redirect), code exchange and refresh with an injected `post` and
  `nowMs` (rotation persisted, skew), claim parsing → account, host guard,
  `publicRegistry` never contains a token.
- `test/codex.proxy.test.js` (loopback mock upstream): **canary** (literal
  + base64 secret absent from the body the mock received), fail-closed
  (untranslatable body → 400 and the mock receives nothing), SSE translated
  back, `401` → refresh → replay, `/v1/models` and `count_tokens` never hit
  the mock, `max_tokens` absent from what left, `429` passthrough.
- `test/codex-login.test.js`: login endpoint returns the right URL and
  starts the listener on an injectable port; wrong `state` → 400 and nothing
  stored; good callback with a fake token endpoint and fake models endpoint
  → tokens + models stored, public view clean.
