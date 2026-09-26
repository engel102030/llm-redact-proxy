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
