// Unit tests for the model list helpers: [1m] tagging rule and the
// synthesize-when-the-gateway-has-no-/v1/models fallback.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CANONICAL_MODELS,
  tagModelIds,
  modelsEnvelope,
  buildModelsResponse,
} from '../src/models.js';

test('tagModelIds tags 1M families, leaves Haiku and Sonnet<5 base', () => {
  const out = tagModelIds([
    { id: 'claude-opus-4-8' },
    { id: 'claude-opus-4-1-20250805' },
    { id: 'claude-sonnet-5' },
    { id: 'claude-fable-5' },
    { id: 'claude-sonnet-4-6' },
    { id: 'claude-sonnet-4-5-20250929' },
    { id: 'claude-haiku-4-5-20251001' },
  ]);
  const ids = out.map((m) => m.id);
  assert.deepEqual(ids, [
    'claude-opus-4-8[1m]',
    'claude-opus-4-1-20250805[1m]',
    'claude-sonnet-5[1m]',
    'claude-fable-5[1m]',
    'claude-sonnet-4-6',
    'claude-sonnet-4-5-20250929',
    'claude-haiku-4-5-20251001',
  ]);
});

test('tagModelIds is idempotent (no double [1m]) and keeps display names clean', () => {
  const once = tagModelIds([{ id: 'claude-opus-4-8', display_name: 'Claude Opus 4.8' }]);
  const twice = tagModelIds(once);
  assert.equal(twice[0].id, 'claude-opus-4-8[1m]');
  assert.equal(twice[0].display_name, 'Claude Opus 4.8');
});

test('every canonical Opus/Sonnet5/Fable id supports 1M; Haiku and Sonnet4.x do not', () => {
  for (const src of CANONICAL_MODELS) {
    const [tagged] = tagModelIds([src]);
    const isNoOneM = /haiku|sonnet-4/i.test(src.id);
    assert.equal(tagged.id.endsWith('[1m]'), !isNoOneM, `${src.id} tag mismatch`);
  }
});

test('buildModelsResponse tags a usable upstream list, no synthesis', () => {
  const raw = JSON.stringify({ data: [{ id: 'claude-opus-4-8', type: 'model' }], has_more: false });
  const r = buildModelsResponse(200, raw);
  assert.equal(r.synthesized, false);
  assert.equal(r.status, 200);
  assert.equal(r.body.data[0].id, 'claude-opus-4-8[1m]');
});

test('buildModelsResponse synthesizes the canonical list on a 501 error body', () => {
  const raw = JSON.stringify({ type: 'error', error: { type: 'not_implemented' } });
  const r = buildModelsResponse(501, raw);
  assert.equal(r.synthesized, true);
  assert.equal(r.status, 200);
  assert.equal(r.body.data.length, CANONICAL_MODELS.length);
  assert.ok(r.body.data.map((m) => m.id).includes('claude-opus-4-8[1m]'));
});

test('buildModelsResponse synthesizes on a 200 that is not a list (no data array)', () => {
  const r = buildModelsResponse(200, JSON.stringify({ ok: true }));
  assert.equal(r.synthesized, true);
  assert.equal(r.body.data.length, CANONICAL_MODELS.length);
});

test('buildModelsResponse synthesizes on unparseable body', () => {
  const r = buildModelsResponse(200, 'not json <<<');
  assert.equal(r.synthesized, true);
  assert.equal(r.body.data.length, CANONICAL_MODELS.length);
});

test('modelsEnvelope first_id/last_id reference the array ends', () => {
  const env = modelsEnvelope([{ id: 'a' }, { id: 'b' }, { id: 'c' }]);
  assert.equal(env.first_id, 'a');
  assert.equal(env.last_id, 'c');
  assert.equal(env.has_more, false);
});
