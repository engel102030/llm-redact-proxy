// The runner executes commands LOCALLY with real secret values substituted
// in, and returns output that has already been redacted. The secret must
// never appear in anything the runner returns.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRunner } from '../src/runner.js';
import { createRedactor } from '../src/redact.js';

const SECRET = { name: 'RUNNER_TOKEN', value: 'runner-secret-value-123xyz' };

function makeRunner(secrets = [SECRET]) {
  const redactor = createRedactor({ secrets });
  return createRunner({
    getSecrets: () => secrets,
    getRedactor: () => redactor,
  });
}

test('substitutes {{NAME}} placeholders and redacts the output', async () => {
  const runner = makeRunner();
  const result = await runner.run({ command: 'echo "token is {{RUNNER_TOKEN}}"' });
  assert.equal(result.exitCode, 0);
  assert.ok(result.output.includes('[REDACTED:RUNNER_TOKEN]'));
  assert.ok(!result.output.includes(SECRET.value), 'secret leaked in runner output');
});

test('secrets are also injected as environment variables', async () => {
  const runner = makeRunner();
  const result = await runner.run({ command: 'printf %s "$RUNNER_TOKEN"' });
  assert.equal(result.exitCode, 0);
  assert.ok(result.output.includes('[REDACTED:RUNNER_TOKEN]'));
  assert.ok(!result.output.includes(SECRET.value));
});

test('command output without secrets passes through', async () => {
  const runner = makeRunner();
  const result = await runner.run({ command: 'echo hello world' });
  assert.equal(result.exitCode, 0);
  assert.ok(result.output.includes('hello world'));
});

test('exit code is reported', async () => {
  const runner = makeRunner();
  const result = await runner.run({ command: 'exit 3' });
  assert.equal(result.exitCode, 3);
});

test('stderr is captured and redacted too', async () => {
  const runner = makeRunner();
  const result = await runner.run({ command: 'echo "err {{RUNNER_TOKEN}}" 1>&2' });
  assert.ok(result.output.includes('[REDACTED:RUNNER_TOKEN]'));
  assert.ok(!result.output.includes(SECRET.value));
});

test('timeout kills the process', async () => {
  const runner = makeRunner();
  const result = await runner.run({ command: 'sleep 30', timeoutMs: 200 });
  assert.equal(result.timedOut, true);
  assert.notEqual(result.exitCode, 0);
});

test('unknown placeholder is a hard error, command does not run', async () => {
  const runner = makeRunner();
  await assert.rejects(
    () => runner.run({ command: 'echo {{DOES_NOT_EXIST}}' }),
    /DOES_NOT_EXIST/,
  );
});

test('no result field ever contains the secret value', async () => {
  const runner = makeRunner();
  const results = [];
  results.push(await runner.run({ command: 'echo {{RUNNER_TOKEN}}' }));
  results.push(await runner.run({ command: 'printf %s "$RUNNER_TOKEN" 1>&2' }));
  results.push(await runner.run({ command: 'echo plain' }));
  const transcript = JSON.stringify(results);
  assert.ok(!transcript.includes(SECRET.value), 'secret leaked in runner transcript');
});
