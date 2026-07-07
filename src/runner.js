// Local command runner for the MCP "run" tool. The model sends a command
// with {{NAME}} placeholders; we substitute the real values (and expose them
// as environment variables), execute LOCALLY, and return output that has
// been redacted by the same engine the proxy uses. The literal value never
// travels back into the model context.
import { spawn } from 'node:child_process';

const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_TIMEOUT_MS = 600_000;
const MAX_OUTPUT_CHARS = 200_000;

const PLACEHOLDER_RE = /\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}/g;

export function createRunner({ getSecrets, getRedactor }) {
  async function run({ command, timeoutMs = DEFAULT_TIMEOUT_MS }) {
    if (typeof command !== 'string' || !command.trim()) {
      throw new Error('command must be a non-empty string');
    }
    const timeout = Math.min(Math.max(1, Number(timeoutMs) || DEFAULT_TIMEOUT_MS), MAX_TIMEOUT_MS);

    const secrets = getSecrets();
    const byName = new Map(secrets.map((s) => [s.name, s.value]));

    const unknown = [];
    const resolved = command.replace(PLACEHOLDER_RE, (whole, name) => {
      if (!byName.has(name)) {
        unknown.push(name);
        return whole;
      }
      return byName.get(name);
    });
    if (unknown.length > 0) {
      // Refuse to run rather than execute a command with a literal
      // "{{NAME}}" in it - that is never what the model intended.
      throw new Error(
        `unknown secret placeholder(s): ${unknown.join(', ')}. ` +
          'Use secret_list to see available names or secret_add to register one.',
      );
    }

    const env = { ...process.env };
    for (const { name, value } of secrets) env[name] = value;

    const result = await new Promise((resolve, reject) => {
      const child = spawn('/bin/sh', ['-c', resolved], { env });
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeout);
      timer.unref();

      child.stdout.on('data', (d) => {
        if (stdout.length < MAX_OUTPUT_CHARS) stdout += d.toString('utf8');
      });
      child.stderr.on('data', (d) => {
        if (stderr.length < MAX_OUTPUT_CHARS) stderr += d.toString('utf8');
      });
      child.on('error', (err) => {
        clearTimeout(timer);
        reject(new Error(`failed to spawn command: ${err.message}`));
      });
      child.on('close', (code, signal) => {
        clearTimeout(timer);
        resolve({ stdout, stderr, code, signal, timedOut });
      });
    });

    let output = result.stdout;
    if (result.stderr) output += `${output ? '\n' : ''}[stderr]\n${result.stderr}`;
    if (output.length > MAX_OUTPUT_CHARS) {
      output = `${output.slice(0, MAX_OUTPUT_CHARS)}\n[output truncated]`;
    }
    if (result.timedOut) output += `\n[killed: timeout after ${timeout}ms]`;

    // Redact BEFORE the output ever leaves this function.
    const { body: redacted } = getRedactor().redactBody(output, 'text/plain');

    return {
      output: redacted,
      exitCode: result.code ?? (result.timedOut ? 124 : -1),
      timedOut: result.timedOut,
    };
  }

  return { run };
}
