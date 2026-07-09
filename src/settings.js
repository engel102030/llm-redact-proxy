// Runtime settings persisted to a JSON file so the dashboard can configure the
// provider without editing .env or restarting. Only the tunable fields live
// here; everything else stays env/config driven. The file may hold an
// upstreamKey, so it is written chmod 600 and never committed.
import fs from 'node:fs';
import path from 'node:path';

const ALLOWED = ['upstreamUrl', 'upstreamAuth', 'upstreamKey', 'redactMode', 'restoreMarkers'];

function pickAllowed(obj) {
  const out = {};
  for (const k of ALLOWED) if (obj[k] !== undefined) out[k] = obj[k];
  return out;
}

export function loadSettings(filePath) {
  try {
    return pickAllowed(JSON.parse(fs.readFileSync(filePath, 'utf8')));
  } catch {
    // Missing or malformed file: no persisted settings yet.
    return null;
  }
}

export function saveSettings(filePath, settings) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(pickAllowed(settings), null, 2)}\n`, { mode: 0o600 });
}
