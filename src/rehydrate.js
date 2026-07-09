// Response rehydration (OPT-IN, default off). The INVERSE of redaction: when the
// model writes a {{NAME}} placeholder in its reply, the proxy substitutes the
// real secret VALUE back in before handing the response to the CLI - so a Bash
// command the model emits runs with the true credential locally, and the vendor
// never saw it (the request was redacted on the way out).
//
// SECURITY: this re-hydrates a secret into the LOCAL transcript and screen. It is
// off by default and only substitutes {{NAME}} for a REGISTERED secret name. It
// does NOT restore [REDACTED:NAME] markers (that would leak values the model only
// echoed). Layer-B rule markers have no value and are never restorable.
//
// Streaming-safe: a marker can arrive split across SSE deltas ("{{VIBE" then
// "CODE_KEY}}"); the field replacer carries a bounded tail so it still matches.

const MARKER_SOURCE = '\\{\\{([A-Za-z_][A-Za-z0-9_]*)\\}\\}';

// Build a name -> value map from the registered secrets. Empty values are
// skipped (nothing to restore to).
export function buildMarkerMap(secrets = []) {
  const map = new Map();
  for (const s of secrets) {
    if (s && s.name && typeof s.value === 'string' && s.value.length > 0) map.set(s.name, s.value);
  }
  return map;
}

// JSON string-escape a value WITHOUT the surrounding quotes, so it can be
// spliced inside an existing JSON string (used for tool_use input_json_delta,
// whose partial_json field is a raw JSON fragment).
export function jsonEscapeInner(value) {
  const s = JSON.stringify(value);
  return s.slice(1, -1);
}

// Replace every COMPLETE {{NAME}} for a known NAME. Unknown names are left as-is.
function replaceComplete(text, map, escape) {
  return text.replace(new RegExp(MARKER_SOURCE, 'g'), (whole, name) => {
    if (!map.has(name)) return whole;
    const value = map.get(name);
    return escape ? jsonEscapeInner(value) : value;
  });
}

// The most a still-incomplete marker tail can be: "{{" + longest name + "}}".
function maxMarkerLen(map) {
  let longest = 0;
  for (const name of map.keys()) if (name.length > longest) longest = name.length;
  return longest + 4;
}

// Split text into [safe-to-emit, hold]. `hold` is a trailing fragment that could
// still grow into a real marker on the next chunk, so it is kept back.
function splitSafe(s, cap) {
  const lastOpen = s.lastIndexOf('{{');
  if (lastOpen !== -1 && s.indexOf('}}', lastOpen + 2) === -1) {
    // A dangling "{{" with no closing "}}" yet. Hold it if it is still short
    // enough to become a registered marker; otherwise it can never match.
    if (s.length - lastOpen <= cap) return [s.slice(0, lastOpen), s.slice(lastOpen)];
  }
  // A lone trailing "{" could become "{{" next chunk.
  if (s.endsWith('{')) return [s.slice(0, -1), '{'];
  return [s, ''];
}

// A stateful replacer for ONE streamed text field (carries a tail across chunks).
// escape=true for JSON fragments (tool_use partial_json), false for plain text.
export function createFieldReplacer(map, { escape = false } = {}) {
  if (map.size === 0) return { push: (c) => c, flush: () => '' };
  const cap = maxMarkerLen(map);
  let pending = '';
  return {
    push(chunk) {
      pending += chunk;
      const [emit, hold] = splitSafe(pending, cap);
      pending = hold;
      return replaceComplete(emit, map, escape);
    },
    flush() {
      const out = replaceComplete(pending, map, escape);
      pending = '';
      return out;
    },
  };
}

// One-shot rehydration of a NON-streamed JSON response body. Markers live inside
// JSON string values, so the value is spliced in JSON-escaped to keep it valid.
export function rehydrateJsonBody(jsonText, map) {
  if (map.size === 0) return jsonText;
  return replaceComplete(jsonText, map, true);
}

// A stateful SSE transform. Feed it decoded response text; it returns transformed
// text with {{NAME}} substituted inside text_delta / thinking_delta / tool_use
// input_json_delta events, matching markers even when split across events.
export function createSseRehydrator(map) {
  let buf = '';
  const blockType = new Map(); // content-block index -> "text" | "tool_use" | "thinking"
  const replacers = new Map(); // index -> field replacer
  const getRepl = (index, escape) => {
    let r = replacers.get(index);
    if (!r) {
      r = createFieldReplacer(map, { escape });
      replacers.set(index, r);
    }
    return r;
  };

  function processLine(line) {
    if (!line.startsWith('data:')) return line;
    const jsonStr = line.slice(5).trimStart();
    let obj;
    try {
      obj = JSON.parse(jsonStr);
    } catch {
      return line; // not single-line JSON we understand - pass through untouched
    }
    if (!obj || typeof obj !== 'object') return line;

    if (obj.type === 'content_block_start') {
      blockType.set(obj.index, obj.content_block && obj.content_block.type);
      return line;
    }

    if (obj.type === 'content_block_delta' && obj.delta) {
      const d = obj.delta;
      if (d.type === 'text_delta' && typeof d.text === 'string') {
        d.text = getRepl(obj.index, false).push(d.text);
        return `data: ${JSON.stringify(obj)}`;
      }
      if (d.type === 'thinking_delta' && typeof d.thinking === 'string') {
        d.thinking = getRepl(obj.index, false).push(d.thinking);
        return `data: ${JSON.stringify(obj)}`;
      }
      if (d.type === 'input_json_delta' && typeof d.partial_json === 'string') {
        d.partial_json = getRepl(obj.index, true).push(d.partial_json);
        return `data: ${JSON.stringify(obj)}`;
      }
      return line;
    }

    if (obj.type === 'content_block_stop') {
      const r = replacers.get(obj.index);
      if (r) {
        const tail = r.flush();
        replacers.delete(obj.index);
        if (tail) {
          const bt = blockType.get(obj.index);
          const dtype =
            bt === 'tool_use' ? 'input_json_delta' : bt === 'thinking' ? 'thinking_delta' : 'text_delta';
          const field =
            dtype === 'input_json_delta' ? 'partial_json' : dtype === 'thinking_delta' ? 'thinking' : 'text';
          const ev = { type: 'content_block_delta', index: obj.index, delta: { type: dtype, [field]: tail } };
          // Emit the held remainder as its own delta event, then the stop.
          return `data: ${JSON.stringify(ev)}\n\n${line}`;
        }
      }
      return line;
    }

    return line;
  }

  return {
    push(text) {
      buf += text;
      let out = '';
      let nl;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        out += `${processLine(line)}\n`;
      }
      return out;
    },
    flush() {
      if (!buf) return '';
      const out = processLine(buf);
      buf = '';
      return out;
    },
  };
}
