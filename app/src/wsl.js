// Thin wrapper for running commands inside WSL from the Electron main process.
// OpenShell/Docker/nemoclaw all live in WSL; this app runs on the Windows host.
const { spawn } = require("node:child_process");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function toWslTmpPath(winPath) {
  return winPath.replace(/^([A-Za-z]):\\/, (_m, d) => `/mnt/${d.toLowerCase()}/`).replace(/\\/g, "/");
}

// Live feed of every command this app runs, for the "Command activity" log
// (main.js forwards these to the renderer). Each command gets its own
// numeric id so a "finish" event can be matched to its "start" even when
// several commands are in flight at once (one UI action can fire more
// than one command -- e.g. creating a protected folder resets a file,
// then execs inside the sandbox, then checks the result).
const commandEvents = new EventEmitter();
let nextCommandId = 1;

// The ONE rule for whether a field name is credential-like, used by every
// redaction path: parsed JSON (below), free-form text (scrubKeyedValues),
// and the policy display in runner.js. Two separate rules used to drift
// apart -- the text path only knew bare words like "secret", so
// `"secret_key": "..."` in a partial or prefixed JSON document went
// through untouched, and the JSON path's `_`-only separators missed
// `x-api-key`. The name is compared with case and separators removed, and
// the word may appear anywhere in it (`access_token`, `clientSecret`,
// `x-api-key`, `secret_key`). That also hides harmless names such as
// "tokenizer" -- an accepted trade: this only ever over-redacts.
const CREDENTIAL_NAME_WORDS = /authorization|apikey|token|secret|password|passwd|signature|credential|accesskey|privatekey|passphrase/;

function isCredentialKey(name) {
  return CREDENTIAL_NAME_WORDS.test(String(name).toLowerCase().replace(/[^a-z0-9]/g, ""));
}

// Deep-clones a JSON-shaped value, replacing the VALUE of any object key
// whose name looks credential-like with a fixed marker -- never touching
// the surrounding structure, so the result is always still valid JSON
// (unlike a text-level regex scrub, which can't tell a JSON value's own
// quotes/commas from the string's punctuation). `mapString`, when given,
// is applied to every other string leaf.
function redactCredentialFields(value, mapString) {
  if (Array.isArray(value)) return value.map((v) => redactCredentialFields(v, mapString));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = isCredentialKey(k) ? "[REDACTED]" : redactCredentialFields(v, mapString);
    }
    return out;
  }
  if (typeof value === "string" && mapString) return mapString(value);
  return value;
}

// Where a value that starts at `i` ends. Anything that never closes -- a
// chunk that is still streaming in, or truncated output -- runs to the end
// of its line (quoted) or of the whole text (a `{`/`[` structure), so what
// has arrived so far is hidden rather than shown up to its first space.
function endOfValue(s, i) {
  const escaped = /^(\\+)"/.exec(s.slice(i, i + 64));
  if (escaped) {
    // Value in ESCAPED quotes -- JSON encoded inside another string, at
    // any depth (`\"`, `\\\"`, ...). It ends at the next delimiter of the
    // same depth, but only if nothing between contains a backslash: one
    // there means a deeper escape (e.g. an escaped quote inside the
    // value), and the true end can't be placed with confidence -- so the
    // rest of the line is hidden instead of guessing and leaking a tail.
    const delim = escaped[1] + '"';
    const nl = s.indexOf("\n", i);
    const lineEnd = nl >= 0 ? nl : s.length;
    const close = s.indexOf(delim, i + delim.length);
    if (close >= 0 && close < lineEnd && !s.slice(i + delim.length, close).includes("\\")) return close + delim.length;
    return lineEnd;
  }
  const c = s[i];
  if (c === '"' || c === "'") {
    for (let j = i + 1; j < s.length; j++) {
      if (s[j] === "\\") j++;
      else if (s[j] === c) return j + 1;
    }
    // A quoted value may span lines (a multi-line password or key): it ends
    // at its closing quote, wherever that is. One that never closes -- still
    // streaming in, or truncated -- hides everything after it.
    return s.length;
  }
  if (c === "{" || c === "[") {
    let depth = 0;
    let inString = false;
    for (let j = i; j < s.length; j++) {
      const ch = s[j];
      if (inString) {
        if (ch === "\\") j++;
        else if (ch === '"') inString = false;
      } else if (ch === '"') inString = true;
      else if (ch === "{" || ch === "[") depth++;
      else if (ch === "}" || ch === "]") {
        depth--;
        if (depth === 0) return j + 1;
      }
    }
    return s.length;
  }
  const m = /^\S+/.exec(s.slice(i));
  return i + (m ? m[0].length : 0);
}

// `name: value` / `name=value` pairs in free-form text, with the name
// optionally quoted (`"name"`, `'name'`, or escaped `\"name\"`). Every
// pair is found; whether it gets redacted is decided by isCredentialKey(),
// the same rule the parsed-JSON path uses.
const KEY_RE = /(\\*["']?)([A-Za-z0-9_.-]+)\1?\s*[:=]\s*/g;

function scrubKeyedValues(s) {
  let out = "";
  let pos = 0;
  KEY_RE.lastIndex = 0;
  let m;
  while ((m = KEY_RE.exec(s))) {
    if (!isCredentialKey(m[2])) {
      // Step past the name only, not its value: a credential can sit
      // inside a harmless field's value (`note="token=..."`).
      KEY_RE.lastIndex = m.index + m[1].length + m[2].length;
      continue;
    }
    const valueEnd = endOfValue(s, m.index + m[0].length);
    out += s.slice(pos, m.index) + m[2] + "=[REDACTED]";
    pos = valueEnd;
    KEY_RE.lastIndex = Math.max(valueEnd, m.index + m[0].length);
  }
  return out + s.slice(pos);
}

// A complete JSON string literal whose content is itself encoded text
// (it contains `\"`) -- typically a log line carrying a JSON document as a
// string. Decoded, scrubbed as a whole (so a nested JSON document gets
// the exact structural redaction, at any depth), and re-encoded. Only
// literals that decode cleanly and actually change are replaced.
const STRING_LITERAL = /"(?:[^"\\\n]|\\.)*"/g;
const MAX_NESTING = 6;

function scrubInsideStringLiterals(s, depth) {
  if (depth >= MAX_NESTING) return s;
  return s.replace(STRING_LITERAL, (lit) => {
    if (!lit.includes('\\"')) return lit;
    let decoded;
    try {
      decoded = JSON.parse(lit);
    } catch {
      return lit;
    }
    if (typeof decoded !== "string") return lit;
    const scrubbed = scrubAtDepth(decoded, depth + 1);
    return scrubbed === decoded ? lit : JSON.stringify(scrubbed);
  });
}

function scrubText(text, depth = 0) {
  const s = String(text)
      // "Bearer <token>" is space-separated, not key:value -- the actual
      // secret is the word AFTER "Bearer", which the generic pattern below
      // would miss entirely (it would redact only the literal word
      // "Bearer", leaving the real token in plain sight).
      .replace(/\bbearer\s+\S+/gi, "Bearer [REDACTED]")
      // CONFIRMED real bug: an "Authorization: <scheme> <value>" HTTP
      // header (e.g. "Authorization: Basic DUMMY_TOKEN") is SPACE-
      // separated, not a single token -- the generic key=value pattern
      // below only ever captures up to the first whitespace (its \S+
      // fallback), so it redacted just the word "Basic" and left the
      // actual credential value sitting in plain text right after
      // "[REDACTED]". Directly confirmed: scrubCredentials("Authorization:
      // Basic DUMMY_TOKEN") returned "Authorization=[REDACTED] DUMMY_TOKEN".
      // Must run BEFORE the keyed-value pass below, which would otherwise
      // take only "Basic" as the value. Redacts to the END OF THE LINE,
      // not just the next token -- this also safely over-redacts a
      // compact one-line JSON blob that happens to embed this same key,
      // which is fine (widening, never narrowing what gets hidden).
      .replace(/\bauthorization\s*:\s*\S[^\r\n]*/gi, "Authorization: [REDACTED]");
  return scrubKeyedValues(scrubInsideStringLiterals(s, depth))
    // Short query-string names that carry secrets in signed URLs (sig=, key=, ...).
    .replace(/([?&;])(sig|key|auth|jwt|sas|code)=[^&\s'"#]*/gi, "$1$2=[REDACTED]")
    .replace(/\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g, "[REDACTED_JWT]");
}

// For the live Command activity view while a command is still running.
// A JSON structure that has started arriving but not finished can't be
// redacted by structure yet, so everything from its first `{`/`[` is held
// back until the command finishes and the complete output can be scrubbed
// as a whole (scrubCredentials). Text before it is shown, scrubbed.
function scrubPartialOutput(text) {
  const s = String(text ?? "");
  const i = s.search(/[{[]/);
  if (i < 0) return scrubCredentials(s);
  return scrubCredentials(s.slice(0, i)) + "[structured output still arriving -- shown once the command finishes]";
}

// Best-effort scrub of anything that looks like a credential, used for
// the Command activity log and for every command output this app stores
// or returns. Output that is a complete JSON document is redacted by KEY
// NAME on the parsed value (the only way to be exact about where a value
// ends, whatever quotes or escapes it contains), with the text scrub
// applied to each remaining string inside it. Anything else -- JSON after
// a log prefix, or a truncated document -- goes through the text scrub,
// which finds every `name: value` pair and applies the same name rule.
// (While a command is still running, the live view uses
// scrubPartialOutput() instead.) Pattern-matching, not a guarantee, so it
// only ever widens what gets redacted, never narrows it.
function scrubCredentials(text) {
  return scrubAtDepth(text, 0);
}

// `depth` counts how many layers of encoding we are inside (a JSON string
// holding JSON holding ...), so decoding can't recurse without bound.
function scrubAtDepth(text, depth) {
  const s = String(text ?? "");
  const trimmed = s.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      parsed = undefined;
    }
    if (parsed !== undefined && typeof parsed === "object" && parsed !== null) {
      // A string value inside the document may itself carry encoded JSON
      // or `key=value` text, so every remaining string is scrubbed too.
      const mapString = (v) => (depth + 1 >= MAX_NESTING ? scrubText(v, depth + 1) : scrubAtDepth(v, depth + 1));
      return JSON.stringify(redactCredentialFields(parsed, mapString), null, 2) + (s.endsWith("\n") ? "\n" : "");
    }
  }
  return scrubText(s, depth);
}

// IMPORTANT, confirmed experimentally: passing the command as a `bash -lc
// "<string>"` argv element (the previous approach) silently corrupts any
// command that relies on shell positional parameters (e.g. `sh -c '...' _
// arg1 arg2`) -- `$1`/`$2` come back empty and `$0` defaults to the
// *outer* shell's own path, even though the exact same line works
// perfectly from a script file. (Minimal repro: `/bin/sh -c 'echo
// $0,$1,$2' myname first second` via this spawn path prints
// "/bin/bash,," instead of "myname,first,second"; the same line in a .sh
// file run as `bash file.sh` is correct.) This silently broke every
// baseline reset / file-state check that uses that pattern -- not just a
// style issue, a real correctness bug in test results. The fix: always
// write the command to a real script file in WSL's own filesystem and run
// that, never hand a multi-word command as a `-c` string.
// `redactOutput: true` is for internal measurement calls that read a
// protected file's real content purely to compare it against a baseline
// (fileState()'s `cat`) -- the live log shows that the command ran and
// what it returned structurally, never the actual bytes.
// `redactStdoutWith(rawStdout) -> string` lets a caller that knows the
// output's real SHAPE (e.g. getActivePolicy, which parses it as JSON)
// supply its own stronger, structure-aware redaction for what the log
// shows -- rather than this module's generic text-regex scrub, which is
// the right default for arbitrary command output but weaker than
// redacting a parsed object by key name. If it throws (unparseable
// output), the log shows a safe placeholder instead of the raw text.
function runInWsl(command, { timeoutMs = 60_000, redactOutput = false, redactStdoutWith, label } = {}) {
  const id = nextCommandId++;
  const startedAt = Date.now();
  const loggedCommand = scrubCredentials(command);
  commandEvents.emit("start", { id, command: loggedCommand, label, startedAt });

  function renderStdoutForLog(stdout, { complete }) {
    if (redactOutput) return stdout ? "[redacted: protected file content]" : "";
    if (redactStdoutWith) {
      if (!complete) return stdout ? "[receiving response...]" : "";
      try {
        return redactStdoutWith(stdout);
      } catch {
        return "[could not safely render this command's output for the log]";
      }
    }
    return complete ? scrubCredentials(stdout) : scrubPartialOutput(stdout);
  }

  // Every exit from this function, including a setup failure before a
  // process ever existed, must emit exactly one "finish" -- otherwise the
  // log row this command's "start" created is stuck on "Running..." forever.
  const finish = (payload) => {
    const logged = {
      ...payload,
      stdout: renderStdoutForLog(payload.stdout, { complete: true }),
      stderr: scrubCredentials(payload.stderr),
    };
    commandEvents.emit("finish", { id, startedAt, ...logged, finishedAt: Date.now() });
    return payload;
  };

  return new Promise((resolve) => {
    let tmpFile;
    try {
      tmpFile = path.join(os.tmpdir(), `oea-cmd-${Date.now()}-${Math.random().toString(36).slice(2)}.sh`);
      fs.writeFileSync(tmpFile, command, "utf8");
    } catch (err) {
      // Never got as far as spawning anything -- still resolve AND finish,
      // so the row updates instead of hanging on "Running..." forever.
      resolve(finish({ code: -1, stdout: "", stderr: `Could not stage the command script: ${err}`, timedOut: false }));
      return;
    }
    const wslScriptPath = toWslTmpPath(tmpFile);

    const cleanup = () => {
      fs.unlink(tmpFile, () => {});
    };

    let child;
    try {
      // stdin must be explicitly closed ('ignore'): Node's default pipe stays
      // open with nothing ever written to it, and `openshell sandbox exec`
      // (TTY auto-detection falls back to reading stdin) then blocks waiting
      // for input/EOF that never comes -- this was an earlier intermittent hang.
      // -l (login): without it, PATH additions from .profile/.bashrc (where
      // `openshell`/`docker` live, under ~/.local/bin) aren't in effect and
      // every command fails with "command not found".
      child = spawn("wsl.exe", ["bash", "-l", wslScriptPath], {
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      cleanup();
      resolve(finish({ code: -1, stdout: "", stderr: `Could not start wsl.exe: ${err}`, timedOut: false }));
      return;
    }

    let stdout = "";
    let stderr = "";
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      // SIGTERM alone can leave the inner WSL process running (wsl.exe is
      // only a bridge to the Linux-side process, not its direct parent);
      // SIGKILL on the bridge at least stops us from waiting on it forever.
      child.kill("SIGKILL");
    }, timeoutMs);

    // Streamed as output arrives, not just once at the end, so a
    // long-running command's row shows live partial output instead of
    // sitting on "Running..." with no feedback until it fully completes.
    // What's shown is still passed through the same redaction as the
    // final result (a protected-file read can only be judged sensitive
    // as a whole, so a redacted command's partial output is withheld
    // entirely rather than leaking it one chunk at a time).
    const emitUpdate = () => {
      commandEvents.emit("update", {
        id,
        stdout: renderStdoutForLog(stdout, { complete: false }),
        stderr: scrubPartialOutput(stderr),
      });
    };

    child.stdout.on("data", (d) => {
      stdout += d.toString();
      emitUpdate();
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
      emitUpdate();
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      cleanup();
      resolve(finish({ code, stdout, stderr, timedOut }));
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      cleanup();
      resolve(finish({ code: -1, stdout, stderr: String(err), timedOut: false }));
    });
  });
}

module.exports = { runInWsl, commandEvents, scrubCredentials, scrubPartialOutput, redactCredentialFields, isCredentialKey };
