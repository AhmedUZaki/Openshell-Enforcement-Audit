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

// Best-effort scrub of anything that looks like a credential, so the live
// log never shows one even if a command happened to carry one -- this is
// pattern-matching, not a guarantee, so it only ever widens what gets
// redacted, never narrows it.
function scrubCredentials(text) {
  return (
    String(text)
      // "Bearer <token>" is space-separated, not key:value -- the actual
      // secret is the word AFTER "Bearer", which the generic pattern below
      // would miss entirely (it would redact only the literal word
      // "Bearer", leaving the real token in plain sight).
      .replace(/\bbearer\s+\S+/gi, "Bearer [REDACTED]")
      // Optional quote BEFORE the keyword (a JSON key: `"password"`), and
      // the VALUE matched as a whole quoted string first (greedy up to the
      // next matching quote) before falling back to a bare \S+ token --
      // without that quoted-string alternative, a value containing a
      // comma/space/brace of its own (`"token": "abc,def"`) only matched
      // up to the first such character, leaving the rest of the real
      // secret sitting in plain text right after "[REDACTED]". This is
      // the same hazard getActivePolicy()'s redactCredentialFields() was
      // written to avoid for the policy JSON display; command stdout/stderr
      // shown in the Command activity log goes through this function
      // instead (free-form text, not a parsed object), so it needs the
      // same quoted-value awareness to redact as completely.
      .replace(/"?(authorization|api[_-]?key|token|secret|password)"?\s*[:=]\s*("[^"]*"|'[^']*'|\S+)/gi, "$1=[REDACTED]")
      .replace(/\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g, "[REDACTED_JWT]")
  );
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
    return scrubCredentials(stdout);
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
        stderr: scrubCredentials(stderr),
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

module.exports = { runInWsl, commandEvents, scrubCredentials };
