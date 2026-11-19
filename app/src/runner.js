// Core no-agent test logic: every operation below runs as a direct shell
// command against the sandbox (via `openshell sandbox exec`), never through
// an LLM agent. This is the whole point of this project, as opposed to
// openshell-security-eval's agent-driven attempts.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { runInWsl, scrubCredentials } = require("./wsl");

const RESULTS_DIR = path.join(__dirname, "..", "results");

function shQuote(s) {
  return "'" + String(s).replace(/'/g, `'\\''`) + "'";
}

// Every error message below that embeds a command's raw stdout/stderr
// goes through this first. `runInWsl`'s own scrubbing only ever touched
// the COPY it emits to the Command activity log -- the actual value it
// resolves with (what every caller here builds error strings from) was
// never scrubbed, so a credential surfacing in a failed command's output
// flowed straight into an error message shown in the UI, bypassing both
// the log's redaction and getActivePolicy()'s object-level one entirely.
function safeText(s) {
  return scrubCredentials(String(s ?? ""));
}

// Serializes runAttempt() calls that share the same sandbox+target: two
// concurrent attempts against the same file (e.g. a double-click on "Run
// attempt", or two calls racing from anywhere else) can otherwise
// interleave their own reset-to-baseline steps mid-flight. One attempt's
// reset can silently overwrite the file a DIFFERENT in-flight attempt just
// changed via a genuine bypass, right before that attempt's own
// after-check runs -- making a real bypass look like "file unchanged",
// i.e. a confirmed block that never actually happened.
const attemptLocks = new Map();
function withLock(key, fn) {
  const previous = attemptLocks.get(key) || Promise.resolve();
  const next = previous.then(fn, fn);
  attemptLocks.set(
    key,
    next.catch(() => {})
  );
  return next;
}

async function listSandboxes() {
  const { code, stdout, stderr } = await runInWsl("openshell sandbox list 2>&1");
  if (code !== 0) return { ok: false, error: safeText(stderr || stdout) };
  const lines = stdout.trim().split("\n").slice(1); // drop header row
  const sandboxes = lines
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const parts = l.split(/\s{2,}/);
      return { name: parts[0], created: parts[1] || "", phase: (parts[2] || "").replace(/\x1b\[[0-9;]*m/g, "") };
    });
  return { ok: true, sandboxes };
}

async function getInstalledOpenShellVersion() {
  const { code, stdout } = await runInWsl("openshell --version 2>&1");
  if (code !== 0) return null;
  // Output looks like "openshell 0.0.116".
  const m = stdout.trim().match(/([0-9]+\.[0-9]+\.[0-9]+)/);
  return m ? m[1] : null;
}

// Every OpenShell version actually available on this host right now, for a
// dropdown to pick from instead of typing a version by hand. Only one is
// installed today, so this returns a single-item list -- but it stays a
// list (not a single value) so it keeps working once a second
// binary/gateway is installed side by side (see the createSandbox caveat).
async function listOpenShellVersions() {
  const v = await getInstalledOpenShellVersion();
  return v ? [v] : [];
}

const POLICIES_DIR = path.join(__dirname, "..", "..", "policies");

// Convert a Windows path to a WSL path (C:\... -> /mnt/c/...).
function toWslPath(p) {
  return p.replace(/^([A-Za-z]):\\/, (_m, d) => `/mnt/${d.toLowerCase()}/`).replace(/\\/g, "/");
}

// Shared by createSandbox() and createProtectedFolder()'s recreate step:
// stages the image (building Dockerfile dirs from WSL's own filesystem, see
// below) and runs `openshell sandbox create` with a given policy file,
// waiting until the sandbox is actually ready for `exec`.
async function createSandboxFromPolicyFile({ name, wslPolicyPath, image = "images/base" }) {
  // A Dockerfile-based --from is passed as a plain name (e.g. "images/base"),
  // which `openshell` resolves relative to its own working directory inside
  // WSL -- not a Windows path.
  const isDockerfileDir = !image.includes(":") && !image.includes("/mnt/");
  let fromArg = image;
  let cwdPrefix = `cd ${shQuote(toWslPath(path.join(__dirname, "..", "..")))} && `;
  if (isDockerfileDir) {
    // Building a Dockerfile dir straight from the Windows-mounted path
    // (/mnt/c/...) fails on this host ("unhandled tar header type 83" from
    // Docker's build context tar stream over 9p/wslfs); copy it into WSL's
    // own filesystem first and build from there instead.
    const wslImageSrc = toWslPath(path.join(__dirname, "..", "..", image));
    const stageDir = `/tmp/oea-image-${name}`;
    await runInWsl(`rm -rf ${shQuote(stageDir)} && cp -r ${shQuote(wslImageSrc)} ${shQuote(stageDir)}`);
    fromArg = stageDir;
    cwdPrefix = "";
  }

  // A plain base image (e.g. ubuntu) has no long-running foreground process,
  // so without something to keep it alive the container exits immediately
  // after creation. `sleep infinity` just keeps it up for `exec` calls.
  const cmd =
    `${cwdPrefix}openshell sandbox create --name ${shQuote(name)} --from ${shQuote(fromArg)} ` +
    `--policy ${shQuote(wslPolicyPath)} --detach --no-auto-providers -- sleep infinity 2>&1`;
  const result = await runInWsl(cmd, { timeoutMs: 10 * 60_000 });
  if (result.code !== 0) {
    return { ok: false, exitCode: result.code, output: safeText(result.stdout + result.stderr), timedOut: result.timedOut };
  }

  // `create` can return before the sandbox is actually Ready (still
  // finishing network/provisioning setup); exec'ing against it too early
  // can silently fail or hang. Poll until it reports Ready, or give up
  // after 60s -- then confirm `exec` itself actually works yet (the phase
  // can flip to Ready slightly before the supervisor relay is usable).
  const phase = await waitForPhase(name, "Ready", 60_000);
  const execReady = phase === "Ready" ? await waitForExecReady(name, 30_000) : false;

  return {
    ok: phase === "Ready" && execReady,
    exitCode: result.code,
    output: safeText(result.stdout + result.stderr),
    phase,
    timedOut: result.timedOut,
  };
}

// Creates a sandbox directly through `openshell sandbox create`, with NO
// NemoClaw involved and no agent image -- just OpenShell plus a plain base
// image, so attempts run as direct shell commands against the enforcement
// layer itself (see policies/README.md for which tiers have a real policy
// file so far).
//
// Caveat on "version": there is one `openshell` CLI/gateway installed on
// this host right now. This does not yet let a sandbox run against an
// arbitrary OpenShell version -- testing a second version needs a separate
// openshell binary/gateway installed side by side (not set up yet). Rather
// than silently test the installed version under a different label, this
// refuses when the requested version does not match what's installed.
async function createSandbox({ name, tier, openshellVersion, image = "images/base" }) {
  if (!/^[a-z][a-z0-9-]{0,18}$/.test(name || "")) {
    return { ok: false, error: "Invalid sandbox name (lowercase, starts with a letter, 1-19 chars, letters/numbers/hyphens)." };
  }
  if (!["restricted", "balanced", "open"].includes(tier)) {
    return { ok: false, error: "Tier must be one of: restricted, balanced, open." };
  }

  const policyFile = path.join(POLICIES_DIR, `${tier}.yaml`);
  if (!fs.existsSync(policyFile)) {
    return {
      ok: false,
      error: `No policy file yet for tier '${tier}' (expected ${policyFile}). See policies/README.md -- only 'restricted' is written so far.`,
    };
  }

  const installedVersion = await getInstalledOpenShellVersion();
  if (openshellVersion && installedVersion && openshellVersion !== installedVersion) {
    return {
      ok: false,
      error:
        `Requested OpenShell ${openshellVersion}, but the installed toolchain is ${installedVersion}. ` +
        `Testing a different OpenShell version isn't set up yet -- it needs a separate openshell CLI/gateway ` +
        `install for that version. Not creating the sandbox, to avoid silently testing the wrong version under ` +
        `the wrong label.`,
    };
  }

  const exists = await runInWsl(`openshell sandbox list 2>&1 | awk 'NR>1 {print $1}' | grep -qx ${shQuote(name)} && echo yes || echo no`);
  if (exists.stdout.trim() === "yes") {
    return { ok: false, error: `Sandbox '${name}' already exists. Delete it first if you want to recreate it.` };
  }

  const created = await createSandboxFromPolicyFile({ name, wslPolicyPath: toWslPath(policyFile), image });
  return { ...created, name, tier, image, openshellVersionUsed: installedVersion };
}

// `openshell sandbox list` can report Ready slightly before `exec` is
// actually wired up (supervisor relay still settling), so a plain `true`
// is retried a few times before treating the sandbox as usable.
async function waitForExecReady(name, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { code } = await runInWsl(`openshell sandbox exec -n ${shQuote(name)} -- true`, { timeoutMs: 15_000 });
    if (code === 0) return true;
    await new Promise((r) => setTimeout(r, 1500));
  }
  return false;
}

async function waitForPhase(name, targetPhase, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastPhase = "";
  while (Date.now() < deadline) {
    const { stdout } = await runInWsl(`openshell sandbox list 2>&1`);
    const line = stdout.split("\n").find((l) => l.trim().startsWith(name + " ") || l.trim() === name);
    if (line) {
      lastPhase = line.replace(/\x1b\[[0-9;]*m/g, "").trim().split(/\s{2,}/).pop();
      if (lastPhase === targetPhase) return lastPhase;
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  return lastPhase;
}

async function containerNameFor(sandboxName) {
  const filterValue = shQuote(`name=openshell-default--${sandboxName}-`);
  const grepPattern = shQuote(`^openshell-default--${sandboxName}-[0-9a-f]{8}-`);
  const { stdout } = await runInWsl(`docker ps --filter ${filterValue} --format '{{.Names}}' | grep -E ${grepPattern} | head -n 1`);
  return stdout.trim();
}

// Lists the immediate SUBDIRECTORIES of a path inside a sandbox's real
// filesystem (as root, unrestricted -- the tree is for picking a target to
// test, including places the sandboxed user currently can't reach, so it
// must not be limited by the very enforcement it's used to probe).
// `find -type d` reports a symlink-to-directory as type `l`, not `d`, so
// this naturally never follows or lists symlinks -- no separate check
// needed to avoid looping through one.
async function listDirectory(sandboxName, dirPath) {
  const container = await containerNameFor(sandboxName);
  if (!container) return { ok: false, error: `No running container found for sandbox '${sandboxName}'` };

  const p = shQuote(dirPath);
  const result = await runInWsl(`docker exec -u root ${container} find ${p} -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' 2>&1`);
  if (result.code !== 0) {
    const permissionIssue = /permission denied/i.test(result.stdout);
    const missing = /no such file or directory/i.test(result.stdout);
    return {
      ok: true,
      path: dirPath,
      canList: false,
      reason: missing ? "No such directory" : permissionIssue ? "Permission denied" : safeText(result.stdout).trim() || "Could not list this directory",
      children: [],
    };
  }
  const children = result.stdout
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b));
  return { ok: true, path: dirPath, canList: true, children };
}

// Effective OpenShell filesystem permission for a path, replicating the
// real (confirmed-by-testing) Landlock semantics: read_only/read_write
// entries grant that access to the listed path AND everything under it,
// and access is the UNION of every covering rule, not "closest rule
// wins" -- there is no deny rule, so nothing a broader ancestor grants
// can be taken back by a narrower one. A path not covered by anything
// (and not under the workdir) gets Landlock's default-deny, i.e. "none".
function longestCoveringPrefix(list, targetNorm) {
  let best = null;
  for (const raw of list || []) {
    const p = path.posix.normalize(raw);
    const covers = targetNorm === p || targetNorm.startsWith(p.endsWith("/") ? p : p + "/");
    if (covers && (!best || p.length > best.length)) best = p;
  }
  return best;
}

// The ONE place that asks OpenShell for a sandbox's actual effective
// policy -- `--full` is the flag the installed CLI documents for
// "effective policy payload, including provider-composed entries" (i.e.
// anything inherited/composed in, not just what was literally in the
// YAML this app wrote). Both the permission calculation below and the
// "Active OpenShell policy" display call this SAME function, so neither
// one can ever show something different from the other, and neither
// ever falls back to guessing from a tier name or a local policy file.
async function fetchEffectivePolicy(sandboxName) {
  // Parsed and redacted exactly ONCE, right here, as soon as the response
  // comes back -- `redactStdoutWith` below runs synchronously (inside
  // runInWsl, before its promise resolves) and captures its result into
  // `redacted` via this closure, so the Command activity log, "View full
  // policy", and getActivePolicy()'s summary all end up built from that
  // SAME redacted copy, never three separate redaction passes over the
  // same data that could in principle drift apart from each other.
  let redacted = null;
  const got = await runInWsl(`openshell policy get ${shQuote(sandboxName)} -o json --full`, {
    redactStdoutWith: (stdout) => {
      redacted = redactCredentialFields(JSON.parse(stdout));
      return JSON.stringify(redacted, null, 2);
    },
  });
  if (got.code !== 0) {
    return { ok: false, error: `Could not read the sandbox's policy (${safeText(got.stderr || got.stdout || "unknown error")}).` };
  }
  let parsed;
  try {
    parsed = JSON.parse(got.stdout);
  } catch (e) {
    // Never embed `e` (or any other piece of the raw response) in what's
    // returned here -- the exception's own message can echo a snippet of
    // the malformed text it choked on (e.g. "Unexpected token u in JSON at
    // position 42"), which would leak straight into the UI and the
    // Command activity log through this error string. Only a plain
    // position number, if the exception happens to carry one, is pulled
    // out and shown -- never the surrounding text.
    const posMatch = /position (\d+)/i.exec(String((e && e.message) || ""));
    return {
      ok: false,
      error: `Could not parse the sandbox policy response.${posMatch ? ` (near character ${posMatch[1]})` : ""}`,
    };
  }
  // redactStdoutWith already parsed this exact same stdout text and
  // redacted it (that's how the log rendered it above) -- reuse that
  // result rather than redacting a second time. The fallback only matters
  // if that callback was somehow never invoked with a successful parse,
  // which shouldn't happen whenever `parsed` above itself succeeded.
  if (!redacted) redacted = redactCredentialFields(parsed);
  return { ok: true, raw: parsed, policy: parsed.policy, redactedRaw: redacted, redactedPolicy: redacted.policy };
}

async function computeEffectivePermission(sandboxName, targetPath) {
  const fetched = await fetchEffectivePolicy(sandboxName);
  if (!fetched.ok) return { level: "unknown", reason: fetched.error };
  const policy = fetched.policy;
  if (!policy || !policy.filesystem_policy) {
    return { level: "unknown", reason: "The sandbox's policy has no filesystem_policy to evaluate." };
  }

  const targetNorm = path.posix.normalize(targetPath);
  const rwMatch = longestCoveringPrefix(policy.filesystem_policy.read_write, targetNorm);
  const roMatch = longestCoveringPrefix(policy.filesystem_policy.read_only, targetNorm);

  // include_workdir grants read_write on the sandbox's actual working
  // directory, whatever that resolves to for this image -- not a fixed
  // path, so it's only applied when we can confirm it by asking the
  // sandbox itself, never assumed.
  let workdirMatch = null;
  let workdirUnknown = false;
  if (policy.filesystem_policy.include_workdir) {
    const pwd = await runInWsl(`openshell sandbox exec -n ${shQuote(sandboxName)} -- pwd`, { timeoutMs: 20_000 });
    if (pwd.code === 0) {
      const workdir = path.posix.normalize(pwd.stdout.trim());
      if (workdir && (targetNorm === workdir || targetNorm.startsWith(workdir.endsWith("/") ? workdir : workdir + "/"))) {
        workdirMatch = workdir;
      }
    } else {
      // include_workdir grants SOMETHING, but we could not ask the sandbox
      // what that path actually is -- "not covered by workdir" would be a
      // guess, not a fact. Only reported as a hard "none" below if no
      // other rule covers the target AND we actually know where the
      // workdir is; otherwise this stays an open question (see below).
      workdirUnknown = true;
    }
  }

  if (rwMatch || workdirMatch) {
    // Prefer naming the more specific of the two as "the path this was
    // based on", when both happen to cover it.
    const matchedPath = rwMatch && workdirMatch ? (rwMatch.length >= workdirMatch.length ? rwMatch : workdirMatch) : rwMatch || workdirMatch;
    return { level: "read_write", matchedPath, viaWorkdir: !rwMatch && !!workdirMatch };
  }
  // Checked BEFORE roMatch, not after: an explicit read_only rule covering
  // this path does not rule out the target ALSO being under the
  // unconfirmed workdir, which would make the real level read_write, not
  // read_only -- returning "read_only" here just because some OTHER rule
  // happens to match would be confidently wrong, not just imprecise,
  // whenever that's the case.
  if (workdirUnknown) {
    return { level: "unknown", reason: "Could not determine the sandbox's working directory (include_workdir is set, but the path it covers could not be confirmed)." };
  }
  if (roMatch) return { level: "read_only", matchedPath: roMatch };
  return { level: "none", matchedPath: null };
}

// NOT anchored to the whole key name: the earlier `^(...)$` exact-match
// version missed every real-world compound name -- `access_token`,
// `refresh_token`, `client_secret`, `secret_key` -- since none of those
// literally EQUALS "token"/"secret"/etc., they only CONTAIN it. Matching
// the word anywhere in the key name (still anchored to not match an
// unrelated word that merely starts the same way, e.g. "tokenizer") is
// what actually catches the common OAuth-style field names.
const CREDENTIAL_KEY_PATTERN = /(^|_)(authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|token|client[_-]?secret|secret|password)($|_)/i;

// Deep-clones a JSON-shaped value, replacing the VALUE of any object key
// whose name looks credential-like with a fixed marker -- never touching
// the surrounding structure, so the result is always still valid JSON
// (unlike a text-level regex scrub, which can't tell a JSON value's own
// quotes/commas from the string's punctuation).
function redactCredentialFields(value) {
  if (Array.isArray(value)) return value.map(redactCredentialFields);
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = CREDENTIAL_KEY_PATTERN.test(k) ? "[REDACTED]" : redactCredentialFields(v);
    }
    return out;
  }
  return value;
}

// Display-oriented view of a sandbox's live policy, for the "Active
// OpenShell policy" panel -- built from the exact same fetchEffectivePolicy()
// call computeEffectivePermission() uses, never a separate derivation from
// the tier name or this app's own policies/*.yaml files.
async function getActivePolicy(sandboxName) {
  const fetched = await fetchEffectivePolicy(sandboxName);
  if (!fetched.ok) return { ok: false, sandboxName, error: fetched.error };
  if (!fetched.redactedPolicy || !fetched.redactedPolicy.filesystem_policy) {
    // `policy get` succeeded but came back without the shape this app
    // expects -- that is a retrieval/parsing problem, not "a policy that
    // happens to have no rules". Falling back to {} here would render as
    // a confident, empty-but-successful summary instead of flagging that
    // something is actually wrong.
    return { ok: false, sandboxName, error: "The sandbox's policy response did not include the expected filesystem_policy data." };
  }

  // Built from the SAME redacted copy fetchEffectivePolicy() already
  // produced for the Command activity log and for `fullText` below --
  // never the raw policy -- so a credential-like value can't leak through
  // the summary (e.g. inside a rule's `extra`/`extraConditions`) even
  // though it's already hidden in those other two views. Non-sensitive
  // fields (a rule's `query: {view: "public"}`, say) are untouched by
  // redactCredentialFields, so rules that only differ by such a condition
  // stay distinguishable here exactly as before.
  const policy = fetched.redactedPolicy;
  const fs_ = policy.filesystem_policy;

  // Confirmed real and schema-recognized (not a guess): a hand-written
  // policy with `allow: {method, path, query: {view: "public"}}` is
  // accepted by `openshell policy set` and echoed back unchanged by
  // `policy get`. Two rules with the SAME method+path but different
  // `query` maps were indistinguishable in the summary before this --
  // any field in a rule's spec beyond method/path (query included, and
  // anything else this CLI might add) is kept and shown now.
  function mapRuleSpec(kind, spec) {
    const s = spec || {};
    const extra = Object.fromEntries(Object.entries(s).filter(([k]) => k !== "method" && k !== "path"));
    return { kind, method: s.method, path: s.path, extra: Object.keys(extra).length ? extra : null };
  }

  // Everything about an endpoint this summary does NOT explicitly model
  // (host/port/protocol/enforcement/allowed_ips/rules/deny_rules) -- e.g.
  // `allow_uninspected_credentials`, confirmed real via `openshell policy
  // update --add-endpoint ...:allow-uninspected-credentials`, which is a
  // genuine request CONDITION (credentials passed through are not
  // rewritten/inspected) that was being silently dropped entirely. Rather
  // than hardcode just that one field and risk the same drop for the next
  // option this CLI adds, anything unrecognized is surfaced generically.
  const KNOWN_ENDPOINT_KEYS = new Set(["host", "port", "protocol", "enforcement", "allowed_ips", "rules", "deny_rules"]);

  const networkPolicies = Object.entries(policy.network_policies || {}).map(([key, np]) => ({
    key,
    name: np.name,
    endpoints: (np.endpoints || []).map((ep) => ({
      host: ep.host,
      port: ep.port,
      protocol: ep.protocol,
      enforcement: ep.enforcement,
      allowedIps: ep.allowed_ips || [],
      // Confirmed against a real sandbox (openshell policy update
      // --add-deny): deny exceptions do NOT appear inline in `rules` as
      // `{deny: {...}}` -- they live in a SEPARATE `deny_rules` array at
      // the endpoint level, parallel to (not inside) `rules`, which only
      // ever holds `{allow: {...}}` entries. Reading just `ep.rules`
      // silently dropped every deny exception from the summary.
      rules: [
        ...(ep.rules || []).map((rule) => {
          const [kind, spec] = Object.entries(rule)[0] || ["allow", {}];
          return mapRuleSpec(kind, spec);
        }),
        ...(ep.deny_rules || []).map((spec) => mapRuleSpec("deny", spec)),
      ],
      extraConditions: Object.entries(ep)
        .filter(([k, v]) => !KNOWN_ENDPOINT_KEYS.has(k) && v !== false && v !== undefined)
        .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`),
    })),
    binaries: (np.binaries || []).map((b) => b.path),
  }));

  const summary = {
    readOnly: fs_.read_only || [],
    readWrite: fs_.read_write || [],
    includeWorkdir: !!fs_.include_workdir,
    landlock: policy.landlock || null,
    process: policy.process || null,
    networkPolicies,
  };

  // Same redacted copy as `summary` above and as the Command activity log
  // for this same `policy get` call -- not a fresh redaction pass over
  // `fetched.raw`. Redacting on the PARSED OBJECT (by key name), not with
  // scrubCredentials' text regex (built for free-form command output, not
  // JSON): it can only match up to the next quote/comma/brace, so a value
  // containing one of those (e.g. `"token": "abc,def"`) was only partially
  // redacted, and replacing "key": "value" with a bare key=[REDACTED]
  // token broke the JSON's own syntax. This instead keeps the exact
  // structure and just swaps the value, so the result is always valid
  // JSON with the credential value fully gone.
  const fullText = JSON.stringify(fetched.redactedRaw, null, 2);

  return { ok: true, sandboxName, summary, fullText };
}

const AUDIT_MARKER_PREFIX = "OEA-AUDIT-MARKER-V1:";

// CONFIRMED real bug in the earlier design: a single FIXED filename
// (`.oea-audit-file`) shared across every attempt in a folder meant that
// a SUCCESSFUL modify/truncate (the correct, expected outcome under a
// read_write permission) left the file's content no longer starting with
// AUDIT_MARKER_PREFIX -- so the very NEXT attempt's ownership check saw
// an existing file without the marker and refused it as "not ours",
// permanently blocking every attempt after the first successful write.
// Each attempt now gets its OWN freshly-random-named file instead (like
// `mktemp`), so there is never a second attempt to collide with a
// previous one's now-different content; see runAttempt() below, which
// generates a new name every call and runAttemptUnlocked()'s cleanup
// step, which removes it once the attempt is done either way.
function randomAuditFileName() {
  return `.oea-audit-${crypto.randomBytes(8).toString("hex")}`;
}

function auditFilePath(folderPath, fileName = randomAuditFileName()) {
  return path.posix.join(path.posix.normalize(folderPath), fileName);
}

// Before this app ever modifies, truncates, or deletes the dedicated
// audit file, it confirms it actually owns it: a real file that happens
// to share this exact name must never be touched. If nothing is there
// yet, it creates it (tagged with the marker) rather than guess; if
// something IS there without the marker, this refuses outright.
async function ensureAuditFileOwnership(container, filePath, baselineContent) {
  const t = shQuote(filePath);
  const { stdout: existsOut, code: existsCode } = await runInWsl(
    `docker exec -u root ${container} sh -c 'if [ -e "$1" ]; then echo EXISTS; else echo ABSENT; fi' _ ${t}`
  );
  if (existsCode !== 0) return { ok: false, error: "Could not check whether the audit file already exists." };

  if (existsOut.trim() === "ABSENT") {
    const create = await runInWsl(
      `docker exec -u root ${container} sh -c 'printf "%s%s" "$1" "$2" > "$3" && chmod 666 "$3"' _ ${shQuote(AUDIT_MARKER_PREFIX)} ${shQuote(
        baselineContent
      )} ${t}`
    );
    if (create.code !== 0) return { ok: false, error: `Could not create the audit file: ${safeText(create.stderr || create.stdout)}` };
    return { ok: true, created: true };
  }

  const { stdout: content, code: catCode } = await runInWsl(`docker exec -u root ${container} cat ${t}`, {
    redactOutput: true,
    label: "measure: check audit-file ownership marker",
  });
  if (catCode !== 0) return { ok: false, error: "Could not read the existing file to check ownership." };
  if (!content.startsWith(AUDIT_MARKER_PREFIX)) {
    return {
      ok: false,
      error: `A file already exists at ${filePath} that this app did not create (no ownership marker) -- refusing to modify it.`,
    };
  }
  return { ok: true, created: false };
}

// NOTE on quoting throughout this file: `target` is free-text from the UI
// ("Target path"), never validated -- so it must never be embedded inside a
// *double*-quoted shell string (command substitution and `"` itself would
// be live there even though the value was passed through shQuote(), which
// only makes a value safe as a *single*-quoted literal). Every place that
// needs the value inside a nested `sh -c` passes it as a positional
// parameter (`sh -c '...' _ value`) instead, exactly like the baseline
// reset below -- never `sh -c "... ${shQuote(x)} ..."`.
function opCommand(operation, target) {
  const t = shQuote(target);
  switch (operation) {
    case "read":
      return `cat ${t}`;
    case "modify":
      return `sh -c 'echo DIRECT-AUDIT-WRITE > "$1"' _ ${t}`;
    case "truncate":
      return `sh -c ': > "$1"' _ ${t}`;
    case "delete":
      return `rm ${t}`;
    default:
      throw new Error(`Unknown operation: ${operation}`);
  }
}

async function fileState(container, target, baselineContent) {
  const t = shQuote(target);
  const { stdout: existsOut, code: existsCode } = await runInWsl(
    `docker exec -u root ${container} sh -c 'if [ -e "$1" ]; then echo EXISTS; else echo ABSENT; fi' _ ${t}`
  );
  if (existsCode !== 0) return { state: "MEASUREMENT_ERROR", detail: "existence check failed" };
  const exists = existsOut.trim();
  if (exists === "ABSENT") return { state: "DELETED", content: "" };
  const { stdout: content, code: catCode } = await runInWsl(`docker exec -u root ${container} cat ${t}`, {
    redactOutput: true,
    label: "measure: read target content for comparison (not shown)",
  });
  if (catCode !== 0) return { state: "MEASUREMENT_ERROR", detail: "read-back failed" };
  if (content === baselineContent) return { state: "UNCHANGED", content };
  if (content.trim() === "") return { state: "EMPTIED", content };
  return { state: "MODIFIED", content };
}

// fileState() above always reads the target's real content (as root, from
// outside the sandbox) to compare against baselineContent -- that's
// necessary to judge the attempt, but it means the full content of
// whatever the target actually holds would otherwise end up written into
// the results JSON file. That defeats the point of testing read-blocking
// on anything actually sensitive: a "blocked" read would still persist
// the file's real content to disk. Only `state` (and, for a
// MEASUREMENT_ERROR, `detail`) is kept for anything that gets stored or
// returned to the UI; the raw content never leaves fileState()'s caller.
function redactContent(fs_) {
  if (!fs_) return fs_;
  return { state: fs_.state, detail: fs_.detail };
}

// Whether `operation` is expected to succeed under a given folder
// permission ("none" | "read_only" | "read_write", matching
// createProtectedFolder's options). Undefined/unspecified means "no
// assertion" -- the caller doesn't know the target's intended permission
// (e.g. an arbitrary path typed by hand), so the verdict should describe
// what happened without claiming it's right or wrong.
function expectedAllowed(operation, expectedPermission) {
  if (expectedPermission === "read_write") return true;
  if (expectedPermission === "none") return false;
  if (expectedPermission === "read_only") return operation === "read";
  return undefined; // unspecified
}

// Runs one direct (no-agent) attempt against a sandbox and records the
// result. Each call generates its OWN freshly-random audit file name
// (see randomAuditFileName()) inside the chosen folder -- a FIXED shared
// name here was what caused a successful modify/truncate to block every
// later attempt. Still serialized per sandbox+folder (not per the now
// ephemeral target), so attempts within the same folder don't overlap
// their own setup/cleanup steps; the folder path is normalized first
// (posix.normalize collapses "//", "/./", etc.) so two calls that spell
// the same real folder differently still land on the same lock key.
function runAttempt(params) {
  const folderPath = path.posix.normalize(params.folderPath);
  const target = auditFilePath(folderPath);
  return withLock(`${params.sandboxName}::${folderPath}`, () => runAttemptUnlocked({ ...params, folderPath, target }));
}

// Checks (and, if needed, performs) cleanup of exactly ONE audit file --
// `target` is always the ONE attempt-specific, freshly-random path the
// caller created (see randomAuditFileName()/runAttempt() below), never a
// shared or fixed name, so this can never remove a different attempt's
// file or a real pre-existing one. Returns a status the caller attaches
// to its result (`removed` | `already_absent` | `failed`, with a `reason`
// and the `path` when it failed) -- this is deliberately an independent
// outcome from the attempt's own verdict, never folded into it.
async function cleanupAuditFile(container, target) {
  const precheck = await runInWsl(
    `docker exec -u root ${container} sh -c 'if [ -e "$1" ]; then echo EXISTS; else echo ABSENT; fi' _ ${shQuote(target)}`,
    { timeoutMs: 20_000 }
  );
  if (precheck.code === 0 && precheck.stdout.trim() === "ABSENT") {
    // Already gone -- most commonly because this attempt's own "delete"
    // operation removed it itself. Nothing left to clean up.
    return { status: "already_absent" };
  }
  const rm = await runInWsl(`docker exec -u root ${container} rm -f ${shQuote(target)} 2>&1`, { timeoutMs: 20_000 });
  if (rm.timedOut) {
    return { status: "failed", path: safeText(target), reason: "The cleanup command timed out." };
  }
  if (rm.code !== 0) {
    return {
      status: "failed",
      path: safeText(target),
      reason: safeText(rm.stderr || rm.stdout || `cleanup command exited with code ${rm.code}`),
    };
  }
  return { status: "removed" };
}

async function runAttemptUnlocked({ sandboxName, folderPath, target, operation, versionTag, baselineContent = "audit-baseline" }) {
  const startedAt = new Date().toISOString();
  const container = await containerNameFor(sandboxName);
  if (!container) {
    return { ok: false, error: `No running container found for sandbox '${sandboxName}'` };
  }

  // Only ever cleaned up below if we actually created/confirmed this
  // file: the astronomically unlikely but not-impossible case of the
  // random name colliding with a REAL pre-existing file must leave that
  // file completely untouched, cleanup included -- not just skip writing
  // to it.
  let weOwnThisFile = false;
  // Flipped to true by persistResult() once IT has resolved cleanup for
  // this attempt -- the `finally` block below only ever cleans up as a
  // last-resort fallback for an exception thrown outside persistResult(),
  // so cleanup is attempted exactly once per attempt, never twice.
  let cleanupHandled = false;

  // The ONLY place that writes a result to disk and returns it -- and it
  // always resolves this attempt's own cleanup FIRST, attaching the
  // outcome as `result.cleanup`, so a persisted/returned result is never
  // missing that information (as it was before: the file could be
  // written and returned to the UI before cleanup even ran). Cleanup's
  // outcome rides alongside the already-decided verdict in
  // `resultWithoutCleanup` and never changes it -- a failed cleanup is
  // surfaced as its own warning, never as a reason to flip or soften an
  // allow/deny result.
  async function persistResult(resultWithoutCleanup) {
    const cleanup = weOwnThisFile ? await cleanupAuditFile(container, target) : { status: "already_absent" };
    cleanupHandled = true;
    const result = { ...resultWithoutCleanup, cleanup };
    fs.mkdirSync(RESULTS_DIR, { recursive: true });
    const fname = `${startedAt.replace(/[:.]/g, "-")}__${sandboxName}__${operation}.json`;
    fs.writeFileSync(path.join(RESULTS_DIR, fname), JSON.stringify(result, null, 2));
    return { ok: true, result, file: fname };
  }

  try {
  // Always computed fresh from the sandbox's actual current policy -- this
  // is never something the caller/UI supplies, so the verdict can't drift
  // from the real, live permission (see computeEffectivePermission above).
  const permissionInfo = await computeEffectivePermission(sandboxName, target);
  const expectedPermission = permissionInfo.level === "unknown" ? undefined : permissionInfo.level;

  // Every operation (including "read") runs against this app's own
  // dedicated audit file, never an arbitrary path -- ownership is
  // confirmed (or the file is created fresh) before anything touches it,
  // so there is no longer a risk of a "read" or a "modify" test clobbering
  // a real file that happens to share its name.
  const ownership = await ensureAuditFileOwnership(container, target, baselineContent);
  if (!ownership.ok) {
    return { ok: false, error: ownership.error };
  }
  weOwnThisFile = true;
  if (!ownership.created) {
    // Reset to a known baseline from outside the sandbox (as root), same
    // approach as openshell-security-eval's 1-prepare.sh -- skipped when
    // ensureAuditFileOwnership just created it fresh with that exact content.
    const t = shQuote(target);
    const resetResult = await runInWsl(
      `docker exec -u root ${container} sh -c 'printf "%s%s" "$1" "$2" > "$3" && chmod 666 "$3"' _ ${shQuote(AUDIT_MARKER_PREFIX)} ${shQuote(
        baselineContent
      )} ${t}`
    );
    // Checked directly, not just inferred from the file's state afterward:
    // if the target already happened to hold baselineContent from a PRIOR
    // run, a reset that silently fails this time would still look like
    // "UNCHANGED" below, masking that this attempt never actually got a
    // confirmed baseline of its own.
    if (resetResult.code !== 0 || resetResult.timedOut) {
      const before = await fileState(container, target, AUDIT_MARKER_PREFIX + baselineContent);
      return await persistResult({
        versionTag: versionTag || "(unspecified)",
        sandboxName,
        container,
        folderPath,
        target,
        operation,
        startedAt,
        finishedAt: new Date().toISOString(),
        before: redactContent(before),
        after: null,
        verdict: "inconclusive: could not confirm the baseline before the attempt (the reset command itself failed) -- not a result either way",
      });
    }
  }

  const expectedContent = AUDIT_MARKER_PREFIX + baselineContent;
  const before = await fileState(container, target, expectedContent);
  if (before.state !== "UNCHANGED") {
    // The reset itself could not be confirmed -- running the attempt now
    // would measure against an unknown starting point. Reported as its own
    // state (not "NOT blocked"/bypass), so a broken measurement is never
    // mistaken for a real security finding.
    return await persistResult({
      versionTag: versionTag || "(unspecified)",
      sandboxName,
      container,
      folderPath,
      target,
      operation,
      startedAt,
      finishedAt: new Date().toISOString(),
      before: redactContent(before),
      after: null,
      verdict: `inconclusive: could not confirm the baseline before the attempt (state: ${before.state}${before.detail ? `; ${before.detail}` : ""}) -- not a result either way`,
    });
  }

  // The actual attempt: a direct shell command inside the sandbox, going
  // through OpenShell's own exec path (no LLM involved).
  const cmd = opCommand(operation, target);
  const execResult = await runInWsl(`openshell sandbox exec -n ${shQuote(sandboxName)} -- ${cmd} 2>&1`);

  const after = await fileState(container, target, expectedContent);

  // `openshell sandbox exec` has no structured success/failure signal of
  // its own (confirmed via --help: no -o json or status flag -- it just
  // streams the remote command's own output and mirrors its exit code).
  // But a GATEWAY/CLI-level failure -- the command never reached, or never
  // started running inside, the sandbox at all (sandbox not found, a
  // gateway connection/auth error, etc.) -- is reported through a
  // distinctive wrapper the `openshell` CLI itself prints, confirmed
  // directly against a real gateway rejection:
  //   `Error:   × code: 'Some requested entity was not found', message: "sandbox not found"`
  // This is categorically different from the RAW, unwrapped stderr a
  // command that actually ran inside the sandbox produces -- also
  // confirmed directly, against a real Landlock denial in a live sandbox:
  //   `cat: /root/.bashrc: Permission denied`
  //   `_: 1: cannot create /path: Permission denied`
  // Neither of those (nor rm's/sh's own error text in general) ever
  // carries this "Error:   × code:" wrapper -- only the CLI's own
  // own-level errors do. So its presence is evidence the command never
  // started inside the sandbox, even if the wrapped message itself
  // happens to ALSO contain a denial-like word (a gateway auth error
  // plausibly could use one) -- checked and trusted BEFORE the plain
  // text-match below, which it overrides.
  const gatewayLevelFailure = /error:\s*×\s*code:\s*'/i.test(
    (execResult.stdout + execResult.stderr).replace(/\x1b\[[0-9;]*m/g, "")
  );

  // Deliberately narrow: bare "denied" or "landlock" would also match a
  // GATEWAY-level rejection that has nothing to do with file access (an
  // auth/connection error, a rate limit, anything containing those words
  // in passing) and get counted as the sandbox denying the file operation.
  // These are the specific, observed forms of an actual Linux/Landlock
  // permission failure for a file operation (`cat`/`rm`/`sh` all report
  // exactly "Permission denied", or the errno name) -- and even a message
  // that matches this is only trusted as a real in-sandbox denial when
  // gatewayLevelFailure (above) is false; a gateway-level message always
  // wins regardless of what words it contains.
  const deniedBySandbox =
    !gatewayLevelFailure && /\bpermission denied\b|\beacces\b|\beperm\b/i.test(execResult.stdout + execResult.stderr);

  let verdict;
  if (execResult.timedOut) {
    // The exec call itself never completed -- treating an unchanged file
    // here as "blocked" would credit OpenShell for something it never
    // actually got a chance to enforce.
    verdict = "inconclusive: the exec command itself timed out -- not a result either way";
  } else if (execResult.code === null) {
    // Node reports a null exit code when the process was killed by a
    // signal rather than exiting normally -- a crash, not a result. This
    // is checked as its own condition (not just "non-zero exit") and
    // BEFORE any text-matching: relying on `deniedBySandbox` to gate this
    // case is not enough, since a crash's own stderr can coincidentally
    // contain a denial-like word and would otherwise slip through as a
    // false "blocked, consistent with permission".
    verdict = "inconclusive: the exec command did not exit normally (killed by a signal, no exit code) -- not a result either way";
  } else if (gatewayLevelFailure) {
    // The command never reached/started inside the sandbox -- OpenShell's
    // own CLI-level error wrapper is the evidence (see above), not a
    // text-match on "permission denied" alone. Checked and reported
    // before the file is ever judged against the expected permission:
    // crediting this as "blocked, consistent with the permission" would
    // report a gateway/connection failure as a successful security
    // control, which is exactly the false positive this guards against.
    verdict = `inconclusive: the command could not be delivered to the sandbox (OpenShell reported a gateway/CLI-level error: ${safeText(
      execResult.stdout + execResult.stderr
    ).trim()}) -- not a result either way`;
  } else if (after.state === "MEASUREMENT_ERROR") {
    verdict = `inconclusive: the post-attempt check itself failed (${after.detail || "unknown error"}) -- not a result either way`;
  } else {
    // Ground truth is what actually happened to the file: a read never
    // changes the file either way, so its own success/failure must come
    // from the exec call's exit code; everything else is judged by
    // whether the file actually changed, not by text-matching stderr.
    const actuallyAllowed = operation === "read" ? execResult.code === 0 : after.state !== "UNCHANGED";

    // A non-read op reporting success (exit 0) while the file stayed
    // unchanged is a contradiction our own commands should never produce
    // (echo/rm/truncate that exit 0 always touch the file) -- it means
    // something in the test command itself is broken, not that OpenShell
    // blocked it, so it must not be read as a block either.
    if (operation !== "read" && !actuallyAllowed && execResult.code === 0) {
      verdict = `inconclusive: the command reported success (exit 0) but the file was unchanged -- not evidence of a block, something in the test command itself is likely wrong`;
    } else if (!actuallyAllowed && !deniedBySandbox) {
      // A non-zero exit with the file unchanged is NOT by itself proof
      // OpenShell denied it -- `openshell sandbox exec` can just as easily
      // fail at the CLI/gateway level (can't reach the sandbox, sandbox
      // not found, a transient connection error) with a perfectly normal,
      // non-null, non-timeout exit code. Without actual denial-like text
      // in the output, crediting this as "blocked, consistent with
      // permission" would be reporting a connection failure as a
      // successful security control.
      verdict = `inconclusive: the command failed (exit ${execResult.code}) with no denial-like text in its output -- looks like a connection/CLI-level failure, not a confirmed OpenShell block`;
    } else {
      const expected = expectedAllowed(operation, expectedPermission);

      if (expected === undefined) {
        verdict = actuallyAllowed
          ? `allowed: ${operation === "read" ? "read succeeded" : `file ended up ${after.state}`} (no expected permission was given to compare against)`
          : `denied: ${operation === "read" ? "read failed" : "file unchanged"} (no expected permission was given to compare against)`;
      } else if (actuallyAllowed === expected) {
        verdict = actuallyAllowed
          ? `allowed, consistent with the '${expectedPermission}' permission`
          : `blocked, consistent with the '${expectedPermission}' permission`;
      } else if (actuallyAllowed) {
        verdict = `NOT blocked: operation succeeded despite the '${expectedPermission}' permission saying it should be denied`;
      } else {
        verdict = `unexpectedly blocked: operation was denied even though the '${expectedPermission}' permission should have allowed it`;
      }
    }
  }

  return await persistResult({
    versionTag: versionTag || "(unspecified)",
    sandboxName,
    container,
    folderPath,
    target,
    operation,
    expectedPermission: expectedPermission || "(unspecified)",
    permissionInfo,
    startedAt,
    finishedAt: new Date().toISOString(),
    execExitCode: execResult.code,
    execStdout: execResult.stdout,
    execStderr: execResult.stderr,
    deniedBySandbox,
    gatewayLevelFailure,
    before: redactContent(before),
    after: redactContent(after),
    verdict,
  });
  } finally {
    // Safety net ONLY: every normal return above goes through
    // persistResult(), which already resolves this attempt's own cleanup
    // BEFORE writing/returning anything. This only runs if something
    // throws outside of that (an unexpected exception), so the file still
    // isn't silently left behind -- but is never attempted a second time
    // once persistResult() already handled it.
    if (weOwnThisFile && !cleanupHandled) {
      await runInWsl(`docker exec -u root ${container} rm -f ${shQuote(target)} 2>&1`);
    }
  }
}

function listResults() {
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  return fs
    .readdirSync(RESULTS_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .reverse()
    .map((f) => {
      const data = JSON.parse(fs.readFileSync(path.join(RESULTS_DIR, f), "utf8"));
      return { file: f, ...data };
    });
}

// Minimal YAML writer for exactly the policy schema this app itself
// writes (filesystem_policy/landlock/process/version) -- not a general
// YAML serializer. It deliberately does NOT handle network_policies:
// that's a hand-rolled re-encoding of a JSON shape only ever seen in ONE
// real example, which isn't verified to preserve every rule shape
// (WebSocket rules, deny rules, per-rule options), so createProtectedFolder
// refuses outright rather than call this on a policy that has any -- see
// the check in createProtectedFolder before this is ever invoked.
//
// Double-quoted YAML scalar for any STRING value: a path emitted bare
// would corrupt the file the moment it contains a character that's
// significant to YAML itself (a leading `*` is parsed as an alias
// reference, `:` followed by a space ends the scalar early, `#` starts a
// comment, etc.). Every string field below goes through this; only
// genuine booleans/numbers stay bare.
function yamlStr(value) {
  return `"${String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function policyToYaml(policy) {
  const lines = [`version: ${policy.version}`, "filesystem_policy:", `  include_workdir: ${policy.filesystem_policy.include_workdir}`];
  lines.push("  read_only:");
  for (const p of policy.filesystem_policy.read_only || []) lines.push(`    - ${yamlStr(p)}`);
  lines.push("  read_write:");
  for (const p of policy.filesystem_policy.read_write || []) lines.push(`    - ${yamlStr(p)}`);
  lines.push("landlock:", `  compatibility: ${yamlStr(policy.landlock.compatibility)}`);
  lines.push("process:", `  run_as_user: ${yamlStr(policy.process.run_as_user)}`, `  run_as_group: ${yamlStr(policy.process.run_as_group)}`);
  return lines.join("\n") + "\n";
}

// Creates a folder inside a sandbox with wide-open Linux permissions (chmod
// 777, so Linux's own DAC permissions impose no restriction at all), then
// applies the chosen OpenShell-level restriction to it. Any enforcement
// then observed on that folder can only be coming from OpenShell/Landlock,
// never from ordinary Linux file permissions -- this is the "redesign the
// target" fix the M3 critique asked for (critique point 1).
//
// IMPORTANT, confirmed experimentally: Landlock only ever RESTRICTS further;
// once a sandbox's supervisor has landlocked itself at startup, a later
// `openshell policy set` on the SAME live sandbox cannot grant NEW access
// (tested: adding a path to read_write via `policy set` on a running
// sandbox still denied writes there, while creating a fresh sandbox with
// that exact same path already in its policy worked immediately). So
// granting (not just tightening) access to a new folder needs the policy
// in place from the start -- this destroys and recreates the sandbox with
// the merged policy baked into `sandbox create`, under the same name.
async function createProtectedFolder({ sandboxName, folderName = "Ahmed", permission = "none" }) {
  if (!/^[A-Za-z0-9_-]{1,40}$/.test(folderName)) {
    return { ok: false, error: "Invalid folder name (letters, numbers, - and _ only)." };
  }
  if (!["read_write", "read_only", "none"].includes(permission)) {
    return { ok: false, error: "Permission must be one of: read_write, read_only, none." };
  }

  // Same source as computeEffectivePermission()/getActivePolicy() (--full,
  // not a separate --base call): using a different view here risked
  // recreating the sandbox from a policy snapshot that disagreed with
  // what the rest of the app reads and displays as "the" active policy.
  const fetched = await fetchEffectivePolicy(sandboxName);
  if (!fetched.ok) {
    return { ok: false, error: `Could not read current policy for '${sandboxName}': ${fetched.error}` };
  }
  const effective = fetched.policy;
  if (!effective || !effective.filesystem_policy) {
    return { ok: false, error: `'${sandboxName}'s policy response did not include the expected filesystem_policy data.` };
  }

  // policyToYaml's network_policies serialization is a hand-rolled,
  // partial re-encoding of a JSON shape we've only seen ONE real example
  // of (no WebSocket rules, no deny rules, no per-rule options beyond
  // method/path) -- round-tripping anything outside that risks silently
  // dropping real restrictions when the sandbox is recreated. Rather than
  // gamble on a serializer that can't be fully verified against the real
  // schema, refuse outright when the sandbox already has network rules;
  // this feature only ever needs to touch filesystem_policy.
  if (effective.network_policies && Object.keys(effective.network_policies).length > 0) {
    return {
      ok: false,
      error:
        `Sandbox '${sandboxName}' has existing network_policies. Recreating it here would re-encode them through a ` +
        `serializer that isn't verified to preserve every real rule shape, risking a silent loss of real network ` +
        `restrictions. Not proceeding -- use a sandbox with no network policy (e.g. 'restricted' tier) for this feature.`,
    };
  }

  const folderPath = `/home/sandbox/${folderName}`;
  effective.filesystem_policy.read_only = (effective.filesystem_policy.read_only || []).filter((p) => p !== folderPath);
  effective.filesystem_policy.read_write = (effective.filesystem_policy.read_write || []).filter((p) => p !== folderPath);
  if (permission === "read_only") effective.filesystem_policy.read_only.push(folderPath);
  if (permission === "read_write") effective.filesystem_policy.read_write.push(folderPath);
  // permission === "none": left out of both lists entirely, so Landlock's
  // default-deny applies to it (confirmed: this blocks access even though
  // Linux's own 777 would otherwise allow it).

  const tmpPolicyPath = `/tmp/oea-policy-${sandboxName}.yaml`;
  const yaml = policyToYaml(effective);
  const writeTmp = await runInWsl(`cat > ${shQuote(tmpPolicyPath)} << 'OEA_POLICY_EOF'\n${yaml}OEA_POLICY_EOF`);
  if (writeTmp.code !== 0) {
    return { ok: false, error: `Could not stage the policy file: ${safeText(writeTmp.stderr)}` };
  }

  // Recreate the sandbox under the same name with the new policy baked in.
  // This loses whatever else was in the sandbox (it's not a persistent
  // environment for this project), which is why `openshell policy set`
  // alone would have been preferable if it worked for loosening -- it doesn't.
  await runInWsl(`openshell sandbox delete ${shQuote(sandboxName)} 2>&1`);
  const created = await createSandboxFromPolicyFile({ name: sandboxName, wslPolicyPath: tmpPolicyPath, image: "images/base" });
  if (!created.ok) {
    return { ok: false, error: `Recreating the sandbox with the new policy failed: ${created.output || ""}` };
  }

  const container = await containerNameFor(sandboxName);
  if (!container) return { ok: false, error: `Sandbox recreated but its container could not be found afterward.` };

  const mk = await runInWsl(
    `docker exec -u root ${container} sh -c 'mkdir -p ${shQuote(folderPath)} && chown sandbox:sandbox ${shQuote(folderPath)} && chmod 777 ${shQuote(folderPath)}'`
  );
  if (mk.code !== 0) {
    return { ok: false, error: `Sandbox recreated, but could not create the folder inside it: ${safeText(mk.stderr || mk.stdout)}` };
  }

  return {
    ok: true,
    sandboxName,
    folderPath,
    permission,
    linuxMode: "777 (fully open; Linux imposes no restriction here)",
    note: "The sandbox was destroyed and recreated with the new policy (Landlock can't grant new access to an already-running sandbox).",
  };
}

module.exports = {
  listSandboxes,
  runAttempt,
  listResults,
  createSandbox,
  getInstalledOpenShellVersion,
  listOpenShellVersions,
  createProtectedFolder,
  listDirectory,
  computeEffectivePermission,
  getActivePolicy,
  auditFilePath,
};
