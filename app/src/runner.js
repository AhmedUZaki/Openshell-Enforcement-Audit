// Core no-agent test logic: every operation below runs as a direct shell
// command against the sandbox (via `openshell sandbox exec`), never through
// an LLM agent. This is the whole point of this project, as opposed to
// openshell-security-eval's agent-driven attempts.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { runInWsl, scrubCredentials, redactCredentialFields } = require("./wsl");

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

const PROJECT_ROOT = path.resolve(__dirname, "..", "..");

// `image` names a local Dockerfile folder only if it really is one: a
// relative path inside this project that contains a Dockerfile (e.g.
// "images/base"). Anything else -- `ubuntu`, `ghcr.io/org/img:tag`, an
// `oea-preserved/...` pin -- is an image reference passed straight to
// `--from`. Guessing from the spelling used to treat a familiar name like
// `ubuntu` as a project folder, try to copy it, and carry on after the
// copy failed.
function localDockerfileDir(image) {
  const dir = path.resolve(PROJECT_ROOT, image);
  if (!dir.startsWith(PROJECT_ROOT + path.sep)) return null;
  return fs.existsSync(path.join(dir, "Dockerfile")) ? dir : null;
}

// Shared by createSandbox() and createProtectedFolder()'s recreate step:
// stages the image (building Dockerfile dirs from WSL's own filesystem, see
// below) and runs `openshell sandbox create` with a given policy file,
// waiting until the sandbox is actually ready for `exec`. Every failure
// comes back as `{ ok: false, error }` -- the shape every caller and the UI
// read -- with the raw command output kept alongside as `output`.
async function createSandboxFromPolicyFile({ name, wslPolicyPath, image = "images/base" }) {
  let fromArg = image;
  const dockerfileDir = localDockerfileDir(image);
  if (dockerfileDir) {
    // Building a Dockerfile dir straight from the Windows-mounted path
    // (/mnt/c/...) fails on this host ("unhandled tar header type 83" from
    // Docker's build context tar stream over 9p/wslfs); copy it into WSL's
    // own filesystem first and build from there instead.
    const stageDir = `/tmp/oea-image-${name}`;
    const staged = await runInWsl(`rm -rf ${shQuote(stageDir)} && cp -r ${shQuote(toWslPath(dockerfileDir))} ${shQuote(stageDir)} 2>&1`);
    if (staged.code !== 0) {
      return { ok: false, error: `Could not stage the image folder '${image}' for building: ${safeText(staged.stdout + staged.stderr).trim()}` };
    }
    fromArg = stageDir;
  }

  // A plain base image (e.g. ubuntu) has no long-running foreground process,
  // so without something to keep it alive the container exits immediately
  // after creation. `sleep infinity` just keeps it up for `exec` calls.
  const cmd =
    `openshell sandbox create --name ${shQuote(name)} --from ${shQuote(fromArg)} ` +
    `--policy ${shQuote(wslPolicyPath)} --detach --no-auto-providers -- sleep infinity 2>&1`;
  const result = await runInWsl(cmd, { timeoutMs: 10 * 60_000 });
  if (result.code !== 0) {
    const output = safeText(result.stdout + result.stderr);
    return {
      ok: false,
      error: result.timedOut
        ? "`openshell sandbox create` timed out."
        : `\`openshell sandbox create\` failed (exit ${result.code}): ${output.replace(/\x1b\[[0-9;]*m/g, "").trim().slice(-600)}`,
      exitCode: result.code,
      output,
      timedOut: result.timedOut,
    };
  }

  // `create` can return before the sandbox is actually Ready (still
  // finishing network/provisioning setup); exec'ing against it too early
  // can silently fail or hang. Poll until it reports Ready, or give up
  // after 60s -- then confirm `exec` itself actually works yet (the phase
  // can flip to Ready slightly before the supervisor relay is usable).
  const phase = await waitForPhase(name, "Ready", 60_000);
  const execReady = phase === "Ready" ? await waitForExecReady(name, 30_000) : false;
  const ok = phase === "Ready" && execReady;

  return {
    ok,
    error: ok
      ? undefined
      : phase === "Ready"
        ? `Sandbox '${name}' was created and reports Ready, but commands could not be run in it within 30s.`
        : `Sandbox '${name}' was created but did not become Ready within 60s (last phase: ${phase || "unknown"}).`,
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
async function createSandbox({ name, tier, openshellVersion, image }) {
  image = (image || "").trim() || "images/base";
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
// Container name per sandbox, reused while browsing the tree: looking it
// up (`docker ps`) for every single folder listing doubled the commands
// per expand. A stale entry -- the sandbox was recreated and its container
// renamed -- shows up as docker refusing the name, and is looked up again
// once.
const treeContainerCache = new Map();

async function listDirectory(sandboxName, dirPath) {
  const p = shQuote(dirPath);
  let result;
  for (let attempt = 0; attempt < 2; attempt++) {
    let container = attempt === 0 ? treeContainerCache.get(sandboxName) : undefined;
    if (!container) {
      container = await containerNameFor(sandboxName);
      if (!container) {
        treeContainerCache.delete(sandboxName);
        return { ok: false, error: `No running container found for sandbox '${sandboxName}'` };
      }
      treeContainerCache.set(sandboxName, container);
    }
    result = await runInWsl(`docker exec -u root ${container} find ${p} -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' 2>&1`);
    const containerGone = result.code !== 0 && /no such container|is not running/i.test(result.stdout + result.stderr);
    if (!containerGone) break;
    treeContainerCache.delete(sandboxName);
  }
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

// Predicts the effective permission `targetPath` WOULD get under a given
// filesystem_policy object, without asking any live sandbox -- used by
// createProtectedFolder() to check a proposed policy edit BEFORE it ever
// deletes anything (the sandbox that would have this policy doesn't
// exist yet). Mirrors computeEffectivePermission()'s own precedence
// (read_write/include_workdir beat read_only, union of rules, no rule
// takes access back from a broader one) but can't confirm include_workdir
// itself -- that needs a live sandbox's actual working directory (see
// computeEffectivePermission) -- so it's reported as "unknown" rather
// than guessed either way.
// `workdir`, when known, is the CONFIRMED real working directory a
// recreated sandbox will have (see createProtectedFolder: read from the
// live, about-to-be-replaced sandbox, which is recreated from its exact
// same image ID and re-checked to have the same workdir afterward).
// Without it, include_workdir's own contribution genuinely can't be
// ruled out either way, so this stays "unknown" rather than guessed.
function computeStaticPermission(fsPolicy, targetPath, { workdir } = {}) {
  const targetNorm = path.posix.normalize(targetPath);
  const rwMatch = longestCoveringPrefix(fsPolicy.read_write, targetNorm);
  if (rwMatch) return { level: "read_write", matchedPath: rwMatch };
  if (fsPolicy.include_workdir) {
    if (workdir) {
      const workdirNorm = path.posix.normalize(workdir);
      if (targetNorm === workdirNorm || targetNorm.startsWith(workdirNorm.endsWith("/") ? workdirNorm : workdirNorm + "/")) {
        return { level: "read_write", matchedPath: workdirNorm, viaWorkdir: true };
      }
      // Confirmed the real workdir does NOT cover this path -- include_workdir
      // contributes nothing here, so this falls through to read_only/none
      // below instead of being reported as unconfirmable.
    } else {
      return {
        level: "unknown",
        matchedPath: null,
        reason: "include_workdir is set on this policy, and whether it covers this path can only be confirmed by asking a running sandbox for its actual working directory.",
      };
    }
  }
  const roMatch = longestCoveringPrefix(fsPolicy.read_only, targetNorm);
  if (roMatch) return { level: "read_only", matchedPath: roMatch };
  return { level: "none", matchedPath: null };
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
// The file op itself -- run through `sh -c` with `target` passed as a
// positional parameter ($1), never interpolated into a double-quoted
// string (see the quoting note above opCommand).
function opBody(operation) {
  switch (operation) {
    case "read":
      return `cat "$1"`;
    case "modify":
      return `echo DIRECT-AUDIT-WRITE > "$1"`;
    case "truncate":
      return `: > "$1"`;
    case "delete":
      return `rm "$1"`;
    default:
      throw new Error(`Unknown operation: ${operation}`);
  }
}

// `startMarker` is a fresh, random, per-ATTEMPT token (see
// randomExecStartMarker()) that the wrapper below prints to stderr as the
// very FIRST thing it does inside the sandbox -- before the file op runs
// at all. Its presence in the command's output is then direct proof this
// specific attempt's command actually started executing inside the
// sandbox (Landlock can only have denied the file op AFTER this point);
// its absence means the command never got that far, regardless of what
// the surrounding error text happens to look like. This is deliberately
// NOT another regex guess at the gateway's own wording (which can change
// across OpenShell versions) -- it's a signal this app itself controls
// and injects, so detecting it never depends on matching anyone else's
// error-message format. Printed to stderr, not stdout, so a "read"
// operation's actual file content (which lands on stdout) is never mixed
// with it.
//
// The second line reports the uid/gid/groups the operation actually runs
// with inside the sandbox -- needed afterward to check whether ordinary
// Linux permissions would refuse that same identity anyway (see
// linuxPermissionCheck). The marker is only ever [A-Z0-9-], so it is
// safe to embed unquoted here.
function opCommand(operation, target, startMarker) {
  const t = shQuote(target);
  const body = opBody(operation);
  return `sh -c 'echo ${startMarker} >&2; echo ${startMarker}:id=$(id -u):$(id -g):$(id -G) >&2; ${body}' _ ${t}`;
}

function randomExecStartMarker() {
  return `OEA-EXEC-STARTED-${crypto.randomBytes(8).toString("hex")}`;
}

// The identity line opCommand() prints, matched as a whole line only (same
// reasoning as the start marker itself: text merely quoting the command
// back must never count).
function parseProcessIdentity(output, startMarker) {
  const re = new RegExp(`^${startMarker}:id=(\\d+):(\\d+):([\\d ]+)$`);
  for (const line of output.split(/\r?\n/)) {
    const m = re.exec(line.trim());
    if (m) return { uid: m[1], gid: m[2], groups: m[3].trim().split(/\s+/).sort() };
  }
  return null;
}

function stripMarkerLines(text, startMarker) {
  return text
    .split("\n")
    .filter((line) => {
      const l = line.trim();
      return l !== startMarker && !l.startsWith(`${startMarker}:id=`);
    })
    .join("\n");
}

// A denial observed AFTER the start marker proves the operation ran inside
// the sandbox and was refused -- not WHO refused it. Ordinary Linux
// permissions can refuse the same operation on their own (e.g. a delete in
// a directory the sandbox user can't write: the audit file's own 666 mode
// doesn't help there). This replays only the permission CHECK, as the
// exact same uid/gid, from a plain `docker exec` -- which runs outside the
// OpenShell supervisor, so Landlock is not in play -- and reports whether
// Linux alone would already refuse. Nothing is modified.
async function linuxPermissionCheck(container, identity, operation, target) {
  if (!identity) return { status: "unknown", detail: "the sandboxed process's uid/gid could not be determined" };
  const probe =
    `docker exec -u ${identity.uid}:${identity.gid} ${container} sh -c '` +
    `echo "GROUPS=$(id -G)"; op="$1"; f="$2"; d=$(dirname "$f"); ` +
    `case "$op" in ` +
    `read) if [ -r "$f" ]; then echo ALLOWS; else echo "DENIES: no read permission on the file (or a directory on its path)"; fi;; ` +
    `modify|truncate) if [ -w "$f" ]; then echo ALLOWS; else echo "DENIES: no write permission on the file (or search permission on its path)"; fi;; ` +
    `delete) if ! [ -w "$d" ] || ! [ -x "$d" ]; then echo "DENIES: no write+search permission on the parent directory $d"; ` +
    `elif [ -k "$d" ] && [ "$(stat -c %u "$f")" != "$(id -u)" ] && [ "$(stat -c %u "$d")" != "$(id -u)" ]; then ` +
    `echo "DENIES: the parent directory is sticky and neither it nor the file is owned by this user"; ` +
    `else echo ALLOWS; fi;; ` +
    `*) echo "UNKNOWN_OP";; esac' _ ${shQuote(operation)} ${shQuote(target)}`;
  const r = await runInWsl(probe, { timeoutMs: 20_000 });
  if (r.code !== 0) return { status: "unknown", detail: "the Linux permission check could not be run" };
  const lines = r.stdout.split(/\r?\n/).map((l) => l.trim());
  const groupsLine = lines.find((l) => l.startsWith("GROUPS="));
  const probeGroups = groupsLine ? groupsLine.slice("GROUPS=".length).trim().split(/\s+/).sort() : [];
  // A check run with different supplementary groups than the real process
  // would be checking a different identity -- not evidence either way.
  if (probeGroups.join(",") !== identity.groups.join(",")) {
    return { status: "unknown", detail: `could not reproduce the process's exact groups (${identity.groups.join(" ")} vs ${probeGroups.join(" ")})` };
  }
  const verdictLine = lines.find((l) => l === "ALLOWS" || l.startsWith("DENIES:"));
  if (verdictLine === "ALLOWS") return { status: "allows", detail: `Linux permissions allow this for uid ${identity.uid}` };
  if (verdictLine) return { status: "denies", detail: `${verdictLine.slice("DENIES: ".length)} (uid ${identity.uid})` };
  return { status: "unknown", detail: "the Linux permission check gave no usable answer" };
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
  if (recreatesInProgress.has(params.sandboxName)) {
    return Promise.resolve({
      ok: false,
      error: `'${params.sandboxName}' is being deleted and recreated right now (protected-folder change). Run the attempt once that finishes.`,
    });
  }
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
    const { attemptId, file } = writeResultFile(
      (id) => `${startedAt.replace(/[:.]/g, "-")}__${safeFileNamePart(sandboxName)}__${safeFileNamePart(operation)}__${id}.json`,
      (id) => ({ ...resultWithoutCleanup, attemptId: id, cleanup })
    );
    return { ok: true, result: { ...resultWithoutCleanup, attemptId, cleanup }, file };
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
  // through OpenShell's own exec path (no LLM involved). `execStartMarker`
  // is a fresh, random token unique to THIS attempt (see opCommand/
  // randomExecStartMarker above) that the command itself prints from
  // inside the sandbox before touching the file at all.
  const execStartMarker = randomExecStartMarker();
  const cmd = opCommand(operation, target, execStartMarker);
  const execResult = await runInWsl(`openshell sandbox exec -n ${shQuote(sandboxName)} -- ${cmd} 2>&1`);

  const after = await fileState(container, target, expectedContent);

  // `openshell sandbox exec` has no structured success/failure signal of
  // its own (confirmed via --help: no -o json or status flag -- it just
  // streams the remote command's own output and mirrors its exit code).
  // Rather than guess whether the command ever reached/started inside the
  // sandbox by pattern-matching OpenShell's own CLI-level error wording
  // (which can change across versions, and would need a new regex for
  // every new wrapper format), this checks for this ATTEMPT's own
  // execStartMarker: a signal this app itself injects and controls. Its
  // absence from the combined output is direct proof the command never
  // started running inside the sandbox at all -- a gateway/CLI-level
  // failure (sandbox not found, a connection/auth error, etc.), whatever
  // words that failure happens to use. Its presence is equally direct
  // proof the opposite happened: the command DID start inside the
  // sandbox, so anything that follows (including a denial) is a genuine
  // in-sandbox result, not a gateway issue -- confirmed directly against
  // both a real gateway rejection (no marker in the output) and a real
  // Landlock denial in a live sandbox (marker present, followed by
  // `cat: /root/.bashrc: Permission denied` / `_: 1: cannot create /path:
  // Permission denied`).
  // CONFIRMED real bug: a plain substring search for the marker is not
  // enough -- a gateway-level failure can itself echo the FULL failed
  // command back inside its own error message (e.g. quoting the exact
  // `sh -c 'echo OEA-EXEC-STARTED-... >&2; ...'` it tried and failed to
  // run), which would make the marker appear in the output even though
  // the command never actually started executing inside the sandbox.
  // The marker only proves the command started when it shows up as its
  // OWN output line -- i.e. printed by the inner shell's own `echo`, not
  // merely quoted back as part of someone else's error text -- so this
  // requires an exact match against a whole (trimmed) line, never a
  // substring match anywhere in the combined output.
  const combinedOutput = (execResult.stdout + execResult.stderr).replace(/\x1b\[[0-9;]*m/g, "");
  const commandStartedInSandbox = combinedOutput.split(/\r?\n/).some((line) => line.trim() === execStartMarker);
  const gatewayLevelFailure = !commandStartedInSandbox;

  // Deliberately narrow: bare "denied" or "landlock" would also match a
  // GATEWAY-level rejection that has nothing to do with file access (an
  // auth/connection error, a rate limit, anything containing those words
  // in passing) and get counted as the sandbox denying the file operation.
  // These are the specific forms of a refused file operation: EACCES and
  // EPERM, both by errno name and by the text tools actually print for
  // them -- "Permission denied" (EACCES, e.g. a Landlock refusal) and
  // "Operation not permitted" (EPERM, e.g. `rm` of someone else's file in
  // a sticky directory). Matching the name "EPERM" alone missed the
  // second form entirely, so such a refusal fell through to "looks like
  // a connection failure" without ever being checked. Only trusted when
  // gatewayLevelFailure (above) is false; a gateway-level message always
  // wins regardless of what words it contains. This says the operation
  // was REFUSED, not by whom -- see linuxPermissionCheck() below.
  const REFUSAL_TEXT = /\bpermission denied\b|\boperation not permitted\b|\beacces\b|\beperm\b/i;
  const outputLines = combinedOutput.split(/\r?\n/);
  const refusalTextSeen = !gatewayLevelFailure && outputLines.some((l) => REFUSAL_TEXT.test(l));
  // The start marker proves the WRAPPER shell started -- not that the file
  // tool (cat/rm/...) ever reached the file. E.g. `cat` failing to launch
  // prints "sh: 1: cat: Permission denied" (exit 126) with the file itself
  // perfectly readable, and that was being credited to OpenShell. Every
  // operation here reports a refusal of the file with the file's own path
  // on the same line ("cat: <path>: ...", "cannot create <path>: ...",
  // "rm: cannot remove '<path>': ..."), and the path is this attempt's own
  // random name, so a refusal only counts as the file operation's when it
  // names `target`.
  const refusalOnTarget = !gatewayLevelFailure && outputLines.some((l) => REFUSAL_TEXT.test(l) && l.includes(target));
  // 126 = found but could not be executed, 127 = not found: the shell's
  // own codes for "the command never ran", whatever text accompanies them.
  const toolNotStarted = !gatewayLevelFailure && (execResult.code === 126 || execResult.code === 127);
  const processIdentity = gatewayLevelFailure ? null : parseProcessIdentity(combinedOutput, execStartMarker);

  // "Was it refused?" and "did OpenShell refuse it?" are kept as separate
  // fields in the result, so nothing reading it can take the first for
  // the second:
  //   operationRefused   -- it started inside the sandbox and was refused
  //   refusedByOpenShell -- true only once ordinary Linux permissions are
  //                         ruled out as the cause; null while that is
  //                         undetermined; false when nothing was refused
  let operationRefused = false;
  let refusedByOpenShell = false;
  let linuxCheck = null;
  let denialAttribution = null;

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
    // BEFORE any text-matching: relying on `refusalTextSeen` to gate this
    // case is not enough, since a crash's own stderr can coincidentally
    // contain a denial-like word and would otherwise slip through as a
    // false "blocked, consistent with permission".
    verdict = "inconclusive: the exec command did not exit normally (killed by a signal, no exit code) -- not a result either way";
  } else if (gatewayLevelFailure) {
    // The command never reached/started inside the sandbox -- this
    // attempt's own execStartMarker never showing up in the output is the
    // evidence (see above), not a text-match on any particular error
    // wording. Checked and reported before the file is ever judged
    // against the expected permission: crediting this as "blocked,
    // consistent with the permission" would report a gateway/connection
    // failure as a successful security control, which is exactly the
    // false positive this guards against.
    verdict = `inconclusive: the command never started running inside the sandbox (this attempt's own start marker never appeared in the output -- a gateway/CLI-level issue: ${safeText(
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
    } else if (!actuallyAllowed && toolNotStarted) {
      verdict = `inconclusive: the file tool itself could not be started (exit ${execResult.code}) -- the operation never reached the file, so this says nothing about OpenShell's file policy`;
    } else if (!actuallyAllowed && refusalTextSeen && !refusalOnTarget) {
      verdict =
        "inconclusive: a refusal was reported, but not for the target file -- it cannot be tied to the file operation itself, so it is not credited to OpenShell";
    } else if (!actuallyAllowed && !refusalTextSeen) {
      // A non-zero exit with the file unchanged is NOT by itself proof
      // OpenShell denied it -- `openshell sandbox exec` can just as easily
      // fail at the CLI/gateway level (can't reach the sandbox, sandbox
      // not found, a transient connection error) with a perfectly normal,
      // non-null, non-timeout exit code. Without actual denial-like text
      // in the output, crediting this as "blocked, consistent with
      // permission" would be reporting a connection failure as a
      // successful security control.
      verdict = `inconclusive: the command failed (exit ${execResult.code}) with no denial-like text in its output -- looks like a connection/CLI-level failure, not a confirmed OpenShell block`;
    } else if (!actuallyAllowed && (linuxCheck = await linuxPermissionCheck(container, processIdentity, operation, target)).status !== "allows") {
      // The refusal is real (it happened after the start marker), but
      // plain Linux permissions would refuse this same uid anyway -- or
      // that can't be ruled out -- so crediting OpenShell for it, either
      // as "consistent" or as "unexpectedly blocked", would be a guess.
      operationRefused = true;
      refusedByOpenShell = null;
      denialAttribution = "undetermined";
      verdict =
        `denied, cause undetermined: the operation started inside the sandbox and was refused, but ` +
        (linuxCheck.status === "denies"
          ? `ordinary Linux permissions would refuse it too (${linuxCheck.detail})`
          : `it could not be ruled out that ordinary Linux permissions alone refused it (${linuxCheck.detail})`) +
        ` -- not attributable to OpenShell`;
    } else {
      if (!actuallyAllowed) {
        // Linux permissions would have allowed it, so the refusal came from
        // the enforcement layer -- that is what refusedByOpenShell records.
        operationRefused = true;
        refusedByOpenShell = true;
        denialAttribution = "not_linux_permissions";
      }
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
    // Never the raw execResult.stdout/stderr: those are only for internal
    // measurement above (gatewayLevelFailure/refusalTextSeen text-checks).
    // What's actually persisted and returned over IPC is this attempt's
    // own start-marker and identity lines stripped out (their job is done
    // once gatewayLevelFailure/processIdentity were computed above) and
    // the SAME credential-scrubbing pass used everywhere else in this
    // file, so a credential a command happened to echo back can't flow
    // into the result JSON on disk, the IPC reply, or the results table.
    execStdout: safeText(stripMarkerLines(execResult.stdout, execStartMarker)),
    execStderr: safeText(stripMarkerLines(execResult.stderr, execStartMarker)),
    // The old single `deniedBySandbox` flag is gone: it was true whenever
    // denial-like text appeared, even when the result also said the cause
    // was undetermined, so anything counting it would credit OpenShell.
    operationRefused,
    refusedByOpenShell,
    gatewayLevelFailure,
    processIdentity,
    linuxPermissionCheck: linuxCheck,
    denialAttribution,
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

// CONFIRMED real bug: `{ file: f, ...data }` returned every field a
// result file happens to contain, including `before.content`/
// `after.content` -- fileState()'s raw file content, which redactContent()
// only ever strips for a result persisted AFTER that redaction was added.
// A result file from before that fix (or any future bug that writes one
// without it) would have the protected file's real content spread
// straight into the IPC reply and the UI's reach, even though every field
// this view actually needs is already covered by `before`/`after` just
// carrying `state`/`detail`. Listing exactly the fields the UI uses --
// never a blanket spread of the parsed JSON -- means a stray extra field
// in ANY result file (old or new, this one or a future one) can't reach
// the renderer no matter what it's named.
function safeFileNamePart(s) {
  return String(s || "unknown").replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 60) || "unknown";
}

// Writes one result file and returns its name. Two attempts used to be
// able to produce the SAME name (same sandbox and operation, started in
// the same millisecond) and the second silently replaced the first; the
// name now carries a random per-attempt ID, and the file is published by
// hard-linking a fully written temp file into place -- a link fails if the
// name already exists, so nothing is ever overwritten (a fresh ID is
// drawn instead), and a reader never sees a half-written file.
function writeResultFile(makeName, makeResult) {
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  for (let tries = 0; tries < 5; tries++) {
    const attemptId = crypto.randomBytes(6).toString("hex");
    const file = makeName(attemptId);
    const finalPath = path.join(RESULTS_DIR, file);
    const tmpPath = path.join(RESULTS_DIR, `.${file}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`);
    fs.writeFileSync(tmpPath, JSON.stringify(makeResult(attemptId), null, 2), { flag: "wx" });
    try {
      fs.linkSync(tmpPath, finalPath);
      return { attemptId, file };
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
    } finally {
      fs.unlinkSync(tmpPath);
    }
  }
  throw new Error("Could not find an unused result file name after 5 tries.");
}

// The parsed result object, or null if the file can't be read as one.
function readResultFile(f) {
  try {
    const data = JSON.parse(fs.readFileSync(path.join(RESULTS_DIR, f), "utf8"));
    return data && typeof data === "object" && !Array.isArray(data) ? data : null;
  } catch {
    return null;
  }
}

function listResults() {
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  return fs
    .readdirSync(RESULTS_DIR)
    .filter((f) => f.endsWith(".json") && !f.startsWith("."))
    .sort()
    .reverse()
    .map((f) => {
      const data = readResultFile(f);
      if (!data) {
        // One damaged file used to throw out of listResults() and blank the
        // whole Results table. It's shown as its own row instead -- with a
        // fixed message, never the parser's error, which can quote the file.
        return { file: f, unreadable: true, verdict: "unreadable result file (not valid JSON) -- skipped" };
      }
      // Defense in depth for display, not a rewrite of the file on disk:
      // a result persisted before execStdout/execStderr were scrubbed at
      // write time (or by any future mistake) must still never show a raw
      // credential in the UI. Applied to every text field that can embed
      // a command's own output, using the exact same scrubCredentials
      // pass used when these fields are first written.
      return {
        file: f,
        startedAt: data.startedAt,
        finishedAt: data.finishedAt,
        versionTag: data.versionTag,
        sandboxName: data.sandboxName,
        operation: data.operation,
        verdict: typeof data.verdict === "string" ? safeText(data.verdict) : data.verdict,
        execStdout: typeof data.execStdout === "string" ? safeText(data.execStdout) : data.execStdout,
        execStderr: typeof data.execStderr === "string" ? safeText(data.execStderr) : data.execStderr,
        cleanup: data.cleanup
          ? {
              status: data.cleanup.status,
              path: data.cleanup.path,
              reason: typeof data.cleanup.reason === "string" ? safeText(data.cleanup.reason) : data.cleanup.reason,
            }
          : undefined,
      };
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
// What a sandbox actually runs, read from its live container rather than
// from anything this app remembers: the exact image ID, and the
// `--workdir` OpenShell passed to the sandbox supervisor (confirmed
// against a real container: Config.Cmd is `["--workdir", "/sandbox"]`
// and Config.Image is the full `sha256:` ID). Both are needed to replace
// a sandbox with an equivalent one -- the image a user picked at creation
// time can be anything (the create dialog accepts a custom image), so
// assuming `images/base` here could silently swap it out.
async function inspectSandboxRuntime(sandboxName) {
  const container = await containerNameFor(sandboxName);
  if (!container) return { ok: false, error: `no running container found for sandbox '${sandboxName}'` };
  const inspected = await runInWsl(`docker inspect -f '{{.Image}}|{{json .Config.Cmd}}' ${shQuote(container)}`);
  if (inspected.code !== 0) return { ok: false, error: `could not inspect container ${container}` };
  const sep = inspected.stdout.indexOf("|");
  const imageId = inspected.stdout.slice(0, sep).trim();
  if (sep < 0 || !/^sha256:[0-9a-f]{64}$/.test(imageId)) {
    return { ok: false, error: `could not determine the exact image ID of container ${container}` };
  }
  let cmd;
  try {
    cmd = JSON.parse(inspected.stdout.slice(sep + 1).trim());
  } catch {
    cmd = null;
  }
  let workdir = null;
  if (Array.isArray(cmd)) {
    const i = cmd.indexOf("--workdir");
    if (i >= 0 && typeof cmd[i + 1] === "string") workdir = cmd[i + 1];
    const eq = cmd.find((a) => typeof a === "string" && a.startsWith("--workdir="));
    if (!workdir && eq) workdir = eq.slice("--workdir=".length);
  }
  if (!workdir) return { ok: false, error: `could not determine the working directory OpenShell configured for container ${container}` };
  return { ok: true, container, imageId, workdir };
}

// Sandboxes with a delete-and-recreate in flight. Two of these for the
// same sandbox used to run side by side: both read the same policy, both
// reached `sandbox delete`, and one could recreate the sandbox with the
// other's policy or delete the environment the other had just built. Only
// one may run per sandbox; a second request is refused, not queued (by
// the time it ran, what the user saw when asking would be out of date).
// Attempts against a sandbox that is being replaced are refused too,
// rather than measured against a container that is about to disappear.
const recreatesInProgress = new Set();

async function createProtectedFolder(params) {
  const sandboxName = params && params.sandboxName;
  if (recreatesInProgress.has(sandboxName)) {
    return {
      ok: false,
      error: `A protected-folder change for '${sandboxName}' is already running (it deletes and recreates the sandbox). Wait for it to finish, then try again.`,
    };
  }
  recreatesInProgress.add(sandboxName);
  try {
    return await createProtectedFolderUnlocked(params);
  } finally {
    recreatesInProgress.delete(sandboxName);
  }
}

async function createProtectedFolderUnlocked({ sandboxName, folderName = "Ahmed", permission = "none" }) {
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

  // The replacement must be the SAME environment with only the policy
  // changed: same exact image (by ID, not by whatever `images/base`
  // happens to build into today -- the sandbox may have been created from
  // a custom image) and the same working directory, which is what
  // include_workdir's coverage is predicted from below. Both are read from
  // the live container now; if either can't be determined, nothing has
  // been deleted yet, so stop here.
  const runtime = await inspectSandboxRuntime(sandboxName);
  if (!runtime.ok) {
    return { ok: false, error: `Cannot identify what '${sandboxName}' currently runs (${runtime.error}). Not deleting the existing sandbox.` };
  }

  // The workdir OpenShell configured (container Cmd) must also be the one
  // the sandboxed process actually sees -- if the two disagree, the
  // current environment isn't understood well enough to replace it.
  // This is its own precondition, checked whatever the permission
  // prediction below would say: an explicit read_write rule settles that
  // prediction before include_workdir is ever consulted, so leaving this
  // check to the prediction let a mismatched workdir through to the delete.
  const pwd = await runInWsl(`openshell sandbox exec -n ${shQuote(sandboxName)} -- pwd`, { timeoutMs: 20_000 });
  const livePwd = pwd.code === 0 && pwd.stdout.trim() ? path.posix.normalize(pwd.stdout.trim()) : null;
  if (!livePwd || livePwd !== path.posix.normalize(runtime.workdir)) {
    return {
      ok: false,
      error:
        `Cannot confirm '${sandboxName}'s working directory: OpenShell configured ${runtime.workdir}, but the sandboxed ` +
        `process ${livePwd ? `reports ${livePwd}` : "could not be asked"}. Not deleting the existing sandbox.`,
    };
  }
  const workdir = livePwd;

  // A parent of folderPath (e.g. /home/sandbox) can already be granted
  // read_write by some OTHER existing rule -- Landlock access is the UNION
  // of every covering rule (see longestCoveringPrefix), so nothing this
  // folder's OWN entry omits can take that broader grant back. Predicted
  // here against the PROPOSED policy, before anything is deleted -- a
  // mismatch (or an unconfirmable include_workdir) must stop the whole
  // operation now, not after the sandbox is already gone.
  const predicted = computeStaticPermission(effective.filesystem_policy, folderPath, { workdir });
  if (predicted.level === "unknown") {
    return {
      ok: false,
      error: `Cannot confirm the requested permission '${permission}' for ${folderPath} before recreating the sandbox: ${predicted.reason} Not deleting the existing sandbox.`,
    };
  }
  if (predicted.level !== permission) {
    return {
      ok: false,
      error:
        `Requested permission '${permission}' for ${folderPath} would NOT actually take effect -- the proposed policy ` +
        `would still grant '${predicted.level}' there` +
        (predicted.matchedPath ? ` (covered by an existing rule for '${predicted.matchedPath}')` : "") +
        `. Not deleting the existing sandbox.`,
    };
  }

  // The user/group the sandboxed process runs as comes from the policy,
  // not an assumption: a custom image may not have `sandbox:sandbox` at
  // all, and finding that out by a failed `chown` AFTER the original
  // sandbox is deleted would leave the user with neither. Checked against
  // the current environment (same image as the replacement) now.
  const runAsUser = effective.process && effective.process.run_as_user;
  const runAsGroup = effective.process && effective.process.run_as_group;
  const NAME_RE = /^[a-z_][a-z0-9_-]*\$?$/i;
  if (!NAME_RE.test(runAsUser || "") || !NAME_RE.test(runAsGroup || "")) {
    return { ok: false, error: `'${sandboxName}'s policy does not name a usable run_as_user/run_as_group. Not deleting the existing sandbox.` };
  }
  const idCheck = await runInWsl(
    `docker exec -u root ${runtime.container} sh -c 'id -u "$1" >/dev/null && getent group "$2" >/dev/null' _ ${shQuote(runAsUser)} ${shQuote(runAsGroup)}`
  );
  if (idCheck.code !== 0) {
    return {
      ok: false,
      error: `The policy runs the sandbox as ${runAsUser}:${runAsGroup}, but that user or group does not exist in '${sandboxName}'s image. Not deleting the existing sandbox.`,
    };
  }

  // Unique per request: a shared fixed name let two requests overwrite
  // each other's policy between writing it and `sandbox create` reading it.
  const tmpPolicyPath = `/tmp/oea-policy-${sandboxName}-${crypto.randomBytes(8).toString("hex")}.yaml`;
  try {
    return await recreateWithPolicy({ sandboxName, effective, folderPath, permission, runtime, tmpPolicyPath, runAsUser, runAsGroup });
  } finally {
    await runInWsl(`rm -f ${shQuote(tmpPolicyPath)}`);
  }
}

async function recreateWithPolicy({ sandboxName, effective, folderPath, permission, runtime, tmpPolicyPath, runAsUser, runAsGroup }) {
  const yaml = policyToYaml(effective);
  const writeTmp = await runInWsl(`cat > ${shQuote(tmpPolicyPath)} << 'OEA_POLICY_EOF'\n${yaml}OEA_POLICY_EOF`);
  if (writeTmp.code !== 0) {
    return { ok: false, error: `Could not stage the policy file: ${safeText(writeTmp.stderr)}` };
  }

  // Pin the exact image under a local tag BEFORE deleting anything, and
  // confirm the tag really resolves to that image ID. Confirmed live:
  // `sandbox create --from <local tag>` reuses the local image ("Image
  // already present") and the new container runs the identical sha256 ID
  // with the same `--workdir`. The tag also keeps the image from being
  // garbage-collected once the old container is gone.
  const pinnedImage = `oea-preserved/${sandboxName}:${runtime.imageId.slice("sha256:".length, "sha256:".length + 32)}`;
  const tag = await runInWsl(
    `docker tag ${shQuote(runtime.imageId)} ${shQuote(pinnedImage)} && docker image inspect -f '{{.Id}}' ${shQuote(pinnedImage)}`
  );
  if (tag.code !== 0 || tag.stdout.trim() !== runtime.imageId) {
    return { ok: false, error: `Could not pin the sandbox's current image (${runtime.imageId}) for reuse. Not deleting the existing sandbox.` };
  }

  // Recreate the sandbox under the same name with the new policy baked in.
  // This loses whatever else was in the sandbox (it's not a persistent
  // environment for this project), which is why `openshell policy set`
  // alone would have been preferable if it worked for loosening -- it doesn't.
  const del = await runInWsl(`openshell sandbox delete ${shQuote(sandboxName)} 2>&1`);
  if (del.code !== 0) {
    return { ok: false, error: `Could not delete the existing sandbox: ${safeText(del.stdout + del.stderr).trim()}` };
  }
  const created = await createSandboxFromPolicyFile({ name: sandboxName, wslPolicyPath: tmpPolicyPath, image: pinnedImage });
  if (!created.ok) {
    return {
      ok: false,
      error: `Recreating the sandbox with the new policy failed (its image is still kept as ${pinnedImage}): ${created.error}`,
    };
  }

  // The replacement must actually be the same environment, not just have
  // been asked to be -- checked before anything is reported as success.
  const after = await inspectSandboxRuntime(sandboxName);
  if (!after.ok) return { ok: false, error: `Sandbox recreated, but it could not be inspected afterward (${after.error}).` };
  if (after.imageId !== runtime.imageId || path.posix.normalize(after.workdir) !== path.posix.normalize(runtime.workdir)) {
    return {
      ok: false,
      error:
        `Sandbox recreated, but it does not match the original: image ${after.imageId} (was ${runtime.imageId}), ` +
        `workdir ${after.workdir} (was ${runtime.workdir}). Treating this as a failure.`,
    };
  }
  const container = after.container;

  const mk = await runInWsl(
    `docker exec -u root ${container} sh -c 'mkdir -p "$1" && chown "$2:$3" "$1" && chmod 777 "$1"' _ ${shQuote(folderPath)} ${shQuote(runAsUser)} ${shQuote(runAsGroup)}`
  );
  if (mk.code !== 0) {
    return { ok: false, error: `Sandbox recreated, but could not create the folder inside it: ${safeText(mk.stderr || mk.stdout)}` };
  }

  // The prediction above was checked against the POLICY TEXT this app was
  // about to write -- it never asked the sandbox itself. Before telling the
  // user this succeeded, confirm the ACTUAL live policy (same
  // computeEffectivePermission() the rest of the app trusts) agrees, so a
  // bug in policyToYaml's serialization, in how `openshell` parsed it, or
  // an include_workdir contribution that only a live sandbox can resolve,
  // is caught here instead of silently shown as a success.
  const verified = await computeEffectivePermission(sandboxName, folderPath);
  if (verified.level !== permission) {
    return {
      ok: false,
      error:
        `Sandbox recreated, but its ACTUAL effective permission for ${folderPath} is '${verified.level}', not the requested '${permission}'` +
        (verified.matchedPath ? ` (matched rule: ${verified.matchedPath})` : "") +
        (verified.reason ? ` (${verified.reason})` : "") +
        `. Treating this as a failure rather than showing a false success.`,
    };
  }

  return {
    ok: true,
    sandboxName,
    folderPath,
    permission,
    actualPermission: verified.level,
    imageId: after.imageId,
    workdir: after.workdir,
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
