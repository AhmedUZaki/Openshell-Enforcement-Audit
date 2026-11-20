// What a sandbox's EXISTING network policy says should happen to one request,
// and how that compares with what OpenShell actually did. Pure functions, no
// I/O -- the network test (runner.js) feeds them the live policy and the
// OpenShell log lines.
//
// Only behaviour that was MEASURED against a live OpenShell is modelled
// (0.0.116, `curl` inside a sandbox, https, on a real network):
//   - no rule naming this binary for host:port -> the connection is refused
//     (also true when the rule lists no binaries, or only other binaries);
//   - protocol rest + enforcement enforce:
//       * explicit `rules` -> allowed when an allow rule's method and path
//         glob match; `*` stays inside one path segment, `**` crosses them,
//         query strings are ignored, method names are case-insensitive and
//         `*` matches every method; a rule for GET also covers HEAD;
//       * `access` presets: read-only = GET HEAD OPTIONS; read-write adds
//         POST PUT PATCH; full adds DELETE;
//       * `deny_rules` subtract from whatever the above allows, and a deny
//         for GET also denies HEAD;
//   - an endpoint with no protocol (host and port only) is not inspected:
//     every method passes;
//   - several rules for the same host:port combine (any one may allow).
// Anything else -- other protocols, audit enforcement, allowed_ips,
// wildcard hosts, glob binaries, IP-literal hosts, plain http, methods
// beyond the seven below, rule forms with extra fields -- comes back as
// level "unknown" with the reason, never as a guess either way.

const MODELED_METHODS = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];
const BODY_METHODS = ["POST", "PUT", "PATCH"];
const PRESET_METHODS = {
  "read-only": ["GET", "HEAD", "OPTIONS"],
  "read-write": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"],
  full: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
};
const MODEL_VERIFIED_ON = "0.0.116";

const unknown = (reason) => ({ level: "unknown", layer: null, rule: null, reason });

function globToRegExp(glob) {
  let re = "";
  const g = String(glob);
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === "*" && g[i + 1] === "*") {
      re += ".*";
      i++;
    } else if (c === "*") {
      re += "[^/]*";
    } else {
      re += c.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${re}$`);
}

function stripQuery(p) {
  return String(p).split(/[?#]/)[0];
}

function pathMatches(glob, p) {
  return globToRegExp(glob).test(stripQuery(p));
}

// Does a rule written for `ruleMethod` apply to a request using `method`?
// HEAD is covered by rules for HEAD or for GET (measured, for allow and deny).
function ruleCovers(ruleMethod, method) {
  const rm = String(ruleMethod || "").toUpperCase();
  if (rm === "*" || rm === method) return true;
  return method === "HEAD" && rm === "GET";
}

const normalizeHost = (h) => String(h || "").toLowerCase().replace(/\.$/, "");
const isIpLiteral = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(":");

// Validates and splits a user-typed URL. Rejects anything that could carry
// a credential (user:pass@host) or that is not a plain http(s) URL.
function parseTarget(urlString) {
  const s = String(urlString ?? "").trim();
  if (!s) return { ok: false, error: "Enter a URL." };
  if (s.length > 2000 || /[\s\u0000-\u001f\u007f]/.test(s)) return { ok: false, error: "The URL must be a single line without spaces or control characters." };
  let u;
  try {
    u = new URL(s);
  } catch {
    return { ok: false, error: "That is not a valid URL (expected something like https://example.com/path)." };
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return { ok: false, error: "Only http:// and https:// URLs are supported." };
  if (u.username || u.password) return { ok: false, error: "URLs with a user name or password in them are not allowed (they would be logged)." };
  if (!u.hostname) return { ok: false, error: "The URL has no host." };
  const scheme = u.protocol === "https:" ? "https" : "http";
  const port = u.port ? Number(u.port) : scheme === "https" ? 443 : 80;
  return { ok: true, url: u.href, scheme, host: normalizeHost(u.hostname), port, path: u.pathname || "/", search: u.search };
}

// ---------------------------------------------------------------------
// Expected outcome from the live policy
// ---------------------------------------------------------------------
const ENDPOINT_KEYS_L4 = new Set(["host", "port", "ports"]);
const ENDPOINT_KEYS_L7 = new Set(["host", "port", "ports", "protocol", "enforcement", "access", "rules", "deny_rules"]);

function checkMethodPathRule(spec) {
  return spec && typeof spec === "object" && typeof spec.path === "string" && typeof spec.method === "string" && Object.keys(spec).every((k) => k === "method" || k === "path");
}

function evaluateEndpoint(name, ep, method, path) {
  const portText = ep.port ?? (Array.isArray(ep.ports) ? ep.ports.join("/") : "?");
  if (!ep.protocol) {
    const extra = Object.keys(ep).filter((k) => !ENDPOINT_KEYS_L4.has(k));
    if (extra.length) return { unknown: `rule '${name}' has options that are not modelled (${extra.join(", ")})` };
    return { allowed: true, layer: "l4", name, why: `rule '${name}' allows ${ep.host}:${portText} with no HTTP-level restrictions` };
  }
  if (ep.protocol !== "rest" || ep.enforcement !== "enforce") {
    return { unknown: `rule '${name}' uses protocol '${ep.protocol}' with enforcement '${ep.enforcement}', which is not modelled` };
  }
  const extra = Object.keys(ep).filter((k) => !ENDPOINT_KEYS_L7.has(k));
  if (extra.length) return { unknown: `rule '${name}' has options that are not modelled (${extra.join(", ")})` };
  if (ep.access && ep.rules) return { unknown: `rule '${name}' combines an access level with explicit rules, which is not modelled` };

  let allowed;
  let why;
  if (ep.access) {
    const set = PRESET_METHODS[ep.access];
    if (!set) return { unknown: `rule '${name}' uses access level '${ep.access}', which is not modelled` };
    allowed = set.includes(method);
    why = `rule '${name}' (access ${ep.access}) ${allowed ? "allows" : "does not allow"} ${method}`;
  } else if (Array.isArray(ep.rules) && ep.rules.length) {
    for (const r of ep.rules) {
      if (!r || typeof r !== "object" || Object.keys(r).length !== 1 || !checkMethodPathRule(r.allow)) {
        return { unknown: `rule '${name}' has a rule form that is not modelled` };
      }
    }
    const hit = ep.rules.find((r) => ruleCovers(r.allow.method, method) && pathMatches(r.allow.path, path));
    allowed = !!hit;
    why = hit ? `rule '${name}' allows ${hit.allow.method} ${hit.allow.path}` : `rule '${name}' has no allow rule for ${method} ${path}`;
  } else {
    return { unknown: `rule '${name}' defines neither an access level nor explicit rules` };
  }

  if (ep.deny_rules !== undefined) {
    if (!Array.isArray(ep.deny_rules) || !ep.deny_rules.every(checkMethodPathRule)) {
      return { unknown: `rule '${name}' has a deny rule form that is not modelled` };
    }
    const deny = ep.deny_rules.find((d) => ruleCovers(d.method, method) && pathMatches(d.path, path));
    if (deny) {
      allowed = false;
      why = `a deny rule in '${name}' blocks ${deny.method} ${deny.path}`;
    }
  }
  return { allowed, layer: "l7", name, why, hasDeny: Array.isArray(ep.deny_rules) && ep.deny_rules.length > 0 };
}

// networkPolicies: the live policy's `network_policies` object.
// request: { binary, host, port, method, path, scheme }
function evaluateNetworkPolicy(networkPolicies, request) {
  const { binary, host, port, method, path, scheme } = request;
  if (scheme !== "https") return unknown("plain http requests were not measured, so no expectation is given");
  if (!MODELED_METHODS.includes(method)) return unknown(`${method} was not measured, so no expectation is given`);
  if (isIpLiteral(host)) return unknown("IP-address destinations are not modelled, so no expectation is given");

  const candidates = [];
  for (const [key, np] of Object.entries(networkPolicies || {})) {
    const name = (np && np.name) || key;
    const binaries = ((np && np.binaries) || []).map((b) => b && b.path).filter((p) => typeof p === "string");
    for (const ep of (np && np.endpoints) || []) {
      const hostPattern = normalizeHost(ep.host);
      const wildcardHost = hostPattern.includes("*");
      if (wildcardHost) {
        const probe = new RegExp("^" + hostPattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$");
        if (!probe.test(host)) continue;
      } else if (hostPattern !== host) {
        continue;
      }
      const ports = Number.isInteger(ep.port) ? [ep.port] : Array.isArray(ep.ports) ? ep.ports.filter(Number.isInteger) : null;
      if (ports && !ports.includes(port)) continue;
      if (wildcardHost) return unknown(`rule '${name}' uses a wildcard host ('${ep.host}'), which is not modelled`);
      if (!ports) return unknown(`rule '${name}' does not state a port in a form that is modelled`);
      if (binaries.some((b) => /[*?]/.test(b)) && !binaries.includes(binary)) {
        return unknown(`rule '${name}' lists binary patterns, which are not modelled`);
      }
      if (!binaries.includes(binary)) continue; // measured: a rule that does not name this binary does not apply
      candidates.push({ name, ep });
    }
  }

  if (!candidates.length) {
    return { level: "block_connection", layer: null, rule: null, reason: `no rule lets ${binary} reach ${host}:${port}` };
  }
  const evals = candidates.map(({ name, ep }) => evaluateEndpoint(name, ep, method, path));
  const bad = evals.find((e) => e.unknown);
  if (bad) return unknown(bad.unknown);
  if (evals.length > 1) {
    if (evals.some((e) => e.hasDeny)) return unknown("several rules cover this destination and one has deny rules, which is not modelled");
    if (evals.some((e) => e.layer === "l4")) return unknown("several rules cover this destination and one is a plain endpoint, which is not modelled");
  }
  const allowing = evals.filter((e) => e.allowed);
  if (allowing.length) {
    return { level: "allow", layer: allowing[0].layer, rule: allowing.map((e) => e.name).join(", "), reason: allowing[0].why };
  }
  return { level: "block_request", layer: "l7", rule: evals.map((e) => e.name).join(", "), reason: evals.map((e) => e.why).join("; ") };
}

// ---------------------------------------------------------------------
// What OpenShell actually decided, from its own log lines
// ---------------------------------------------------------------------
const NET_LINE = /NET:OPEN \[[A-Z]+\] (ALLOWED|DENIED) (\S+?)\((\d+)\) -> ([^\s:]+):(\d+) \[policy:([^\s\]]*) engine:(\w+)\](?: \[reason:(.*)\])?/;
const HTTP_LINE = /HTTP:([A-Z]+) \[[A-Z]+\] (ALLOWED|DENIED) ([A-Z]+) https?:\/\/([^\s/:]+):(\d+)(\/\S*)? \[policy:([^\s\]]*) engine:(\w+)\](?: \[reason:(.*)\])?/;
// Plain-http requests go through OpenShell's forward proxy and are logged in
// one shape of their own: the binary and method inline, the port omitted
// for 80, and the engine telling the layer apart (opa = no rule covers the
// destination / connection-level, l7 = the request rules).
const FORWARD_LINE = /HTTP:([A-Z]+) \[[A-Z]+\] (ALLOWED|DENIED) (\S+?)\((\d+)\) -> ([A-Z]+) https?:\/\/([^\s/:]+)(?::(\d+))?(\/\S*)? \[policy:([^\s\]]*) engine:(\w+)\](?: \[reason:(.*)\])?/;

// Which of the new log lines belong to THIS request?
//  * Connection-level lines name the process (`curl(53)`); HTTP-level
//    lines of the https shape do not.
//  * If the lines for this destination come from more than one process
//    (another curl, or a different request of the same one), nothing
//    ties the decision to this request, so `ambiguous` is set and the
//    caller must not judge it. With `pid` known (the test's own curl),
//    any line from another process is such a case; without it, two
//    different pids are.
function parseDecisionLines(lines, { binary, host, port, method, path, pid }) {
  const out = { connection: null, connectionRule: null, connectionReason: null, http: null, httpRule: null, httpReason: null, lines: [], ambiguous: false, pids: [] };
  const wantPath = stripQuery(path);
  const pids = new Set();
  const matched = [];
  for (const line of lines) {
    const f = FORWARD_LINE.exec(line);
    if (f && f[3] === binary && normalizeHost(f[6]) === host && Number(f[7] || 80) === port) {
      pids.add(f[4]);
      matched.push({ kind: "forward", m: f, pid: f[4], line });
      continue;
    }
    const n = NET_LINE.exec(line);
    if (n && n[2] === binary && normalizeHost(n[4]) === host && Number(n[5]) === port) {
      pids.add(n[3]);
      matched.push({ kind: "net", m: n, pid: n[3], line });
      continue;
    }
    const h = HTTP_LINE.exec(line);
    if (h && h[3] === method && normalizeHost(h[4]) === host && Number(h[5]) === port && stripQuery(h[6] || "/") === wantPath) {
      matched.push({ kind: "http", m: h, pid: null, line });
    }
  }
  out.pids = [...pids];
  const others = pid ? [...pids].filter((p) => p !== String(pid)) : [];
  out.ambiguous = pid ? others.length > 0 : pids.size > 1;

  // An https HTTP-level line names no process. It is tied to this request
  // only through a connection line of the SAME request; with none (e.g. DNS
  // failed before any connection) it belongs to someone else and is dropped.
  const ownConnection = matched.some((x) => x.kind !== "http" && (!pid || x.pid === String(pid)));

  for (const { kind, m, pid: linePid, line } of matched) {
    if (kind === "http" && !ownConnection) continue;
    if (kind === "forward") {
      if (pid && linePid !== String(pid)) continue;
      if (m[5] !== method || stripQuery(m[8] || "/") !== wantPath) continue;
      out.lines.push(line);
      const rule = m[9] === "-" ? null : m[9];
      const layer = m[10] === "l7" ? "http" : "connection";
      if (m[2] === "DENIED") {
        out[layer] = "denied";
        if (layer === "http") {
          out.httpRule = rule;
          out.httpReason = m[11] || null;
        } else {
          out.connectionReason = m[11] || null;
        }
      } else if (out[layer] !== "denied") {
        out[layer] = "allowed";
        if (layer === "http") out.httpRule = rule;
        else out.connectionRule = rule;
      }
    } else if (kind === "net") {
      if (pid && linePid !== String(pid)) continue;
      out.lines.push(line);
      if (m[1] === "DENIED") {
        out.connection = "denied";
        out.connectionReason = m[8] || null;
      } else if (out.connection !== "denied") {
        out.connection = "allowed";
        out.connectionRule = m[6] === "-" ? null : m[6];
      }
    } else {
      out.lines.push(line);
      if (m[2] === "DENIED") {
        out.http = "denied";
        out.httpRule = m[7] === "-" ? null : m[7];
        out.httpReason = m[9] || null;
      } else if (out.http !== "denied") {
        out.http = "allowed";
        out.httpRule = m[7] === "-" ? null : m[7];
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------
const LAYER_TEXT = { connection: "at the connection", request: "at the HTTP request" };

// observed: parseDecisionLines() result. curl: { status, exit }.
function composeNetworkVerdict({ expected, observed, curl, method, target }) {
  const where = `${method} ${target.host}:${target.port}${target.path}`;
  let seen = null; // "allowed" | "blocked_connection" | "blocked_request" | "connection_only"
  if (observed.ambiguous) {
    return {
      outcome: "inconclusive",
      verdict: `inconclusive: the sandbox log shows decisions for ${target.host}:${target.port} from more than one process (pids ${observed.pids.join(", ")}) in the same window, so none can be tied to this request -- run it again when nothing else is contacting that host`,
    };
  }
  if (observed.connection === "denied") seen = "blocked_connection";
  else if (observed.http === "denied") seen = "blocked_request";
  else if (observed.http === "allowed") seen = "allowed";
  else if (observed.connection === "allowed") seen = "connection_only";
  if (!seen) {
    return {
      outcome: "inconclusive",
      verdict: `inconclusive: no OpenShell decision line for ${where} was found in the sandbox log (curl exit ${curl.exit}) -- cannot say whether the policy allowed or blocked it`,
    };
  }

  // An uninspected (plain) endpoint logs only the connection decision.
  if (seen === "connection_only") {
    if (expected.level === "allow" && expected.layer === "l4") seen = "allowed";
    else if (expected.level === "block_connection") {
      // The policy says this connection must never open; OpenShell opened
      // it. That is the violation, whatever HTTP-level decision follows.
      return {
        outcome: "not_blocked",
        verdict: `NOT blocked: OpenShell allowed the connection for ${where}, but the policy says it should be blocked at the connection (${expected.reason}) (curl exit ${curl.exit})`,
      };
    } else if (expected.level === "unknown") {
      return {
        outcome: "no_expectation",
        verdict: `connection allowed by OpenShell, but no HTTP-level decision was logged (curl exit ${curl.exit}); no expectation for this rule: ${expected.reason}`,
      };
    } else {
      return {
        outcome: "inconclusive",
        verdict: `inconclusive: OpenShell allowed the connection but logged no HTTP-level decision for ${where} (curl exit ${curl.exit}), so the policy's request rules were never exercised`,
      };
    }
  }

  const failedNote = seen === "allowed" && curl.exit !== 0 ? ` (the request itself then failed: curl exit ${curl.exit}, which is not a policy decision)` : "";
  const serverNote = seen === "allowed" && curl.exit === 0 && curl.status && curl.status !== "200" ? ` (the server answered ${curl.status})` : "";
  const ruleNote = (r) => (r ? ` by rule '${r}'` : "");

  if (expected.level === "unknown") {
    const what =
      seen === "allowed"
        ? `allowed by OpenShell${ruleNote(observed.httpRule || observed.connectionRule)}`
        : `blocked by OpenShell ${LAYER_TEXT[seen === "blocked_connection" ? "connection" : "request"]}`;
    return { outcome: "no_expectation", verdict: `${what}${failedNote}${serverNote}; no expectation for this policy: ${expected.reason}` };
  }

  const expectedSeen = expected.level === "allow" ? "allowed" : expected.level === "block_connection" ? "blocked_connection" : "blocked_request";
  if (seen === expectedSeen) {
    if (seen === "allowed") return { outcome: "consistent_allowed", verdict: `allowed, consistent with the policy (${expected.reason})${failedNote}${serverNote}` };
    return {
      outcome: "consistent_blocked",
      verdict: `blocked ${LAYER_TEXT[seen === "blocked_connection" ? "connection" : "request"]}, consistent with the policy (${expected.reason})`,
    };
  }
  if (seen === "allowed") {
    return { outcome: "not_blocked", verdict: `NOT blocked: OpenShell allowed ${where}, but the policy says it should be blocked (${expected.reason})` };
  }
  if (expected.level === "allow") {
    return {
      outcome: "unexpectedly_blocked",
      verdict: `unexpectedly blocked: OpenShell blocked ${where} ${LAYER_TEXT[seen === "blocked_connection" ? "connection" : "request"]}, but the policy says it should be allowed (${expected.reason})`,
    };
  }
  return {
    outcome: "layer_mismatch",
    verdict: `blocked, but ${LAYER_TEXT[seen === "blocked_connection" ? "connection" : "request"]} where the policy predicts it ${LAYER_TEXT[expected.level === "block_connection" ? "connection" : "request"]} (${expected.reason})`,
  };
}

module.exports = {
  MODELED_METHODS,
  BODY_METHODS,
  PRESET_METHODS,
  MODEL_VERIFIED_ON,
  globToRegExp,
  pathMatches,
  ruleCovers,
  parseTarget,
  evaluateNetworkPolicy,
  parseDecisionLines,
  composeNetworkVerdict,
};
