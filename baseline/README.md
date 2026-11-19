# baseline

Space for initial manual experiments against OpenShell (commands run and their results), before they get automated.

## Allow-listed fields for recorded experiments

A raw `curl -I`/command capture carries more than this project needs, some
of it identifying (client IP, GeoIP-derived location, per-visitor cookies,
request IDs). When writing a NEW experiment into this folder, keep only:

- the command actually run (and the policy/rule set up for it, if any)
- the destination (host:port, path)
- the HTTP status line (and `Location` header, if the test is about a
  redirect)
- OpenShell's own decision and rule name from its log line (`ALLOWED` /
  `DENIED`, `policy:<name>`, `engine:<...>`, `reason:...`)

Everything else -- `Set-Cookie` values, `x-client-ip`, `x-request-id`,
GeoIP/analytics headers, cache/server-timing internals, container
hostnames, process IDs -- gets dropped or replaced with a
`[REDACTED...]` placeholder rather than recorded verbatim. This only
applies going forward to what this folder shows; it does not rewrite
this repo's git history, so an earlier, unsanitized capture of the same
experiment may still be reachable in an older commit (e.g. `a21c68f`) --
that history is left alone, not force-pushed over.

## Experiments

- `baseline_test1.txt` -- allowed: a read-only network rule for a specific
  endpoint lets a matching request through.
- `baseline_test2.txt` -- denied: an endpoint with no matching rule at all
  is blocked by default.
- `baseline_test3.txt` -- rule IMPACT: the exact same request, measured
  twice in one disposable sandbox (the same running container both times)
  -- once before and once after adding one allow rule to its live policy.
  The rule is the only thing deliberately changed; time, remote server
  state and the sandbox's own history were not controlled, so the result
  is attributed through OpenShell's decision log naming the new rule, not
  through the HTTP result alone. Run for real against a live OpenShell
  gateway/sandbox, not simulated.
