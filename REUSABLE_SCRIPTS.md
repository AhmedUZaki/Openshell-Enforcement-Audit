# Scripts reusable from openshell-security-eval

## Reusable as-is (infrastructure, version-agnostic)
- `scripts/1-install-dependencies.{sh,cmd}` — installs Docker/nemoclaw/openshell CLI deps
- `scripts/2-check-environment.{sh,cmd}` — environment sanity checks
- `scripts/start-everything.{sh,cmd}` / `stop-everything.{sh,cmd}` — gateway/sandbox lifecycle
- `scripts/check-status.{sh,cmd}` — status overview
- `scripts/fix-network-error.{sh,cmd}` — Ollama/network troubleshooting
- `scripts/restart-wsl.cmd`

## Reusable with changes (need parameterizing by OpenShell/NemoClaw version)
- `scripts/3-create-tier-sandboxes.{sh,cmd}` — currently hardcodes the model and
  onboard flags for one version; needs a version/tag parameter to build
  sandboxes pinned to a specific OpenShell release.

## Reusable directly for no-agent testing (already bypass the agent)
- `experiments/01-etc-read-only/<tier>/1-prepare.{sh,cmd}` — plants the target
  file from outside the agent (`docker exec` as root). No LLM involved.
- `experiments/01-etc-read-only/<tier>/2-snapshot.{sh,cmd}` — reads the file
  back and diffs against baseline, independent of the agent. No LLM involved.

## NOT reusable (agent-dependent — the opposite of this project's goal)
- `experiments/01-etc-read-only/<tier>/3-run-attempts.{sh,cmd}` — drives the
  test THROUGH `nemoclaw <sandbox> agent`, i.e. through the LLM. This is
  exactly the layer this project removes: here, attempts should run as direct
  `docker exec` / `openshell sandbox exec` calls instead.
- `experiments/01-etc-read-only/4-compare-tiers.{sh,cmd}` — aggregates
  agent-run results; would need rewriting around direct-exec results instead.
