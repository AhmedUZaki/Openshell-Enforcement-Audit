# Policies

Native OpenShell policy YAML (consumed by `openshell sandbox create --policy`
and `openshell policy set`), independent of NemoClaw.

- `restricted.yaml` — done: shared filesystem baseline, no network presets
  (deny-by-default), matching the report's Restricted tier.
- `balanced.yaml`, `open.yaml` — not written yet. NemoClaw's tier presets
  (npm, pypi, huggingface, brave, slack, jira, ...) are NemoClaw-specific
  shortcuts, not OpenShell's own format, and we don't have their exact
  resolved endpoint/rule definitions. Rather than guess at them, these are
  left as a follow-up: write the actual `network_policies` entries once we
  decide which destinations each tier should allow for this project.
