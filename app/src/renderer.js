// ---------------------------------------------------------------------
// Global state: one selected sandbox drives the protected-folder feature,
// the folder tree, and the attempt target -- switching it clears
// everything downstream so nothing from the previous sandbox lingers.
// ---------------------------------------------------------------------
const state = {
  sandboxName: "",
  folderPath: null,
};

// Bumped on every sandbox or folder switch. Any in-flight async call
// (tree loading, effective-permission lookup) captures the generation it
// started with and discards its own result if a newer selection has
// already superseded it by the time it resolves -- otherwise a slow
// response for the PREVIOUS sandbox/folder could land after a fast one
// for the NEW selection and overwrite it with stale data.
let selectionGeneration = 0;

// Separate from selectionGeneration: a policy refresh can be triggered by
// things that are NOT a sandbox/folder switch (the "Refresh policy"
// button, a policy-changing action finishing) and must still discard a
// stale in-flight reply the same way.
let policyGeneration = 0;

function verdictClass(verdict) {
  if (/^NOT blocked|^unexpectedly blocked/.test(verdict)) return "bad";
  if (/^inconclusive/.test(verdict)) return "warn";
  if (/consistent with the/.test(verdict)) return "ok";
  return "warn";
}

function td(text, className) {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = text; // never innerHTML: exec output/verdict text is untrusted data from inside the sandbox, not markup
  return cell;
}

// =======================================================================
// Results table
// =======================================================================
// `r.cleanup` is only present on results written after this field was
// introduced -- an older persisted result file simply won't have it.
// `r.cleanup` itself being absent/undefined is treated the same as
// "nothing to report" (never an error), so older results keep rendering
// exactly as before instead of showing a blank/broken cell.
function cleanupCellText(cleanup) {
  if (!cleanup || !cleanup.status) return "";
  if (cleanup.status === "removed") return "removed";
  if (cleanup.status === "already_absent") return "(n/a)";
  if (cleanup.status === "failed") return `FAILED to remove audit file${cleanup.reason ? `: ${cleanup.reason}` : ""}`;
  return cleanup.status;
}

async function refreshResults() {
  const results = await window.audit.listResults();
  const tbody = document.querySelector("#resultsTable tbody");
  tbody.innerHTML = "";
  for (const r of results) {
    const tr = document.createElement("tr");
    tr.appendChild(td(r.startedAt || ""));
    tr.appendChild(td(r.versionTag || ""));
    tr.appendChild(td(r.sandboxName || ""));
    tr.appendChild(td(r.operation || ""));
    tr.appendChild(td(r.verdict || "", verdictClass(r.verdict || "")));
    // Cleanup is reported as its own, independent cell -- it never
    // affects the verdict cell above, win or lose: a failed cleanup is a
    // warning about a leftover audit file, not evidence for or against
    // how OpenShell handled the actual attempt.
    tr.appendChild(td(cleanupCellText(r.cleanup), r.cleanup && r.cleanup.status === "failed" ? "warn" : undefined));
    const outputCell = document.createElement("td");
    const pre = document.createElement("pre");
    pre.textContent = (r.execStdout || "") + (r.execStderr || "");
    outputCell.appendChild(pre);
    tr.appendChild(outputCell);
    tbody.appendChild(tr);
  }
}
document.getElementById("refreshBtn").addEventListener("click", refreshResults);

// =======================================================================
// Version dropdowns (installed OpenShell version(s))
// =======================================================================
async function populateVersionDropdowns() {
  const versions = await window.audit.listOpenShellVersions();
  for (const id of ["newSandboxVersion", "versionTag"]) {
    const select = document.getElementById(id);
    select.innerHTML = "";
    if (versions.length === 0) {
      select.innerHTML = '<option value="">(no OpenShell install detected)</option>';
      continue;
    }
    for (const v of versions) {
      const opt = document.createElement("option");
      opt.value = v;
      opt.textContent = v;
      select.appendChild(opt);
    }
  }
}
populateVersionDropdowns();

// =======================================================================
// Global sandbox selection
// =======================================================================
const globalSandboxSelect = document.getElementById("globalSandboxName");
const protectedFolderSection = document.getElementById("protectedFolderSection");
const treeSection = document.getElementById("treeSection");
const attemptSection = document.getElementById("attemptSection");
const networkSection = document.getElementById("networkSection");
const folderDialogSandboxName = document.getElementById("folderDialogSandboxName");

function applySandboxGatedUI() {
  const has = !!state.sandboxName;
  protectedFolderSection.disabled = !has;
  treeSection.disabled = !has;
  attemptSection.disabled = !has;
  networkSection.disabled = !has;
  folderDialogSandboxName.textContent = state.sandboxName || "(none)";
}

async function populateGlobalSandboxDropdown(selectName) {
  const previous = selectName || globalSandboxSelect.value;
  const res = await window.audit.listSandboxes();
  globalSandboxSelect.innerHTML = "";
  if (!res.ok || res.sandboxes.length === 0) {
    globalSandboxSelect.innerHTML = '<option value="">(no sandboxes found)</option>';
    await onSandboxChanged("");
    return;
  }
  const opt0 = document.createElement("option");
  opt0.value = "";
  opt0.textContent = "(none selected)";
  globalSandboxSelect.appendChild(opt0);
  for (const sb of res.sandboxes) {
    const opt = document.createElement("option");
    opt.value = sb.name;
    opt.textContent = `${sb.name} (${sb.phase})`;
    globalSandboxSelect.appendChild(opt);
  }
  const names = res.sandboxes.map((s) => s.name);
  const next = names.includes(previous) ? previous : "";
  globalSandboxSelect.value = next;
  await onSandboxChanged(next);
}

// Switching sandboxes clears the previously selected folder/permission and
// reloads the tree from scratch -- nothing left over from the old
// selection should ever be shown against the new one.
async function onSandboxChanged(sandboxName) {
  const myGeneration = ++selectionGeneration;
  state.sandboxName = sandboxName;
  state.folderPath = null;
  applySandboxGatedUI();
  updateTargetDisplays();
  loadActivePolicy(sandboxName, { autoOpen: true }); // not awaited: independent of the tree/permission loads below
  refreshNetworkExpectation(); // not awaited either
  await refreshEffectivePermission(myGeneration);
  if (myGeneration !== selectionGeneration) return; // superseded by a newer switch while awaiting above
  if (sandboxName) {
    await mainTree.loadRoot(sandboxName); // the tree controller guards its own in-flight async work internally (treeGeneration)
  } else {
    mainTree.clear();
  }
}

// =======================================================================
// Active OpenShell policy (feature: live, read-only policy display)
// =======================================================================
const activePolicyDetails = document.getElementById("activePolicyDetails");
const policySandboxNameEl = document.getElementById("policySandboxName");
const policyStatusEl = document.getElementById("policyStatus");
const policySummaryEl = document.getElementById("policySummary");
const policyFullJsonEl = document.getElementById("policyFullJson");

function pathListGroup(title, paths) {
  const group = document.createElement("div");
  group.className = "policy-group";
  const h4 = document.createElement("h4");
  h4.textContent = title;
  group.appendChild(h4);
  if (paths.length === 0) {
    const none = document.createElement("div");
    none.className = "sub";
    none.textContent = "(none)";
    group.appendChild(none);
    return group;
  }
  const ul = document.createElement("ul");
  ul.className = "path-list";
  for (const p of paths) {
    const li = document.createElement("li");
    li.textContent = p;
    ul.appendChild(li);
  }
  group.appendChild(ul);
  return group;
}

function renderPolicySummary(summary) {
  policySummaryEl.innerHTML = "";

  const roPaths = summary.includeWorkdir ? [...summary.readOnly] : summary.readOnly;
  policySummaryEl.appendChild(pathListGroup("Read-only paths", roPaths));
  const rwLabel = summary.includeWorkdir ? "Read-write paths (plus the sandbox's working directory)" : "Read-write paths";
  policySummaryEl.appendChild(pathListGroup(rwLabel, summary.readWrite));

  const netGroup = document.createElement("div");
  netGroup.className = "policy-group";
  const netH4 = document.createElement("h4");
  netH4.textContent = "Network rules";
  netGroup.appendChild(netH4);
  if (summary.networkPolicies.length === 0) {
    const none = document.createElement("div");
    none.className = "sub";
    none.textContent = "(none configured)";
    netGroup.appendChild(none);
  } else {
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    thead.innerHTML = "";
    const headRow = document.createElement("tr");
    for (const h of ["Destination", "Enforcement", "Rules", "Allowed IPs", "Other conditions", "Binaries"]) {
      const th = document.createElement("th");
      th.textContent = h;
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    for (const np of summary.networkPolicies) {
      // Binaries apply to the whole named policy group (every endpoint
      // under it), not to one endpoint specifically -- shown on each of
      // its endpoint rows so it's never implied that only SOME of a
      // group's endpoints are restricted to those binaries.
      // A rule that lists no binaries is NOT "any binary": measured, curl
      // was refused by such a rule, so it is shown as what it is.
      const binariesText = np.binaries && np.binaries.length ? np.binaries.join(", ") : "(none listed)";
      for (const ep of np.endpoints) {
        const tr = document.createElement("tr");
        tr.appendChild(td(`${ep.host}:${ep.port} (${ep.protocol})`));
        tr.appendChild(td(ep.enforcement));
        const rulesCell = document.createElement("td");
        // `extra` (e.g. a `query` map) is what tells apart two rules that
        // otherwise share the same method+path -- shown as JSON when it's
        // not something this UI specifically knows how to format nicer.
        rulesCell.textContent =
          ep.rules
            .map((r) => `${r.kind} ${r.method || "*"} ${r.path || "*"}` + (r.extra ? ` (${JSON.stringify(r.extra)})` : ""))
            .join(", ") || "(no explicit rules)";
        tr.appendChild(rulesCell);
        // Computed by getActivePolicy() but previously never shown here --
        // a restriction to specific IP ranges is a real, meaningful part
        // of the network rule, not something to drop from the summary.
        tr.appendChild(td(ep.allowedIps && ep.allowedIps.length ? ep.allowedIps.join(", ") : "(any)"));
        tr.appendChild(td(ep.extraConditions && ep.extraConditions.length ? ep.extraConditions.join(", ") : "(none)"));
        tr.appendChild(td(binariesText));
        tbody.appendChild(tr);
      }
    }
    table.appendChild(tbody);
    netGroup.appendChild(table);
  }
  policySummaryEl.appendChild(netGroup);

  const miscGroup = document.createElement("div");
  miscGroup.className = "policy-group";
  const miscH4 = document.createElement("h4");
  miscH4.textContent = "Landlock / process";
  miscGroup.appendChild(miscH4);
  const miscLines = [];
  if (summary.landlock) miscLines.push(`Landlock compatibility: ${summary.landlock.compatibility}`);
  if (summary.process) miscLines.push(`Runs as: ${summary.process.run_as_user}:${summary.process.run_as_group}`);
  const miscDiv = document.createElement("div");
  miscDiv.className = "sub";
  miscDiv.textContent = miscLines.length ? miscLines.join(" -- ") : "(not reported by OpenShell for this sandbox)";
  miscGroup.appendChild(miscDiv);
  policySummaryEl.appendChild(miscGroup);
}

async function loadActivePolicy(sandboxName, { autoOpen = false } = {}) {
  // Checked BEFORE the generation counter is touched at all -- not after
  // incrementing it. A stale call for a sandbox the user has since
  // switched AWAY from (e.g. the "reload after folder creation"
  // follow-up, which can be invoked minutes after the user moved on,
  // since createProtectedFolder recreates the whole sandbox) must be a
  // complete no-op, INCLUDING never consuming a generation token: if it
  // incremented the shared counter here and then returned, a different,
  // legitimately in-flight call for the sandbox the user actually
  // selected -- one that captured an OLDER generation value before this
  // stale call's increment -- would wrongly see itself as "superseded"
  // once ITS OWN correct, newer reply resolves (myGeneration no longer
  // matches the now-higher counter), discarding a valid result. Returning
  // here before ++policyGeneration ever runs avoids that entirely.
  if (sandboxName !== state.sandboxName) return;
  const myGeneration = ++policyGeneration;
  policySandboxNameEl.textContent = sandboxName || "(none selected)";

  if (!sandboxName) {
    policyStatusEl.className = "sub";
    policyStatusEl.textContent = "Select a sandbox to see its policy.";
    policySummaryEl.innerHTML = "";
    policyFullJsonEl.textContent = "";
    activePolicyDetails.open = false;
    return;
  }

  policyStatusEl.className = "sub";
  policyStatusEl.textContent = "Loading policy...";
  policySummaryEl.innerHTML = "";
  policyFullJsonEl.textContent = "";
  if (autoOpen) activePolicyDetails.open = true;

  const res = await window.audit.getActivePolicy(sandboxName);
  // Discard if a newer sandbox was selected, or a newer refresh started,
  // while this was in flight -- an old reply must never overwrite a
  // newer selection's (possibly already-displayed) policy.
  if (myGeneration !== policyGeneration || sandboxName !== state.sandboxName) return;

  if (!res.ok) {
    policyStatusEl.className = "bad";
    policyStatusEl.textContent = "Could not load policy: " + res.error;
    return;
  }

  const netCount = res.summary.networkPolicies.length;
  policyStatusEl.className = "sub";
  policyStatusEl.textContent =
    netCount === 0
      ? "Policy loaded successfully. No network rules are configured for this sandbox."
      : `Policy loaded successfully (${netCount} network rule set${netCount === 1 ? "" : "s"}).`;
  renderPolicySummary(res.summary);
  policyFullJsonEl.textContent = res.fullText;
}

document.getElementById("refreshPolicyBtn").addEventListener("click", () => {
  if (!state.sandboxName) return;
  loadActivePolicy(state.sandboxName, { autoOpen: false });
  // The "Effective permission" badge in "Run an attempt" is computed from
  // this exact same policy -- refreshing one without the other left it
  // showing whatever permission was true before the policy was last
  // reloaded, even though the user just asked to see the current policy.
  if (state.folderPath) refreshEffectivePermission(++selectionGeneration);
  refreshNetworkExpectation(); // the network test's expectation comes from this same policy
});

globalSandboxSelect.addEventListener("change", () => onSandboxChanged(globalSandboxSelect.value));
document.getElementById("refreshSandboxesBtn").addEventListener("click", () => populateGlobalSandboxDropdown());

// =======================================================================
// Collapsible "Create a new sandbox" (a <details> element keeps its
// children's values when collapsed -- nothing extra needed for that part).
// =======================================================================
document.getElementById("createSandboxBtn").addEventListener("click", async () => {
  const name = document.getElementById("newSandboxName").value.trim();
  const tier = document.getElementById("newSandboxTier").value;
  const openshellVersion = document.getElementById("newSandboxVersion").value.trim();
  const image = document.getElementById("newSandboxImage").value.trim();
  const status = document.getElementById("createSandboxStatus");

  if (!name) {
    status.textContent = "Sandbox name is required.";
    return;
  }

  status.textContent = "Creating sandbox (this can take a minute)...";
  const res = await window.audit.createSandbox({ name, tier, openshellVersion, image });
  if (!res.ok) {
    status.textContent = "Error: " + res.error;
    return;
  }
  status.textContent = `Created '${res.name}' (tier: ${res.tier}, OpenShell ${res.openshellVersionUsed}).`;
  await populateGlobalSandboxDropdown(res.name);
  document.getElementById("createSandboxDetails").open = false;
});

// =======================================================================
// Folder tree: one reusable controller, two instances (the inline
// browser and the picker dialog). Lazy-loads children on first expand.
// =======================================================================
function createTreeController(containerEl, { onSelect } = {}) {
  let sandboxName = "";
  let selectedPath = null;
  let treeGeneration = 0; // bumped on every loadRoot()/clear(); stale async work for a PRIOR sandbox checks this before touching the DOM
  const nodesByPath = new Map(); // path -> { rowEl, childrenEl, loaded, canList }

  function clear() {
    treeGeneration++;
    containerEl.innerHTML = "";
    nodesByPath.clear();
    selectedPath = null;
  }

  function makeRow(nodePath, label, depth) {
    const row = document.createElement("div");
    row.className = "tree-row";
    row.style.paddingLeft = `${depth * 4}px`;

    const toggle = document.createElement("span");
    toggle.className = "tree-toggle";
    toggle.textContent = "▸";
    row.appendChild(toggle);

    const nameSpan = document.createElement("span");
    nameSpan.textContent = label;
    row.appendChild(nameSpan);

    const reasonSpan = document.createElement("span");
    reasonSpan.className = "tree-reason";
    row.appendChild(reasonSpan);

    row.addEventListener("click", (e) => {
      if (e.target === toggle) {
        toggleExpand(nodePath);
      } else {
        select(nodePath);
      }
    });

    return { row, toggle, reasonSpan };
  }

  function select(nodePath) {
    const prev = selectedPath && nodesByPath.get(selectedPath);
    if (prev) prev.rowEl.classList.remove("selected");
    selectedPath = nodePath;
    const cur = nodesByPath.get(nodePath);
    if (cur) cur.rowEl.classList.add("selected");
    if (onSelect) onSelect(nodePath);
  }

  async function toggleExpand(nodePath) {
    const node = nodesByPath.get(nodePath);
    if (!node || !node.canList) return;
    if (node.loaded) {
      const nowHidden = node.childrenEl.style.display !== "none";
      node.childrenEl.style.display = nowHidden ? "none" : "block";
      node.toggleEl.textContent = nowHidden ? "▸" : "▾";
      return;
    }
    node.toggleEl.textContent = "▾";
    node.childrenEl.style.display = "block";
    await loadChildren(nodePath, node, node.depth + 1);
  }

  async function loadChildren(nodePath, node, depth) {
    const myGeneration = treeGeneration;
    const sandboxAtCall = sandboxName;
    node.childrenEl.innerHTML = "";
    const res = await window.audit.listDirectory(sandboxAtCall, nodePath);
    if (myGeneration !== treeGeneration) return; // a newer loadRoot()/clear() happened while this was in flight
    node.loaded = true;
    if (!res.ok || !res.canList) {
      node.canList = false;
      node.toggleEl.textContent = " ";
      node.reasonEl.textContent = ` (could not be listed: ${res.ok ? res.reason : res.error})`;
      return;
    }
    if (res.children.length === 0) {
      node.toggleEl.textContent = " ";
      const msg = document.createElement("div");
      msg.className = "tree-reason";
      msg.style.paddingLeft = `${depth * 14 + 18}px`;
      msg.textContent = "(empty)";
      node.childrenEl.appendChild(msg);
      return;
    }
    for (const name of res.children) {
      const childPath = nodePath === "/" ? `/${name}` : `${nodePath}/${name}`;
      addNode(childPath, name, depth, node.childrenEl);
    }
  }

  function addNode(nodePath, label, depth, parentEl) {
    const wrapper = document.createElement("div");
    wrapper.className = "tree-node";
    const { row, toggle, reasonSpan } = makeRow(nodePath, label, depth);
    wrapper.appendChild(row);
    const childrenEl = document.createElement("div");
    childrenEl.className = "tree-children";
    childrenEl.style.display = "none";
    wrapper.appendChild(childrenEl);
    parentEl.appendChild(wrapper);

    // Nothing is fetched when a row is drawn: a folder is listed only when
    // it is expanded (loadChildren), and that result stays in the DOM for
    // collapsing/re-expanding. Drawing a folder with 100 subfolders used to
    // fire one listing per row -- ~200 WSL/docker commands -- before the
    // user had opened any of them. A folder that can't be listed now shows
    // why when it's expanded, rather than up front.
    const node = { rowEl: row, toggleEl: toggle, reasonEl: reasonSpan, childrenEl, loaded: false, canList: true, depth };
    nodesByPath.set(nodePath, node);
    return node;
  }

  async function loadRoot(forSandbox) {
    sandboxName = forSandbox;
    clear();
    addNode("/", "/", 0, containerEl);
  }

  async function refresh() {
    if (!sandboxName) return;
    const keep = selectedPath;
    await loadRoot(sandboxName);
    if (keep) {
      await selectPath(keep);
      if (selectedPath !== keep && onSelect) {
        // The previously-selected folder no longer exists after the
        // refresh (e.g. deleted outside this app) -- the caller's
        // downstream state (target display, effective permission) must
        // be told the selection is gone, not left showing a folder that
        // no longer exists as if it were still current.
        onSelect(null);
      }
    }
  }

  // Expands every path component down to `targetPath` and selects it --
  // used right after creating a folder so the new node is visible without
  // the user having to manually drill down to it.
  async function selectPath(targetPath) {
    if (!nodesByPath.has("/")) addNode("/", "/", 0, containerEl);
    const parts = targetPath.split("/").filter(Boolean);
    let current = "/";
    for (const part of parts) {
      const node = nodesByPath.get(current);
      if (node && node.canList && !node.loaded) {
        await loadChildren(current, node, node.depth + 1);
        node.childrenEl.style.display = "block";
        node.toggleEl.textContent = "▾";
      } else if (node) {
        node.childrenEl.style.display = "block";
        node.toggleEl.textContent = "▾";
      }
      current = current === "/" ? `/${part}` : `${current}/${part}`;
    }
    if (nodesByPath.has(current)) select(current);
  }

  return { loadRoot, refresh, selectPath, clear, getSelected: () => selectedPath };
}

const mainTree = createTreeController(document.getElementById("mainTree"), {
  onSelect: (p) => setSelectedFolder(p),
});
document.getElementById("refreshTreeBtn").addEventListener("click", () => mainTree.refresh());

function setSelectedFolder(p) {
  const myGeneration = ++selectionGeneration;
  state.folderPath = p;
  updateTargetDisplays();
  refreshEffectivePermission(myGeneration);
}

// =======================================================================
// Target display (feature 4): shows the chosen folder. The audit file
// itself is no longer a fixed, predictable name -- runAttempt() generates
// a fresh random one for every single attempt (a shared fixed name was
// what let a successful modify/truncate permanently block every later
// attempt in the same folder, since the file's content no longer matched
// the ownership marker). There is nothing concrete to preview here
// anymore; the actual path used for a given attempt is only known once
// it runs, and is shown with that attempt's own result instead.
// =======================================================================
function updateTargetDisplays() {
  document.getElementById("targetFolderDisplay").value = state.folderPath || "(none selected)";
  document.getElementById("targetFileDisplay").value = state.folderPath
    ? "(a fresh, uniquely-named audit file is created inside this folder for each attempt)"
    : "";
}

// =======================================================================
// Target picker dialog (feature 4): same tree, in a dialog, committed
// only when "Choose" is clicked.
// =======================================================================
const pickerDialog = document.getElementById("pickerDialog");
let pickerPendingPath = null;
const pickerTree = createTreeController(document.getElementById("pickerTree"), {
  onSelect: (p) => (pickerPendingPath = p),
});

document.getElementById("browseBtn").addEventListener("click", async () => {
  if (!state.sandboxName) return;
  pickerPendingPath = state.folderPath;
  await pickerTree.loadRoot(state.sandboxName);
  if (state.folderPath) await pickerTree.selectPath(state.folderPath);
  pickerDialog.showModal();
});
document.getElementById("pickerCancelBtn").addEventListener("click", () => pickerDialog.close());
document.getElementById("pickerChooseBtn").addEventListener("click", () => {
  if (pickerPendingPath) setSelectedFolder(pickerPendingPath);
  pickerDialog.close();
});

// =======================================================================
// Effective permission (feature 5): always recomputed from the live
// policy, never chosen by the user.
// =======================================================================
async function refreshEffectivePermission(myGeneration) {
  const badge = document.getElementById("effectivePermBadge");
  const detail = document.getElementById("effectivePermDetail");
  if (!state.sandboxName || !state.folderPath) {
    if (myGeneration === undefined || myGeneration === selectionGeneration) {
      badge.className = "perm-badge perm-unknown";
      badge.textContent = "Unknown";
      detail.textContent = "Select a sandbox and a folder first.";
    }
    return;
  }
  // Capture the exact sandbox/folder this call is checking -- by the time
  // the lookup below resolves, `state` may already reflect a newer
  // selection, so the values to display must come from what was true
  // when THIS call started, not whatever `state` says afterward.
  const sandboxAtCall = state.sandboxName;
  const folderAtCall = state.folderPath;
  badge.className = "perm-badge perm-unknown";
  badge.textContent = "...";
  detail.textContent = "";
  const info = await window.audit.computeEffectivePermission(sandboxAtCall, folderAtCall);
  if (myGeneration !== undefined && myGeneration !== selectionGeneration) return; // a newer selection superseded this lookup
  const labels = { none: "No access", read_only: "Read-only", read_write: "Read-write", unknown: "Unknown" };
  badge.className = `perm-badge perm-${info.level}`;
  badge.textContent = labels[info.level] || info.level;
  if (info.level === "unknown") {
    detail.textContent = info.reason || "Could not determine this with confidence.";
  } else if (info.matchedPath) {
    detail.textContent = `based on policy path: ${info.matchedPath}${info.viaWorkdir ? " (sandbox working directory)" : ""}`;
  } else {
    detail.textContent = "not covered by any policy rule (Landlock default-deny)";
  }
}

// =======================================================================
// Protected folder dialog
// =======================================================================
const folderDialog = document.getElementById("folderDialog");
document.getElementById("openFolderDialogBtn").addEventListener("click", () => {
  document.getElementById("folderDialogStatus").textContent = "";
  folderDialog.showModal();
});
document.getElementById("folderCancelBtn").addEventListener("click", () => folderDialog.close());

document.getElementById("folderCreateBtn").addEventListener("click", async () => {
  const sandboxName = state.sandboxName;
  const folderName = document.getElementById("folderName").value.trim();
  const permission = document.getElementById("folderPermission").value;
  const dialogStatus = document.getElementById("folderDialogStatus");
  const status = document.getElementById("folderStatus");

  if (!sandboxName) {
    dialogStatus.textContent = "Select a sandbox first.";
    return;
  }
  if (!folderName) {
    dialogStatus.textContent = "Folder name is required.";
    return;
  }

  // Captured once, right as this click starts -- identifies THIS specific
  // selection INSTANCE, not just the sandbox's name. selectionGeneration
  // bumps on every sandbox/folder switch, including switching back to a
  // sandbox that happens to share this exact name later -- so, unlike a
  // plain name-equality snapshot, this can't be fooled by an A -> B -> A
  // sequence that lands back on the same name by coincidence while this
  // (much slower, since createProtectedFolder recreates the sandbox)
  // follow-up was still pending: that later A is a different selection
  // instance than the one that started this click, even though the name
  // matches again.
  const selectionAtStart = selectionGeneration;

  // One request at a time from this window (the main process also refuses
  // a second recreate of the same sandbox, whichever window it comes from).
  const createBtn = document.getElementById("folderCreateBtn");
  createBtn.disabled = true;
  dialogStatus.textContent = "Creating... (the sandbox is deleted and recreated; this can take a few minutes)";
  let res;
  try {
    res = await window.audit.createProtectedFolder({ sandboxName, folderName, permission });
  } finally {
    createBtn.disabled = false;
  }
  if (!res.ok) {
    dialogStatus.textContent = "Error: " + res.error;
    return;
  }
  status.textContent = `Created ${res.folderPath} in '${sandboxName}' -- Linux: ${res.linuxMode}; OpenShell permission: ${res.actualPermission || permission} (verified against the sandbox's actual policy).`;
  folderDialog.close();

  // Folder creation recreates the whole sandbox, which can take minutes --
  // re-checked again after EACH subsequent await below (not just once
  // here), since every one of them is its own chance for the user to have
  // moved on to a different selection before the next step runs. A stale
  // instance must never force the tree/policy panels away from whatever
  // is actually selected now.
  if (selectionGeneration !== selectionAtStart) return;

  // The sandbox was recreated to apply the new policy, so the whole tree
  // (and whatever was selected in it) is stale -- reload it, then select
  // straight into the folder that was just created.
  await mainTree.loadRoot(sandboxName);
  if (selectionGeneration !== selectionAtStart) return;
  await mainTree.selectPath(res.folderPath);
  // Not re-checked again here: selectPath() above, if it actually
  // committed a selection, already advanced selectionGeneration as its
  // OWN legitimate effect (the exact same path a user's own click on that
  // tree node would take) -- comparing against selectionAtStart after
  // that would wrongly treat selectPath's own success as staleness.
  // loadActivePolicy() re-verifies the sandbox identity itself, right
  // before it would touch the panel (see its own guard above), which is
  // what actually covers this last step.
  loadActivePolicy(sandboxName, { autoOpen: false });
});

// =======================================================================
// Run an attempt
// =======================================================================
const runBtn = document.getElementById("runBtn");
runBtn.addEventListener("click", async () => {
  const sandboxName = state.sandboxName;
  const folderPath = state.folderPath;
  const versionTag = document.getElementById("versionTag").value.trim();
  const operation = document.getElementById("operation").value;
  const status = document.getElementById("runStatus");

  if (!sandboxName) {
    status.textContent = "Select a sandbox first.";
    return;
  }
  if (!folderPath) {
    status.textContent = "Pick a target folder first (use the folder browser or Browse...).";
    return;
  }

  runBtn.disabled = true;
  status.textContent = "Running...";
  try {
    const res = await window.audit.runAttempt({ sandboxName, versionTag, folderPath, operation });
    if (!res.ok) {
      status.textContent = "Error: " + res.error;
      return;
    }
    status.textContent = `Done (${res.result.target}): ${res.result.verdict}`;
    // A failed cleanup never changes the verdict above -- it's reported
    // as its own, separate warning, since it means this attempt's own
    // temp audit file may have been left behind, not that the verdict
    // itself is in question.
    if (res.result.cleanup && res.result.cleanup.status === "failed") {
      status.textContent += ` -- WARNING: could not remove this attempt's temp audit file (${res.result.cleanup.reason || "unknown reason"}).`;
    }
    await refreshResults();
  } finally {
    runBtn.disabled = false;
  }
});

// =======================================================================
// Network test: runs under the sandbox's EXISTING policy and never changes
// it. The expectation shown here comes from the live policy; nothing is
// sent until "Run network test" is clicked.
// =======================================================================
const netUrlEl = document.getElementById("netUrl");
const netMethodEl = document.getElementById("netMethod");
const netBodyRow = document.getElementById("netBodyRow");
const netBodyEl = document.getElementById("netBody");
const netExpectBadge = document.getElementById("netExpectBadge");
const netExpectDetail = document.getElementById("netExpectDetail");
const netRunBtn = document.getElementById("netRunBtn");
const netStatus = document.getElementById("netStatus");
const NET_BODY_METHODS = ["POST", "PUT", "PATCH"];

// Bumped on every refresh: a slow reply for an earlier URL/method/sandbox
// must not overwrite the expectation for what is selected now.
let netExpectGeneration = 0;

function setNetBadge(cls, text, detail) {
  netExpectBadge.className = `perm-badge ${cls}`;
  netExpectBadge.textContent = text;
  netExpectDetail.textContent = detail;
}

async function refreshNetworkExpectation() {
  const myGeneration = ++netExpectGeneration;
  const sandboxAtCall = state.sandboxName;
  if (!sandboxAtCall) {
    setNetBadge("perm-unknown", "Unknown", "Select a sandbox first.");
    return;
  }
  setNetBadge("perm-unknown", "...", "");
  const res = await window.audit.previewNetworkExpectation({ sandboxName: sandboxAtCall, url: netUrlEl.value.trim(), method: netMethodEl.value });
  if (myGeneration !== netExpectGeneration || sandboxAtCall !== state.sandboxName) return;
  if (!res.ok) {
    setNetBadge("perm-unknown", "Unknown", res.error);
    return;
  }
  const e = res.expected;
  const policyNote = ` (policy version ${res.policy.version})`;
  if (e.level === "allow") setNetBadge("net-allow", "Allowed", e.reason + policyNote);
  else if (e.level === "block_connection") setNetBadge("net-block", "Blocked (connection)", e.reason + policyNote);
  else if (e.level === "block_request") setNetBadge("net-block", "Blocked (HTTP request)", e.reason + policyNote);
  else setNetBadge("perm-unknown", "No expectation", e.reason + policyNote);
}

function syncNetBodyRow() {
  netBodyRow.style.display = NET_BODY_METHODS.includes(netMethodEl.value) ? "block" : "none";
}
netMethodEl.addEventListener("change", () => {
  syncNetBodyRow();
  refreshNetworkExpectation();
});
netUrlEl.addEventListener("change", refreshNetworkExpectation);
syncNetBodyRow();

netRunBtn.addEventListener("click", async () => {
  const sandboxName = state.sandboxName;
  if (!sandboxName) {
    netStatus.textContent = "Select a sandbox first.";
    return;
  }
  const url = netUrlEl.value.trim();
  const method = netMethodEl.value;
  const body = NET_BODY_METHODS.includes(method) ? netBodyEl.value : undefined;
  const versionTag = document.getElementById("versionTag").value.trim();

  netRunBtn.disabled = true;
  netStatus.textContent = "Running...";
  try {
    const res = await window.audit.runNetworkTest({ sandboxName, url, method, body, versionTag });
    if (!res.ok) {
      netStatus.textContent = "Error: " + res.error;
      return;
    }
    const r = res.result;
    netStatus.textContent = `[${sandboxName}] ${r.method} ${r.url} -- HTTP status ${r.httpStatus ?? "-"}: ${r.verdict}`;
    await refreshResults();
  } finally {
    netRunBtn.disabled = false;
  }
});

// =======================================================================
// Command activity log
// =======================================================================
const commandRows = new Map(); // command id -> <tr>
const commandTbody = document.querySelector("#commandTable tbody");

function formatDuration(evt) {
  if (!evt.finishedAt) return "";
  return `${evt.finishedAt - evt.startedAt}ms`;
}

window.audit.onCommandStart((evt) => {
  const tr = document.createElement("tr");
  const cmdCell = document.createElement("td");
  const pre = document.createElement("pre");
  pre.textContent = evt.command;
  cmdCell.appendChild(pre);
  if (evt.label) {
    const lbl = document.createElement("div");
    lbl.className = "sub";
    lbl.textContent = evt.label;
    cmdCell.appendChild(lbl);
  }
  tr.appendChild(cmdCell);
  const respCell = document.createElement("td");
  respCell.textContent = "Running...";
  tr.appendChild(respCell);
  commandTbody.appendChild(tr);
  commandRows.set(evt.id, { tr, respCell });
  commandTbody.parentElement.parentElement.scrollTop = commandTbody.parentElement.parentElement.scrollHeight;
});

function renderOutput(cell, stdout, stderr) {
  if (stdout) {
    const pre = document.createElement("pre");
    pre.textContent = stdout;
    cell.appendChild(pre);
  }
  if (stderr) {
    const pre = document.createElement("pre");
    pre.textContent = stderr;
    pre.style.color = "#dc2626";
    cell.appendChild(pre);
  }
}

// Updates the row WHILE the command is still running, as soon as output
// starts arriving -- a long command no longer just sits on "Running..."
// with zero feedback until it fully finishes.
window.audit.onCommandUpdate((evt) => {
  const row = commandRows.get(evt.id);
  if (!row) return;
  row.respCell.innerHTML = "";
  const statusLine = document.createElement("div");
  statusLine.className = "sub";
  statusLine.textContent = "Running...";
  row.respCell.appendChild(statusLine);
  renderOutput(row.respCell, evt.stdout, evt.stderr);
});

window.audit.onCommandFinish((evt) => {
  const row = commandRows.get(evt.id);
  if (!row) return;
  row.respCell.innerHTML = "";
  const statusLine = document.createElement("div");
  if (evt.timedOut) {
    statusLine.textContent = `timed out (${formatDuration(evt)})`;
    statusLine.className = "warn";
  } else {
    statusLine.textContent = `exit ${evt.code === null ? "null (killed by signal)" : evt.code} (${formatDuration(evt)})`;
    statusLine.className = evt.code === 0 ? "ok" : "bad";
  }
  row.respCell.appendChild(statusLine);
  renderOutput(row.respCell, evt.stdout, evt.stderr);
});

// =======================================================================
// Initial load
// =======================================================================
applySandboxGatedUI();
updateTargetDisplays();
populateGlobalSandboxDropdown();
refreshResults();
