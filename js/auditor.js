// ── Auditor State ──────────────────────────────────
let auditorScanId = null;
let auditorPollTimer = null;
let auditorFindings = [];

// ── DOM References ─────────────────────────────────
const auditorView = document.getElementById("auditor-view");
const builderView = document.getElementById("builder-view");
const modeToggle = document.getElementById("mode-toggle");
const auditOpsList = document.getElementById("audit-ops-list");
const auditCategoryChecks = document.querySelectorAll(".audit-category");
const auditStartBtn = document.getElementById("audit-start-btn");
const auditProgress = document.getElementById("audit-progress");
const auditProgressBar = document.getElementById("audit-progress-bar");
const auditProgressText = document.getElementById("audit-progress-text");
const auditFindingsTable = document.getElementById("audit-findings-body");
const auditFindingsSection = document.getElementById("audit-findings-section");
const auditExportBtn = document.getElementById("audit-export-btn");
const auditSelectAllOps = document.getElementById("audit-select-all-ops");

// ── Mode Toggle ────────────────────────────────────
let currentMode = "builder";

modeToggle.addEventListener("click", () => {
  if (currentMode === "builder") {
    currentMode = "auditor";
    modeToggle.textContent = "◀ Builder";
    builderView.style.display = "none";
    auditorView.style.display = "flex";
    populateAuditorOps();
  } else {
    currentMode = "builder";
    modeToggle.textContent = "Auditor ▶";
    auditorView.style.display = "none";
    builderView.style.display = "flex";
  }
});

// ── Populate Operations ────────────────────────────
function populateAuditorOps() {
  auditOpsList.innerHTML = "";

  if (!currentSchema) {
    auditOpsList.innerHTML = '<div class="empty-msg">No schema loaded. Introspect first.</div>';
    return;
  }

  const queryTypeName = currentSchema.queryType?.name || "Query";
  const mutationTypeName = currentSchema.mutationType?.name || null;

  const queryType = typeMap[queryTypeName];
  if (queryType?.fields) {
    for (const field of queryType.fields) {
      if (field.name.startsWith("__")) continue;
      auditOpsList.appendChild(buildOpRow(field, true));
    }
  }

  if (mutationTypeName && typeMap[mutationTypeName]?.fields) {
    for (const field of typeMap[mutationTypeName].fields) {
      if (field.name.startsWith("__")) continue;
      auditOpsList.appendChild(buildOpRow(field, false));
    }
  }
}

function buildOpRow(field, isQuery) {
  const row = document.createElement("div");
  row.className = "audit-op-row";

  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.dataset.opName = field.name;
  cb.dataset.isQuery = isQuery;
  cb.id = "audit-op-" + field.name;

  const label = document.createElement("label");
  label.htmlFor = cb.id;

  const badge = document.createElement("span");
  badge.className = "op-badge " + (isQuery ? "op-query" : "op-mutation");
  badge.textContent = isQuery ? "Q" : "M";

  const name = document.createElement("span");
  name.textContent = field.name;

  const injectableArgs = (field.args || []).filter(a => {
    const t = resolveBaseTypeName(a.type);
    return t === "String" || t === "ID";
  });

  const argCount = document.createElement("span");
  argCount.className = "op-arg-count";
  argCount.textContent = injectableArgs.length + " injectable arg" + (injectableArgs.length !== 1 ? "s" : "");

  label.appendChild(badge);
  label.appendChild(name);
  row.appendChild(cb);
  row.appendChild(label);
  row.appendChild(argCount);

  // Store metadata on the checkbox
  cb.dataset.args = JSON.stringify(injectableArgs.map(a => ({
    name: a.name,
    typeName: resolveBaseTypeName(a.type),
  })));
  cb.dataset.allArgs = JSON.stringify((field.args || []).map(a => ({
    name: a.name,
    typeName: resolveTypeName(a.type),
  })));

  return row;
}

function resolveBaseTypeName(type) {
  if (!type) return "Unknown";
  if (type.ofType) return resolveBaseTypeName(type.ofType);
  return type.name || "Unknown";
}

// ── Select All ─────────────────────────────────────
auditSelectAllOps.addEventListener("change", () => {
  const cbs = auditOpsList.querySelectorAll('input[type="checkbox"]');
  cbs.forEach(cb => cb.checked = auditSelectAllOps.checked);
});

// ── Start Scan ─────────────────────────────────────
auditStartBtn.addEventListener("click", startAuditScan);

async function startAuditScan() {
  const url = urlInput.value.trim();
  if (!url) {
    setStatus("Enter a GraphQL endpoint URL first", "error");
    return;
  }

  // Gather selected operations
  const opCheckboxes = auditOpsList.querySelectorAll('input[type="checkbox"]:checked');
  if (opCheckboxes.length === 0) {
    setStatus("Select at least one operation to test", "error");
    return;
  }

  // Gather selected categories
  const categories = [];
  auditCategoryChecks.forEach(cb => {
    if (cb.checked) categories.push(cb.value);
  });
  if (categories.length === 0) {
    setStatus("Select at least one injection category", "error");
    return;
  }

  // Build operations
  const operations = [];
  opCheckboxes.forEach(cb => {
    const args = JSON.parse(cb.dataset.args);
    const allArgs = JSON.parse(cb.dataset.allArgs);
    const isQuery = cb.dataset.isQuery === "true";
    const name = cb.dataset.opName;

    // Build a minimal query with placeholder args
    const query = buildScanQuery(name, allArgs, isQuery);

    operations.push({
      name: name,
      isQuery: isQuery,
      query: query,
      args: args,
    });
  });

  const headers = getCustomHeaders();

  setStatus("Starting security scan...");
  auditStartBtn.disabled = true;
  auditStartBtn.textContent = "Scanning...";
  auditProgress.style.display = "";
  auditFindingsSection.style.display = "none";
  auditFindingsTable.innerHTML = "";
  auditorFindings = [];

  try {
    const resp = await fetch("/api/security/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: url,
        headers: headers,
        operations: operations,
        categories: categories,
        rateLimit: parseInt(document.getElementById("audit-rate-limit").value) || 0,
      }),
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(text);
    }

    const data = await resp.json();
    auditorScanId = data.id;

    // Start polling
    auditorPollTimer = setInterval(pollScanResults, 1500);
    setStatus("Scan started — testing " + operations.length + " operation(s)...");
  } catch (err) {
    setStatus("Failed to start scan: " + err.message, "error");
    auditStartBtn.disabled = false;
    auditStartBtn.textContent = "▶ Start Scan";
    auditProgress.style.display = "none";
  }
}

function buildScanQuery(name, allArgs, isQuery) {
  const keyword = isQuery ? "query" : "mutation";
  let argsStr = "";
  if (allArgs.length > 0) {
    const parts = allArgs.map(a => {
      const base = a.typeName.replace(/[!\[\]]/g, "");
      let val = '"test"';
      if (base === "Int" || base === "Float") val = "0";
      else if (base === "Boolean") val = "true";
      else if (base === "ID") val = '"1"';
      return a.name + ": " + val;
    });
    argsStr = "(" + parts.join(", ") + ")";
  }
  return keyword + " { " + name + argsStr + " }";
}

// ── Poll Results ───────────────────────────────────
async function pollScanResults() {
  if (!auditorScanId) return;

  try {
    const resp = await fetch("/api/security/scan/" + auditorScanId);
    if (!resp.ok) return;

    const job = await resp.json();

    // Update progress
    const pct = job.progress.total > 0
      ? Math.round((job.progress.completed / job.progress.total) * 100)
      : 0;
    auditProgressBar.style.width = pct + "%";
    auditProgressText.textContent = job.progress.completed + " / " + job.progress.total + " tests (" + pct + "%)";

    // Update findings
    if (job.findings.length > auditorFindings.length) {
      auditorFindings = job.findings;
      renderFindings();
    }

    // Check completion
    if (job.status === "complete" || job.status === "failed") {
      clearInterval(auditorPollTimer);
      auditorPollTimer = null;
      auditStartBtn.disabled = false;
      auditStartBtn.textContent = "▶ Start Scan";

      if (job.status === "complete") {
        setStatus("Scan complete — " + job.findings.length + " finding(s)", job.findings.length > 0 ? "error" : "success");
        auditExportBtn.style.display = "";
      } else {
        setStatus("Scan failed: " + (job.error || "unknown error"), "error");
      }
    }
  } catch (err) {
    // Ignore transient poll errors
  }
}

// ── Render Findings ────────────────────────────────
function renderFindings() {
  auditFindingsSection.style.display = "";
  auditFindingsTable.innerHTML = "";

  for (const f of auditorFindings) {
    const tr = document.createElement("tr");
    tr.className = "finding-row";
    tr.addEventListener("click", () => toggleInlineDetail(tr, f));

    const sevTd = document.createElement("td");
    const sevBadge = document.createElement("span");
    sevBadge.className = "sev-badge sev-" + f.severity.toLowerCase();
    sevBadge.textContent = f.severity;
    sevTd.appendChild(sevBadge);

    const catTd = document.createElement("td");
    catTd.textContent = categoryDisplayName(f.category);

    const opTd = document.createElement("td");
    opTd.textContent = f.operation;

    const argTd = document.createElement("td");
    argTd.textContent = f.argument;

    const payloadTd = document.createElement("td");
    payloadTd.className = "payload-cell";
    payloadTd.textContent = f.payload;

    tr.appendChild(sevTd);
    tr.appendChild(catTd);
    tr.appendChild(opTd);
    tr.appendChild(argTd);
    tr.appendChild(payloadTd);
    auditFindingsTable.appendChild(tr);
  }
}

function categoryDisplayName(cat) {
  const names = {
    SQL_INJECTION: "SQL Injection",
    NOSQL_INJECTION: "NoSQL Injection",
    SSTI: "SSTI",
    COMMAND_INJECTION: "Command Injection",
    PATH_TRAVERSAL: "Path Traversal",
    XSS_REFLECTED: "Reflected XSS",
    XSS_STORED: "Stored XSS",
    CSRF: "CSRF",
  };
  return names[cat] || cat;
}

// ── Finding Detail (inline below row) ──────────────
function toggleInlineDetail(tr, f) {
  // If there's already a detail row right after this one, toggle it
  const next = tr.nextElementSibling;
  if (next && next.classList.contains("finding-detail-row")) {
    next.remove();
    tr.classList.remove("expanded");
    return;
  }

  // Remove any other open detail rows
  auditFindingsTable.querySelectorAll(".finding-detail-row").forEach(r => r.remove());
  auditFindingsTable.querySelectorAll(".expanded").forEach(r => r.classList.remove("expanded"));

  tr.classList.add("expanded");

  const detailTr = document.createElement("tr");
  detailTr.className = "finding-detail-row";
  const detailTd = document.createElement("td");
  detailTd.colSpan = 5;
  detailTd.className = "finding-detail-cell";

  const header = document.createElement("div");
  header.className = "finding-detail-header";
  header.innerHTML = '<span class="sev-badge sev-' + f.severity.toLowerCase() + '">' +
    f.severity + '</span> ' + escapeHtml(categoryDisplayName(f.category));

  const desc = document.createElement("p");
  desc.className = "finding-desc";
  desc.textContent = f.description;

  const meta = document.createElement("div");
  meta.className = "finding-meta";
  meta.innerHTML =
    '<div><strong>Operation:</strong> ' + escapeHtml(f.operation) + '</div>' +
    '<div><strong>Argument:</strong> ' + escapeHtml(f.argument) + '</div>' +
    '<div><strong>HTTP Status:</strong> ' + f.statusCode + '</div>';

  const payloadLabel = document.createElement("h5");
  payloadLabel.textContent = "Payload";
  const payloadPre = document.createElement("pre");
  payloadPre.className = "finding-code";
  payloadPre.textContent = f.payload;

  const evidenceLabel = document.createElement("h5");
  evidenceLabel.textContent = "Evidence";
  const evidencePre = document.createElement("pre");
  evidencePre.className = "finding-code";
  evidencePre.textContent = f.evidence;

  detailTd.appendChild(header);
  detailTd.appendChild(desc);
  detailTd.appendChild(meta);
  detailTd.appendChild(payloadLabel);
  detailTd.appendChild(payloadPre);
  detailTd.appendChild(evidenceLabel);
  detailTd.appendChild(evidencePre);

  if (f.baselineBody) {
    const bl = document.createElement("h5");
    bl.textContent = "Baseline Response";
    const blPre = document.createElement("pre");
    blPre.className = "finding-code";
    blPre.textContent = f.baselineBody;
    detailTd.appendChild(bl);
    detailTd.appendChild(blPre);
  }

  if (f.injectedBody) {
    const ij = document.createElement("h5");
    ij.textContent = "Injected Response";
    const ijPre = document.createElement("pre");
    ijPre.className = "finding-code";
    ijPre.textContent = f.injectedBody;
    detailTd.appendChild(ij);
    detailTd.appendChild(ijPre);
  }

  detailTr.appendChild(detailTd);
  tr.after(detailTr);
}

// ── Export Report ───────────────────────────────────
auditExportBtn.addEventListener("click", async () => {
  if (!auditorScanId) return;
  window.open("/api/security/scan/" + auditorScanId + "/report", "_blank");
});
