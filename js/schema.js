// ── Introspection ──────────────────────────────────
async function introspect() {
  targetURL = urlInput.value.trim();
  if (!targetURL) {
    setStatus("Please enter a GraphQL endpoint URL", "error");
    return;
  }

  setStatus("Running introspection query...");

  try {
    const data = await proxyRequest(targetURL, { query: INTROSPECTION_QUERY });

    if (data.errors) {
      responseViewer.textContent = JSON.stringify(data, null, 2);
      setStatus("Introspection returned errors", "error");
      return;
    }

    responseViewer.textContent = JSON.stringify(data, null, 2);

    await fetch("/api/schema", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });

    parseSchema(data);
    setStatus("Schema loaded and saved to schema.json", "success");
  } catch (err) {
    setStatus("Introspection failed: " + err.message, "error");
  }
}

// ── Load Saved Schema ──────────────────────────────
async function loadSavedSchema() {
  setStatus("Loading saved schema...");
  try {
    const resp = await fetch("/api/schema");
    if (!resp.ok) {
      setStatus("No saved schema found. Run introspection first.", "error");
      return;
    }
    const data = await resp.json();
    parseSchema(data);
    responseViewer.textContent = JSON.stringify(data, null, 2);
    setStatus("Loaded schema from schema.json", "success");
  } catch (err) {
    setStatus("Failed to load schema: " + err.message, "error");
  }
}

// ── Schema Parsing ─────────────────────────────────
function parseSchema(data) {
  const schema = data?.data?.__schema;
  if (!schema) {
    setStatus("Invalid schema response — missing data.__schema", "error");
    return;
  }
  currentSchema = schema;

  const queryTypeName = schema.queryType?.name || "Query";
  const mutationTypeName = schema.mutationType?.name || null;

  typeMap = {};
  for (const t of schema.types) {
    typeMap[t.name] = t;
  }

  const queryType = typeMap[queryTypeName];
  renderFieldList(queriesList, queryType?.fields || [], true);

  if (mutationTypeName && typeMap[mutationTypeName]) {
    renderFieldList(mutationsList, typeMap[mutationTypeName].fields || [], false);
  } else {
    mutationsList.innerHTML = '<li class="empty-msg">None</li>';
  }

  argsPanel.style.display = "none";
  fieldsPanel.style.display = "none";
  typeInfo.style.display = "none";
  activeField = null;
}

// ── Field List Rendering ───────────────────────────
function renderFieldList(ul, fields, isQuery) {
  ul.innerHTML = "";
  if (fields.length === 0) {
    ul.innerHTML = '<li class="empty-msg">None</li>';
    return;
  }
  for (const field of fields) {
    if (field.name.startsWith("__")) continue;

    const li = document.createElement("li");
    li.dataset.fieldName = field.name;

    const argsStr = field.args.length > 0
      ? "(" + field.args.map(a => a.name + ": " + resolveTypeName(a.type)).join(", ") + ")"
      : "";

    li.innerHTML =
      '<span class="field-name">' + escapeHtml(field.name) + '</span>' +
      '<span class="field-args">' + escapeHtml(argsStr) + '</span>' +
      '<br><span class="field-type">→ ' + escapeHtml(resolveTypeName(field.type)) + '</span>';

    li.addEventListener("click", () => {
      queriesList.querySelectorAll("li").forEach(l => l.classList.remove("active"));
      mutationsList.querySelectorAll("li").forEach(l => l.classList.remove("active"));
      li.classList.add("active");
      selectField(field, isQuery);
    });

    ul.appendChild(li);
  }
}
