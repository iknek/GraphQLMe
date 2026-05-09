// ── Field Selection ─────────────────────────────────
function selectField(field, isQuery) {
  activeField = field;
  activeIsQuery = isQuery;

  const returnTypeName = resolveTypeName(field.type);
  let infoHtml = '<span>Returns: <span class="return-type">' + escapeHtml(returnTypeName) + '</span></span>';
  if (field.description) {
    infoHtml += '<div class="description">' + escapeHtml(field.description) + '</div>';
  }
  typeInfo.innerHTML = infoHtml;
  typeInfo.style.display = "";

  if (field.args && field.args.length > 0) {
    argsPanel.style.display = "";
    argsForm.innerHTML = "";
    for (const arg of field.args) {
      argsForm.appendChild(buildArgRow(arg));
    }
  } else {
    argsPanel.style.display = "none";
    argsForm.innerHTML = "";
  }

  const base = getBaseType(field.type);
  const typeDef = base ? typeMap[base.name] : null;
  if (typeDef && typeDef.fields && typeDef.fields.length > 0) {
    fieldsPanel.style.display = "";
    fieldsTree.innerHTML = "";

    const selectAllRow = document.createElement("div");
    selectAllRow.className = "select-all-row";
    const selectAllCb = document.createElement("input");
    selectAllCb.type = "checkbox";
    selectAllCb.checked = true;
    selectAllCb.id = "select-all-fields";
    const selectAllLabel = document.createElement("label");
    selectAllLabel.htmlFor = "select-all-fields";
    selectAllLabel.textContent = "Select all / none";
    selectAllCb.addEventListener("change", () => {
      fieldsTree.querySelectorAll('input[type="checkbox"]').forEach(cb => {
        if (cb !== selectAllCb) cb.checked = selectAllCb.checked;
      });
      regenerateQuery();
    });
    selectAllRow.appendChild(selectAllCb);
    selectAllRow.appendChild(selectAllLabel);
    fieldsTree.appendChild(selectAllRow);

    const visited = new Set();
    visited.add(base.name);
    fieldsTree.appendChild(buildFieldsTree(typeDef.fields, 0, visited));
  } else {
    fieldsPanel.style.display = "none";
    fieldsTree.innerHTML = "";
  }

  regenerateQuery();
}

// ── Argument Row ───────────────────────────────────
function buildArgRow(arg) {
  const row = document.createElement("div");
  row.className = "arg-row";

  const isRequired = arg.type.kind === "NON_NULL";

  const label = document.createElement("span");
  label.className = "arg-label";
  label.innerHTML = escapeHtml(arg.name) +
    (isRequired ? ' <span class="required">*</span>' : "");

  const typeSpan = document.createElement("span");
  typeSpan.className = "arg-type";
  typeSpan.textContent = resolveTypeName(arg.type);

  const input = document.createElement("input");
  input.className = "arg-input";
  input.type = "text";
  input.dataset.argName = arg.name;
  input.dataset.argType = resolveTypeName(arg.type);
  input.placeholder = placeholderForType(arg.type);
  if (isRequired) input.dataset.required = "true";
  input.addEventListener("input", regenerateQuery);

  row.appendChild(label);
  row.appendChild(typeSpan);
  row.appendChild(input);
  return row;
}

function placeholderForType(type) {
  if (!type) return "";
  if (type.kind === "NON_NULL") return placeholderForType(type.ofType);
  if (type.kind === "LIST") return "[ ]";
  const name = type.name;
  if (name === "Int" || name === "Float") return "0";
  if (name === "Boolean") return "true / false";
  if (name === "ID") return "id value";
  return "value";
}

// ── Fields Tree ────────────────────────────────────
function buildFieldsTree(fields, depth, visitedTypes) {
  visitedTypes = visitedTypes || new Set();
  const container = document.createElement("div");

  for (const field of fields) {
    if (field.name.startsWith("__")) continue;

    if (isScalarReturn(field.type)) {
      const row = document.createElement("div");
      row.className = "field-row";
      row.style.paddingLeft = (depth * 10) + "px";

      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = true;
      cb.dataset.fieldPath = field.name;
      cb.id = "field-" + depth + "-" + field.name;
      cb.addEventListener("change", regenerateQuery);

      const lbl = document.createElement("label");
      lbl.htmlFor = cb.id;
      lbl.textContent = field.name;

      const hint = document.createElement("span");
      hint.className = "type-hint";
      hint.textContent = " " + resolveTypeName(field.type);

      row.appendChild(cb);
      row.appendChild(lbl);
      row.appendChild(hint);
      container.appendChild(row);
    } else {
      const base = getBaseType(field.type);
      const typeDef = base ? typeMap[base.name] : null;
      const isCycle = base && visitedTypes.has(base.name);
      const hasChildren = typeDef && typeDef.fields && typeDef.fields.length > 0 && !isCycle;

      const group = document.createElement("div");
      group.className = "field-group";
      group.style.marginLeft = (depth * 10) + "px";

      const header = document.createElement("div");
      header.className = "field-group-header";

      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = hasChildren;
      cb.dataset.fieldPath = field.name;

      const toggle = document.createElement("span");
      toggle.className = "toggle";
      toggle.textContent = "▼";

      const lbl = document.createElement("label");
      lbl.textContent = field.name;

      const hint = document.createElement("span");
      hint.className = "type-hint";
      hint.textContent = " " + resolveTypeName(field.type);

      header.appendChild(cb);
      header.appendChild(toggle);
      header.appendChild(lbl);
      header.appendChild(hint);

      const childDiv = document.createElement("div");
      childDiv.className = "field-group-children";

      if (hasChildren) {
        const childVisited = new Set(visitedTypes);
        childVisited.add(base.name);
        childDiv.appendChild(buildFieldsTree(typeDef.fields, depth + 1, childVisited));
      } else if (isCycle) {
        const msg = document.createElement("div");
        msg.className = "field-row";
        msg.style.paddingLeft = "16px";
        msg.innerHTML = '<span class="type-hint">— circular reference to ' + escapeHtml(base.name) + ' —</span>';
        childDiv.appendChild(msg);
      } else {
        const msg = document.createElement("div");
        msg.className = "field-row";
        msg.style.paddingLeft = "16px";
        msg.innerHTML = '<span class="type-hint">— no sub-fields —</span>';
        childDiv.appendChild(msg);
      }

      header.addEventListener("click", (e) => {
        if (e.target === cb) return;
        childDiv.classList.toggle("collapsed");
        toggle.textContent = childDiv.classList.contains("collapsed") ? "►" : "▼";
      });

      cb.addEventListener("change", () => {
        const childCbs = childDiv.querySelectorAll('input[type="checkbox"]');
        childCbs.forEach(c => c.checked = cb.checked);
        regenerateQuery();
      });

      group.appendChild(header);
      group.appendChild(childDiv);
      container.appendChild(group);
    }
  }

  requestAnimationFrame(() => wireChildToParent(container));
  return container;
}

function wireChildToParent(root) {
  const allGroups = root.querySelectorAll(".field-group");
  for (const group of allGroups) {
    const parentCb = group.querySelector(":scope > .field-group-header > input[type='checkbox']");
    const childDiv = group.querySelector(":scope > .field-group-children");
    if (!parentCb || !childDiv) continue;

    const childCbs = childDiv.querySelectorAll('input[type="checkbox"]');
    for (const childCb of childCbs) {
      childCb.addEventListener("change", () => {
        const anyChecked = Array.from(childDiv.querySelectorAll('input[type="checkbox"]')).some(c => c.checked);
        parentCb.checked = anyChecked;
        regenerateQuery();
      });
    }
  }
}

// ── Query Generation ───────────────────────────────
function regenerateQuery() {
  if (!activeField) return;

  const keyword = activeIsQuery ? "query" : "mutation";
  const fieldName = activeField.name;

  let argsStr = "";
  const argInputs = argsForm.querySelectorAll(".arg-input");
  if (argInputs.length > 0) {
    const argParts = [];
    for (const input of argInputs) {
      const val = input.value.trim();
      if (!val && !input.dataset.required) continue;
      const formatted = formatArgValue(val, input.dataset.argType);
      argParts.push(input.dataset.argName + ": " + formatted);
    }
    if (argParts.length > 0) {
      argsStr = "(" + argParts.join(", ") + ")";
    }
  }

  const fieldSelection = buildFieldSelectionFromTree(fieldsTree);

  let query;
  if (fieldSelection) {
    query = keyword + " {\n  " + fieldName + argsStr + " {\n" + fieldSelection + "\n  }\n}";
  } else {
    query = keyword + " {\n  " + fieldName + argsStr + "\n}";
  }

  queryEditor.value = query;
}

function formatArgValue(val, typeStr) {
  if (!val) return '""';
  if (val.startsWith('"') || val.startsWith('[') || val.startsWith('{')) return val;
  if (/^-?\d+(\.\d+)?$/.test(val)) return val;
  if (val === "true" || val === "false" || val === "null") return val;
  const baseType = typeStr.replace(/[!\[\]]/g, "");
  if (baseType === "Int" || baseType === "Float" || baseType === "Boolean") return val;
  return '"' + val.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

function buildFieldSelectionFromTree(container, depth) {
  depth = depth || 2;
  const indent = "  ".repeat(depth);
  const lines = [];

  for (const child of container.children) {
    if (child.classList.contains("field-row")) {
      const cb = child.querySelector('input[type="checkbox"]');
      if (cb && cb.checked) {
        lines.push(indent + cb.dataset.fieldPath);
      }
    } else if (child.classList.contains("field-group")) {
      const header = child.querySelector(".field-group-header");
      const cb = header.querySelector('input[type="checkbox"]');
      if (cb && cb.checked) {
        const childDiv = child.querySelector(".field-group-children");
        const subFields = buildFieldSelectionFromTree(childDiv, depth + 1);
        if (subFields) {
          lines.push(indent + cb.dataset.fieldPath + " {\n" + subFields + "\n" + indent + "}");
        }
      }
    } else if (child.tagName === "DIV" && !child.classList.contains("select-all-row")) {
      const inner = buildFieldSelectionFromTree(child, depth);
      if (inner) lines.push(inner);
    }
  }

  return lines.length > 0 ? lines.join("\n") : "";
}
