// ── Search ─────────────────────────────────────────
schemaSearch.addEventListener("input", function () {
  const term = this.value.toLowerCase();
  filterList(queriesList, term);
  filterList(mutationsList, term);
});

function filterList(ul, term) {
  for (const li of ul.children) {
    if (li.classList.contains("empty-msg")) continue;
    const name = li.dataset.fieldName || "";
    li.style.display = name.toLowerCase().includes(term) ? "" : "none";
  }
}

// ── Tab key support in the editor ──────────────────
queryEditor.addEventListener("keydown", function (e) {
  if (e.key === "Tab") {
    e.preventDefault();
    const start = this.selectionStart;
    const end = this.selectionEnd;
    this.value = this.value.substring(0, start) + "  " + this.value.substring(end);
    this.selectionStart = this.selectionEnd = start + 2;
  }
});

// ── Headers toggle & key-value rows ────────────────
document.getElementById("headers-toggle").addEventListener("click", function () {
  const panel = document.getElementById("headers-panel");
  const isHidden = panel.style.display === "none";
  panel.style.display = isHidden ? "flex" : "none";
  this.textContent = isHidden ? "▼ Headers" : "► Headers";
});

function addHeaderRow(key, value) {
  const row = document.createElement("div");
  row.className = "header-row";
  const keyInput = document.createElement("input");
  keyInput.type = "text";
  keyInput.placeholder = "Header name";
  keyInput.value = key || "";
  const valInput = document.createElement("input");
  valInput.type = "text";
  valInput.placeholder = "Value";
  valInput.value = value || "";
  const removeBtn = document.createElement("button");
  removeBtn.className = "btn-remove";
  removeBtn.textContent = "×";
  removeBtn.addEventListener("click", () => row.remove());
  row.appendChild(keyInput);
  row.appendChild(valInput);
  row.appendChild(removeBtn);
  document.getElementById("headers-rows").appendChild(row);
}

document.getElementById("add-header-btn").addEventListener("click", () => addHeaderRow());
addHeaderRow();

// ── Resizable split pane ───────────────────────────
(function initSplitter() {
  const editorPane = document.getElementById("editor-pane");
  const responsePane = document.getElementById("response-pane");
  const divider = document.getElementById("pane-divider");
  let dragging = false;

  divider.addEventListener("mousedown", (e) => {
    e.preventDefault();
    dragging = true;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  });

  document.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    const main = document.querySelector("main");
    const mainRect = main.getBoundingClientRect();
    const browser = document.getElementById("schema-browser");
    const browserWidth = browser.getBoundingClientRect().width;
    const available = mainRect.width - browserWidth - 6;
    const offset = e.clientX - mainRect.left - browserWidth;
    const ratio = Math.max(0.15, Math.min(0.85, offset / available));
    editorPane.style.flex = "none";
    responsePane.style.flex = "none";
    editorPane.style.width = (ratio * available) + "px";
    responsePane.style.width = ((1 - ratio) * available) + "px";
  });

  document.addEventListener("mouseup", () => {
    if (dragging) {
      dragging = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    }
  });
})();
