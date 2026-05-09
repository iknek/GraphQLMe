// ── Introspection Query ────────────────────────────
const INTROSPECTION_QUERY = `{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        description
        args {
          name
          type {
            ...TypeRef
          }
        }
        type {
          ...TypeRef
        }
      }
    }
  }
}

fragment TypeRef on __Type {
  name
  kind
  ofType {
    name
    kind
    ofType {
      name
      kind
      ofType {
        name
        kind
        ofType {
          name
          kind
          ofType {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
      }
    }
  }
}`;

// ── State ──────────────────────────────────────────
let currentSchema = null;
let typeMap = {};
let targetURL = "";
let activeField = null;
let activeIsQuery = true;

// ── DOM References ─────────────────────────────────
const urlInput = document.getElementById("url-input");
const queryEditor = document.getElementById("query-editor");
const responseViewer = document.getElementById("response-viewer");
const queriesList = document.getElementById("queries-list");
const mutationsList = document.getElementById("mutations-list");
const statusBar = document.getElementById("status-bar");
const schemaSearch = document.getElementById("schema-search");
const argsPanel = document.getElementById("args-panel");
const argsForm = document.getElementById("args-form");
const fieldsPanel = document.getElementById("fields-panel");
const fieldsTree = document.getElementById("fields-tree");
const typeInfo = document.getElementById("type-info");

// ── Helpers ────────────────────────────────────────
function setStatus(msg, type = "") {
  statusBar.textContent = msg;
  statusBar.className = type;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function toggleSection(el) {
  el.classList.toggle("open");
  if (el.classList.contains("open")) {
    el.textContent = el.textContent.replace("►", "▼");
  } else {
    el.textContent = el.textContent.replace("▼", "►");
  }
}

// ── Type Resolution ────────────────────────────────
function resolveTypeName(type) {
  if (!type) return "Unknown";
  if (type.kind === "NON_NULL") return resolveTypeName(type.ofType) + "!";
  if (type.kind === "LIST") return "[" + resolveTypeName(type.ofType) + "]";
  return type.name || "Unknown";
}

function getBaseType(type) {
  if (!type) return null;
  if (type.ofType) return getBaseType(type.ofType);
  return type;
}

function isScalarReturn(type) {
  const base = getBaseType(type);
  return base && (base.kind === "SCALAR" || base.kind === "ENUM");
}
