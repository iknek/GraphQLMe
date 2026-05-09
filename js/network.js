// ── Custom Headers ─────────────────────────────────
function getCustomHeaders() {
  const headers = {};
  const rows = document.querySelectorAll(".header-row");
  for (const row of rows) {
    const inputs = row.querySelectorAll("input");
    const key = inputs[0].value.trim();
    const value = inputs[1].value.trim();
    if (key) headers[key] = value;
  }
  return headers;
}

// ── Proxy Helper ───────────────────────────────────
async function proxyRequest(url, body) {
  const customHeaders = getCustomHeaders();
  const resp = await fetch("/api/proxy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url, body: body, headers: customHeaders }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error("HTTP " + resp.status + " — " + (text || resp.statusText));
  }
  return resp.json();
}

// ── Run Query ──────────────────────────────────────
async function runQuery() {
  targetURL = urlInput.value.trim();
  if (!targetURL) {
    setStatus("Please enter a GraphQL endpoint URL", "error");
    return;
  }

  const query = queryEditor.value.trim();
  if (!query) {
    setStatus("Query editor is empty", "error");
    return;
  }

  setStatus("Running query...");

  try {
    const data = await proxyRequest(targetURL, { query: query });
    responseViewer.textContent = JSON.stringify(data, null, 2);

    if (data.errors) {
      setStatus("Query returned errors", "error");
    } else {
      setStatus("Query completed", "success");
    }
  } catch (err) {
    setStatus("Query failed: " + err.message, "error");
    responseViewer.textContent = err.message;
  }
}
