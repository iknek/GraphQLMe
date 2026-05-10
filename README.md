# GraphQLMe

I tend to test a lot of GraphQL implementations, and frankly the existing tools are all incredibly frustrating. Either they're reliant on tons of npm dependencies, or they require an account to a service you'll never use, they lack extensibility, or they're flat out broken and deprecated. 

This, therefore, is a small, open-source and lightweight, self-hosted GraphQL IDE and security auditor, which aims to simplifying GraphQL testing. 

**GraphQLMe** lets you introspect any local or remote GraphQL endpoint, browse its schema interactively, visually compose queries and mutations with argument forms and field selectors, run them, and audit them for security vulnerabilities — all from a single, hackable, binary.
<img width="1512" height="862" alt="Screenshot 2026-05-09 at 18 01 38" src="https://github.com/user-attachments/assets/fced4f06-f8b8-402b-8817-b7cc13e5a2ca" />

## Features

### Query Builder
- **Schema introspection** — Point at any GraphQL endpoint and instantly browse all queries, mutations, types, and arguments.
- **Visual query builder** — Select fields with checkboxes, fill in arguments with typed inputs, and watch the query assemble in real time. No more troubleshooting syntax errors!
- **Custom headers** — Add key-value headers (auth tokens, API keys, etc.) that get forwarded to the target endpoint.
- **Schema persistence** — Introspected schemas are saved to `schema.json` and can be reloaded without re-querying.
- **CORS proxy** — Built-in local proxy forwards requests to third-party GraphQL APIs, bypassing browser CORS restrictions.

### Security Auditor
Toggle into **Auditor mode** to scan GraphQL endpoints for vulnerabilities. Select which operations and attack categories to test, then let the scanner run through payloads automatically.

**Injection testing:**
- **SQL Injection** — Error-based, UNION-based, and blind detection with 17+ payloads.
- **NoSQL Injection** — MongoDB-style operator injection (`$gt`, `$ne`, `$where`, etc.).
- **SSTI** — Server-Side Template Injection across Jinja2, Twig, Freemarker, and more.
- **OS Command Injection** — Shell metacharacter payloads with output detection.
- **Path Traversal** — LFI payloads with encoding bypass variants.

**Web security:**
- **Reflected XSS** — 14 XSS payloads with unescaped reflection detection.
- **Stored XSS** — Mutation→query-back pipeline to detect persistent XSS.
- **CSRF** — Content-Type enforcement check, Origin validation, and **auto-generated PoC HTML forms** for each mutation.
- **SSRF** — 30+ payloads targeting cloud metadata (AWS/GCP/Azure), internal services, and protocol handlers.
- **IDOR** — Probes ID-based arguments with sequential/boundary values and response diffing.

**Smart features:**
- **Contextual payloads** — Argument names are analyzed (e.g., `email`, `url`, `search`, `password`) and extra targeted payloads are automatically added.
- **Dual detection** — Error-based signature matching + response diff comparison against automatic baselines.
- **Rate limiting** — Configurable delay between requests to avoid detection/bans.
- **Inline findings** — Click any finding to expand full details including payload, evidence, and request/response pairs.
- **Markdown report export** — Download a full security report with severity ratings, evidence, and PoC details.

### General
- **Single lightweight binary** — All HTML, CSS, and JS is embedded in the Go binary. No Node.js, no npm, no build step, just compile and go.
- **Easily extendable and hackable** — Add your own features, change the introspection query, or build a whole new tool on top of this one. This tool is easily modifiable to support your needs.

## Quick Start

```bash
go build -o graphqlme .
./graphqlme
```

Open [http://localhost:8080](http://localhost:8080), paste a GraphQL endpoint URL, and hit **Introspect**.

## Project Structure

```
├── main.go          # Go server: static file serving, CORS proxy, schema persistence, security API
├── index.html       # Single-page UI (builder + auditor modes)
├── style.css        # Dark-themed styles
├── js/
│   ├── state.js     # Global state, DOM refs, type resolution helpers
│   ├── schema.js    # Introspection query, schema parsing, field list rendering
│   ├── builder.js   # Query builder: args form, fields tree, query generation
│   ├── network.js   # Proxy requests, custom headers, query execution
│   ├── auditor.js   # Security auditor UI: scan config, findings table, detail view
│   └── ui.js        # Search, splitter, headers panel, keyboard shortcuts
├── scanner/
│   ├── types.go     # Scan request/response types, severity levels, categories
│   ├── payloads.go  # Built-in injection payloads per category
│   ├── context.go   # Contextual payload generation based on argument names
│   ├── detector.go  # Error-based signature matching + response diff detection
│   ├── scanner.go   # Scan engine: job management, concurrency, test execution
│   ├── csrf.go      # CSRF testing: Content-Type, Origin validation, PoC generation
│   ├── xss.go       # XSS detection: reflected + stored, payload reflection analysis
│   ├── ssrf.go      # SSRF payloads + detection signatures
│   ├── idor.go      # IDOR probing: ID enumeration + response comparison
│   └── report.go    # Markdown report generation
└── schema.json      # Auto-saved introspection result (gitignored)
```

## License

GPLv3
