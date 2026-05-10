# GraphQLMe

I tend to test a lot of GraphQL implementations, and frankly the existing tools are all incredibly frustrating. Either they're reliant on tons of npm dependencies, or they require an account to a service you'll never use, they lack extensibility, or they're flat out broken and deprecated. 

This, therefore, is a small, open-source and lightweight, self-hosted GraphQL IDE, which aims to simplifying GraphQL testing. 

**GraphQLMe** lets you introspect any local or remote GraphQL endpoint, browse its schema interactively, visually compose queries and mutations with argument forms and field selectors, and run them — all from a single, hackable, binary.
<img width="1512" height="862" alt="Screenshot 2026-05-09 at 18 01 38" src="https://github.com/user-attachments/assets/fced4f06-f8b8-402b-8817-b7cc13e5a2ca" />

## Features

- **Schema introspection** — Point at any GraphQL endpoint and instantly browse all queries, mutations, types, and arguments.
- **Visual query builder** — Select fields with checkboxes, fill in arguments with typed inputs, and watch the query assemble in real time. No more troubleshooting syntax errors!
- **Custom headers** — Add key-value headers (auth tokens, API keys, etc.) that get forwarded to the target endpoint.
- **Schema persistence** — Introspected schemas are saved to `schema.json` and can be reloaded without re-querying.
- **CORS proxy** — Built-in local proxy forwards requests to third-party GraphQL APIs, bypassing browser CORS restrictions.
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
├── main.go          # Go server: static file serving, CORS proxy, schema persistence
├── index.html       # Single-page UI
├── style.css        # Dark-themed styles
├── js/
│   ├── state.js     # Global state, DOM refs, type resolution helpers
│   ├── schema.js    # Introspection query, schema parsing, field list rendering
│   ├── builder.js   # Query builder: args form, fields tree, query generation
│   ├── network.js   # Proxy requests, custom headers, query execution
│   └── ui.js        # Search, splitter, headers panel, keyboard shortcuts
└── schema.json      # Auto-saved introspection result (gitignored)
```

## License

GPLv3
