# ES-Paste (Log Vault)

Minimal monospace pastebin and crash log analysis service built with Axum, Tokio, SQLite, and Zstandard.

## Features
- **Monospace Web Editor**: Dark-themed UI with dynamic line numbers at `/`.
- **Paste & Log Upload**: `POST /api/paste` accepting raw text or JSON with optional TTL.
- **Zstandard Compression**: Logs stored as compressed blobs in SQLite.
- **Automated Log Analysis**: Integrated heuristics from `mc-log-analyzer` displaying diagnosis banners for known crash signatures (EULA, Port Bind, OOM Heap, Java versions, corrupted chunks, etc.).
- **Raw View**: `GET /raw/:id` for curl and terminal inspection.
- **Syntax & Web View**: `GET /p/:id` with HTML escaping and diagnosis breakdown.

## Endpoints
- `GET /`: Minimal dark-themed editor.
- `POST /api/paste`: Create paste. JSON payload `{"content": "...", "ttl_hours": 12}` or raw text body.
  - Header `Authorization: Bearer <AUTH_TOKEN>` enables TTL up to 14 days (default guest max 12h).
- `GET /p/:id`: Formatted web view with diagnosis banner.
- `GET /raw/:id`: Raw UTF-8 text output.

## Build and Run
```bash
cargo check
cargo test
cargo run
```

Environment variables:
- `BIND_ADDR`: Listen address (default `0.0.0.0:8080`)
- `BASE_URL`: Base URL prefix for links (default `http://localhost:8080`)
- `DATABASE_PATH`: SQLite file path (default `pastes.db`)
- `AUTH_TOKEN`: Secret bearer token for extended TTL (default `es-secret-admin`)
