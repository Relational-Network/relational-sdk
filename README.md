# Relational-SDK

Barebones Rust API server scaffold for enclave use.

## Run

```bash
cargo run
```

## Endpoints

- `GET /health` -> readiness summary (200 or 503)
- `GET /health/live` -> liveness details
- `GET /health/ready` -> readiness details (200 or 503)
- `GET /docs` -> Swagger UI
- `GET /api-doc/openapi.json` -> OpenAPI spec

Optional readiness checks:
- `DATA_DIR` -> if set, readiness verifies the directory exists.

Note: `0.0.0.0` is a bind address, not a browser URL. Use `http://127.0.0.1:8080/docs`
or `http://<vm-ip>:8080/docs` depending on where you're accessing the server from.

## Threads and SGX

The runtime uses `worker_threads = 2` to keep enclave thread usage predictable. When sizing
`sgx.max_threads`, account for:
- 4 Gramine/helper threads (main + IPC + async + one TLS-handshake)
- Tokio worker threads (currently 2)
- Any extra threads from blocking pools or future background tasks

## License

This project is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later), see LICENSE for details.