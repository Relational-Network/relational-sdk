# Relational-SDK

Barebones Rust API server scaffold for enclave use.

## Build

```bash
make all
```

## Run

```bash
gramine-sgx relational-sdk
```

## Endpoints

- `GET /health` -> readiness summary (200 or 503)
- `GET /health/live` -> liveness details
- `GET /health/ready` -> readiness details (200 or 503)
- `GET /attestation/public-key` -> enclave public key (JWK) for browser encryption
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

## RA-TLS (DCAP)

When running in SGX with Gramine, the manifest uses `gramine-ratls` to generate a RA-TLS
certificate and key in `/tmp`. The server reads the fixed paths:
- `/tmp/ra-tls.crt.pem`
- `/tmp/ra-tls.key.pem`

TLS is required for RA-TLS deployments; the server will fail fast if the files are missing.

Example:

```bash
make RA_TYPE=dcap
gramine-sgx relational-sdk
```

## License

This project is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later), see LICENSE for details.