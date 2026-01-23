# Relational-SDK

SGX enclave server with RA-TLS, JWT validation, and role-based access control (RBAC).

## Features

- **RA-TLS (DCAP)**: TLS certificates bound to SGX attestation
- **JWT Validation**: Validates AVS-issued tokens with JWKS caching
- **RBAC**: Role-based access control (admin, user, read_only)
- **WebCrypto Ready**: Exposes P-256 public key for browser-side encryption

## Build

```bash
make SGX=1 RA_TYPE=dcap
```

## Run

```bash
gramine-sgx relational-sdk
```

## Endpoints

All API endpoints are versioned with `/v1/` prefix. Health endpoints remain unversioned for k8s probe compatibility.

### Health (unversioned)
- `GET /health` → readiness summary (200 or 503)
- `GET /health/live` → liveness details
- `GET /health/ready` → readiness details (200 or 503)

### Attestation
- `GET /v1/attestation/public-key` → enclave public key (JWK) for browser encryption

### Protected (require JWT)
- `GET /v1/protected` → any authenticated user
- `GET /v1/admin/status` → admin role required
- `POST /v1/data/upload` → user or admin role required
- `GET /v1/data/query` → read_only, user, or admin role

### Documentation
- `GET /docs` → Swagger UI
- `GET /api-doc/openapi.json` → OpenAPI spec

## JWT Authentication

### How It Works

1. Client obtains JWT from AVS by calling `POST /attest` with enclave URL
2. AVS verifies enclave via RA-TLS and issues signed JWT
3. Client sends JWT in `Authorization: Bearer <token>` header
4. Enclave validates JWT against AVS JWKS and extracts user/role

### Token Claims

The enclave expects these claims in AVS-issued tokens:

| Claim | Description |
|-------|-------------|
| `iss` | Issuer (must be AVS) |
| `sub` | Subject (user identifier) |
| `aud` | Audience (must be `relational-sdk`) |
| `exp` | Expiration timestamp |
| `role` | User role: `admin`, `user`, or `read_only` |

### Role Hierarchy

Roles follow a hierarchy where higher roles include lower permissions:

- **admin** → Full access (includes user and read_only)
- **user** → Read/write access (includes read_only)
- **read_only** → Read-only access

### Example: Calling Protected Endpoints

```bash
# 1. Get attestation token from AVS
TOKEN=$(curl -s -X POST http://127.0.0.1:9100/v1/attest \
  -H 'Content-Type: application/json' \
  -d '{"enclave_url":"https://127.0.0.1:8080","user_id":"alice","role":"admin"}' \
  | jq -r '.token')

# 2. Call protected endpoint with token
curl -sk https://127.0.0.1:8080/v1/protected \
  -H "Authorization: Bearer $TOKEN"

# 3. Call admin endpoint
curl -sk https://127.0.0.1:8080/v1/admin/status \
  -H "Authorization: Bearer $TOKEN"

# 4. Upload data (requires user or admin role)
curl -sk -X POST https://127.0.0.1:8080/v1/data/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"encrypted_data":"base64..."}'

# 5. Query data (requires read_only, user, or admin role)
curl -sk https://127.0.0.1:8080/v1/data/query \
  -H "Authorization: Bearer $TOKEN"
```

### JWKS Caching

The enclave caches JWKS from AVS with a 5-minute TTL:
- Fetched from `http://127.0.0.1:9100/.well-known/jwks.json`
- Automatically refreshed when TTL expires
- Configure via `AVS_JWKS_URL` environment variable (future)

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TLS_CERT_PATH` | `/tmp/ra-tls.crt.pem` | RA-TLS certificate path |
| `TLS_KEY_PATH` | `/tmp/ra-tls.key.pem` | RA-TLS private key path |
| `DATA_DIR` | (none) | If set, readiness verifies directory exists |

Note: `0.0.0.0` is a bind address, not a browser URL. Use `https://127.0.0.1:8080/docs`
or `https://<vm-ip>:8080/docs` depending on where you're accessing the server from.

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
make SGX=1 RA_TYPE=dcap
gramine-sgx relational-sdk
```

## Module Structure

The codebase is organized into logical modules:

| Module | Description |
|--------|-------------|
| `main.rs` | Application entry point, router setup |
| `config.rs` | Configuration constants |
| `auth.rs` | JWT validation, JWKS caching, RBAC extractors |
| `crypto.rs` | Enclave keypair, JWK types |
| `handlers.rs` | HTTP request handlers |
| `health.rs` | Health check endpoints |
| `tls.rs` | TLS utilities and PEM normalization |

## License

This project is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later), see LICENSE for details.