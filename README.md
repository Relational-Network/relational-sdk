# Relational-SDK

SGX enclave server with RA-TLS, JWT validation, and role-based access control (RBAC).

## Features

- **RA-TLS (DCAP)**: TLS certificates bound to SGX attestation
- **JWT Validation**: Validates AVS-issued tokens with JWKS caching
- **RBAC**: Role-based access control (admin, user, read_only)
- **WebCrypto Ready**: Exposes P-256 public key for browser-side encryption

## Build

### Native (requires SGX hardware)

```bash
# Build and sign enclave
make SGX=1 RA_TYPE=dcap

# Run
gramine-sgx relational-sdk
```

### Docker (requires SGX hardware)

> **Note:** The Docker image is based on Ubuntu 20.04 (focal) for compatibility with
> Gramine, Intel SGX, and Azure DCAP libraries.

```bash
# Build Docker image
make docker-build

# Run container (requires SGX devices)
make docker-run

# Stop container
make docker-stop
```

Manual Docker run with host networking (recommended for E2E testing):

```bash
docker run --rm -d \
  --name relational-sdk-sgx \
  --network host \
  --device /dev/sgx/enclave \
  --device /dev/sgx/provision \
  -v "$HOME/.config/gramine/enclave-key.pem:/keys/enclave-key.pem:ro" \
  -e GRAMINE_SGX_SIGNING_KEY=/keys/enclave-key.pem \
  -e AVS_JWKS_URL=https://127.0.0.1:9100/.well-known/jwks.json \
  relationalnetwork/relational-sdk:focal
```

Manual Docker run with port mapping:

```bash
docker run --rm -it \
  --name relational-sdk-sgx \
  --device /dev/sgx/enclave \
  --device /dev/sgx/provision \
  -p 8080:8080 \
  -v "$HOME/.config/gramine/enclave-key.pem:/keys/enclave-key.pem:ro" \
  -e GRAMINE_SGX_SIGNING_KEY=/keys/enclave-key.pem \
  -e AVS_JWKS_URL=https://your-avs-host:9100/.well-known/jwks.json \
  relationalnetwork/relational-sdk:focal
```

### Quick E2E Test (with HTTPS AVS)

```bash
# 1. Build and run enclave container (with HTTPS AVS JWKS URL)
docker run --rm -d --name enclave --network host \
  --device /dev/sgx/enclave --device /dev/sgx/provision \
  -v "$HOME/.config/gramine/enclave-key.pem:/keys/enclave-key.pem:ro" \
  -e GRAMINE_SGX_SIGNING_KEY=/keys/enclave-key.pem \
  -e AVS_JWKS_URL=https://127.0.0.1:9100/.well-known/jwks.json \
  relationalnetwork/relational-sdk:focal

# 2. Test health
curl -sk https://127.0.0.1:8080/health

# 3. Get enclave public key
curl -sk https://127.0.0.1:8080/v1/attestation/public-key | jq
```

## CI/CD

This repo uses GitHub Actions:

- **CI** (`.github/workflows/ci.yml`): Runs on push/PR to main/staging
  - Lint (rustfmt, clippy)
  - Test
  - Build release binary
  - Security audit

- **CD** (`.github/workflows/cd-staging.yml`): Runs on push to staging
  - Build Docker image with SGX support
  - Push to GHCR
  - Deploy to staging SGX VM

### Required Secrets

| Secret | Description |
|--------|-------------|
| `GITHUB_TOKEN` | Automatic, for GHCR |
| `STAGING_SGX_HOST` | (optional) SSH host for SGX VM deployment |

### Enclave Signing

SGX enclaves must be signed before running. The signing key should be kept secure and NOT committed to git.

```bash
# Generate signing key (one-time, keep secure)
gramine-sgx-gen-private-key ~/.config/gramine/enclave-key.pem

# View enclave measurements after build
make show-measurements
```

## SGX VM Requirements

Install required dependencies on SGX-capable VM:

```bash
# Gramine repository
sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg \
  https://packages.gramineproject.io/gramine-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] \
  https://packages.gramineproject.io/ $(lsb_release -sc) main" \
  | sudo tee /etc/apt/sources.list.d/gramine.list

# Intel SGX repository
sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc \
  https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] \
  https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -sc) main" \
  | sudo tee /etc/apt/sources.list.d/intel-sgx.list

# Azure DCAP client (for Azure DCsv3 VMs)
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add
sudo add-apt-repository "deb [arch=amd64] https://packages.microsoft.com/ubuntu/$(lsb_release -rs)/prod $(lsb_release -cs) main"

# Install packages
sudo apt-get update
sudo apt-get install -y \
  gramine \
  gramine-ratls-dcap \
  sgx-aesm-service \
  libsgx-aesm-ecdsa-plugin \
  libsgx-aesm-quote-ex-plugin \
  az-dcap-client \
  gcc make pkg-config libssl-dev libffi-dev
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
# 1. Get attestation token from AVS (use HTTPS if AVS is in HTTPS mode)
TOKEN=$(curl -sk -X POST https://127.0.0.1:9100/v1/attest \
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
- Default URL: `http://127.0.0.1:9100/.well-known/jwks.json`
- Configure via `AVS_JWKS_URL` environment variable for HTTPS:
  ```bash
  export AVS_JWKS_URL=https://avs.example.com/.well-known/jwks.json
  ```
- Automatically refreshed when TTL expires
- Supports self-signed certificates for development

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TLS_CERT_PATH` | `/tmp/ra-tls.crt.pem` | RA-TLS certificate path |
| `TLS_KEY_PATH` | `/tmp/ra-tls.key.pem` | RA-TLS private key path |
| `DATA_DIR` | (none) | If set, readiness verifies directory exists |
| `AVS_JWKS_URL` | `http://127.0.0.1:9100/.well-known/jwks.json` | AVS JWKS endpoint for token validation |

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

## Testing Attestation

A C-based RA-TLS verification client is included in `attestation-client/` for testing SGX attestation. It uses Intel DCAP to verify the SGX quote embedded in the RA-TLS certificate.

### Quick Start

```bash
# Terminal 1: Start the enclave
make SGX=1 RA_TYPE=dcap
gramine-sgx relational-sdk

# Terminal 2: Test attestation
make test-attest
```

### Available Test Commands

| Command | Description |
|---------|-------------|
| `make attest` | Build attestation client |
| `make test-attest` | Test attestation (auto-extracts measurements from .sig) |
| `make test-attest-all` | Run all tests including negative tests |
| `make show-measurements` | Show current enclave measurements |

### Testing Against Remote Enclave

```bash
# Test against a remote enclave
cd attestation-client
make test HOST=enclave.example.com PORT=443
```

### Verifying Wrong Measurements Are Rejected

```bash
make test-attest-all
# Output shows:
# ✓ Correctly rejected wrong MRENCLAVE
# ✓ Correctly rejected wrong MRSIGNER
```

### How It Works

1. Client connects to enclave over TLS
2. During handshake, receives RA-TLS certificate containing SGX quote
3. `libra_tls_verify_dcap.so` verifies the quote via Intel DCAP
4. Client compares enclave measurements (MRENCLAVE, MRSIGNER) against expected values
5. If all checks pass, handshake completes and client can communicate securely

See `attestation-client/README.md` for detailed documentation.

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