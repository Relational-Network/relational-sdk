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

## Deployment

### ✅ Automated CI/CD via Staging VM

**relational-sdk requires SGX hardware to build.** CI/CD builds on the staging VM (which has SGX) and pushes to GHCR.

- **CI** (`.github/workflows/ci.yml`): Lint, test (non-SGX) on push/PR  
- **CD** (`.github/workflows/cd-staging.yml`): SSH to staging → build Docker → push to GHCR → deploy
- **Trigger**: Push to `staging` branch
- **Image**: `ghcr.io/relational-network/relational-sdk:staging-latest`

### Staging Deployment

**Live URL:** https://iob-staging.duckdns.org (via Caddy reverse proxy)

**VM:** Azure DCsv3 (`iob-staging` in resource group `iob`)

**Automated Deployment:**
```bash
# Push to staging branch triggers CD
git checkout staging
git merge main
git push origin staging
# CD workflow: builds on VM → pushes to GHCR → restarts service → verifies health
```

**Manual Deployment (if needed):**
```bash
# SSH into staging VM
ssh azureuser@20.86.174.127

# Run deployment script
cd /opt/relational-sdk
./scripts/deploy-staging.sh
```

The CD workflow / script will:
1. Pull latest code from git
2. Build Docker image with SGX support
3. Push image to GHCR
4. Extract and validate measurements (MRSIGNER change = failure)
5. Update `/opt/iob-micres/.env` with new MRENCLAVE
6. Restart enclave and AVS services
7. Verify health and attestation

### Systemd Service (Docker-based)

The enclave runs as a Docker container managed by systemd:

```bash
# Install service file
sudo cp scripts/enclave.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable enclave
sudo systemctl start enclave

# View logs
sudo journalctl -u enclave -f

# Status
sudo systemctl status enclave
```

### Manual Docker Run (for testing)

SSH into the staging VM and run:

```bash
# 1. Pull the image
docker pull ghcr.io/relational-network/relational-sdk:staging-latest

# 2. Run container
docker run --rm -d --name enclave \
  --network host \
  --device /dev/sgx/enclave \
  --device /dev/sgx/provision \
  -v /opt/iob-micres/secrets/enclave-key.pem:/keys/enclave-key.pem:ro \
  -v /opt/iob-micres/data:/data \
  -e GRAMINE_SGX_SIGNING_KEY=/keys/enclave-key.pem \
  -e AVS_JWKS_URL=http://127.0.0.1:9100/.well-known/jwks.json \
  ghcr.io/relational-network/relational-sdk:staging-latest

# 3. Verify
curl -sk https://127.0.0.1:8080/health
```

### Build from Source on Staging VM (if needed)

```bash
# 1. Clone the repo
cd /opt
sudo git clone https://github.com/Relational-Network/relational-sdk.git
cd relational-sdk

# 2. Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 3. Build the enclave
make SGX=1 RA_TYPE=dcap

# 4. Extract and record measurements
gramine-sgx-sigstruct-view relational-sdk.sig
# Note: MRENCLAVE and MRSIGNER values - update AVS config if changed

# 5. Test locally
gramine-sgx relational-sdk &
curl -sk https://127.0.0.1:8080/health

# 6. If using systemd, restart the service
sudo systemctl restart enclave
```

### Update AVS with New Measurements

After building, if MRENCLAVE changed, update AVS config:

```bash
# On staging VM
sudo nano /opt/iob-micres/.env
# Update AVS_EXPECTED_MRENCLAVE=<new_value>

sudo systemctl restart avs
```

### Required GitHub Secrets (for CI/CD)

| Secret | Description |
|--------|-------------|
| `STAGING_HOST` | Staging VM IP (20.86.174.127) |
| `STAGING_USER` | SSH user (azureuser) |
| `STAGING_SSH_KEY` | SSH private key for staging VM |
| `GHCR_TOKEN` | PAT with `read:packages`, `write:packages` |

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

## Related Documentation

- [STAGING-DEPLOYMENT.md](../STAGING-DEPLOYMENT.md) - Full staging deployment guide
- [AGENTS.md](../AGENTS.md) - Architecture and development context
- [scripts/deploy-staging.sh](scripts/deploy-staging.sh) - Automated staging deployment script

## License

This project is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later), see LICENSE for details.