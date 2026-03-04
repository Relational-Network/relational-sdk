# Relational-SDK

SGX enclave server with RA-TLS, JWT validation, and role-based access control (RBAC).

## Features

- **RA-TLS (DCAP)**: TLS certificates bound to SGX attestation
- **JWT Validation**: Validates AVS-issued tokens with JWKS caching
- **RBAC**: Role-based access control (admin, user, read_only)
- **WebCrypto Ready**: Exposes P-256 public key for browser-side encryption

---

## Build

### Requirements

⚠️ **IMPORTANT:** `aws-lc-rs` requires **clang** on Ubuntu 20.04. GCC 9.4 has a memcmp bug
that aws-lc-rs refuses to compile against. The Docker build already uses clang.

```bash
sudo apt-get install -y clang
```

### Native (requires SGX hardware + Gramine)

```bash
# Debug build (allows GDB, memory inspection — dev only)
CC=clang CXX=clang++ make RA_TYPE=dcap SGX_DEBUG=1
gramine-sgx relational-sdk

# Production build
CC=clang CXX=clang++ make RA_TYPE=dcap SGX_DEBUG=0
gramine-sgx relational-sdk
```

### Docker (no SGX hardware needed to build)

The image is pre-signed at build time — no signing key is needed at runtime.

```bash
# Build (signs enclave at build time via BuildKit secret)
make docker-build
# or with a custom key:
make docker-build SIGNING_KEY=/path/to/enclave-key.pem

# Run (requires SGX hardware)
make docker-run

# Stop
make docker-stop
```

Manual Docker run:

```bash
docker run --rm -d \
  --name relational-sdk-sgx \
  --network host \
  --device /dev/sgx/enclave \
  --device /dev/sgx/provision \
  -e AVS_JWKS_URL=http://127.0.0.1:9100/.well-known/jwks.json \
  -e SECRET_PROVISION_SERVERS=127.0.0.1:4433 \
  relationalnetwork/relational-sdk:focal
```

---

## Local Development (Full Stack)

Requires SGX hardware (Azure DCsv3 or bare-metal) and AVS running.

### Quick Start (3 terminals)

**Terminal 1 — AVS:**
```bash
cd ../attestation-verification-service
AVS_SIGNING_KEY_PATH="$(pwd)/secrets/avs-signing-key.pem" \
AVS_ALLOW_DEBUG_ENCLAVE=1 \
AVS_ALLOW_OUTDATED_TCB=1 \
RUST_LOG=info \
./target/release/attestation-verification-service
```

**Terminal 2 — Enclave:**
```bash
CC=clang CXX=clang++ make RA_TYPE=dcap SGX_DEBUG=1
gramine-sgx relational-sdk
```

**Terminal 3 — Test:**
```bash
curl -s http://127.0.0.1:9100/health
curl -sk https://127.0.0.1:8080/health
curl -sk https://127.0.0.1:8080/v1/attestation/public-key | jq
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AVS_JWKS_URL` | `http://127.0.0.1:9100/.well-known/jwks.json` | AVS JWKS endpoint |
| `SECRET_PROVISION_SERVERS` | — | Secret provisioning server (e.g. `127.0.0.1:4433`) |
| `RUST_LOG` | `info` | Log level |

---

## Enclave Measurements & Reproducibility

The MRENCLAVE hash uniquely identifies the enclave binary and trusted files. `measurements.txt`
is the committed source of truth.

**Current measurements:** [`measurements.txt`](measurements.txt)

```bash
# Build locally (no cache) and compare against measurements.txt
make verify-mrenclave

# Also compare against a specific GHCR image
make verify-mrenclave DOCKER_IMAGE=ghcr.io/relational-network/relational-sdk:sha-<commit>
```

**When MRENCLAVE changes** (code, Gramine/SGX packages, Rust toolchain, or `SGX_DEBUG` changes):
1. Run `make verify-mrenclave` — prints both old and new hashes
2. Update `measurements.txt` with the new hash
3. Commit code change + `measurements.txt` together in the same PR

CI fails if the built `mr_enclave` differs from `measurements.txt`, preventing silent changes.

| Factor | MRENCLAVE | MRSIGNER |
|--------|:---------:|:--------:|
| Source code | ✅ | ❌ |
| Gramine / SGX package versions | ✅ | ❌ |
| Rust toolchain | ✅ | ❌ |
| `SGX_DEBUG` | ✅ | ❌ |
| Signing key | ❌ | ✅ |

---

## Deployment

### CI/CD Overview

- **CI** (`ci.yml`): Lint, test, build + sign Docker image, push to GHCR, verify MRENCLAVE matches `measurements.txt`
- **CD** (`cd-staging.yml`): Pull pre-built image from GHCR, deploy to staging VM

The staging VM does **not** build or sign — it only runs the pre-built image from GHCR.

**Image tags:**
- `sha-<commit>` — every push (canonical, used by CD)
- `staging-latest` — latest `staging` branch push
- `latest` — latest `main` branch push

### Staging Deployment

**Live URL:** https://iob-staging.duckdns.org
**VM:** Azure DCsv3 (`iob-staging` in resource group `iob`)

```bash
# Push to staging branch — triggers CI (build + sign) then CD (pull + deploy)
git checkout staging
git merge main
git push origin staging
```

### Systemd Service

```bash
sudo systemctl start enclave
sudo systemctl status enclave
sudo journalctl -u enclave -f
```

### Required GitHub Secrets

| Secret | Description |
|--------|-------------|
| `STAGING_HOST` | Staging VM IP |
| `STAGING_USER` | SSH user |
| `STAGING_SSH_KEY` | SSH private key for staging VM |
| `GHCR_TOKEN` | PAT with `read:packages`, `write:packages` |
| `ENCLAVE_SIGNING_KEY` | PEM content of enclave signing key (`cat enclave-key.pem`) |

### Signing Key Setup (one-time)

The enclave is signed at CI build time via `--mount=type=secret`. The key is never stored
in any Docker layer or on the staging VM.

```bash
# Generate signing key
openssl genrsa -out ~/.config/gramine/enclave-key.pem -3 3072

# Add to GitHub secret ENCLAVE_SIGNING_KEY
cat ~/.config/gramine/enclave-key.pem
```

---

## Endpoints

Health endpoints are unversioned; all others use `/v1/` prefix.

### Health
- `GET /health` — readiness summary (200 or 503)
- `GET /health/live` — liveness
- `GET /health/ready` — readiness

### Attestation
- `GET /v1/attestation/public-key` — enclave public key (JWK)

### Protected (require JWT)
- `GET /v1/protected` — any authenticated user
- `GET /v1/admin/status` — admin only
- `POST /v1/data/validate` — validate CSV against `schema_id`
- `POST /v1/data/upload-file` — validate + persist CSV
- `POST /v1/data/upload` — user or admin
- `GET /v1/data/query` — read_only, user, or admin

### Docs
- `GET /docs` — Swagger UI
- `GET /api-doc/openapi.json` — OpenAPI spec

---

## JWT Authentication

1. Client calls AVS `POST /v1/attest` with enclave URL → receives signed JWT
2. Client sends JWT in `Authorization: Bearer <token>`
3. Enclave validates JWT against AVS JWKS

**Required claims:** `iss`, `sub`, `aud` (`relational-sdk`), `exp`, `role` (`admin`/`user`/`read_only`)

**Role hierarchy:** `admin` ⊃ `user` ⊃ `read_only`

```bash
TOKEN=$(curl -sk -X POST https://127.0.0.1:9100/v1/attest \
  -H 'Content-Type: application/json' \
  -d '{"enclave_url":"https://127.0.0.1:8080","user_id":"alice","role":"admin"}' \
  | jq -r '.token')

curl -sk https://127.0.0.1:8080/v1/protected -H "Authorization: Bearer $TOKEN"
curl -sk https://127.0.0.1:8080/v1/admin/status -H "Authorization: Bearer $TOKEN"
```

---

## Testing Attestation

A C-based RA-TLS client in `attestation-client/` verifies the SGX quote in the TLS certificate.

```bash
make test-attest        # basic attestation test
make test-attest-all    # includes negative tests (wrong MRENCLAVE/MRSIGNER)
make show-measurements  # print current enclave measurements from .sig
```

See [`attestation-client/README.md`](attestation-client/README.md) for details.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AVS_JWKS_URL` | `http://127.0.0.1:9100/.well-known/jwks.json` | AVS JWKS endpoint |
| `SECRET_PROVISION_SERVERS` | — | Secret provisioning server |
| `RUST_LOG` | `info` | Log level |
| `TLS_CERT_PATH` | `/tmp/ra-tls.crt.pem` | RA-TLS certificate |
| `TLS_KEY_PATH` | `/tmp/ra-tls.key.pem` | RA-TLS private key |
| `DATA_DIR` | — | If set, readiness checks this directory exists |

## Module Structure

| Module | Description |
|--------|-------------|
| `main.rs` | Entry point, router |
| `config.rs` | Configuration constants |
| `auth.rs` | JWT validation, JWKS caching, RBAC |
| `crypto.rs` | Enclave keypair, JWK types |
| `handlers.rs` | HTTP handlers |
| `health.rs` | Health endpoints |
| `tls.rs` | TLS utilities |

## License

AGPL-3.0-or-later — see LICENSE.
