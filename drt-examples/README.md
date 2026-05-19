# drt-examples

Sample DRT scripts that run inside the SGX enclave when an analyst invokes a
granted Data Rights Token. Each script is a Rust crate compiled to
`wasm32-unknown-unknown`, with its SHA-256 pinned on-chain at DRT
registration time and re-verified on every fetch.

## Layout

```
drt-examples/
├── README.md         (this file)
└── mean/             canonical sample DRT
    ├── Cargo.toml
    ├── .cargo/config.toml   (sets default target = wasm32-unknown-unknown)
    ├── src/lib.rs
    └── dist/mean.wasm       (committed build artifact)
```

Future DRTs live as sibling crates (`drt-examples/<name>/`). They are not
part of the parent Cargo workspace — each is built standalone so its WASM
profile (`opt-level = "z"`, LTO, panic = abort, strip) does not leak into
the SDK build.

## Trust contract

The enclave will run a DRT script only if its SHA-256 matches the
`code_hash` recorded in the on-chain `DrtConfig`. The pipeline:

1. Admin builds and publishes the `.wasm`.
2. Admin records `(code_repo_url, code_hash)` on-chain via pool creation.
3. Enclave fetches `code_repo_url`, SHA-256-checks the bytes against
   `code_hash` (see `relational-sdk/src/drt/verified_fetch.rs`), rejects on
   mismatch, caches verified bytes under `/data/drt-scripts/<hash>`.
4. Enclave loads the cached bytes into the `wasmi` sandbox (see
   `relational-sdk/src/drt/runtime.rs`) and invokes the `run` export.

The cache is keyed by hash — the filename *is* the integrity claim, and the
runtime re-hashes the bytes on every read.

## Host ABI

A DRT module must export one function and import four:

| Direction | Signature | Notes |
|---|---|---|
| export | `run() -> i32` | 0 = success; non-zero = script-level error |
| import | `env.host_input_len() -> i32` | bytes the host has staged |
| import | `env.host_input_copy(dst: i32, len: i32) -> i32` | copies into wasm memory |
| import | `env.host_output_write(src: i32, len: i32) -> i32` | appends to host output buffer; returns -1 on overflow |
| import | `env.host_log(src: i32, len: i32)` | best-effort `debug!` log |

Input format (UTF-8 JSON, staged by the enclave):

```json
{ "csv": "<header row plus all body rows>",
  "args": { "...": "DRT-specific" } }
```

Output should be UTF-8 JSON. Errors should be `{"error": "..."}` with a
non-zero exit from `run`.

Sandbox limits enforced by the runtime: 64 MiB input, 4 MiB output, 50 M
wasmi "fuel" instructions (~1 s on modest hardware), 30 s wall clock. No
WASI, no filesystem, no clock — only the four imports above.

## Build

```bash
cd mean
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/drt_mean.wasm dist/mean.wasm
sha256sum dist/mean.wasm
```

Host-side tests (no wasm runtime needed):

```bash
cargo test --target x86_64-unknown-linux-gnu
```

End-to-end test through the enclave's wasmi runtime against the committed
`dist/mean.wasm` lives at `relational-sdk/src/drt/runtime.rs` (run with
`cd .. && cargo test drt::`).

## Publish

The `code_repo_url` recorded on-chain must resolve to the exact bytes that
hashed to `code_hash`. Commit `dist/<name>.wasm` to the relational-sdk repo
so the URL

```
https://raw.githubusercontent.com/relational-network/relational-sdk/<ref>/drt-examples/<name>/dist/<name>.wasm
```

resolves to the same bytes `sha256sum` reports locally. Update the DRT
registry entry (in the dashboard) with the new hash whenever the script
changes — the enclave will refuse to run any script whose fetched bytes
don't match the on-chain hash.

The enclave only accepts URLs on `raw.githubusercontent.com` under the
`relational-network/*` owner (allowlist in
`relational-sdk/src/drt/verified_fetch.rs`).

## Adding a new DRT

1. Copy `mean/` to `drt-examples/<your-drt>/`.
2. Rename the crate in `Cargo.toml` (set `name = "drt-<your-drt>"`).
3. Implement `run()` against the host ABI above.
4. Build and commit `dist/<your-drt>.wasm`.
5. Add a registry entry on the dashboard side pointing at the raw URL and
   the SHA-256.
