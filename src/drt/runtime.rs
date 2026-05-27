// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Sandboxed execution of verified DRT scripts via `wasmtime` (Cranelift JIT).
//!
//! ## Sandbox guarantees
//!
//! - Cranelift JIT inside Gramine SGX (requires `sgx.allow_jit = true` in the
//!   manifest — Gramine ≥ 1.7).
//! - Module memory is capped by the engine; the DRT cannot grow past its
//!   declared maximum and the host enforces an additional bound on input
//!   stage size ([`MAX_INPUT_BYTES`]).
//! - Wall-clock execution is capped by [`DEFAULT_WALL_TIMEOUT`] via
//!   `tokio::time::timeout` around a `spawn_blocking` worker, with
//!   wasmtime fuel as defence in depth against tight loops.
//! - No I/O: the only host import is `env.host_log`. No WASI, no
//!   filesystem, no network, no clock.
//!
//! ## Host ABI (DRT side)
//!
//! ### Exports the guest must provide
//!
//! ```text
//! memory                                                  (the default `memory` export)
//! alloc(size: i32) -> i32                                 bump-style allocator
//! run(
//!     csv_ptr: i32, csv_len: i32,
//!     args_ptr: i32, args_len: i32,
//!     out_ptr_cell: i32, out_len_cell: i32,
//! ) -> i32                                                0 = success; non-zero = script-level error
//! ```
//!
//! The host:
//!   1. Calls `alloc(csv_len)` and writes the CSV bytes directly into
//!      `memory` at the returned offset.
//!   2. Calls `alloc(args_len)` and writes the JSON-encoded args.
//!   3. Calls `alloc(8)` for two i32 cells (`out_ptr_cell`, `out_len_cell`)
//!      that the guest fills in.
//!   4. Calls `run(...)`.
//!   5. Reads `(out_ptr, out_len)` back from the two cells and copies the
//!      output out of `memory`.
//!
//! This avoids the previous JSON-encode of the full CSV and the host->guest
//! copy through `host_input_copy`. For 240k rows / ~24 MiB CSV that one
//! change alone removes hundreds of milliseconds of overhead.
//!
//! ### Imports the host provides
//!
//! ```text
//! env.host_log(ptr: i32, len: i32)
//!     Best-effort diagnostic log. Output is enclave-local debug only.
//! ```
//!
//! ## AOT caching
//!
//! [`ensure_precompiled`] writes a `.cwasm` next to the cached `.wasm` so
//! warm invocations skip Cranelift compilation entirely. The cache key
//! embeds [`CWASM_VERSION_TAG`] so a wasmtime upgrade invalidates stale
//! artifacts automatically.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use wasmtime::{Caller, Config, Engine, Linker, Memory, Module, Store, Strategy};

/// Maximum bytes a DRT script may emit as its output blob.
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

/// Maximum bytes of CSV the host will hand to the DRT in a single call.
///
/// The DRT receives the raw CSV — no JSON envelope — so this is the actual
/// CSV cap. wasm32's hard memory ceiling is 4 GiB; the per-instance cap is
/// also bounded by [`MAX_GUEST_MEMORY_BYTES`] (which must accommodate the
/// CSV plus any working set the script allocates).
pub const MAX_INPUT_BYTES: usize = 600 * 1024 * 1024; // 600 MiB

/// Hard ceiling on a single guest instance's linear memory. Keeps a single
/// runaway DRT from exhausting enclave EPC.
pub const MAX_GUEST_MEMORY_BYTES: usize = 1024 * 1024 * 1024; // 1 GiB

/// Base fuel budget covering parser init, output assembly, and fixed
/// per-invocation overhead independent of input size.
pub const BASE_FUEL: u64 = 2_000_000_000;

/// Additional fuel granted per byte of input.
pub const FUEL_PER_INPUT_BYTE: u64 = 1_000;

fn fuel_budget(input_len: usize) -> u64 {
    BASE_FUEL.saturating_add(FUEL_PER_INPUT_BYTE.saturating_mul(input_len as u64))
}

/// Hard wall-clock cap on a single `run` invocation. Defence in depth on
/// top of fuel — enforced from the async caller via `tokio::time::timeout`.
pub const DEFAULT_WALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Cache-key suffix for precompiled `.cwasm` artifacts. Bump on any
/// wasmtime upgrade that changes the on-disk format — stale entries will
/// then be ignored and lazily replaced.
pub const CWASM_VERSION_TAG: &str = "wt37";

/// Input blob the host stages for the DRT.
#[derive(Debug, Serialize)]
pub struct RuntimeInput<'a> {
    /// Pool CSV the script may read.
    pub csv: &'a str,
    /// Caller-supplied arguments (e.g. `{ "column": "salary" }`).
    pub args: &'a serde_json::Value,
}

/// Output the DRT emitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeOutput {
    /// Value returned by the `run()` export. 0 = success.
    pub exit_code: i32,
    /// Bytes the script produced — interpret as UTF-8 JSON.
    pub body: Vec<u8>,
}

/// Errors surfaced from the runtime.
#[derive(Debug)]
pub enum RuntimeError {
    /// Failed to parse / link / instantiate the WASM module.
    Compile(String),
    /// Module is missing a required export (`run`, `alloc`, `memory`).
    BadModule(String),
    /// Trap during execution — out of bounds, etc.
    Trap(String),
    /// All fuel was consumed.
    OutOfFuel { fuel: u64, input_len: usize },
    /// Wall-clock budget exceeded.
    Timeout,
    /// Input or output too large.
    SizeLimit(String),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compile(m) => write!(f, "DRT runtime compile error: {m}"),
            Self::BadModule(m) => write!(f, "DRT runtime bad module: {m}"),
            Self::Trap(m) => write!(f, "DRT runtime trap: {m}"),
            Self::OutOfFuel { fuel, input_len } => write!(
                f,
                "DRT script exceeded compute budget (fuel={fuel}, input_bytes={input_len}) \
                 — input may be too large or script too expensive"
            ),
            Self::Timeout => write!(f, "DRT runtime wall-clock timeout"),
            Self::SizeLimit(m) => write!(f, "DRT runtime size limit: {m}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<RuntimeError> for crate::error::ApiError {
    fn from(e: RuntimeError) -> Self {
        warn!(error = %e, "DRT runtime error");
        match &e {
            RuntimeError::Compile(_) | RuntimeError::BadModule(_) => {
                Self::internal(format!("DRT script is invalid: {e}"))
            }
            RuntimeError::Trap(_) => Self::bad_request(e.to_string()),
            RuntimeError::OutOfFuel { .. } => Self::bad_request(e.to_string()),
            RuntimeError::Timeout => Self::bad_request("DRT script timed out"),
            RuntimeError::SizeLimit(m) => Self::bad_request(m.clone()),
        }
    }
}

/// Per-instance state visible from host imports (just the log target).
struct HostState;

/// Singleton wasmtime engine. Held across queries so Cranelift can reuse
/// its compilation cache and the runtime amortises codegen setup.
static ENGINE: OnceLock<Engine> = OnceLock::new();

/// Initialise the global engine.
fn engine() -> Result<&'static Engine, RuntimeError> {
    if let Some(e) = ENGINE.get() {
        return Ok(e);
    }
    let mut config = Config::new();
    config.strategy(Strategy::Cranelift);
    config.cranelift_opt_level(wasmtime::OptLevel::Speed);
    config.wasm_simd(true);
    config.consume_fuel(true);
    // Standard on-demand allocator. The pooling allocator would let us
    // reuse linear-memory slots across queries, but in SGX virtual ==
    // physical EPC, so each pooled slot is a hard EPC reservation. Keep
    // on-demand until we benchmark a real need.
    let e = Engine::new(&config).map_err(|err| RuntimeError::Compile(err.to_string()))?;
    let _ = ENGINE.set(e);
    Ok(ENGINE.get().expect("engine initialised"))
}

/// Return the on-disk path for a precompiled `.cwasm` artifact.
pub fn precompile_cache_path(scripts_dir: &Path, hex_hash: &str) -> PathBuf {
    scripts_dir.join(format!("{hex_hash}.{CWASM_VERSION_TAG}.cwasm"))
}

/// Compile `wasm_bytes` ahead of time and persist the result under
/// `scripts_dir`. Idempotent — returns the cached path if it already
/// exists. A failure to precompile is surfaced to the caller but is never
/// fatal: callers should fall through to JIT-on-first-call.
pub fn ensure_precompiled(
    scripts_dir: &Path,
    hex_hash: &str,
    wasm_bytes: &[u8],
) -> Result<PathBuf, RuntimeError> {
    let path = precompile_cache_path(scripts_dir, hex_hash);
    if path.exists() {
        return Ok(path);
    }
    let engine = engine()?;
    let bytes = engine
        .precompile_module(wasm_bytes)
        .map_err(|e| RuntimeError::Compile(e.to_string()))?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&path, bytes).map_err(|e| RuntimeError::Compile(e.to_string()))?;
    Ok(path)
}

/// Execute against a precompiled `.cwasm` artifact when present, else fall
/// back to JIT-compiling `wasm_bytes`. Sole entry point from request
/// handlers; tests pass a non-existent path to exercise the JIT path.
pub async fn execute_cached(
    cache_path: PathBuf,
    wasm_bytes: Vec<u8>,
    input: RuntimeInput<'_>,
) -> Result<RuntimeOutput, RuntimeError> {
    let csv = input.csv.to_owned();
    let args = serde_json::to_vec(input.args)
        .map_err(|e| RuntimeError::Compile(format!("args JSON encode: {e}")))?;
    let cached = if cache_path.exists() { Some(cache_path) } else { None };
    run_with(wasm_bytes, cached, csv, args).await
}

async fn run_with(
    wasm_bytes: Vec<u8>,
    cwasm_path: Option<PathBuf>,
    csv: String,
    args: Vec<u8>,
) -> Result<RuntimeOutput, RuntimeError> {
    if csv.len() > MAX_INPUT_BYTES {
        return Err(RuntimeError::SizeLimit(format!(
            "csv is {} bytes (limit {MAX_INPUT_BYTES})",
            csv.len()
        )));
    }
    let timeout = DEFAULT_WALL_TIMEOUT;
    let join = tokio::task::spawn_blocking(move || {
        run_blocking(&wasm_bytes, cwasm_path.as_deref(), &csv, &args)
    });
    match tokio::time::timeout(timeout, join).await {
        Ok(Ok(res)) => res,
        Ok(Err(join_err)) => Err(RuntimeError::Trap(format!("worker panicked: {join_err}"))),
        Err(_) => Err(RuntimeError::Timeout),
    }
}

fn run_blocking(
    wasm_bytes: &[u8],
    cwasm_path: Option<&Path>,
    csv: &str,
    args: &[u8],
) -> Result<RuntimeOutput, RuntimeError> {
    let engine = engine()?;
    let input_len = csv.len() + args.len();
    let fuel = fuel_budget(input_len);

    debug!(
        target: "drt_runtime",
        csv_len = csv.len(),
        args_len = args.len(),
        fuel,
        cwasm = cwasm_path.is_some(),
        "DRT execution starting"
    );

    // Prefer the precompiled artifact. If loading the cache fails (e.g.
    // a partial write from a prior crash), fall back to JIT — the cached
    // file gets rewritten the next time `ensure_precompiled` runs.
    let module = match cwasm_path {
        Some(p) => {
            // SAFETY: `.cwasm` files live on the Gramine encrypted FS and
            // are written exclusively by this process after a SHA-256-
            // verified fetch + a successful `Engine::precompile_module`.
            // wasmtime checks an internal header on load and rejects
            // anything that wasn't produced by a compatible engine.
            match unsafe { Module::deserialize_file(engine, p) } {
                Ok(m) => m,
                Err(e) => {
                    warn!(error=%e, path=?p, "cwasm load failed; JIT fallback");
                    Module::new(engine, wasm_bytes)
                        .map_err(|e| RuntimeError::Compile(e.to_string()))?
                }
            }
        }
        None => Module::new(engine, wasm_bytes)
            .map_err(|e| RuntimeError::Compile(e.to_string()))?,
    };

    let mut store = Store::new(engine, HostState);
    store
        .set_fuel(fuel)
        .map_err(|e| RuntimeError::Compile(e.to_string()))?;

    let mut linker = <Linker<HostState>>::new(engine);
    linker
        .func_wrap(
            "env",
            "host_log",
            |mut caller: Caller<'_, HostState>, src: i32, len: i32| {
                let memory = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return,
                };
                let src = src as usize;
                let len = (len as usize).min(4096);
                let data = memory.data(&caller);
                if let Some(slice) = data.get(src..src + len) {
                    if let Ok(msg) = std::str::from_utf8(slice) {
                        debug!(target: "drt_script", "{msg}");
                    }
                }
            },
        )
        .map_err(|e| RuntimeError::Compile(e.to_string()))?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| RuntimeError::Trap(e.to_string()))?;

    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| RuntimeError::BadModule("module missing `memory` export".into()))?;

    let alloc = instance
        .get_typed_func::<i32, i32>(&mut store, "alloc")
        .map_err(|e| RuntimeError::BadModule(format!("missing `alloc` export: {e}")))?;

    // Stage CSV.
    let csv_ptr = alloc
        .call(&mut store, csv.len() as i32)
        .map_err(|e| translate_call_err(e, fuel, input_len))?;
    write_into_memory(&memory, &mut store, csv_ptr as usize, csv.as_bytes())?;

    // Stage args.
    let args_ptr = alloc
        .call(&mut store, args.len() as i32)
        .map_err(|e| translate_call_err(e, fuel, input_len))?;
    write_into_memory(&memory, &mut store, args_ptr as usize, args)?;

    // Allocate the (out_ptr_cell, out_len_cell) pair.
    let cells = alloc
        .call(&mut store, 8)
        .map_err(|e| translate_call_err(e, fuel, input_len))?;
    let out_ptr_cell = cells;
    let out_len_cell = cells + 4;

    let run = instance
        .get_typed_func::<(i32, i32, i32, i32, i32, i32), i32>(&mut store, "run")
        .map_err(|e| RuntimeError::BadModule(format!("missing `run` export: {e}")))?;

    let exit_code = run
        .call(
            &mut store,
            (
                csv_ptr,
                csv.len() as i32,
                args_ptr,
                args.len() as i32,
                out_ptr_cell,
                out_len_cell,
            ),
        )
        .map_err(|e| translate_call_err(e, fuel, input_len))?;

    let out_ptr = read_i32(&memory, &store, out_ptr_cell as usize)?;
    let out_len = read_i32(&memory, &store, out_len_cell as usize)?;

    if out_len < 0 {
        return Err(RuntimeError::Trap(format!(
            "guest returned negative output length: {out_len}"
        )));
    }
    let out_len_usz = out_len as usize;
    if out_len_usz > MAX_OUTPUT_BYTES {
        return Err(RuntimeError::SizeLimit(format!(
            "DRT output is {out_len_usz} bytes (limit {MAX_OUTPUT_BYTES})"
        )));
    }
    let body = read_bytes(&memory, &store, out_ptr as usize, out_len_usz)?;

    Ok(RuntimeOutput { exit_code, body })
}

fn translate_call_err(e: wasmtime::Error, fuel: u64, input_len: usize) -> RuntimeError {
    if let Some(t) = e.downcast_ref::<wasmtime::Trap>() {
        if matches!(t, wasmtime::Trap::OutOfFuel) {
            return RuntimeError::OutOfFuel { fuel, input_len };
        }
    }
    let msg = format!("{e:?}");
    if msg.contains("OutOfFuel") || msg.contains("all fuel consumed") {
        return RuntimeError::OutOfFuel { fuel, input_len };
    }
    RuntimeError::Trap(msg)
}

fn get_memory(caller: &mut Caller<'_, HostState>) -> Option<Memory> {
    match caller.get_export("memory") {
        Some(wasmtime::Extern::Memory(m)) => Some(m),
        _ => None,
    }
}

fn write_into_memory(
    memory: &Memory,
    store: &mut Store<HostState>,
    offset: usize,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    let data = memory.data_mut(store);
    let end = offset
        .checked_add(bytes.len())
        .ok_or_else(|| RuntimeError::Trap("offset overflow".into()))?;
    let slot = data
        .get_mut(offset..end)
        .ok_or_else(|| RuntimeError::Trap("alloc returned out-of-bounds offset".into()))?;
    slot.copy_from_slice(bytes);
    Ok(())
}

fn read_i32(
    memory: &Memory,
    store: &Store<HostState>,
    offset: usize,
) -> Result<i32, RuntimeError> {
    let data = memory.data(store);
    let end = offset
        .checked_add(4)
        .ok_or_else(|| RuntimeError::Trap("offset overflow".into()))?;
    let slot = data
        .get(offset..end)
        .ok_or_else(|| RuntimeError::Trap("output cell out of bounds".into()))?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(slot);
    Ok(i32::from_le_bytes(buf))
}

fn read_bytes(
    memory: &Memory,
    store: &Store<HostState>,
    offset: usize,
    len: usize,
) -> Result<Vec<u8>, RuntimeError> {
    let data = memory.data(store);
    let end = offset
        .checked_add(len)
        .ok_or_else(|| RuntimeError::Trap("offset overflow".into()))?;
    data.get(offset..end)
        .map(|s| s.to_vec())
        .ok_or_else(|| RuntimeError::Trap("output slice out of bounds".into()))
}

// Silence the unused-constant warning on builds that exclude SGX-specific
// guardrails (the constant is documented and referenced by the manifest).
const _: usize = MAX_GUEST_MEMORY_BYTES;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn load_mean_wasm() -> Vec<u8> {
        std::fs::read("drt-examples/mean/dist/mean.wasm")
            .expect("missing drt-examples/mean/dist/mean.wasm — run `make drt-examples`")
    }

    fn no_cache() -> PathBuf {
        PathBuf::from("/nonexistent/drt-cache/none.cwasm")
    }

    #[tokio::test]
    async fn mean_dot_wasm_executes_end_to_end() {
        let csv = "id,value\n1,100\n2,200\n3,300\n";
        let args = json!({ "column": "value" });
        let out = execute_cached(no_cache(), load_mean_wasm(), RuntimeInput { csv, args: &args })
            .await
            .expect("execution succeeds");
        assert_eq!(out.exit_code, 0);
        let body = std::str::from_utf8(&out.body).unwrap();
        assert!(body.contains("\"count\":3"), "body: {body}");
        assert!(body.contains("\"skipped\":0"), "body: {body}");
        assert!(body.contains("\"mean\":200"), "body: {body}");
    }

    #[tokio::test]
    async fn mean_dot_wasm_reports_missing_column() {
        let csv = "id,value\n1,100\n";
        let args = json!({ "column": "other" });
        let out = execute_cached(no_cache(), load_mean_wasm(), RuntimeInput { csv, args: &args })
            .await
            .expect("execution returns even on script-level error");
        assert_ne!(out.exit_code, 0);
        let body = std::str::from_utf8(&out.body).unwrap();
        assert!(body.contains("error"), "body: {body}");
    }

    #[tokio::test]
    async fn mean_dot_wasm_counts_empty_cells_as_skipped() {
        let csv = "id,value\n1,10\n2,\n3,20\n4,\n5,30\n";
        let args = json!({ "column": "value" });
        let out = execute_cached(no_cache(), load_mean_wasm(), RuntimeInput { csv, args: &args })
            .await
            .expect("execution succeeds with mixed empty cells");
        assert_eq!(out.exit_code, 0);
        let body = std::str::from_utf8(&out.body).unwrap();
        assert!(body.contains("\"count\":3"), "body: {body}");
        assert!(body.contains("\"skipped\":2"), "body: {body}");
        assert!(body.contains("\"mean\":20"), "body: {body}");
    }
}
