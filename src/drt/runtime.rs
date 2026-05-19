// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Sandboxed execution of verified DRT scripts via `wasmi`.
//!
//! ## Sandbox guarantees
//!
//! - Pure-Rust interpreter; no JIT / no `mmap(PROT_EXEC)` (works inside
//!   Gramine without extra syscall whitelisting).
//! - Module memory is capped via `wasmi::Memory` limits.
//! - Wall-clock execution time is capped via fuel (instructions metered).
//! - The DRT cannot perform any I/O: only the host-provided ABI is linked.
//!   No WASI, no filesystem, no network, no clock.
//!
//! ## Host ABI (imported as the `env` module)
//!
//! ```text
//! host_input_len() -> i32
//!     Returns the length in bytes of the input blob the host has staged.
//!
//! host_input_copy(dst: i32, len: i32) -> i32
//!     Copies up to `len` bytes of input into wasm memory at `dst`.
//!     Returns the number of bytes actually copied.
//!
//! host_output_write(src: i32, len: i32) -> i32
//!     Appends `len` bytes from wasm memory at `src` to the host output
//!     buffer. Returns the number of bytes written, or -1 if the output
//!     buffer would exceed [`MAX_OUTPUT_BYTES`].
//!
//! host_log(src: i32, len: i32)
//!     Best-effort diagnostic logging — the host emits a `debug!`.
//! ```
//!
//! The DRT must export `run() -> i32`. A return of 0 means success; non-zero
//! signals an error and the output body is expected to be `{"error":"..."}`.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use wasmi::{Caller, Config, Engine, Extern, Linker, Memory, Module, Store};

/// Maximum bytes a DRT script may emit via `host_output_write`.
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

/// Maximum bytes of the input blob the host passes to the script.
///
/// CSV-bound. The blob is `{"csv": "...", "args": {...}}` so this also has to
/// cover JSON wrapping + escape overhead. With a bump allocator inside the
/// WASM module that never frees, a 500 MiB CSV ends up costing roughly 2× this
/// in WASM linear memory (raw bytes + parsed string copy); wasm32's hard cap
/// is 4 GiB, so don't push this past ~1.5 GiB.
pub const MAX_INPUT_BYTES: usize = 600 * 1024 * 1024; // 600 MiB

/// Base fuel budget covering parser init, output assembly, and fixed
/// per-invocation overhead independent of input size.
pub const BASE_FUEL: u64 = 2_000_000_000;

/// Additional fuel granted per byte of input. Wasmi charges ~1 unit per
/// executed instruction; a typical CSV parser burns ~50–200 instructions
/// per input byte (field scanning, copies, numeric parsing). 1_000/byte
/// leaves a generous safety margin for more complex aggregation scripts
/// while still bounding pathological loops (a 600 MiB input caps the
/// budget at ~602B fuel — well within `u64`).
pub const FUEL_PER_INPUT_BYTE: u64 = 1_000;

/// Compute a fuel budget that scales with the input size. The 120s
/// wall-clock cap (see [`DEFAULT_WALL_TIMEOUT`]) remains the real ceiling;
/// fuel is defence in depth against tight loops in user-supplied WASM.
fn fuel_budget(input_len: usize) -> u64 {
    BASE_FUEL.saturating_add(FUEL_PER_INPUT_BYTE.saturating_mul(input_len as u64))
}

/// Hard wall-clock cap, defence in depth on top of fuel.
pub const DEFAULT_WALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Input blob the host stages for the DRT.
#[derive(Debug, Serialize)]
pub struct RuntimeInput<'a> {
    /// Pool CSV the script may read.
    pub csv: &'a str,
    /// Caller-supplied arguments (e.g. `{ "column": "salary" }`).
    pub args: &'a serde_json::Value,
}

/// Output the DRT emitted via `host_output_write`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeOutput {
    /// Value returned by the `run()` export. 0 = success.
    pub exit_code: i32,
    /// Bytes the script wrote — interpret as UTF-8 JSON.
    pub body: Vec<u8>,
}

/// Errors surfaced from the runtime.
#[derive(Debug)]
pub enum RuntimeError {
    /// Failed to parse / link / instantiate the WASM module.
    Compile(String),
    /// Module is missing a required export (`run` or `memory`).
    BadModule(String),
    /// Trap during execution — out of fuel, out of bounds, etc.
    Trap(String),
    /// Wasmi reported that all fuel was consumed. Distinguished from
    /// generic [`Trap`] so callers (and logs) get a clearer signal.
    OutOfFuel { fuel: u64, input_len: usize },
    /// Wall-clock budget exceeded.
    Timeout,
    /// Input or output too large.
    SizeLimit(String),
    /// Failed to JSON-encode the input blob.
    InputEncoding(String),
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
            Self::InputEncoding(m) => write!(f, "DRT runtime input encoding: {m}"),
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
            RuntimeError::InputEncoding(_) => Self::internal(e.to_string()),
        }
    }
}

/// Host state held in the wasmi `Store`. Mutated by the host functions.
struct HostState {
    input: Vec<u8>,
    input_offset: usize,
    output: Vec<u8>,
    output_overflow: bool,
}

/// Execute `wasm_bytes` with the given input.
///
/// Blocks on a `tokio::task::spawn_blocking` — wasmi is CPU-bound and
/// synchronous. Caller should `.await` this future from an async handler.
pub async fn execute(
    wasm_bytes: Vec<u8>,
    input: RuntimeInput<'_>,
) -> Result<RuntimeOutput, RuntimeError> {
    let input_bytes = serde_json::to_vec(&serde_json::json!({
        "csv": input.csv,
        "args": input.args,
    }))
    .map_err(|e| RuntimeError::InputEncoding(e.to_string()))?;

    if input_bytes.len() > MAX_INPUT_BYTES {
        return Err(RuntimeError::SizeLimit(format!(
            "input is {} bytes (limit {MAX_INPUT_BYTES})",
            input_bytes.len()
        )));
    }

    let timeout = DEFAULT_WALL_TIMEOUT;
    let join = tokio::task::spawn_blocking(move || run_blocking(&wasm_bytes, input_bytes));

    match tokio::time::timeout(timeout, join).await {
        Ok(Ok(res)) => res,
        Ok(Err(join_err)) => Err(RuntimeError::Trap(format!("worker panicked: {join_err}"))),
        Err(_) => Err(RuntimeError::Timeout),
    }
}

fn run_blocking(wasm_bytes: &[u8], input: Vec<u8>) -> Result<RuntimeOutput, RuntimeError> {
    let input_len = input.len();
    let fuel = fuel_budget(input_len);

    debug!(
        target: "drt_runtime",
        input_len, fuel,
        "DRT execution starting"
    );

    let mut config = Config::default();
    config.consume_fuel(true);
    let engine = Engine::new(&config);

    let module = Module::new(&engine, wasm_bytes).map_err(|e| RuntimeError::Compile(e.to_string()))?;

    let host_state = HostState {
        input,
        input_offset: 0,
        output: Vec::new(),
        output_overflow: false,
    };
    let mut store = Store::new(&engine, host_state);
    store
        .set_fuel(fuel)
        .map_err(|e| RuntimeError::Compile(e.to_string()))?;

    let mut linker = <Linker<HostState>>::new(&engine);

    linker
        .func_wrap("env", "host_input_len", |caller: Caller<'_, HostState>| -> i32 {
            caller.data().input.len() as i32
        })
        .map_err(|e| RuntimeError::Compile(e.to_string()))?;

    linker
        .func_wrap(
            "env",
            "host_input_copy",
            |mut caller: Caller<'_, HostState>, dst: i32, len: i32| -> i32 {
                let memory = match get_memory(&caller) {
                    Some(m) => m,
                    None => return -1,
                };
                let dst = dst as usize;
                let len = len as usize;
                let state = caller.data();
                let remaining = state.input.len().saturating_sub(state.input_offset);
                let to_copy = remaining.min(len);
                if to_copy == 0 {
                    return 0;
                }
                let snapshot = {
                    let s = caller.data();
                    s.input[s.input_offset..s.input_offset + to_copy].to_vec()
                };
                if memory.write(&mut caller, dst, &snapshot).is_err() {
                    return -1;
                }
                caller.data_mut().input_offset += to_copy;
                to_copy as i32
            },
        )
        .map_err(|e| RuntimeError::Compile(e.to_string()))?;

    linker
        .func_wrap(
            "env",
            "host_output_write",
            |mut caller: Caller<'_, HostState>, src: i32, len: i32| -> i32 {
                let memory = match get_memory(&caller) {
                    Some(m) => m,
                    None => return -1,
                };
                let src = src as usize;
                let len = len as usize;
                if caller.data().output.len() + len > MAX_OUTPUT_BYTES {
                    caller.data_mut().output_overflow = true;
                    return -1;
                }
                let mut buf = vec![0u8; len];
                if memory.read(&caller, src, &mut buf).is_err() {
                    return -1;
                }
                caller.data_mut().output.extend_from_slice(&buf);
                len as i32
            },
        )
        .map_err(|e| RuntimeError::Compile(e.to_string()))?;

    linker
        .func_wrap(
            "env",
            "host_log",
            |caller: Caller<'_, HostState>, src: i32, len: i32| {
                let memory = match get_memory(&caller) {
                    Some(m) => m,
                    None => return,
                };
                let src = src as usize;
                let len = (len as usize).min(4096);
                let mut buf = vec![0u8; len];
                if memory.read(&caller, src, &mut buf).is_ok() {
                    if let Ok(msg) = std::str::from_utf8(&buf) {
                        debug!(target: "drt_script", "{msg}");
                    }
                }
            },
        )
        .map_err(|e| RuntimeError::Compile(e.to_string()))?;

    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|e| RuntimeError::Trap(e.to_string()))?;

    let run = instance
        .get_typed_func::<(), i32>(&store, "run")
        .map_err(|e| RuntimeError::BadModule(format!("missing `run` export: {e}")))?;

    let exit_code = run
        .call(&mut store, ())
        .map_err(|e| {
            let msg = e.to_string();
            // wasmi surfaces "all fuel consumed by WebAssembly" on exhaustion.
            if msg.contains("fuel") {
                RuntimeError::OutOfFuel { fuel, input_len }
            } else {
                RuntimeError::Trap(msg)
            }
        })?;

    let state = store.into_data();
    if state.output_overflow {
        return Err(RuntimeError::SizeLimit(format!(
            "DRT output exceeded {MAX_OUTPUT_BYTES} bytes"
        )));
    }

    Ok(RuntimeOutput {
        exit_code,
        body: state.output,
    })
}

fn get_memory(caller: &Caller<'_, HostState>) -> Option<Memory> {
    match caller.get_export("memory") {
        Some(Extern::Memory(m)) => Some(m),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn load_mean_wasm() -> Vec<u8> {
        std::fs::read("drt-examples/mean/dist/mean.wasm")
            .expect("missing drt-examples/mean/dist/mean.wasm — run `make drt-examples`")
    }

    #[tokio::test]
    async fn mean_dot_wasm_executes_end_to_end() {
        let csv = "id,value\n1,100\n2,200\n3,300\n";
        let args = json!({ "column": "value" });
        let out = execute(
            load_mean_wasm(),
            RuntimeInput { csv, args: &args },
        )
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
        let out = execute(
            load_mean_wasm(),
            RuntimeInput { csv, args: &args },
        )
        .await
        .expect("execution returns even on script-level error");
        assert_ne!(out.exit_code, 0);
        let body = std::str::from_utf8(&out.body).unwrap();
        assert!(body.contains("error"), "body: {body}");
    }

    #[tokio::test]
    async fn mean_dot_wasm_counts_empty_cells_as_skipped() {
        // Two rows have an empty `value` cell — surfaced as `skipped` in the
        // result rather than silently dropped.
        let csv = "id,value\n1,10\n2,\n3,20\n4,\n5,30\n";
        let args = json!({ "column": "value" });
        let out = execute(
            load_mean_wasm(),
            RuntimeInput { csv, args: &args },
        )
        .await
        .expect("execution succeeds with mixed empty cells");
        assert_eq!(out.exit_code, 0);
        let body = std::str::from_utf8(&out.body).unwrap();
        assert!(body.contains("\"count\":3"), "body: {body}");
        assert!(body.contains("\"skipped\":2"), "body: {body}");
        assert!(body.contains("\"mean\":20"), "body: {body}");
    }
}
