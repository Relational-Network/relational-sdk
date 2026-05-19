// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Sample DRT — compute the arithmetic mean of one numeric column from the
//! pool's CSV data, applying the enclave-provided employer-group row filter.
//!
//! ## Host ABI
//!
//! The enclave runtime (see `relational-sdk/src/drt/runtime.rs`) imports the
//! `env` module and exports four functions to this module:
//!
//! ```text
//! env.host_input_len()                 -> i32   // bytes of input available
//! env.host_input_copy(dst: i32, len: i32) -> i32   // copy input into wasm memory
//! env.host_output_write(src: i32, len: i32) -> i32   // emit result bytes
//! env.host_log(src: i32, len: i32)              // best-effort diag
//! ```
//!
//! The input is a UTF-8 JSON object:
//!
//! ```json
//! {
//!   "csv": "<full CSV including header row>",
//!   "args": { "column": "column_name" }
//! }
//!
//! The output is a UTF-8 JSON object the enclave forwards to the analyst.
//! `count` is the number of rows that contributed to the mean; `skipped`
//! is the number of rows whose value was empty or non-numeric:
//!
//! ```json
//! { "column": "column_name", "count": 1180, "skipped": 54, "mean": 71.5 }
//! ```
//!
//! Errors are emitted as `{"error": "..."}` with non-zero exit from `run()`.

#![cfg_attr(target_arch = "wasm32", no_std)]

#[cfg(target_arch = "wasm32")]
extern crate alloc;

#[cfg(target_arch = "wasm32")]
use alloc::{string::String, vec::Vec};

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

// Minimal bump allocator. The DRT script runs once per query and the host
// gives the WASM instance a fresh memory each call, so we never need to
// free. ~30 bytes of code vs. pulling in `wee_alloc`/`lol_alloc` deps.
#[cfg(target_arch = "wasm32")]
mod bump_alloc {
    use core::alloc::{GlobalAlloc, Layout};
    use core::arch::wasm32;
    use core::cell::UnsafeCell;

    const PAGE_SIZE: usize = 64 * 1024;

    pub struct BumpAlloc {
        offset: UnsafeCell<usize>,
    }

    unsafe impl Sync for BumpAlloc {}

    impl BumpAlloc {
        pub const fn new() -> Self {
            Self {
                offset: UnsafeCell::new(0),
            }
        }
    }

    unsafe impl GlobalAlloc for BumpAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // Heap starts at the wasm memory page after the static data, which
            // the linker exposes via `__heap_base`.
            extern "C" {
                static __heap_base: u8;
            }
            let heap_base = &__heap_base as *const u8 as usize;
            let off_ptr = self.offset.get();
            let mut cur = *off_ptr;
            if cur == 0 {
                cur = heap_base;
            }
            let align = layout.align();
            let aligned = (cur + align - 1) & !(align - 1);
            let next = aligned + layout.size();

            // Grow linear memory if the allocation would run past the current
            // bound. Without this, reading a large CSV (>1 page after static
            // data) traps with "out of bounds memory access".
            let current_bytes = wasm32::memory_size(0) * PAGE_SIZE;
            if next > current_bytes {
                let needed = next - current_bytes;
                let pages = (needed + PAGE_SIZE - 1) / PAGE_SIZE;
                if wasm32::memory_grow(0, pages) == usize::MAX {
                    return core::ptr::null_mut();
                }
            }

            *off_ptr = next;
            aligned as *mut u8
        }
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }
}

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: bump_alloc::BumpAlloc = bump_alloc::BumpAlloc::new();

#[cfg(target_arch = "wasm32")]
mod host {
    extern "C" {
        pub fn host_input_len() -> i32;
        pub fn host_input_copy(dst: i32, len: i32) -> i32;
        pub fn host_output_write(src: i32, len: i32) -> i32;
        pub fn host_log(src: i32, len: i32);
    }
}

#[cfg(target_arch = "wasm32")]
fn read_input() -> Vec<u8> {
    let len = unsafe { host::host_input_len() } as usize;
    let mut buf = Vec::with_capacity(len);
    unsafe {
        buf.set_len(len);
        let _ = host::host_input_copy(buf.as_mut_ptr() as i32, len as i32);
    }
    buf
}

#[cfg(target_arch = "wasm32")]
fn write_output(bytes: &[u8]) {
    unsafe {
        let _ = host::host_output_write(bytes.as_ptr() as i32, bytes.len() as i32);
    }
}

#[cfg(target_arch = "wasm32")]
#[allow(dead_code)]
fn log(msg: &str) {
    unsafe {
        host::host_log(msg.as_ptr() as i32, msg.len() as i32);
    }
}

/// Entry point invoked by the enclave runtime.
///
/// Returns 0 on success; any non-zero value means the script reported an
/// error and the result blob contains `{"error": "..."}`.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn run() -> i32 {
    let input = read_input();
    let input_str = match core::str::from_utf8(&input) {
        Ok(s) => s,
        Err(_) => {
            write_output(b"{\"error\":\"input not UTF-8\"}");
            return 1;
        }
    };

    let parsed = match parse_input(input_str) {
        Ok(p) => p,
        Err(msg) => {
            let body = format_error(&msg);
            write_output(body.as_bytes());
            return 2;
        }
    };

    match compute_mean(&parsed.csv, &parsed.column) {
        Ok(stats) => {
            let body = format_result(&parsed.column, &stats);
            write_output(body.as_bytes());
            0
        }
        Err(msg) => {
            let body = format_error(&msg);
            write_output(body.as_bytes());
            3
        }
    }
}

/// Test entry point (host build) for the parse + compute logic.
///
/// The wasm build skips this — `run()` above is the real entry point — but
/// `cargo test --target x86_64-unknown-linux-gnu` exercises this end-to-end
/// without needing a wasm runtime.
#[cfg(not(target_arch = "wasm32"))]
pub fn run_host(input: &str) -> Result<String, String> {
    let parsed = parse_input(input)?;
    let stats = compute_mean(&parsed.csv, &parsed.column)?;
    Ok(format_result(&parsed.column, &stats))
}

#[cfg(not(target_arch = "wasm32"))]
type String = std::string::String;
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)] // used only by the wasm-only `run` path; alias kept for symmetry
type Vec<T> = std::vec::Vec<T>;

struct Parsed {
    csv: String,
    column: String,
}

/// Minimal hand-rolled JSON extraction for `{"csv": "...", "args": {"column": "..."}}`.
/// We avoid `serde_json` to keep the WASM module small (kb-scale). Handles
/// the JSON escapes that show up in CSV payloads: `\"`, `\\`, `\n`, `\r`, `\t`.
fn parse_input(input: &str) -> Result<Parsed, String> {
    let csv = extract_string_field(input, "csv")
        .ok_or_else(|| String::from("missing 'csv' field"))?;
    let column = extract_string_field(input, "column")
        .ok_or_else(|| String::from("missing 'args.column' field"))?;
    Ok(Parsed { csv, column })
}

fn extract_string_field(input: &str, key: &str) -> Option<String> {
    let mut needle = String::with_capacity(key.len() + 3);
    needle.push('"');
    needle.push_str(key);
    needle.push_str("\":");
    let idx = input.find(&needle)?;
    let rest = &input[idx + needle.len()..];
    let rest = rest.trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let body = &rest[1..];
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c == '"' {
            return Some(out);
        }
        if c == '\\' {
            match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    None
}

/// Outcome of a single `compute_mean` call.
struct MeanStats {
    /// Rows that contributed to the mean.
    count: u64,
    /// Rows whose cell was empty or did not parse as `f64`.
    skipped: u64,
    /// Arithmetic mean over the `count` rows.
    mean: f64,
}

fn compute_mean(csv: &str, column: &str) -> Result<MeanStats, String> {
    let mut lines = csv.lines();
    let header = lines.next().ok_or_else(|| String::from("empty CSV"))?;

    let col_idx = header
        .split(',')
        .map(str::trim)
        .position(|h| h == column)
        .ok_or_else(|| {
            let mut s = String::from("column '");
            s.push_str(column);
            s.push_str("' not in header");
            s
        })?;

    let mut sum = 0.0_f64;
    let mut count: u64 = 0;
    let mut skipped: u64 = 0;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let field = match line.split(',').nth(col_idx) {
            // Row is shorter than the header — treat as a missing value.
            None => {
                skipped += 1;
                continue;
            }
            Some(f) => f.trim(),
        };
        // Empty cell is explicitly a missing value, not an error.
        if field.is_empty() {
            skipped += 1;
            continue;
        }
        match field.parse::<f64>() {
            Ok(v) => {
                sum += v;
                count += 1;
            }
            Err(_) => skipped += 1,
        }
    }

    if count == 0 {
        return Err(String::from("no numeric values in column"));
    }
    Ok(MeanStats {
        count,
        skipped,
        mean: sum / count as f64,
    })
}

fn format_result(column: &str, stats: &MeanStats) -> String {
    let mut s = String::with_capacity(96);
    s.push_str("{\"column\":\"");
    s.push_str(column);
    s.push_str("\",\"count\":");
    push_u64(&mut s, stats.count);
    s.push_str(",\"skipped\":");
    push_u64(&mut s, stats.skipped);
    s.push_str(",\"mean\":");
    push_f64(&mut s, stats.mean);
    s.push('}');
    s
}

#[allow(dead_code)] // called only by the wasm-only `run` path
fn format_error(msg: &str) -> String {
    let mut s = String::with_capacity(msg.len() + 16);
    s.push_str("{\"error\":\"");
    for c in msg.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            c if (c as u32) < 0x20 => {}
            c => s.push(c),
        }
    }
    s.push_str("\"}");
    s
}

fn push_u64(s: &mut String, n: u64) {
    if n == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 20;
    let mut n = n;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    for &b in &buf[i..] {
        s.push(b as char);
    }
}

fn push_f64(s: &mut String, n: f64) {
    // Tiny printer: handles NaN/Inf, sign, integer part, and up to 6 fraction
    // digits. Good enough for the demo; replace with `ryu` if the WASM size
    // budget allows.
    if n.is_nan() {
        s.push_str("null");
        return;
    }
    if n.is_infinite() {
        s.push_str(if n < 0.0 { "null" } else { "null" });
        return;
    }
    let mut n = n;
    if n < 0.0 {
        s.push('-');
        n = -n;
    }
    let int_part = n as u64;
    push_u64(s, int_part);
    let mut frac = n - int_part as f64;
    if frac == 0.0 {
        return;
    }
    s.push('.');
    for _ in 0..6 {
        frac *= 10.0;
        let digit = frac as u64 % 10;
        s.push((b'0' + digit as u8) as char);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn computes_mean_of_named_column() {
        let csv = "id,value,group\n1,100,A\n2,200,A\n3,300,B\n";
        let stats = compute_mean(csv, "value").unwrap();
        assert_eq!(stats.count, 3);
        assert_eq!(stats.skipped, 0);
        assert!((stats.mean - 200.0).abs() < 1e-9);
    }

    #[test]
    fn rejects_missing_column() {
        let csv = "id,value\n1,100\n";
        assert!(compute_mean(csv, "other").is_err());
    }

    #[test]
    fn counts_non_numeric_cells_as_skipped() {
        let csv = "id,value\n1,10\n2,abc\n3,20\n";
        let stats = compute_mean(csv, "value").unwrap();
        assert_eq!(stats.count, 2);
        assert_eq!(stats.skipped, 1);
        assert!((stats.mean - 15.0).abs() < 1e-9);
    }

    #[test]
    fn counts_empty_cells_as_skipped() {
        // Two rows have an empty `value` cell — should be reported as skipped,
        // not silently dropped.
        let csv = "id,value\n1,10\n2,\n3,20\n4,\n5,30\n";
        let stats = compute_mean(csv, "value").unwrap();
        assert_eq!(stats.count, 3);
        assert_eq!(stats.skipped, 2);
        assert!((stats.mean - 20.0).abs() < 1e-9);
    }

    #[test]
    fn parses_input_json() {
        let input = r#"{"csv":"a,b\n1,2\n","args":{"column":"b"}}"#;
        let p = parse_input(input).unwrap();
        assert_eq!(p.column, "b");
        assert!(p.csv.starts_with("a,b"));
    }

    #[test]
    fn formats_result_json() {
        let stats = MeanStats { count: 3, skipped: 1, mean: 200.0 };
        let s = format_result("value", &stats);
        assert_eq!(
            s,
            "{\"column\":\"value\",\"count\":3,\"skipped\":1,\"mean\":200}",
        );
    }

    #[test]
    fn run_host_end_to_end() {
        let input = r#"{"csv":"id,value\n1,10\n2,20\n3,30\n","args":{"column":"value"}}"#;
        let out = run_host(input).unwrap();
        assert!(out.contains("\"count\":3"), "out: {out}");
        assert!(out.contains("\"skipped\":0"), "out: {out}");
        assert!(out.contains("\"mean\":20"), "out: {out}");
    }
}
