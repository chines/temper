//! No application code names the `sensitivity` schema (sensitivity-sweep spec witness 12, Q17).
//!
//! The findings store is a cross-tenant enumeration oracle (spec F5). On this deployment one role
//! migrates and serves, so it owns the schema and no grant can keep it out (Q17). This gate is
//! therefore the whole control, not a backstop: the read paths of `temper-api`, `temper-mcp` and
//! `temper-services/src` never name the schema. Reaching the store is a SQL function's job.
//!
//! The scanned set is derived by walking the trees, never listed (the
//! `reblock_op_is_reachable_only_through_the_gated_write_paths` precedent in `temper-substrate`).
//! Test trees of `temper-services` are outside it, because these witnesses read the store directly.

use std::path::{Path, PathBuf};

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf()
}

fn rust_files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out
}

/// `sensitivity.` or `"sensitivity".`, in any case: every way a query can qualify a name with the
/// schema.
fn names_the_schema(source: &str) -> bool {
    let lower = source.to_ascii_lowercase();
    lower.contains("sensitivity.") || lower.contains("\"sensitivity\".")
}

#[test]
fn no_application_code_names_the_sensitivity_schema() {
    let crates = crates_dir();
    let roots = [
        crates.join("temper-api"),
        crates.join("temper-mcp"),
        crates.join("temper-services/src"),
    ];
    let mut scanned = 0;
    let mut offenders = Vec::new();
    for root in &roots {
        assert!(root.is_dir(), "{} must exist", root.display());
        for file in rust_files_under(root) {
            scanned += 1;
            let source = std::fs::read_to_string(&file).expect("read source");
            if names_the_schema(&source) {
                offenders.push(file.display().to_string());
            }
        }
    }
    // An empty walk would pass vacuously.
    assert!(scanned > 50, "walked only {scanned} files");
    assert!(
        offenders.is_empty(),
        "these files name the sensitivity schema; reach it through a SQL function instead: {offenders:#?}"
    );
}

/// The detector itself bites on each spelling it claims to catch, and not on the bare word, which
/// names the persona and the dispatch type legitimately.
#[test]
fn the_detector_catches_every_qualified_spelling() {
    for hit in [
        "SELECT * FROM sensitivity.findings",
        "select 1 from SENSITIVITY.findings",
        r#"FROM "sensitivity"."findings""#,
    ] {
        assert!(names_the_schema(hit), "{hit}");
    }
    for miss in [
        "Persona::Sensitivity",
        "persona = 'sensitivity'",
        "sensitivity-sweep",
    ] {
        assert!(!names_the_schema(miss), "{miss}");
    }
}
