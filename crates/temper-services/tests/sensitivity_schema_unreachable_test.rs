//! No application code names the `sensitivity` schema (sensitivity-sweep spec witness 12, Q17).
//!
//! The findings store is a cross-tenant enumeration oracle (spec F5). On this deployment one role
//! migrates and serves, so it owns the schema and no grant can keep it out (Q17). This gate is
//! therefore the whole control, not a backstop. Reaching the store is a SQL function's job.
//!
//! The scanned set is every `src/` tree of every crate and every package, derived by walking, never
//! listed (the `reblock_op_is_reachable_only_through_the_gated_write_paths` precedent): any of them
//! can hold the role's credentials, through a linked crate or its own client. Test trees are outside
//! it, because these witnesses read the store directly.

use std::path::{Path, PathBuf};

const EXTENSIONS: &[&str] = &["rs", "ts", "js", "svelte", "sql"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

/// `<root>/crates/*/src` and `<root>/packages/*/src`, for every member that has one.
fn source_trees(root: &Path) -> Vec<PathBuf> {
    let mut trees = Vec::new();
    for parent in ["crates", "packages"] {
        let dir = root.join(parent);
        for member in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let src = member.expect("dir entry").path().join("src");
            if src.is_dir() {
                trees.push(src);
            }
        }
    }
    trees
}

fn source_files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n != "node_modules") {
                    stack.push(path);
                }
            } else if path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| EXTENSIONS.contains(&e))
            {
                out.push(path);
            }
        }
    }
    out
}

/// Every way a query can reach the schema by name: qualified (`sensitivity.`, `"sensitivity".`, in
/// any case), or unqualified after pointing `search_path` at it.
fn names_the_schema(source: &str) -> bool {
    let lower = source.to_ascii_lowercase();
    lower.contains("sensitivity.")
        || lower.contains("\"sensitivity\".")
        || lower
            .lines()
            .any(|l| l.contains("search_path") && l.contains("sensitivity"))
}

#[test]
fn no_application_code_names_the_sensitivity_schema() {
    let root = workspace_root();
    let trees = source_trees(&root);
    for required in [
        "crates/temper-api/src",
        "crates/temper-substrate/src",
        "packages/temper-ui/src",
    ] {
        assert!(
            trees.contains(&root.join(required)),
            "the walk must reach {required}"
        );
    }
    let mut scanned = 0;
    let mut offenders = Vec::new();
    for tree in &trees {
        for file in source_files_under(tree) {
            scanned += 1;
            let source = std::fs::read_to_string(&file).expect("read source");
            if names_the_schema(&source) {
                offenders.push(file.display().to_string());
            }
        }
    }
    // An empty walk would pass vacuously.
    assert!(scanned > 200, "walked only {scanned} files");
    assert!(
        offenders.is_empty(),
        "these files name the sensitivity schema; reach it through a SQL function instead: {offenders:#?}"
    );
}

/// The detector bites on each spelling it claims to catch, and not on the bare word, which names
/// the persona and the dispatch type legitimately.
#[test]
fn the_detector_catches_every_spelling() {
    for hit in [
        "SELECT * FROM sensitivity.findings",
        "select 1 from SENSITIVITY.findings",
        r#"FROM "sensitivity"."findings""#,
        "SET search_path = sensitivity, public",
        "sql`set search_path to 'sensitivity'`",
    ] {
        assert!(names_the_schema(hit), "{hit}");
    }
    for miss in [
        "Persona::Sensitivity",
        "persona = 'sensitivity'",
        "sensitivity-sweep",
        "SET search_path = public",
    ] {
        assert!(!names_the_schema(miss), "{miss}");
    }
}
