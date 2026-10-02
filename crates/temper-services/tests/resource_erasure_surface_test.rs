#![cfg(feature = "test-db")]
//! Every scanned column a resource reaches is handled by the erasure act or declared out of scope;
//! this test is the join that says so.
//!
//! Under goal *"A single resource can be erased out of a live estate"* (spec D9, the table half;
//! Witness 13). Three sources meet here, and only one of them is written for this test:
//!
//! - **Which text is prose** comes from `scripts/sensitivity-scan-surface.txt`, read for its `scan`
//!   lines. The sweep's manifest is the one definition; nothing here re-classifies a column.
//! - **Which tables a resource reaches** comes from the live catalog: the five roots, plus every
//!   base table whose `*_table` CHECK names `kb_resources`, plus every table holding a foreign key
//!   into a reached table, recursively. Nothing enumerates tables by hand (ruled 2026-10-02), so a
//!   new table is reached by construction rather than by someone remembering it.
//! - **What the act does about each column** is declared in `scripts/resource-erasure-surface.txt`,
//!   and every `handled` claim is checked against the live body of
//!   `_resource_erasure_apply_redaction`, the D2 function.
//!
//! **Why the binding to the function body exists.** Without it, the manifest could say a column is
//! handled while the act had stopped touching it, and every test here would stay green. Reverting
//! the joint-read fixes (`kb_chunks.header_path`, `kb_citation_audits.reason`) is the miss this
//! fence exists for, and `reverting_the_joint_read_fixes_fails_the_fence` proves it turns red.
//!
//! **What this does not claim.** The binding is a token check that the function assigns the column
//! in an UPDATE of its table (or deletes from that table). It proves the statement is there, not that
//! its WHERE clause reaches every row of the resource; the erasure act's own witnesses own that. And
//! the walk is blind to references spelled other than a foreign key or a CHECKed `*_table`
//! discriminator, which the manifest header states.

use std::collections::{BTreeMap, BTreeSet};

use sqlx::PgPool;

/// The declaration half. Read from the shipped file so the manifest and this test cannot drift.
const MANIFEST: &str = include_str!("../../../scripts/resource-erasure-surface.txt");

/// The one definition of which text is prose. Read for its `scan` lines only; its own test owns
/// its format and its partition with the personal-data manifest.
const SCAN_MANIFEST: &str = include_str!("../../../scripts/sensitivity-scan-surface.txt");

/// The D2 function: the one home of the content shape (spec D2).
const REDACTION_FN: &str = "_resource_erasure_apply_redaction";

/// The numbered D2 steps a `handled:D2.<step>` line may cite (spec D2, steps 1–9 and 7a).
const D2_STEPS: &[&str] = &["1", "2", "3", "4", "5", "6", "7", "7a", "8", "9"];

/// The tables a resource reaches, derived from the catalog.
///
/// Roots are the five tables the spec names plus the polymorphic owners, found by a CHECK on a
/// `*_table` column that names `kb_resources`: the same structural test the personal-data fence's
/// `poly` derivation uses for `kb_profiles`. The walk follows foreign keys INTO a reached table:
/// a child row exists because of its parent, so the child is the parent's to account for.
const REACHABLE_TABLES: &str = r#"
WITH RECURSIVE
roots(tbl) AS (
  SELECT unnest(ARRAY['kb_resources','kb_content_blocks','kb_chunks','kb_block_revisions','kb_edges'])
  UNION
  SELECT DISTINCT c.conrelid::regclass::text
    FROM pg_constraint c
    JOIN unnest(c.conkey) k(attnum) ON true
    JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
   WHERE c.contype = 'c' AND c.connamespace = 'public'::regnamespace
     AND a.attname LIKE '%\_table'
     AND pg_get_constraintdef(c.oid) LIKE '%''kb_resources''%'),
fk AS (
  SELECT DISTINCT conrelid::regclass::text child, confrelid::regclass::text parent
    FROM pg_constraint
   WHERE contype = 'f' AND connamespace = 'public'::regnamespace),
reach(tbl) AS (
  SELECT tbl FROM roots
  UNION
  SELECT fk.child FROM fk JOIN reach ON fk.parent = reach.tbl)
SELECT tbl FROM reach ORDER BY 1
"#;

/// Base-table `*_table` columns that carry no CHECK naming them. Such a discriminator could point
/// at `kb_resources` without the roots ever seeing it.
const UNCHECKED_DISCRIMINATORS: &str = r#"
SELECT c.table_name || '.' || c.column_name
  FROM information_schema.columns c
  JOIN information_schema.tables t
    ON t.table_name = c.table_name AND t.table_schema = 'public' AND t.table_type = 'BASE TABLE'
 WHERE c.table_schema = 'public' AND c.column_name LIKE '%\_table'
   AND NOT EXISTS (
     SELECT 1
       FROM pg_constraint k
       JOIN unnest(k.conkey) u(attnum) ON true
       JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = u.attnum
      WHERE k.contype = 'c' AND k.conrelid = (quote_ident(c.table_name::text))::regclass
        AND a.attname = c.column_name)
 ORDER BY 1
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Disposition {
    /// Emptied or sentineled by this D2 step.
    Handled(String),
    /// Deliberately left; the note carries the reason.
    OutOfScope,
}

/// `table.column` → (disposition, note), from the manifest's `[tables]` section. Panics with the
/// offending line: a malformed line would otherwise drop a declaration and read as uncovered.
fn declarations() -> BTreeMap<String, (Disposition, String)> {
    let mut out = BTreeMap::new();
    let mut section: Option<&str> = None;
    for (lineno, raw) in MANIFEST.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            assert!(
                name == "tables",
                "resource-erasure-surface.txt:{}: unknown section [{name}] (cut 1 knows only \
                 [tables]; the [payload] section lands with cut 2 and extends this parser)",
                lineno + 1
            );
            section = Some(name);
            continue;
        }
        assert!(
            section == Some("tables"),
            "resource-erasure-surface.txt:{}: a declaration outside any section: {raw:?}",
            lineno + 1
        );
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        assert!(
            cols.len() == 3,
            "resource-erasure-surface.txt:{}: expected `table.column | disposition | note`, got {raw:?}",
            lineno + 1
        );
        let (key, disposition, note) = (cols[0].to_string(), cols[1], cols[2]);
        assert!(
            key.split_once('.')
                .is_some_and(|(t, c)| !t.is_empty() && !c.is_empty()),
            "resource-erasure-surface.txt:{}: {key:?} is not `table.column`",
            lineno + 1
        );
        let disposition = match disposition.strip_prefix("handled:D2.") {
            Some(step) => {
                assert!(
                    D2_STEPS.contains(&step),
                    "resource-erasure-surface.txt:{}: no D2 step {step:?} (known: {D2_STEPS:?})",
                    lineno + 1
                );
                Disposition::Handled(step.to_string())
            }
            None if disposition == "out-of-scope" => Disposition::OutOfScope,
            None => panic!(
                "resource-erasure-surface.txt:{}: unknown disposition {disposition:?} \
                 (known: `handled:D2.<step>`, `out-of-scope`)",
                lineno + 1
            ),
        };
        assert!(
            out.insert(key.clone(), (disposition, note.to_string()))
                .is_none(),
            "resource-erasure-surface.txt:{}: {key} declared twice",
            lineno + 1
        );
    }
    out
}

/// Every column the sweep's manifest classes `scan`.
fn scan_columns() -> BTreeSet<String> {
    SCAN_MANIFEST
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let cols: Vec<&str> = l.split('|').map(str::trim).collect();
            (cols.get(1) == Some(&"scan")).then(|| cols[0].to_string())
        })
        .collect()
}

fn table_of(key: &str) -> &str {
    key.split_once('.').map_or(key, |(t, _)| t)
}

async fn reachable_tables(pool: &PgPool) -> BTreeSet<String> {
    sqlx::query_scalar::<_, String>(REACHABLE_TABLES)
        .fetch_all(pool)
        .await
        .expect("derive the tables a resource reaches")
        .into_iter()
        .collect()
}

async fn redaction_body(pool: &PgPool) -> String {
    sqlx::query_scalar::<_, String>(&format!(
        "SELECT pg_get_functiondef('{REDACTION_FN}'::regproc)"
    ))
    .fetch_one(pool)
    .await
    .expect("read the D2 function's live definition")
}

/// Lowercased tokens of `sql` with `--` comments removed. Punctuation that separates an assignment
/// (`,` `=` `(` `)` `;`) becomes its own token, so `SET a = 1, b = 2;` reads as
/// `set a = 1 , b = 2 ;`.
fn tokens(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in sql.lines() {
        let code = line.find("--").map_or(line, |i| &line[..i]);
        let mut cur = String::new();
        for ch in code.chars() {
            if ch.is_whitespace() || ",=();".contains(ch) {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur).to_lowercase());
                }
                if !ch.is_whitespace() {
                    out.push(ch.to_string());
                }
            } else {
                cur.push(ch);
            }
        }
        if !cur.is_empty() {
            out.push(cur.to_lowercase());
        }
    }
    out
}

/// Whether `body` writes `table.column`: an `UPDATE <table>` whose SET list assigns `<column>`, or
/// a `DELETE FROM <table>`. An assignment target is a token right after `set` or `,` and right
/// before `=`, within the statement (up to its `;`).
fn writes_column(body: &str, key: &str) -> bool {
    let Some((table, column)) = key.split_once('.') else {
        return false;
    };
    let t = tokens(body);
    for i in 0..t.len() {
        if t[i] == "delete"
            && t.get(i + 1).is_some_and(|x| x == "from")
            && t.get(i + 2).is_some_and(|x| x == table)
        {
            return true;
        }
        if t[i] != "update" || t.get(i + 1).is_none_or(|x| x != table) {
            continue;
        }
        let mut seen_set = false;
        for j in i + 2..t.len() {
            match t[j].as_str() {
                ";" => break,
                "set" => seen_set = true,
                tok if seen_set
                    && tok == column
                    && matches!(t[j - 1].as_str(), "set" | ",")
                    && t.get(j + 1).is_some_and(|x| x == "=") =>
                {
                    return true;
                }
                _ => {}
            }
        }
    }
    false
}

/// `scan` columns in reachable tables with no line in the manifest. `scan` is a parameter, not
/// read inside, so the Witness 13 probe can stand in for the sweep PR that would class its column.
fn uncovered(reach: &BTreeSet<String>, scan: &BTreeSet<String>) -> Vec<String> {
    let declared = declarations();
    scan.iter()
        .filter(|k| reach.contains(table_of(k)) && !declared.contains_key(*k))
        .cloned()
        .collect()
}

/// `handled` lines whose column the D2 function does not write.
fn unbound(body: &str) -> Vec<String> {
    declarations()
        .into_iter()
        .filter(|(k, (d, _))| matches!(d, Disposition::Handled(_)) && !writes_column(body, k))
        .map(|(k, _)| k)
        .collect()
}

async fn unchecked_discriminators(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, String>(UNCHECKED_DISCRIMINATORS)
        .fetch_all(pool)
        .await
        .expect("probe base-table *_table columns for a CHECK")
}

/// FAILS IF: a column the sweep classes `scan` sits in a table a resource reaches, and the manifest
/// says nothing about what the erasure act does with it. This is the direction that matters: prose
/// that survives an erasure while the act reports success.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn every_reachable_scan_column_is_handled_or_declared(pool: PgPool) {
    let missing = uncovered(&reachable_tables(&pool).await, &scan_columns());
    assert!(
        missing.is_empty(),
        "these columns are classed `scan` in scripts/sensitivity-scan-surface.txt, sit in a table a \
         resource reaches, and have no line in scripts/resource-erasure-surface.txt.\n\
         Either make `_resource_erasure_apply_redaction` empty or sentinel the column and declare it \
         `handled:D2.<step>`, or declare it `out-of-scope` with the reason the act leaves it.\n\
         Uncovered: {missing:#?}"
    );
}

/// FAILS IF: a `handled` line claims a column the D2 function no longer writes. A manifest that
/// says "handled" while the act moved on is the failure this fence exists to catch.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn every_handled_declaration_is_written_by_the_redaction(pool: PgPool) {
    let broken = unbound(&redaction_body(&pool).await);
    assert!(
        broken.is_empty(),
        "scripts/resource-erasure-surface.txt declares these columns handled, but the live \
         `{REDACTION_FN}` neither assigns them in an UPDATE of their table nor deletes from it.\n\
         Restore the step, or change the line to say what the act now does.\n\
         Unbound: {broken:#?}"
    );
}

/// FAILS IF: a line names a column the sweep does not class `scan` (the manifest's subject is the
/// sweep's prose, nothing else), or an `out-of-scope` line names a table no resource reaches (there
/// is nothing to be out of scope OF). A `handled` line outside the walk is allowed: the binding test
/// checks it against the function body instead (today, `kb_remote_sources.uri`).
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn every_declaration_is_live(pool: PgPool) {
    let scan = scan_columns();
    let reach = reachable_tables(&pool).await;
    let stale: Vec<String> = declarations()
        .into_iter()
        .filter(|(k, (d, _))| {
            !scan.contains(k) || (*d == Disposition::OutOfScope && !reach.contains(table_of(k)))
        })
        .map(|(k, _)| k)
        .collect();
    assert!(
        stale.is_empty(),
        "scripts/resource-erasure-surface.txt declares columns that are not `scan` columns in the \
         sweep's manifest, or are out of scope in a table no resource reaches. Delete the line, or \
         (if the sweep reclassified the column) check the sweep's reason first.\n\
         Stale: {stale:#?}"
    );
}

/// FAILS IF: a base-table `*_table` discriminator carries no CHECK. The polymorphic roots are found
/// by a CHECK naming `kb_resources`; a discriminator without one could point at a resource and the
/// walk would never see the table.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn every_polymorphic_discriminator_carries_a_check(pool: PgPool) {
    let bare = unchecked_discriminators(&pool).await;
    assert!(
        bare.is_empty(),
        "these `*_table` columns carry no CHECK enumerating their targets, so the erasure fence \
         cannot tell whether they reference kb_resources. Add the CHECK (the convention every other \
         discriminator follows).\n\
         Unchecked: {bare:#?}"
    );
}

/// FAILS IF: an `out-of-scope` line gives no reason. The class means "the act leaves this", and a
/// reader needs to know why to tell a judgement from an omission.
#[test]
fn every_out_of_scope_line_states_its_reason() {
    let silent: Vec<String> = declarations()
        .into_iter()
        .filter(|(_, (d, note))| *d == Disposition::OutOfScope && note.is_empty())
        .map(|(k, _)| k)
        .collect();
    assert!(
        silent.is_empty(),
        "`out-of-scope` requires the reason in the note column.\nSilent: {silent:#?}"
    );
}

/// Witness 13. FAILS IF: a `scan` column added to a resource-reachable table, in any of the three
/// ways a table becomes reachable, is not reported until declared.
///
/// The probes cover an existing table, a new table holding a foreign key into a root, a new table
/// two keys away (the walk is transitive, ruled 2026-10-02), and a new polymorphic owner. The new
/// tables are the case a hand-maintained table list would miss. The
/// probe columns join the scan set here, standing in for the sweep PR that would class them `scan`.
/// Each `sqlx::test` runs in its own database, so nothing escapes.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn an_added_scan_column_fails_the_fence_until_declared(pool: PgPool) {
    let before = reachable_tables(&pool).await;
    assert!(
        uncovered(&before, &scan_columns()).is_empty(),
        "precondition: the fence holds before the probes are added"
    );

    for ddl in [
        "ALTER TABLE kb_content_blocks ADD COLUMN erasure_fence_probe text",
        "CREATE TABLE erasure_fence_probe_child (
             id uuid PRIMARY KEY,
             block_id uuid NOT NULL REFERENCES kb_content_blocks(id),
             note text)",
        "CREATE TABLE erasure_fence_probe_grandchild (
             child_id uuid NOT NULL REFERENCES erasure_fence_probe_child(id),
             note text)",
        "CREATE TABLE erasure_fence_probe_owner (
             owner_table text NOT NULL CHECK (owner_table IN ('kb_resources', 'kb_cogmaps')),
             owner_id uuid NOT NULL,
             note text)",
    ] {
        sqlx::query(ddl)
            .execute(&pool)
            .await
            .expect("apply probe DDL");
    }

    let probes = [
        "erasure_fence_probe_child.note",
        "erasure_fence_probe_grandchild.note",
        "erasure_fence_probe_owner.note",
        "kb_content_blocks.erasure_fence_probe",
    ];
    let mut scan = scan_columns();
    scan.extend(probes.iter().map(|p| p.to_string()));

    assert_eq!(
        uncovered(&reachable_tables(&pool).await, &scan),
        probes.map(String::from).to_vec(),
        "every probe column must be reported, and only they"
    );
}

/// The done-when sanity check. FAILS IF: reverting the joint-read fixes leaves the fence green.
///
/// The first draft of D2 missed `kb_chunks.header_path` and `kb_citation_audits.reason`. This
/// rewrites the live function so those two UPDATEs assign something else, and asserts the binding
/// reports exactly those two. Each rewrite must match exactly once, so the probe cannot silently
/// test nothing.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn reverting_the_joint_read_fixes_fails_the_fence(pool: PgPool) {
    let body = redaction_body(&pool).await;
    assert!(
        unbound(&body).is_empty(),
        "precondition: every handled line is bound"
    );

    let mut reverted = body.clone();
    for (fix, revert) in [
        ("SET header_path = NULL", "SET resource_id = resource_id"),
        ("SET reason = NULL", "SET block_id = block_id"),
    ] {
        assert_eq!(
            reverted.matches(fix).count(),
            1,
            "the probe expects `{fix}` exactly once in {REDACTION_FN}; the function changed shape"
        );
        reverted = reverted.replace(fix, revert);
    }
    sqlx::query(&reverted)
        .execute(&pool)
        .await
        .expect("install the reverted function");

    assert_eq!(
        unbound(&redaction_body(&pool).await),
        vec![
            "kb_chunks.header_path".to_string(),
            "kb_citation_audits.reason".to_string()
        ],
        "reverting the joint-read fixes must unbind exactly those two columns"
    );
}

/// FAILS IF: a base-table `*_table` column without a CHECK is not reported by the guard.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn an_unchecked_discriminator_fails_the_guard(pool: PgPool) {
    assert!(
        unchecked_discriminators(&pool).await.is_empty(),
        "precondition"
    );
    sqlx::query("CREATE TABLE erasure_fence_probe_bare (owner_table text, owner_id uuid)")
        .execute(&pool)
        .await
        .expect("create probe table");
    assert_eq!(
        unchecked_discriminators(&pool).await,
        vec!["erasure_fence_probe_bare.owner_table".to_string()]
    );
}

/// The token check itself, on shapes the D2 function uses.
#[test]
fn writes_column_reads_assignments_not_mentions() {
    let sql = "
        UPDATE kb_chunks c
           SET embedding = NULL, embedded_with = NULL -- header_path = NULL
         WHERE c.header_path = 'x';
        WITH ranked AS (SELECT 1)
        UPDATE kb_properties p
           SET property_key   = 'erased-key-' || ranked.n::text,
               property_value = '\"erased\"'::jsonb
          FROM ranked;
        DELETE FROM kb_remote_sources r WHERE r.id = v;
    ";
    assert!(writes_column(sql, "kb_chunks.embedding"));
    assert!(writes_column(sql, "kb_chunks.embedded_with"));
    assert!(
        !writes_column(sql, "kb_chunks.header_path"),
        "a comment and a WHERE comparison are not assignments"
    );
    assert!(writes_column(sql, "kb_properties.property_key"));
    assert!(writes_column(sql, "kb_properties.property_value"));
    assert!(writes_column(sql, "kb_remote_sources.uri"));
    assert!(
        !writes_column(sql, "kb_chunk_content.content"),
        "a table the SQL never writes"
    );
}
