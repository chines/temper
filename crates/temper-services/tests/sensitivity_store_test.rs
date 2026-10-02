#![cfg(feature = "test-db")]
//! The sensitivity sweep's guarded store, its seeded detectors and its validators.
//!
//! Under goal *"Personal data that lands in the corpus by accident is found"*, sensitivity-sweep spec
//! D1, D3-D7 and rulings Q15-Q21. Nothing scans yet; these witnesses hold the shape the scan will
//! write into, and the detectors it will run.
//!
//! Spec witnesses 1 (the column-set half), 18 (`ssn_valid()`) and 19 (the delimiter requirement),
//! plus Q19 (the surface registry equals the manifest, and the enqueue refuses what it does not
//! enable), Q20 (the cursor's tuple watermark) and Q21 (append-only dispositions). Witness 12's grep
//! gate needs no database and lives in `sensitivity_schema_unreachable_test.rs`.

use std::collections::BTreeSet;

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use temper_core::types::workflow_job::{DispatchType, Persona, SensitivityJobPayload};
use temper_services::services::workflow_job_service::enqueue_system;

const SCAN_MANIFEST: &str = include_str!("../../../scripts/sensitivity-scan-surface.txt");

const A_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn code_of(e: &sqlx::Error) -> Option<String> {
    match e {
        sqlx::Error::Database(db) => db.code().map(|c| c.into_owned()),
        _ => None,
    }
}

fn constraint_of(e: &sqlx::Error) -> Option<String> {
    match e {
        sqlx::Error::Database(db) => db.constraint().map(str::to_string),
        _ => None,
    }
}

fn assert_check_violation(e: &sqlx::Error, constraint: &str, what: &str) {
    assert_eq!(code_of(e).as_deref(), Some("23514"), "{what}: {e}");
    assert_eq!(constraint_of(e).as_deref(), Some(constraint), "{what}: {e}");
}

async fn matches(pool: &PgPool, detector: &str, text: &str) -> i32 {
    sqlx::query_scalar::<_, Option<i32>>("SELECT sensitivity.detector_match_count($1, $2)")
        .bind(detector)
        .bind(text)
        .fetch_one(pool)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("detector {detector} is not seeded"))
}

async fn validator(pool: &PgPool, function: &str, text: &str) -> bool {
    sqlx::query_scalar(&format!("SELECT sensitivity.{function}($1)"))
        .bind(text)
        .fetch_one(pool)
        .await
        .unwrap()
}

// ── Witness 1, the column-set half: the store cannot hold content ─────────────────────────────

/// Spec D1, verbatim. A later PR adding `sample_text`, an offset or a window fails here, not in
/// review.
const FINDINGS_COLUMNS: &[(&str, &str)] = &[
    ("id", "uuid"),
    ("surface", "text"),
    ("target_table", "text"),
    ("target_id", "uuid"),
    ("resource_id", "uuid"),
    ("content_hash", "text"),
    ("detector_id", "text"),
    ("detector_version", "integer"),
    ("category", "text"),
    ("severity", "smallint"),
    ("match_count", "integer"),
    ("fingerprint", "bytea"),
    ("first_seen", "timestamp with time zone"),
    ("last_seen", "timestamp with time zone"),
];

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn the_findings_columns_are_exactly_the_d1_allowlist(pool: PgPool) {
    let live: BTreeSet<(String, String)> = sqlx::query_as(
        "SELECT column_name::text, data_type::text FROM information_schema.columns \
          WHERE table_schema = 'sensitivity' AND table_name = 'findings'",
    )
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .collect();
    let allowed: BTreeSet<(String, String)> = FINDINGS_COLUMNS
        .iter()
        .map(|(c, t)| (c.to_string(), t.to_string()))
        .collect();
    assert_eq!(
        live, allowed,
        "sensitivity.findings must carry D1's columns and no others"
    );
}

/// The column names are not the whole guarantee: a `text` column can carry anything. Each text
/// column of `findings` is held to a non-content shape by a CHECK or a foreign key, and a planted
/// value under each is refused.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn content_under_a_findings_text_column_is_refused(pool: PgPool) {
    for (column, value) in [
        ("content_hash", "SSN 219-45-6789"),
        ("target_table", "kb_resources Jane Doe"),
        ("category", "national_id 219-45-6789"),
        ("surface", "kb_resources.title 219-45-6789"),
        ("detector_id", "us_ssn_delimited 219-45-6789"),
    ] {
        let mut row = json!({
            "surface": "kb_resources.title",
            "content_hash": A_HASH,
            "detector_id": "us_ssn_delimited",
            "category": "national_id",
            "target_table": "kb_resources",
        });
        row[column] = json!(value);
        let err = sqlx::query(
            "INSERT INTO sensitivity.findings (surface, target_table, target_id, content_hash, \
               detector_id, detector_version, category, severity, match_count) \
             SELECT r->>'surface', r->>'target_table', gen_random_uuid(), r->>'content_hash', \
                    r->>'detector_id', 1, r->>'category', 4, 1 FROM (SELECT $1::jsonb r) x",
        )
        .bind(row)
        .execute(&pool)
        .await
        .unwrap_err();
        assert!(
            matches!(code_of(&err).as_deref(), Some("23514" | "23503")),
            "{column}: {err}"
        );
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM sensitivity.findings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

/// The positive control for the test above: a well-formed finding is admitted, so the refusals are
/// about the planted values and not about a row that could never be written.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_well_formed_finding_is_admitted_once_per_hash_and_detector_version(pool: PgPool) {
    let insert =
        "INSERT INTO sensitivity.findings (surface, target_table, target_id, content_hash, \
                    detector_id, detector_version, category, severity, match_count, fingerprint) \
                  VALUES ('kb_resources.title', 'kb_resources', $1, $2, 'us_ssn_delimited', 1, \
                          'national_id', 4, 1, sha256('x'::bytea))";
    sqlx::query(insert)
        .bind(Uuid::now_v7())
        .bind(A_HASH)
        .execute(&pool)
        .await
        .unwrap();
    // Hash grain (D2): the same hash under the same detector version is one finding.
    let err = sqlx::query(insert)
        .bind(Uuid::now_v7())
        .bind(A_HASH)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(code_of(&err).as_deref(), Some("23505"), "{err}");
}

// ── Q19: the surface registry is the manifest's scan lines ────────────────────────────────────

fn manifest_scan_lines() -> BTreeSet<String> {
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

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn the_seeded_surfaces_are_the_manifests_scan_lines(pool: PgPool) {
    let seeded: BTreeSet<String> = sqlx::query_scalar("SELECT surface FROM sensitivity.surfaces")
        .fetch_all(&pool)
        .await
        .unwrap()
        .into_iter()
        .collect();
    let manifest = manifest_scan_lines();
    assert!(
        !manifest.is_empty(),
        "the manifest parse found no scan lines"
    );
    assert_eq!(
        manifest.difference(&seeded).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "scan lines with no sensitivity.surfaces row"
    );
    assert_eq!(
        seeded.difference(&manifest).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "sensitivity.surfaces rows that are not scan lines"
    );
}

/// Cut 1 cursors D3's first cut (plan P3), less `kb_blobs.blob_pathname`, which the manifest
/// declares structural, and `kb_workflow_jobs.last_error`, which `workflow_job_reap` rewrites on
/// old ids. Every other scan line is seeded disabled with no cursor kind, which is what the run
/// summary reads to name it as not yet cursored.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn cut_one_enables_the_first_cut_surfaces_and_no_others(pool: PgPool) {
    let enabled: Vec<(String, String)> = sqlx::query_as(
        "SELECT surface, cursor_kind FROM sensitivity.surfaces WHERE enabled ORDER BY surface",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let expect = [
        ("kb_block_content.content", "append_only_v7"),
        ("kb_chunk_content.content", "append_only_v7"),
        ("kb_chunks.header_path", "append_only_v7"),
        ("kb_citation_audits.reason", "append_only_v7"),
        ("kb_edges.label", "append_only_v7"),
        ("kb_properties.property_key", "append_only_v7"),
        ("kb_remote_sources.uri", "append_only_v7"),
        ("kb_resources.origin_uri", "mutable_timestamp"),
        ("kb_resources.title", "mutable_timestamp"),
    ];
    let expect: Vec<(String, String)> = expect
        .iter()
        .map(|(s, k)| (s.to_string(), k.to_string()))
        .collect();
    assert_eq!(enabled, expect);

    let stray: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sensitivity.surfaces WHERE NOT enabled AND cursor_kind IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stray, 0, "a disabled surface carries no cursor kind");

    let err = sqlx::query(
        "UPDATE sensitivity.surfaces SET enabled = true WHERE surface = 'kb_teams.description'",
    )
    .execute(&pool)
    .await
    .unwrap_err();
    assert_check_violation(
        &err,
        "surfaces_enabled_needs_cursor",
        "enable without a cursor",
    );
}

fn order(surface: &str) -> SensitivityJobPayload {
    SensitivityJobPayload {
        surface: surface.into(),
        budget: 500,
    }
}

/// Q19's enqueue half. PR A's CHECK admits any `kb_<table>.<column>`; membership is the real
/// constraint. A surface that is a scan line but not enabled, and one shaped right but naming
/// nothing, are both refused, and the refusal leaves no row.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn the_enqueue_refuses_a_surface_that_is_not_enabled(pool: PgPool) {
    let persona = Persona::Sensitivity.as_str();
    let dispatch = DispatchType::SensitivitySweep.as_str();
    for surface in [
        "kb_teams.description",
        "kb_jane.doe",
        "kb_workflow_jobs.last_error",
    ] {
        // The typed wrapper refuses too, but renders an opaque internal error by design: the
        // database message never reaches a log. The raw call shows which refusal fired.
        assert!(enqueue_system(&pool, persona, dispatch, &order(surface))
            .await
            .is_err());
        let err = sqlx::query("SELECT workflow_job_enqueue_system($1, $2, $3)")
            .bind(persona)
            .bind(dispatch)
            .bind(serde_json::to_value(order(surface)).unwrap())
            .execute(&pool)
            .await
            .unwrap_err();
        assert_eq!(code_of(&err).as_deref(), Some("23514"), "{surface}: {err}");
        assert!(
            err.to_string()
                .contains("sensitivity surface is not enabled"),
            "{surface}: {err}"
        );
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM kb_workflow_jobs WHERE persona = $1")
        .bind(persona)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "a refused enqueue leaves no job");

    enqueue_system(&pool, persona, dispatch, &order("kb_resources.title"))
        .await
        .unwrap()
        .expect("an enabled surface is admitted");
}

/// The membership check runs after the insert, so PR A's work-order CHECK still answers first for
/// a malformed payload rather than being shadowed by the newer refusal.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_malformed_work_order_still_meets_the_check_first(pool: PgPool) {
    let err = sqlx::query("SELECT workflow_job_enqueue_system($1, $2, $3)")
        .bind(Persona::Sensitivity.as_str())
        .bind(DispatchType::SensitivitySweep.as_str())
        .bind(json!({"surface": "jane.doe", "budget": 10}))
        .execute(&pool)
        .await
        .unwrap_err();
    assert_check_violation(
        &err,
        "ck_workflow_jobs_sensitivity_work_order",
        "malformed order",
    );
}

// ── Q18 and Q16: the seeded corpus ────────────────────────────────────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn the_seeded_detectors_are_cut_ones_nine(pool: PgPool) {
    let seeded: Vec<(String, String, i16, Option<String>, bool, i32)> = sqlx::query_as(
        "SELECT id, category, severity, validator, enabled, version \
           FROM sensitivity.detectors ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let expect: Vec<(String, String, i16, Option<String>, bool, i32)> = [
        ("aba_routing", "financial", 3, Some("aba_routing_valid")),
        ("cloud_saas_key", "credential", 4, None),
        ("connection_string_password", "credential", 4, None),
        ("jwt", "credential", 3, None),
        ("local_path_username", "identifier", 1, None),
        ("payment_card", "payment_card", 4, Some("luhn_valid")),
        ("private_key_block", "secret_material", 4, None),
        ("us_ssn_contextual", "national_id", 4, Some("ssn_valid")),
        ("us_ssn_delimited", "national_id", 4, Some("ssn_valid")),
    ]
    .iter()
    .map(|(id, cat, sev, v)| {
        (
            id.to_string(),
            cat.to_string(),
            *sev,
            v.map(str::to_string),
            true,
            1,
        )
    })
    .collect();
    assert_eq!(seeded, expect);
}

/// Q16: email is deferred, so nothing in cut 1 detects `contact` data, and an address yields
/// nothing. The run summary must say so rather than read as "no contact data found".
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn cut_one_detects_no_contact_data(pool: PgPool) {
    let contact: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sensitivity.detectors WHERE category = 'contact'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(contact, 0);
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM sensitivity.detectors")
        .fetch_all(&pool)
        .await
        .unwrap();
    for id in ids {
        assert_eq!(
            matches(&pool, &id, "write to jane.doe@example.org").await,
            0,
            "{id}"
        );
    }
}

/// Each seeded detector finds its own planted value, so every negative in this file is measured
/// against a detector that can fire.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn every_seeded_detector_finds_its_planted_value(pool: PgPool) {
    for (detector, text) in [
        ("private_key_block", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        ("cloud_saas_key", "key AKIAABCDEFGHIJKLMNOP here"),
        (
            "connection_string_password",
            "postgres://app:hunter2@db:5432/x",
        ),
        (
            "jwt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
        ),
        ("payment_card", "card 4111 1111 1111 1111 exp"),
        ("aba_routing", "routing number: 021000021"),
        ("us_ssn_delimited", "ssn 219-45-6789"),
        ("us_ssn_contextual", "SSN: 219456789"),
        ("local_path_username", "see /Users/jdoe/notes.md"),
    ] {
        assert_eq!(
            matches(&pool, detector, text).await,
            1,
            "{detector}: {text}"
        );
    }
}

// ── Witness 18: ssn_valid() rejects what it must ──────────────────────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn ssn_valid_applies_each_structural_rule_and_known_fake(pool: PgPool) {
    assert!(
        validator(&pool, "ssn_valid", "219-45-6789").await,
        "control"
    );
    for (rule, ssn) in [
        ("area 000", "000-45-6789"),
        ("area 666", "666-45-6789"),
        ("area 9xx", "900-45-6789"),
        ("area 9xx", "999-45-6789"),
        ("group 00", "219-00-6789"),
        ("serial 0000", "219-45-0000"),
        ("known fake", "078-05-1120"),
        ("known fake", "219-09-9999"),
        ("known fake", "123-45-6789"),
        ("not nine digits", "219-45-678"),
    ] {
        assert!(!validator(&pool, "ssn_valid", ssn).await, "{rule}: {ssn}");
    }
}

/// The case that decides whether an always-on detector is tolerable: both fakes appear in ordinary
/// tutorials and test data.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn the_tutorial_fakes_yield_no_finding(pool: PgPool) {
    let fixture = "Example: SSN 123-45-6789. The Woolworth card read 078-05-1120. \
                   ssn: 123456789 and social security 078051120.";
    for detector in ["us_ssn_delimited", "us_ssn_contextual"] {
        assert_eq!(matches(&pool, detector, fixture).await, 0, "{detector}");
    }
}

// ── Witness 19: the delimiter requirement holds ───────────────────────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn bare_digits_are_not_a_delimited_ssn(pool: PgPool) {
    for text in [
        "row id 219456789 updated",
        "call +12194567890 today",
        "at 2026-10-02T21:94:56.219456789Z",
        "build 219-45-67890",
    ] {
        assert_eq!(matches(&pool, "us_ssn_delimited", text).await, 0, "{text}");
    }
    for text in ["ssn 219-45-6789", "ssn 219 45 6789"] {
        assert_eq!(matches(&pool, "us_ssn_delimited", text).await, 1, "{text}");
    }
}

/// The contextual detector recovers the pasted-bare case only next to its keyword.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn bare_nine_digits_need_the_keyword(pool: PgPool) {
    assert_eq!(
        matches(&pool, "us_ssn_contextual", "order 219456789").await,
        0
    );
    assert_eq!(
        matches(&pool, "us_ssn_contextual", "ssn 219456789").await,
        1
    );
    assert_eq!(
        matches(&pool, "us_ssn_contextual", "Social Security no. 219456789").await,
        1
    );
}

// ── The other two validators ──────────────────────────────────────────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn luhn_and_aba_adjudicate_what_the_patterns_nominate(pool: PgPool) {
    for (valid, card) in [
        (true, "4111 1111 1111 1111"),
        (true, "5500-0000-0000-0004"),
        (false, "4111 1111 1111 1112"),
        (false, "0000000000000000"),
        (false, "411111111111"),
    ] {
        assert_eq!(validator(&pool, "luhn_valid", card).await, valid, "{card}");
    }
    for (valid, routing) in [
        (true, "021000021"),
        (true, "011000015"),
        (false, "021000022"),
        (false, "000000000"),
        (false, "02100002"),
    ] {
        assert_eq!(
            validator(&pool, "aba_routing_valid", routing).await,
            valid,
            "{routing}"
        );
    }
    // A routing keyword inside a word ("database") is not context.
    assert_eq!(matches(&pool, "aba_routing", "database 021000021").await, 0);
}

// ── Q20: a cursor's watermark is typed by its surface's kind ──────────────────────────────────

async fn insert_cursor(
    pool: &PgPool,
    surface: &str,
    kind: &str,
    lane: &str,
    at: Option<&str>,
    id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO sensitivity.cursors (surface, cursor_kind, detector_id, detector_version, \
           lane, watermark_at, watermark_id) \
         VALUES ($1, $2, 'us_ssn_delimited', 1, $3, $4::timestamptz, $5)",
    )
    .bind(surface)
    .bind(kind)
    .bind(lane)
    .bind(at)
    .bind(id)
    .execute(pool)
    .await
    .map(|_| ())
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_timestamp_watermark_is_a_tuple_and_an_id_watermark_is_an_id(pool: PgPool) {
    let now = Some("2026-10-02T12:00:00Z");
    let id = Some(Uuid::now_v7());

    insert_cursor(
        &pool,
        "kb_resources.title",
        "mutable_timestamp",
        "head",
        now,
        id,
    )
    .await
    .unwrap();
    insert_cursor(&pool, "kb_edges.label", "append_only_v7", "head", None, id)
        .await
        .unwrap();
    insert_cursor(
        &pool,
        "kb_resources.title",
        "mutable_timestamp",
        "backfill",
        None,
        None,
    )
    .await
    .expect("a cursor that has not advanced yet has no watermark");

    for (surface, kind, at, wid, why) in [
        (
            "kb_resources.origin_uri",
            "mutable_timestamp",
            now,
            None,
            "timestamp without id",
        ),
        (
            "kb_resources.origin_uri",
            "mutable_timestamp",
            None,
            id,
            "id without timestamp",
        ),
        (
            "kb_chunks.header_path",
            "append_only_v7",
            now,
            id,
            "timestamp on an id cursor",
        ),
    ] {
        let err = insert_cursor(&pool, surface, kind, "head", at, wid)
            .await
            .unwrap_err();
        assert_check_violation(&err, "cursors_watermark_shape", why);
    }
}

/// The kind is the surface's, not the writer's: the composite foreign key refuses a cursor that
/// claims a kind its surface does not have, and one on a surface nobody enabled a cursor for.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_cursor_cannot_claim_a_kind_its_surface_lacks(pool: PgPool) {
    for (surface, kind) in [
        ("kb_resources.title", "append_only_v7"),
        ("kb_teams.description", "append_only_v7"),
    ] {
        let err = insert_cursor(&pool, surface, kind, "head", None, Some(Uuid::now_v7()))
            .await
            .unwrap_err();
        assert_eq!(code_of(&err).as_deref(), Some("23503"), "{surface}: {err}");
    }
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn backfill_bookkeeping_lives_on_the_backfill_lane_only(pool: PgPool) {
    let err = sqlx::query(
        "INSERT INTO sensitivity.cursors (surface, cursor_kind, detector_id, detector_version, \
           lane, backfill_completed_at) \
         VALUES ('kb_edges.label', 'append_only_v7', 'jwt', 1, 'head', now())",
    )
    .execute(&pool)
    .await
    .unwrap_err();
    assert_check_violation(
        &err,
        "cursors_backfill_lane_only",
        "completion on the head lane",
    );
}

// ── Q21: dispositions ─────────────────────────────────────────────────────────────────────────

async fn a_finding(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO sensitivity.findings (surface, content_hash, detector_id, detector_version, \
           category, severity, match_count) \
         VALUES ('kb_resources.title', $1, 'jwt', 1, 'credential', 3, 1) RETURNING id",
    )
    .bind(A_HASH)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// One disposition row. `Default` is every column NULL, so each case names only what it sets.
#[derive(Default, Clone)]
struct Disposition {
    state: &'static str,
    finding: Option<Uuid>,
    detector: Option<&'static str>,
    fingerprint: Option<Vec<u8>>,
    content_hash: Option<&'static str>,
    expires_in_days: Option<i32>,
}

async fn dispose(pool: &PgPool, d: Disposition) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO sensitivity.dispositions \
           (state, finding_id, detector_id, fingerprint, content_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(days => $6))",
    )
    .bind(d.state)
    .bind(d.finding)
    .bind(d.detector)
    .bind(d.fingerprint)
    .bind(d.content_hash)
    .bind(d.expires_in_days)
    .execute(pool)
    .await
    .map(|_| ())
}

fn a_fingerprint() -> Option<Vec<u8>> {
    Some(vec![7; 32])
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn accepted_risk_carries_a_clock_and_nothing_else_does(pool: PgPool) {
    let f = Some(a_finding(&pool).await);
    for (d, why) in [
        (
            Disposition {
                state: "accepted_risk",
                finding: f,
                ..Default::default()
            },
            "accepted risk with no expiry",
        ),
        (
            Disposition {
                state: "acknowledged",
                finding: f,
                expires_in_days: Some(30),
                ..Default::default()
            },
            "an expiry on another state",
        ),
    ] {
        let err = dispose(&pool, d).await.unwrap_err();
        assert_check_violation(&err, "dispositions_expiry_iff_accepted_risk", why);
    }
    dispose(
        &pool,
        Disposition {
            state: "accepted_risk",
            finding: f,
            expires_in_days: Some(30),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

/// A false positive is a ruling about a matched value, recorded by fingerprint or by content hash
/// so it clears the same string everywhere. Every other state is about one finding.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_false_positive_names_a_value_and_every_other_state_names_a_finding(pool: PgPool) {
    let f = Some(a_finding(&pool).await);
    let fp = Disposition {
        state: "false_positive",
        detector: Some("jwt"),
        ..Default::default()
    };
    for admitted in [
        Disposition {
            content_hash: Some(A_HASH),
            ..fp.clone()
        },
        Disposition {
            fingerprint: a_fingerprint(),
            ..fp.clone()
        },
        Disposition {
            state: "acknowledged",
            finding: f,
            ..Default::default()
        },
    ] {
        dispose(&pool, admitted).await.unwrap();
    }

    for (d, why) in [
        (
            Disposition {
                finding: f,
                content_hash: Some(A_HASH),
                ..fp.clone()
            },
            "false positive on a finding",
        ),
        (
            Disposition {
                detector: None,
                content_hash: Some(A_HASH),
                ..fp.clone()
            },
            "false positive, no detector",
        ),
        (
            Disposition {
                fingerprint: a_fingerprint(),
                content_hash: Some(A_HASH),
                ..fp.clone()
            },
            "both fingerprint and hash",
        ),
        (fp.clone(), "neither fingerprint nor hash"),
        (
            Disposition {
                state: "actioned",
                ..Default::default()
            },
            "actioned with no finding",
        ),
        (
            Disposition {
                state: "actioned",
                finding: f,
                detector: Some("jwt"),
                ..Default::default()
            },
            "actioned naming a detector",
        ),
    ] {
        let err = dispose(&pool, d).await.unwrap_err();
        assert_check_violation(&err, "dispositions_subject", why);
    }
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn dispositions_are_append_only_in_enforcement(pool: PgPool) {
    let f = Some(a_finding(&pool).await);
    dispose(
        &pool,
        Disposition {
            state: "acknowledged",
            finding: f,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    for sql in [
        "UPDATE sensitivity.dispositions SET state = 'actioned'",
        "DELETE FROM sensitivity.dispositions",
    ] {
        let err = sqlx::query(sql).execute(&pool).await.unwrap_err();
        assert!(err.to_string().contains("append-only"), "{sql}: {err}");
    }
}

// ── D9: a run's tally is categories and counts ────────────────────────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_runs_tally_holds_only_categories_and_counts(pool: PgPool) {
    let insert = "INSERT INTO sensitivity.runs (surface, by_category) \
                  VALUES ('kb_resources.title', $1)";
    sqlx::query(insert)
        .bind(json!({"national_id": 2, "credential": 0}))
        .execute(&pool)
        .await
        .unwrap();
    for tally in [
        json!({"219-45-6789": 1}),
        json!({"national_id": "219-45-6789"}),
        json!({"national_id": 123_456_789_012_i64}),
        json!(["national_id"]),
    ] {
        let err = sqlx::query(insert)
            .bind(&tally)
            .execute(&pool)
            .await
            .unwrap_err();
        assert_check_violation(&err, "runs_by_category_check", &tally.to_string());
    }
}
