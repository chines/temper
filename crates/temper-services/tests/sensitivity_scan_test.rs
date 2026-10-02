#![cfg(feature = "test-db")]
//! The sensitivity sweep's scan over its text surfaces (build order 3a, PR C1).
//!
//! Under goal *"Personal data that lands in the corpus by accident is found"*, sensitivity-sweep spec
//! D2, D4, D5, D8 and D11 and rulings Q28-Q33. Spec witnesses 1 (the planted half), 3, 4, 5, 6, 7,
//! 14, 27 (the fingerprint half; the survey half is the erasure bridge's) and 28, plus the two-phase
//! tick: a claim that commits before the scan, so a tick that never finishes keeps its attempt and
//! leaves its run behind.
//!
//! Content is planted with raw inserts, not the write path: these witnesses are about what the scan
//! reads, and every source it reads is a plain table.

use sqlx::{PgPool, Row};
use uuid::Uuid;

const SALT: &[u8] = b"witness-salt";
const SSN_A: &str = "219-45-6789";
const SSN_B: &str = "536-22-8147";
const NO_LAG: &str = "0 seconds";

#[derive(Debug, Clone, Copy)]
struct Tick {
    rows_examined: i32,
    hashes_examined: i32,
    cache_hits: i32,
    new_findings: i32,
    failed: bool,
}

/// Enqueue a work order for `surface`, so the claim's own pick finds a job in flight and takes this
/// one, then run both phases in their own transactions.
async fn tick_salted(pool: &PgPool, surface: &str, salt: Option<&[u8]>) -> Tick {
    sqlx::query("SELECT workflow_job_enqueue_system('sensitivity', 'sensitivity-sweep', $1)")
        .bind(serde_json::json!({ "surface": surface, "budget": 1000 }))
        .execute(pool)
        .await
        .unwrap();
    let (run, job): (Uuid, Uuid) =
        sqlx::query_as("SELECT run_id, job_id FROM sensitivity_sweep_claim()")
            .fetch_one(pool)
            .await
            .unwrap();
    let row = sqlx::query(
        "SELECT rows_examined, hashes_examined, cache_hits, new_findings, failed \
           FROM sensitivity_sweep_tick($1, $2, $3, $4::interval)",
    )
    .bind(run)
    .bind(job)
    .bind(salt)
    .bind(NO_LAG)
    .fetch_one(pool)
    .await
    .unwrap();
    Tick {
        rows_examined: row.get(0),
        hashes_examined: row.get(1),
        cache_hits: row.get(2),
        new_findings: row.get(3),
        failed: row.get(4),
    }
}

async fn tick(pool: &PgPool, surface: &str) -> Tick {
    tick_salted(pool, surface, Some(SALT)).await
}

async fn resource(pool: &PgPool, title: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO kb_resources (title, origin_uri) VALUES ($1, 'test://witness') RETURNING id",
    )
    .bind(title)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn retitle(pool: &PgPool, resource: Uuid, title: &str) {
    sqlx::query("UPDATE kb_resources SET title = $2, updated = clock_timestamp() WHERE id = $1")
        .bind(resource)
        .bind(title)
        .execute(pool)
        .await
        .unwrap();
}

/// A block edit's footprint on the resource: `updated` moves and the title does not.
async fn touch(pool: &PgPool, resource: Uuid) {
    sqlx::query("UPDATE kb_resources SET updated = clock_timestamp() WHERE id = $1")
        .bind(resource)
        .execute(pool)
        .await
        .unwrap();
}

/// One block on `resource` holding `content`; returns the revision id, the surface's target.
async fn block(pool: &PgPool, resource: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar(
        "WITH ev AS (
             INSERT INTO kb_events (event_type_id, emitter_entity_id, category)
             SELECT t.id, (SELECT id FROM kb_entities ORDER BY id LIMIT 1), t.category
               FROM kb_event_types t WHERE t.name = 'resource_updated' RETURNING id),
         b AS (
             INSERT INTO kb_content_blocks (resource_id, seq, genesis_event_id, last_event_id)
             SELECT $1, (SELECT count(*) FROM kb_content_blocks WHERE resource_id = $1), ev.id, ev.id
               FROM ev RETURNING id),
         rev AS (
             INSERT INTO kb_block_revisions (block_id, block_body_hash, chunk_count)
             SELECT id, 'witness', 0 FROM b RETURNING id)
         INSERT INTO kb_block_content (block_revision_id, content, content_hash)
         SELECT id, $2, encode(sha256(convert_to($2, 'UTF8')), 'hex') FROM rev
         RETURNING block_revision_id",
    )
    .bind(resource)
    .bind(content)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn remote_source(pool: &PgPool, uri: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO kb_remote_sources (uri, uri_normalized) VALUES ($1, md5(random()::text)) RETURNING id",
    )
    .bind(uri)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn findings_at(pool: &PgPool, target: Uuid) -> Vec<(Uuid, String, i32, i32, String)> {
    sqlx::query_as(
        "SELECT id, detector_id, detector_version, match_count, fingerprint_state \
           FROM sensitivity.findings WHERE target_id = $1 ORDER BY detector_id, detector_version",
    )
    .bind(target)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn fingerprints(pool: &PgPool, finding: Uuid) -> Vec<Vec<u8>> {
    sqlx::query_scalar(
        "SELECT fingerprint FROM sensitivity.finding_fingerprints WHERE finding_id = $1 ORDER BY 1",
    )
    .bind(finding)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn bump(pool: &PgPool, detector: &str) {
    sqlx::query("UPDATE sensitivity.detectors SET version = version + 1 WHERE id = $1")
        .bind(detector)
        .execute(pool)
        .await
        .unwrap();
}

/// Every row of every table in the `sensitivity` schema, and every sensitivity job, as text.
async fn everything_the_sweep_wrote(pool: &PgPool) -> String {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.tables \
          WHERE table_schema = 'sensitivity' AND table_type = 'BASE TABLE' \
            AND table_name NOT IN ('detectors', 'detector_versions')",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut all = String::new();
    for t in tables {
        let rows: Vec<String> =
            sqlx::query_scalar(&format!("SELECT t::text FROM sensitivity.{t} t"))
                .fetch_all(pool)
                .await
                .unwrap();
        all.push_str(&rows.join("\n"));
    }
    let jobs: Vec<String> =
        sqlx::query_scalar("SELECT j::text FROM kb_workflow_jobs j WHERE persona = 'sensitivity'")
            .fetch_all(pool)
            .await
            .unwrap();
    all.push_str(&jobs.join("\n"));
    all
}

fn assert_holds_none_of(haystack: &str, planted: &str, what: &str) {
    let digits: String = planted.chars().filter(char::is_ascii_digit).collect();
    for needle in [planted, digits.as_str(), &planted[..6], &planted[4..]] {
        assert!(
            !haystack.contains(needle),
            "{what} holds `{needle}`, a piece of the planted value"
        );
    }
}

// ── Witness 1, the planted half: a finding is a pointer and a category ────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_planted_ssn_yields_a_finding_and_nothing_the_sweep_wrote_holds_it(pool: PgPool) {
    let r = resource(&pool, &format!("Payroll for {SSN_A}")).await;
    let t = tick(&pool, "kb_resources.title").await;

    assert!(!t.failed);
    assert_eq!(t.new_findings, 1, "the run counts what it found: {t:?}");
    let found = findings_at(&pool, r).await;
    assert_eq!(found.len(), 1, "one finding for the one SSN: {found:?}");
    assert_eq!(found[0].1, "us_ssn_delimited");
    assert_holds_none_of(
        &everything_the_sweep_wrote(&pool).await,
        SSN_A,
        "the sensitivity store",
    );
}

// ── Witness 3: identical prose scans once and yields one finding per place ────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn identical_prose_in_three_resources_scans_once_and_yields_three_findings(pool: PgPool) {
    let prose = format!("Employee record: SSN {SSN_A}, start date in March.");
    let mut places = Vec::new();
    for title in ["one", "two", "three"] {
        let r = resource(&pool, title).await;
        places.push(block(&pool, r, &prose).await);
    }
    let detectors: i32 =
        sqlx::query_scalar("SELECT count(*)::int FROM sensitivity.detectors WHERE enabled")
            .fetch_one(&pool)
            .await
            .unwrap();

    let t = tick(&pool, "kb_block_content.content").await;

    assert_eq!(t.rows_examined, 3);
    assert_eq!(
        t.hashes_examined, detectors,
        "the shared hash is scanned once per detector"
    );
    assert_eq!(
        t.cache_hits,
        2 * detectors,
        "the other two places are served by the memo"
    );
    let hashes: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT content_hash FROM sensitivity.findings WHERE target_id = ANY($1)",
    )
    .bind(&places)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(hashes.len(), 1, "three findings share one content hash");
    for place in &places {
        assert_eq!(
            findings_at(&pool, *place).await.len(),
            1,
            "each place has its own finding"
        );
    }
}

// ── Witness 4: the sweep does not repeat itself ────────────────────────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_second_tick_with_no_new_content_examines_nothing(pool: PgPool) {
    remote_source(&pool, "https://docs.example/history").await;
    let install = tick(&pool, "kb_remote_sources.uri").await;
    assert_eq!(
        install.rows_examined, 1,
        "the backfill reads history on the first tick"
    );

    // Content past the floor, which only the head reads.
    remote_source(&pool, &format!("https://hr.example/{SSN_A}")).await;
    remote_source(&pool, "https://docs.example/plain").await;
    let first = tick(&pool, "kb_remote_sources.uri").await;
    let second = tick(&pool, "kb_remote_sources.uri").await;

    assert_eq!(first.rows_examined, 2, "the head reads the new rows");
    assert_eq!(
        second.rows_examined, 0,
        "nothing new, so nothing is read again: {second:?}"
    );
}

// ── Witness 5: the commit-order hazard ─────────────────────────────────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_row_committed_after_a_tick_beneath_its_watermark_is_still_found(pool: PgPool) {
    // Install the cursors first, so both rows below land above the backfill floor and only the
    // head can find them.
    tick(&pool, "kb_remote_sources.uri").await;

    let mut slow = pool.begin().await.unwrap();
    let late: Uuid = sqlx::query_scalar(
        "INSERT INTO kb_remote_sources (uri, uri_normalized) VALUES ($1, 'late') RETURNING id",
    )
    .bind(format!("https://hr.example/{SSN_A}"))
    .fetch_one(&mut *slow)
    .await
    .unwrap();
    // A row with a higher v7 id, committed while the slow transaction is still open.
    remote_source(&pool, "https://docs.example/after").await;

    tick(&pool, "kb_remote_sources.uri").await;
    let held: i32 = sqlx::query_scalar(
        "SELECT head_holdback_seconds FROM sensitivity.runs ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        held > 0,
        "the hold is recorded, so a stalled head is not read as quiet"
    );
    slow.commit().await.unwrap();
    tick(&pool, "kb_remote_sources.uri").await;

    assert_eq!(
        findings_at(&pool, late).await.len(),
        1,
        "the head must not advance past a row an open transaction may still commit"
    );
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_transaction_that_has_only_read_does_not_hold_the_head_back(pool: PgPool) {
    tick(&pool, "kb_remote_sources.uri").await;
    let mut reader = pool.begin().await.unwrap();
    sqlx::query("SELECT count(*) FROM kb_remote_sources")
        .execute(&mut *reader)
        .await
        .unwrap();
    let fresh = remote_source(&pool, &format!("https://hr.example/{SSN_B}")).await;

    tick(&pool, "kb_remote_sources.uri").await;

    assert_eq!(
        findings_at(&pool, fresh).await.len(),
        1,
        "an idle reader cannot stall the head"
    );
    reader.rollback().await.unwrap();
}

// ── Witness 6: a mutable surface ───────────────────────────────────────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_title_only_update_is_detected(pool: PgPool) {
    let r = resource(&pool, "Quarterly planning").await;
    tick(&pool, "kb_resources.title").await;
    assert!(findings_at(&pool, r).await.is_empty());

    retitle(&pool, r, &format!("Quarterly planning, {SSN_B}")).await;
    let t = tick(&pool, "kb_resources.title").await;

    assert_eq!(
        t.rows_examined, 1,
        "the head re-reads the updated row and only it"
    );
    assert_eq!(findings_at(&pool, r).await.len(), 1);
}

// ── Witness 7: a version bump backfills one detector without re-running the others ────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_bump_backfills_only_its_detector_and_the_head_keeps_moving(pool: PgPool) {
    let old = remote_source(&pool, &format!("https://hr.example/{SSN_A}")).await;
    remote_source(&pool, "https://docs.example/plain").await;
    tick(&pool, "kb_remote_sources.uri").await;

    bump(&pool, "us_ssn_delimited").await;
    let fresh = remote_source(&pool, &format!("https://hr.example/{SSN_B}")).await;
    let t = tick(&pool, "kb_remote_sources.uri").await;

    let detectors: i32 =
        sqlx::query_scalar("SELECT count(*)::int FROM sensitivity.detectors WHERE enabled")
            .fetch_one(&pool)
            .await
            .unwrap();
    // The fresh row meets every detector once; the two history rows meet only the bumped one.
    assert_eq!(t.hashes_examined, detectors + 2, "{t:?}");
    assert_eq!(
        t.cache_hits, 0,
        "the other detectors do not revisit history: {t:?}"
    );
    let versions: Vec<i32> = findings_at(&pool, old).await.iter().map(|f| f.2).collect();
    assert_eq!(
        versions,
        vec![1, 2],
        "history is re-detected under the new version"
    );
    let fresh_found = findings_at(&pool, fresh).await;
    assert_eq!(fresh_found.len(), 1);
    assert_eq!(
        fresh_found[0].2, 2,
        "new content is found by the current version"
    );
}

// ── Witness 14 and Q32: a failure is coded, and the column refuses anything else ──────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_tick_that_fails_on_a_planted_row_writes_a_code_and_never_the_value(pool: PgPool) {
    sqlx::query(&format!(
        "CREATE FUNCTION witness_boom() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'cannot store {SSN_A}'; END $$"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER boom BEFORE INSERT ON sensitivity.findings \
         FOR EACH ROW EXECUTE FUNCTION witness_boom()",
    )
    .execute(&pool)
    .await
    .unwrap();
    remote_source(&pool, &format!("https://hr.example/{SSN_A}")).await;

    let t = tick(&pool, "kb_remote_sources.uri").await;

    assert!(t.failed);
    let (status, error): (String, Option<String>) = sqlx::query_as(
        "SELECT status, last_error FROM kb_workflow_jobs WHERE persona = 'sensitivity'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, "waiting_for_retry");
    assert_eq!(error.as_deref(), Some("scan_failed"));
    assert_holds_none_of(
        &everything_the_sweep_wrote(&pool).await,
        SSN_A,
        "the sweep's job and store",
    );

    let raw =
        sqlx::query("UPDATE kb_workflow_jobs SET last_error = $1 WHERE persona = 'sensitivity'")
            .bind(format!("cannot store {SSN_A}"))
            .execute(&pool)
            .await
            .unwrap_err();
    let constraint = match &raw {
        sqlx::Error::Database(db) => db.constraint().map(str::to_string),
        _ => None,
    };
    assert_eq!(
        constraint.as_deref(),
        Some("ck_workflow_jobs_sensitivity_last_error_coded"),
        "{raw}"
    );
}

// ── The two-phase tick: a tick that never finishes keeps its attempt and leaves its run ────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_claim_that_is_never_scanned_is_reaped_with_its_attempt_and_its_run_left_open(
    pool: PgPool,
) {
    let (run, job): (Uuid, Uuid) =
        sqlx::query_as("SELECT run_id, job_id FROM sensitivity_sweep_claim()")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "UPDATE kb_workflow_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(job)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("SELECT workflow_job_reap('lease expired')")
        .execute(&pool)
        .await
        .unwrap();

    let (status, attempts): (String, i32) =
        sqlx::query_as("SELECT status, attempts FROM kb_workflow_jobs WHERE id = $1")
            .bind(job)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        (status.as_str(), attempts),
        ("waiting_for_retry", 1),
        "the attempt survives the dead tick"
    );
    let open: bool = sqlx::query_scalar(
        "SELECT outcome IS NULL AND finished_at IS NULL FROM sensitivity.runs WHERE id = $1",
    )
    .bind(run)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(open, "the run is the record of a tick that never finished");

    let late: Option<bool> =
        sqlx::query_scalar("SELECT failed FROM sensitivity_sweep_tick($1, $2, $3)")
            .bind(run)
            .bind(job)
            .bind(SALT)
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert_eq!(late, None, "a reaped claim cannot be scanned late");
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn the_claim_rotates_through_every_enabled_text_surface(pool: PgPool) {
    let enabled: Vec<String> = sqlx::query_scalar(
        "SELECT surface FROM sensitivity.surfaces WHERE enabled AND shape = 'text' ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut picked = Vec::new();
    for _ in 0..enabled.len() {
        let (run, job): (Uuid, Uuid) =
            sqlx::query_as("SELECT run_id, job_id FROM sensitivity_sweep_claim()")
                .fetch_one(&pool)
                .await
                .unwrap();
        sqlx::query("SELECT failed FROM sensitivity_sweep_tick($1, $2, $3)")
            .bind(run)
            .bind(job)
            .bind(SALT)
            .execute(&pool)
            .await
            .unwrap();
        picked.push(
            sqlx::query_scalar::<_, String>("SELECT surface FROM sensitivity.runs WHERE id = $1")
                .bind(run)
                .fetch_one(&pool)
                .await
                .unwrap(),
        );
    }
    picked.sort();
    assert_eq!(
        picked, enabled,
        "each surface once before any surface twice"
    );
}

// ── Witness 27, the fingerprint half: every value in a unit is kept ────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_block_with_two_ssns_keeps_both_fingerprints_and_a_quote_of_either_matches(pool: PgPool) {
    let leak = block(
        &pool,
        resource(&pool, "leak").await,
        &format!("{SSN_A} and {SSN_B}"),
    )
    .await;
    let quote = block(
        &pool,
        resource(&pool, "deriver").await,
        &format!("as noted, {SSN_B}"),
    )
    .await;

    tick(&pool, "kb_block_content.content").await;

    let leak_found = findings_at(&pool, leak).await;
    assert_eq!(
        leak_found.len(),
        1,
        "one finding for the unit: {leak_found:?}"
    );
    assert_eq!((leak_found[0].3, leak_found[0].4.as_str()), (2, "complete"));
    let leak_prints = fingerprints(&pool, leak_found[0].0).await;
    assert_eq!(leak_prints.len(), 2, "both values are kept");
    let quote_prints = fingerprints(&pool, findings_at(&pool, quote).await[0].0).await;
    assert_eq!(quote_prints.len(), 1);
    assert!(
        leak_prints.contains(&quote_prints[0]),
        "the second value reaches the deriver"
    );
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn an_unsalted_or_capped_fingerprint_set_says_so(pool: PgPool) {
    let unsalted = block(&pool, resource(&pool, "u").await, SSN_A).await;
    tick_salted(&pool, "kb_block_content.content", None).await;
    let found = findings_at(&pool, unsalted).await;
    assert_eq!(found[0].4, "unsalted");
    assert!(fingerprints(&pool, found[0].0).await.is_empty());

    let many: Vec<String> = (100..165).map(|area| format!("{area}-01-0001")).collect();
    let capped = block(&pool, resource(&pool, "c").await, &many.join(" ")).await;
    tick(&pool, "kb_block_content.content").await;
    let found = findings_at(&pool, capped).await;
    assert_eq!((found[0].3, found[0].4.as_str()), (65, "truncated"));
    assert_eq!(fingerprints(&pool, found[0].0).await.len(), 64);
}

// ── Witness 28: acknowledgement survives re-reads and bumps, not recurrences ───────────────────

async fn last_seen_after_decision(pool: &PgPool, finding: Uuid, decided: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT f.last_seen > d.decided_at FROM sensitivity.findings f, sensitivity.dispositions d \
          WHERE f.id = $1 AND d.id = $2",
    )
    .bind(finding)
    .bind(decided)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn an_acknowledged_title_stays_acknowledged_until_the_value_comes_back(pool: PgPool) {
    let leaked = format!("Employee {SSN_A}");
    let r = resource(&pool, &leaked).await;
    tick(&pool, "kb_resources.title").await;
    let first = findings_at(&pool, r).await[0].0;
    let ack: Uuid = sqlx::query_scalar(
        "INSERT INTO sensitivity.dispositions (finding_id, state) VALUES ($1, 'acknowledged') RETURNING id",
    )
    .bind(first)
    .fetch_one(&pool)
    .await
    .unwrap();

    touch(&pool, r).await;
    tick(&pool, "kb_resources.title").await;
    assert!(
        !last_seen_after_decision(&pool, first, ack).await,
        "a re-read after a block edit"
    );

    bump(&pool, "us_ssn_delimited").await;
    tick(&pool, "kb_resources.title").await;
    let found = findings_at(&pool, r).await;
    assert_eq!(
        found.len(),
        2,
        "the bump re-detects under version 2: {found:?}"
    );
    assert!(
        !last_seen_after_decision(&pool, found[1].0, ack).await,
        "a bump's re-detection inherits"
    );

    retitle(&pool, r, "Employee (redacted)").await;
    tick(&pool, "kb_resources.title").await;
    retitle(&pool, r, &leaked).await;
    tick(&pool, "kb_resources.title").await;
    assert!(
        last_seen_after_decision(&pool, found[1].0, ack).await,
        "the value came back"
    );
}
