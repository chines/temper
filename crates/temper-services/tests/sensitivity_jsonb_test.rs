#![cfg(feature = "test-db")]
//! The sensitivity sweep over its jsonb surfaces, per-path ledger remediability and derived closure
//! (build order 3a, PR C2).
//!
//! Under goal *"Personal data that lands in the corpus by accident is found"*, sensitivity-sweep spec
//! D2, D3 and rulings Q26, Q34 and Q37-Q39. Spec witnesses 9, 25 (the `blocked:cut-2` half; its
//! `remediable` half needs erasure cut 2, Q39) and 26 (the erasure half; the block-scrub half needs
//! erasure 2e). Also the path walk's guards: user-map keys are written `?`, a jsonb row is scanned
//! whole, and the interim remediability table is held equal to the live erasure survey.
//!
//! Ledger rows are planted with raw inserts: these witnesses are about what the scan reads. Witness
//! 26 runs the real erasure act over a resource built through the real write path.

use sqlx::{PgPool, Row};
use temper_core::types::ids::{EntityId, ProfileId};
use temper_substrate::payloads::AnchorRef;
use temper_substrate::scenario::bootseed;
use temper_substrate::writes::{self, CreateParams};
use uuid::Uuid;

const SALT: &[u8] = b"witness-salt-of-sixteen-plus";
const SSN_A: &str = "219-45-6789";
const SSN_B: &str = "536-22-8147";
const NO_LAG: &str = "0 seconds";

#[derive(Debug, Clone, Copy)]
struct Tick {
    rows_examined: i32,
    failed: bool,
}

async fn tick_budget(pool: &PgPool, surface: &str, budget: i32) -> Tick {
    sqlx::query("SELECT workflow_job_enqueue_system('sensitivity', 'sensitivity-sweep', $1)")
        .bind(serde_json::json!({ "surface": surface, "budget": budget }))
        .execute(pool)
        .await
        .unwrap();
    let (run, job): (Uuid, Uuid) =
        sqlx::query_as("SELECT run_id, job_id FROM sensitivity_sweep_claim()")
            .fetch_one(pool)
            .await
            .unwrap();
    let row = sqlx::query(
        "SELECT rows_examined, failed \
           FROM sensitivity_sweep_tick($1, $2, $3, $4::interval)",
    )
    .bind(run)
    .bind(job)
    .bind(SALT)
    .bind(NO_LAG)
    .fetch_one(pool)
    .await
    .unwrap();
    Tick {
        rows_examined: row.get(0),
        failed: row.get(1),
    }
}

async fn tick(pool: &PgPool, surface: &str) -> Tick {
    tick_budget(pool, surface, 1000).await
}

/// One ledger row of `event_type`, carrying `payload` and `metadata` as given.
async fn event(
    pool: &PgPool,
    event_type: &str,
    payload: serde_json::Value,
    metadata: serde_json::Value,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO kb_events (event_type_id, emitter_entity_id, category, payload, metadata)
         SELECT t.id, (SELECT id FROM kb_entities ORDER BY id LIMIT 1), t.category, $2, $3
           FROM kb_event_types t WHERE t.name = $1
         RETURNING id",
    )
    .bind(event_type)
    .bind(payload)
    .bind(metadata)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// `(path, detector_id)` of every finding at `target`, in path order.
async fn findings_at(pool: &PgPool, target: Uuid) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT path, detector_id FROM sensitivity.findings WHERE target_id = $1 ORDER BY path, detector_id",
    )
    .bind(target)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn remediability_at(pool: &PgPool, target: Uuid) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT f.path, r.remediability FROM sensitivity.ledger_finding_remediability r \
           JOIN sensitivity.findings f ON f.id = r.finding_id WHERE f.target_id = $1 ORDER BY f.path",
    )
    .bind(target)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn closed_by(pool: &PgPool, target: Uuid) -> Vec<Option<String>> {
    sqlx::query_scalar(
        "SELECT c.closed_by FROM sensitivity.findings f \
           LEFT JOIN sensitivity.finding_closure c ON c.finding_id = f.id \
          WHERE f.target_id = $1 ORDER BY f.path NULLS FIRST, f.detector_id",
    )
    .bind(target)
    .fetch_all(pool)
    .await
    .unwrap()
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

// ── Q26: a jsonb finding is a structural path, and a user's keys are never written ────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_user_map_key_is_written_as_a_question_mark_and_still_scanned(pool: PgPool) {
    let e = event(
        &pool,
        "property_set",
        serde_json::json!({
            "property_key": "notes",
            "value": { "jane_doe": format!("ssn {SSN_A}"), format!("ref {SSN_B}"): "x" },
        }),
        serde_json::json!({}),
    )
    .await;

    let t = tick(&pool, "kb_events.payload").await;

    assert!(!t.failed, "{t:?}");
    assert_eq!(
        findings_at(&pool, e).await,
        vec![
            ("/value/?".to_string(), "us_ssn_delimited".to_string()),
            ("/value/?".to_string(), "us_ssn_delimited".to_string()),
        ],
        "a value under a user key, and a user key itself, are found at `?` and never by name"
    );
    let paths: String = sqlx::query_scalar(
        "SELECT string_agg(path, ',') FROM sensitivity.findings WHERE target_id = $1",
    )
    .bind(e)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !paths.contains("jane_doe"),
        "a letters-only user key is still a user's key"
    );
    let store = everything_the_sweep_wrote(&pool).await;
    assert_holds_none_of(&store, SSN_A, "the sensitivity store");
    assert_holds_none_of(&store, SSN_B, "the sensitivity store");
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_webhook_document_is_scanned_at_hidden_paths_and_tallied(pool: PgPool) {
    let e = event(
        &pool,
        "webhook_received",
        serde_json::json!({
            "issue": { "body": format!("my ssn is {SSN_A}"), "number": 7 },
            "resource_id": Uuid::now_v7().to_string(),
        }),
        serde_json::json!({ "provider_event_type": "issues", "provider_event_type_source": "header" }),
    )
    .await;

    tick(&pool, "kb_events.payload").await;

    assert_eq!(
        findings_at(&pool, e).await,
        vec![("/?/?".to_string(), "us_ssn_delimited".to_string())],
        "the provider's keys are its own, so none is written (Q37)"
    );
    let resource: Option<Uuid> =
        sqlx::query_scalar("SELECT resource_id FROM sensitivity.findings WHERE target_id = $1")
            .bind(e)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        resource, None,
        "a webhook belongs to no resource, whatever its provider calls a resource_id"
    );
    let tally: serde_json::Value = sqlx::query_scalar(
        "SELECT units_by_event_type -> 'webhook_received' FROM sensitivity.runs WHERE surface = 'kb_events.payload' \
          ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        tally,
        serde_json::json!(7),
        "each run counts the units each event type contributed: three leaves and four keys"
    );
}

// ── The C1 design review's trap: a row is never scanned in half ───────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_jsonb_row_is_scanned_whole_under_a_one_row_budget(pool: PgPool) {
    // History first, so the one-row budget is spent by the head on this event alone.
    let e = event(
        &pool,
        "resource_created",
        serde_json::json!({ "title": format!("about {SSN_A}"), "origin_uri": format!("https://hr.example/{SSN_B}") }),
        serde_json::json!({}),
    )
    .await;
    tick(&pool, "kb_events.payload").await;
    let later = event(
        &pool,
        "resource_created",
        serde_json::json!({ "title": format!("about {SSN_A}"), "origin_uri": format!("https://hr.example/{SSN_B}") }),
        serde_json::json!({}),
    )
    .await;

    let t = tick_budget(&pool, "kb_events.payload", 1).await;

    assert_eq!(t.rows_examined, 1, "{t:?}");
    assert_eq!(
        findings_at(&pool, later).await.len(),
        2,
        "both of the row's units are scanned before its id passes under the watermark"
    );
    assert_eq!(findings_at(&pool, e).await.len(), 2);
}

// ── A payload's ids are scanned, and not remembered ───────────────────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_jsonb_unit_no_prefilter_nominates_leaves_no_memo_row(pool: PgPool) {
    let prose = "plain words with nothing in them";
    event(
        &pool,
        "resource_created",
        serde_json::json!({ "title": prose }),
        serde_json::json!({}),
    )
    .await;

    tick(&pool, "kb_events.payload").await;

    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sensitivity.memo WHERE content_hash = sensitivity.keyed_hash($1, $2)",
    )
    .bind(SALT)
    .bind(prose)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        rows, 0,
        "a jsonb unit no detector's prefilter matched is not memoised"
    );
}

// ── Witness 25: remediability is per (event_type, path) ───────────────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn remediability_is_read_per_event_type_and_path(pool: PgPool) {
    let created = event(
        &pool,
        "resource_created",
        serde_json::json!({ "title": format!("Payroll for {SSN_A}"), "doc_type": format!("t {SSN_B}") }),
        serde_json::json!({ "reasoning": format!("saw {SSN_A}"), "persona": format!("p {SSN_B}") }),
    )
    .await;
    let renamed = event(
        &pool,
        "context_renamed",
        serde_json::json!({ "to_name": format!("Team {SSN_A}") }),
        serde_json::json!({}),
    )
    .await;
    let set = event(
        &pool,
        "property_set",
        serde_json::json!({ "property_key": "notes", "value": { "k": SSN_B } }),
        serde_json::json!({}),
    )
    .await;

    tick(&pool, "kb_events.payload").await;
    tick(&pool, "kb_events.metadata").await;

    let blocked = "blocked:cut-2".to_string();
    let never = "unremediable".to_string();
    assert_eq!(
        remediability_at(&pool, created).await,
        vec![
            ("/doc_type".to_string(), never.clone()),
            ("/persona".to_string(), never.clone()),
            ("/reasoning".to_string(), blocked.clone()),
            ("/title".to_string(), blocked.clone()),
        ],
        "a ledger_remainder path waits on cut 2; one outside it never has a remedy"
    );
    assert_eq!(
        remediability_at(&pool, renamed).await,
        vec![("/to_name".to_string(), never)],
        "a context's name is permanently outside the redaction (D3)"
    );
    assert_eq!(
        remediability_at(&pool, set).await,
        vec![("/value/?".to_string(), blocked)],
        "a listed path covers its whole subtree"
    );
}

/// The interim table is the live `ledger_remainder` CASE, arm for arm. When erasure changes the
/// CASE, this fails until the table follows.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn the_interim_remediability_table_is_the_live_erasure_survey(pool: PgPool) {
    let live: std::collections::BTreeSet<(Option<String>, String)> = sqlx::query_as(
        r#"WITH def AS (SELECT pg_get_functiondef('resource_erasure_survey_plan'::regproc) AS d)
           SELECT m[1], jsonb_array_elements_text(m[2]::jsonb)
             FROM def, regexp_matches(d, $$WHEN '([a-z_]+)'\s+THEN '(\[[^']*\])'::jsonb$$, 'g') m
           UNION
           SELECT NULL, jsonb_array_elements_text(m[1]::jsonb)
             FROM def, regexp_matches(d, $$THEN '(\["metadata\.[^']*\])'::jsonb$$, 'g') m"#,
    )
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .collect();
    let table: std::collections::BTreeSet<(Option<String>, String)> =
        sqlx::query_as("SELECT event_type, erasure_path FROM sensitivity.ledger_redact_paths")
            .fetch_all(&pool)
            .await
            .unwrap()
            .into_iter()
            .collect();
    assert!(live.len() > 20, "the parse found the CASE: {live:?}");
    assert_eq!(table, live);
}

// ── Witness 9: closure derives, and never from a hash disappearing ────────────────────────────

/// One block on `resource` holding `content`; returns the revision id.
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

async fn bare_resource(pool: &PgPool, title: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO kb_resources (title, origin_uri) VALUES ($1, 'test://witness') RETURNING id",
    )
    .bind(title)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn closure_reads_emptied_content_and_a_changed_title_never_a_missing_hash(pool: PgPool) {
    let r = bare_resource(&pool, &format!("Payroll for {SSN_A}")).await;
    let emptied = block(&pool, r, &format!("SSN {SSN_A}")).await;
    let kept = block(&pool, r, &format!("SSN {SSN_B}")).await;
    tick(&pool, "kb_block_content.content").await;
    tick(&pool, "kb_resources.title").await;
    assert_eq!(closed_by(&pool, emptied).await, vec![None]);
    assert_eq!(closed_by(&pool, r).await, vec![None]);

    // Principal erasure's footprint on content (20260911000000:69, :143): the content emptied, its
    // hash kept in the row and recorded in kb_erased_content.
    sqlx::query("UPDATE kb_block_content SET content = '' WHERE block_revision_id = $1")
        .bind(emptied)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE kb_resources SET title = 'Payroll', updated = clock_timestamp() WHERE id = $1",
    )
    .bind(r)
    .execute(&pool)
    .await
    .unwrap();
    tick(&pool, "kb_resources.title").await;

    let hash_kept: bool = sqlx::query_scalar(
        "SELECT content_hash <> '' FROM kb_block_content WHERE block_revision_id = $1",
    )
    .bind(emptied)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        hash_kept,
        "the source keeps its hash, so a hash-absence rule would not close"
    );
    assert_eq!(
        closed_by(&pool, emptied).await,
        vec![Some("content_empty".to_string())]
    );
    assert_eq!(
        closed_by(&pool, r).await,
        vec![Some("changed".to_string())],
        "the sweep's later observation of the title closes it"
    );
    assert_eq!(
        closed_by(&pool, kept).await,
        vec![None],
        "a live place stays open"
    );
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn every_enabled_surface_has_a_closure_rule(pool: PgPool) {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT surface, sensitivity.place_closure(surface, gen_random_uuid(), repeat('0', 64)) \
           FROM sensitivity.surfaces WHERE enabled ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    for (surface, closed) in rows {
        let expected = if surface.starts_with("kb_events.") {
            None
        } else {
            Some("row_missing".to_string())
        };
        assert_eq!(
            closed, expected,
            "{surface}: a missing place closes, and the ledger never closes here (Q38)"
        );
    }
}

// ── Witness 26: sentinel closure, through the real act ────────────────────────────────────────

async fn system_actor(pool: &PgPool) -> (ProfileId, EntityId) {
    let profile: Uuid = sqlx::query_scalar("SELECT id FROM kb_profiles WHERE handle='system'")
        .fetch_one(pool)
        .await
        .unwrap();
    let entity: Uuid =
        sqlx::query_scalar("SELECT id FROM kb_entities WHERE profile_id=$1 AND name='system'")
            .bind(profile)
            .fetch_one(pool)
            .await
            .unwrap();
    (ProfileId::from(profile), EntityId::from(entity))
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_resource_erasure_closes_its_title_and_property_findings_and_not_its_ledger(
    pool: PgPool,
) {
    bootseed::seed_system(&pool).await.unwrap();
    let (owner, emitter) = system_actor(&pool).await;
    let home: Uuid = sqlx::query_scalar(
        "INSERT INTO kb_contexts (owner_table, owner_id, slug, name) \
         VALUES ('kb_profiles', $1, 'sweep-home', 'sweep-home') RETURNING id",
    )
    .bind(owner.uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    let title = format!("Payroll for {SSN_A}");
    let resource = writes::create_resource_with(
        &pool,
        CreateParams {
            idempotency_key: None,
            title: &title,
            origin_uri: "test://sweep",
            body: "clean prose",
            doc_type: "research",
            home: AnchorRef::context(temper_core::types::ids::ContextId::from(home)),
            owner,
            originator: owner,
            emitter,
            properties: &[],
            chunks: None,
            sources: vec![],
        },
        temper_substrate::events::EventContext::default(),
    )
    .await
    .expect("create through the write path");
    let key = format!("ssn {SSN_B}");
    writes::set_property(&pool, resource, &key, &serde_json::json!("v"), emitter)
        .await
        .unwrap();
    let property: Uuid = sqlx::query_scalar(
        "SELECT id FROM kb_properties WHERE owner_id = $1 AND property_key = $2",
    )
    .bind(resource.uuid())
    .bind(&key)
    .fetch_one(&pool)
    .await
    .unwrap();
    for surface in [
        "kb_resources.title",
        "kb_properties.property_key",
        "kb_events.payload",
    ] {
        assert!(!tick(&pool, surface).await.failed, "{surface}");
    }
    let created: Uuid = sqlx::query_scalar(
        "SELECT f.target_id FROM sensitivity.findings f WHERE f.surface = 'kb_events.payload' \
            AND f.path = '/title' AND f.resource_id = $1",
    )
    .bind(resource.uuid())
    .fetch_one(&pool)
    .await
    .expect("the ledger's copy of the title is found");

    sqlx::query("SELECT resource_erasure_execute($1, $2, $2, $3)")
        .bind(resource.uuid())
        .bind(emitter)
        .bind(Uuid::now_v7())
        .execute(&pool)
        .await
        .expect("the act completes");

    assert_eq!(
        closed_by(&pool, resource.uuid()).await,
        vec![Some("sentinel".to_string())],
        "the husk's title is a sentinel, though the surface is not empty"
    );
    assert_eq!(
        closed_by(&pool, property).await,
        vec![Some("sentinel".to_string())],
        "the property key is a sentinel"
    );
    let ledger: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT c.closed_by FROM sensitivity.findings f \
           LEFT JOIN sensitivity.finding_closure c ON c.finding_id = f.id \
          WHERE f.target_id = $1 AND f.path = '/title'",
    )
    .bind(created)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        ledger,
        vec![None],
        "cut 1 leaves the title in the trail, so its finding stays open (Q38)"
    );
}
