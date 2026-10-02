#![cfg(feature = "test-db")]
//! The queue's SYSTEM family: jobs with no anchor at all, for a sweep that is system-wide by nature.
//!
//! Under goal *"Personal data that lands in the corpus by accident is found"*, sensitivity-sweep spec
//! R5 and D8: the sweep rides `kb_workflow_jobs` rather than minting a second scheduler. That table
//! was built one anchor at a time (cogmap, then resource, then context), and every incumbent primitive
//! assumes an anchor is present. These are the witnesses that the fourth family works where the first
//! three cannot, and that widening the table for it does not loosen anything for the five incumbent
//! personas.
//!
//! Spec witnesses 13 (single-flight on an anchorless job), 15 (the payload is a work order) and 16
//! (anchorless completion). Also the plan's P1 guard: the scope CHECK keeps system personas
//! anchorless-only and everyone else exactly-one-anchor. Plus the guards the two review passes asked
//! for: payload values held to their shape, in-progress-only completion, and no incumbent door
//! reaching an anchorless job.

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use temper_core::types::workflow_job::{DispatchType, Persona, SensitivityJobPayload};
use temper_services::services::workflow_job_service::{
    claim_resource, claim_system, complete_system, enqueue_system, reap,
};

fn persona() -> &'static str {
    Persona::Sensitivity.as_str()
}

fn dispatch() -> &'static str {
    DispatchType::SensitivitySweep.as_str()
}

fn work_order() -> SensitivityJobPayload {
    SensitivityJobPayload {
        surface: "kb_block_content.content".into(),
        budget: 500,
    }
}

async fn jobs_for(pool: &PgPool, persona: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM kb_workflow_jobs WHERE persona = $1")
        .bind(persona)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn status_of(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM kb_workflow_jobs WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn a_resource(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO kb_resources (title, origin_uri) VALUES ('doc', '') RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Enqueue and claim one system job, returning its id in progress.
async fn an_in_progress_job(pool: &PgPool) -> Uuid {
    enqueue_system(pool, persona(), dispatch(), &work_order())
        .await
        .unwrap()
        .expect("enqueue creates a row");
    let claimed = claim_system::<SensitivityJobPayload>(pool, persona(), dispatch(), 10, 600)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    claimed[0].id
}

fn is_check_violation(e: &sqlx::Error, constraint: &str) -> bool {
    matches!(e, sqlx::Error::Database(db)
        if db.code().as_deref() == Some("23514") && db.constraint() == Some(constraint))
}

/// The CHECKs name the persona by a string literal, so the string the Rust enum writes must be the
/// string in the LIVE constraint definitions. Comparing against a constant in this file would only
/// prove two hand-copied strings agree.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn the_live_checks_name_the_persona_the_enum_writes(pool: PgPool) {
    let literal = format!("'{}'", persona());
    for constraint in [
        "ck_workflow_jobs_one_scope",
        "ck_workflow_jobs_sensitivity_work_order",
    ] {
        let def: String = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
              WHERE conrelid = 'kb_workflow_jobs'::regclass AND conname = $1",
        )
        .bind(constraint)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            def.contains(&literal),
            "{constraint} does not name {literal}: {def}"
        );
    }
}

// ── Witness 13: single-flight on an anchorless job ─────────────────────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn concurrent_anchorless_enqueues_yield_one_job(pool: PgPool) {
    let order = work_order();
    let (a, b) = tokio::join!(
        enqueue_system(&pool, persona(), dispatch(), &order),
        enqueue_system(&pool, persona(), dispatch(), &order),
    );
    let created = [a.unwrap(), b.unwrap()];
    assert_eq!(
        created.iter().filter(|id| id.is_some()).count(),
        1,
        "exactly one of two concurrent enqueues creates a row; the other reads as already queued"
    );
    assert_eq!(jobs_for(&pool, persona()).await, 1);
}

/// The bite. Spec F7.3: Postgres treats NULLs in a unique index as distinct, so the incumbent
/// `uq_workflow_jobs_in_flight` cannot see an anchorless row, and without its own index the second
/// insert simply succeeds. With `uq_workflow_jobs_in_flight_system` gone, two jobs coexist. That is
/// the double-scan this index exists to prevent, and it is what makes the witness above a witness.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn without_the_system_index_two_anchorless_jobs_coexist(pool: PgPool) {
    sqlx::query("DROP INDEX uq_workflow_jobs_in_flight_system")
        .execute(&pool)
        .await
        .unwrap();
    enqueue_system(&pool, persona(), dispatch(), &work_order())
        .await
        .unwrap();
    enqueue_system(&pool, persona(), dispatch(), &work_order())
        .await
        .unwrap();
    assert_eq!(jobs_for(&pool, persona()).await, 2);
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_completed_job_frees_the_slot(pool: PgPool) {
    let id = an_in_progress_job(&pool).await;
    complete_system(&pool, id, persona(), dispatch())
        .await
        .unwrap();
    let again = enqueue_system(&pool, persona(), dispatch(), &work_order())
        .await
        .unwrap();
    assert!(
        again.is_some(),
        "a done job no longer holds the in-flight slot"
    );
}

// ── Witness 16: anchorless completion ──────────────────────────────────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn complete_system_completes_by_job_id(pool: PgPool) {
    let id = an_in_progress_job(&pool).await;
    let done = complete_system(&pool, id, persona(), dispatch())
        .await
        .unwrap();
    assert_eq!(done, Some(id));
    assert_eq!(status_of(&pool, id).await, "done");
}

/// None of the three incumbent completers can complete an anchorless job, which is what makes
/// `complete_system` load-bearing rather than a duplicate. `complete` and `complete_resource` match
/// `<anchor> = p_anchor`, which is NULL for a NULL argument and so never true.
///
/// `complete_anchor` is the subtle one. It matches with `IS NOT DISTINCT FROM`, so before this
/// migration a call with both anchors NULL would have completed ANY anchorless job of the tuple: a
/// door into the system family from outside it. The migration that makes anchorless rows legal also
/// gives `complete_anchor` the `num_nonnulls(cogmap_id, context_id) = 1` guard its own claim already
/// carries, and this asserts the guard.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn the_incumbent_completers_cannot_complete_an_anchorless_job(pool: PgPool) {
    let id = an_in_progress_job(&pool).await;
    for door in [
        "SELECT workflow_job_complete(NULL, $1, $2)",
        "SELECT workflow_job_complete_resource(NULL, $1, $2)",
        "SELECT workflow_job_complete_anchor(NULL, NULL, $1, $2)",
    ] {
        let hit: Option<Uuid> = sqlx::query_scalar(door)
            .bind(persona())
            .bind(dispatch())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(hit, None, "{door} matched an anchorless row");
    }
    assert_eq!(status_of(&pool, id).await, "in_progress");
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn complete_system_never_completes_another_tuples_job(pool: PgPool) {
    let id = an_in_progress_job(&pool).await;
    let hit = complete_system(&pool, id, persona(), "some-other-dispatch")
        .await
        .unwrap();
    assert_eq!(hit, None, "a job id under the wrong tuple is not completed");
    assert_eq!(status_of(&pool, id).await, "in_progress");
}

/// A pending job is work nobody has dispatched yet. Completing it would cancel the next sweep tick
/// with nothing recording that it happened, the hazard `workflow_job_complete_claimed` was narrowed
/// against in `20260724000130`.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn complete_system_never_completes_a_pending_job(pool: PgPool) {
    let id = enqueue_system(&pool, persona(), dispatch(), &work_order())
        .await
        .unwrap()
        .unwrap();
    let hit = complete_system(&pool, id, persona(), dispatch())
        .await
        .unwrap();
    assert_eq!(hit, None);
    assert_eq!(status_of(&pool, id).await, "pending");
}

/// The id is the handle, but not a skeleton key. An anchored job's id handed to the system door,
/// under its own tuple, is refused, so a stray id cannot complete another family's job.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn complete_system_never_completes_an_anchored_job(pool: PgPool) {
    let resource = a_resource(&pool).await;
    sqlx::query("SELECT workflow_job_enqueue_resource($1, 'embed', 'embed')")
        .bind(resource)
        .execute(&pool)
        .await
        .unwrap();
    let claimed = claim_resource(&pool, "embed", "embed", 10, 600)
        .await
        .unwrap();
    let id = claimed[0].id;
    let hit = complete_system(&pool, id, "embed", "embed").await.unwrap();
    assert_eq!(hit, None);
    assert_eq!(status_of(&pool, id).await, "in_progress");
}

// ── The claims ─────────────────────────────────────────────────────────────────────────────────

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn claim_system_leases_and_returns_the_work_order(pool: PgPool) {
    enqueue_system(&pool, persona(), dispatch(), &work_order())
        .await
        .unwrap();
    let claimed = claim_system::<SensitivityJobPayload>(&pool, persona(), dispatch(), 10, 600)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].attempts, 1, "attempts incremented at claim");
    assert_eq!(claimed[0].payload, work_order());
    assert_eq!(status_of(&pool, claimed[0].id).await, "in_progress");
    let again = claim_system::<SensitivityJobPayload>(&pool, persona(), dispatch(), 10, 600)
        .await
        .unwrap();
    assert!(again.is_empty(), "in_progress is not re-claimable");
}

/// The system claim takes anchorless rows only. Called with an incumbent tuple, it must not hand
/// out that family's anchored jobs; the worker would receive a job with a scope it does not know it
/// has.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn claim_system_never_claims_an_anchored_row(pool: PgPool) {
    let resource = a_resource(&pool).await;
    sqlx::query("SELECT workflow_job_enqueue_resource($1, 'embed', 'embed')")
        .bind(resource)
        .execute(&pool)
        .await
        .unwrap();
    let claimed = claim_system::<serde_json::Value>(&pool, "embed", "embed", 10, 600)
        .await
        .unwrap();
    assert!(claimed.is_empty());
}

/// The other direction. The cogmap claim had no anchor predicate, and with no principal (its
/// documented unscoped default) it would hand out an anchorless job. It now takes cogmap rows only.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn the_unscoped_cogmap_claim_never_takes_an_anchorless_job(pool: PgPool) {
    enqueue_system(&pool, persona(), dispatch(), &work_order())
        .await
        .unwrap();
    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM workflow_job_claim($1, $2, 10, 600)")
        .bind(persona())
        .bind(dispatch())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(taken, 0);
}

/// Inherited unchanged (spec D8): the reaper is anchor-agnostic, so a system job whose lease
/// expires is retried on the same ladder as every other family.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn an_expired_system_lease_is_reaped_for_retry(pool: PgPool) {
    enqueue_system(&pool, persona(), dispatch(), &work_order())
        .await
        .unwrap();
    let claimed = claim_system::<SensitivityJobPayload>(&pool, persona(), dispatch(), 10, -1)
        .await
        .unwrap();
    assert_eq!(reap(&pool, "lease expired").await.unwrap(), 1);
    assert_eq!(status_of(&pool, claimed[0].id).await, "waiting_for_retry");
}

// ── Witness 15: the job payload is a work order ────────────────────────────────────────────────

async fn raw_enqueue(pool: &PgPool, payload: serde_json::Value) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT workflow_job_enqueue_system($1, $2, $3)")
        .bind(persona())
        .bind(dispatch())
        .bind(payload)
        .execute(pool)
        .await
        .map(|_| ())
}

async fn assert_refused_as_a_work_order(pool: &PgPool, payload: serde_json::Value) {
    let err = raw_enqueue(pool, payload.clone()).await.unwrap_err();
    assert!(
        is_check_violation(&err, "ck_workflow_jobs_sensitivity_work_order"),
        "{payload}: {err}"
    );
}

/// Spec D8 constraint 1: no resource id, no hash, no category, no count. A convenience field added
/// later is rejected by the table, not caught in review.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_payload_carrying_anything_beyond_the_work_order_is_refused(pool: PgPool) {
    for extra in ["resource_id", "content_hash", "category", "new_findings"] {
        let mut payload = serde_json::to_value(work_order()).unwrap();
        payload[extra] = json!("x");
        assert_refused_as_a_work_order(&pool, payload).await;
    }
    assert_eq!(jobs_for(&pool, persona()).await, 0);
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_payload_missing_part_of_the_work_order_is_refused(pool: PgPool) {
    for payload in [
        json!({}),
        json!({"surface": "kb_resources.title"}),
        json!({"budget": 10}),
        json!(["surface", "budget"]),
    ] {
        assert_refused_as_a_work_order(&pool, payload).await;
    }
}

/// The keys alone are not the guarantee. Each of these was accepted when only the key set was
/// checked, and the security review enqueued exactly this kind of row: content travelling under a
/// legitimate key. Each value is now held to the shape its key promises.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn content_under_a_legitimate_key_is_refused(pool: PgPool) {
    for (key, value) in [
        (
            "surface",
            json!({"resource_id": "x", "content": "jane@example.com"}),
        ),
        ("surface", json!("jane.doe@example.com")),
        ("surface", json!("kb_resources.title SSN 123-45-6789")),
        ("budget", json!("Jane Doe DOB 1980-01-01")),
        ("budget", json!(-1)),
        ("budget", json!(1.5)),
        ("budget", json!(10_000_000_000_i64)),
        // An SSN with its dashes stripped: inside an int, outside a tick budget.
        ("budget", json!(123_456_789)),
        ("budget", json!(100_001)),
        ("budget", json!(0)),
        // Shaped like `x.y` but no kb_ table: the re-review's probe.
        ("surface", json!("jane.doe")),
    ] {
        let mut payload = serde_json::to_value(work_order()).unwrap();
        payload[key] = value;
        assert_refused_as_a_work_order(&pool, payload).await;
    }
    assert_eq!(jobs_for(&pool, persona()).await, 0);
}

/// The budget bound is inclusive at both ends, so tightening it cannot quietly refuse a real tick.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn the_budget_bounds_admit_one_and_one_hundred_thousand(pool: PgPool) {
    for budget in [1, 100_000] {
        let order = SensitivityJobPayload {
            surface: "kb_resources.title".into(),
            budget,
        };
        enqueue_system(&pool, persona(), dispatch(), &order)
            .await
            .unwrap_or_else(|e| panic!("{budget}: {e}"))
            .expect("the slot is free");
        let claimed = claim_system::<SensitivityJobPayload>(&pool, persona(), dispatch(), 1, 600)
            .await
            .unwrap();
        assert_eq!(claimed[0].payload, order);
        complete_system(&pool, claimed[0].id, persona(), dispatch())
            .await
            .unwrap();
    }
}

/// The ruling of 2026-10-02: no cursor travels in the payload. On an append-only surface a
/// watermark is the id of the last row read, a row from some tenant's content, and the claim that
/// hands the payload out is unscoped. So a resume point is refused in any shape, including the two
/// shapes spec D4's cursors would take. The watermark lives in the sweep's guarded store.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_resume_point_is_never_part_of_the_work_order(pool: PgPool) {
    for cursor in [
        json!(null),
        json!("01a0e9e6-959b-7780-af70-25ceb0f632e3"),
        json!("2026-10-01T21:30:10.123456Z"),
    ] {
        let mut payload = serde_json::to_value(work_order()).unwrap();
        payload["cursor_from"] = cursor;
        assert_refused_as_a_work_order(&pool, payload).await;
    }
    assert_eq!(jobs_for(&pool, persona()).await, 0);
}

/// Asserted over every sensitivity job's jsonb keys, as the spec words witness 15, so the test reads
/// the stored rows and not the type that wrote them.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn every_enqueued_sensitivity_payload_is_exactly_the_work_order(pool: PgPool) {
    enqueue_system(&pool, persona(), dispatch(), &work_order())
        .await
        .unwrap();
    let keys: Vec<Vec<String>> = sqlx::query_scalar(
        "SELECT array_agg(k ORDER BY k) FROM kb_workflow_jobs j, jsonb_object_keys(j.payload) k \
          WHERE j.persona = $1 GROUP BY j.id",
    )
    .bind(persona())
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(keys, vec![vec!["budget", "surface"]]);
}

// ── P1: the scope CHECK, in both directions ────────────────────────────────────────────────────

/// The incumbent wrappers say an anchorless row of their family "should be unreachable"
/// (`workflow_job_service.rs`, `claim_anchor`). Widening the CHECK must not make it reachable: a NULL
/// passed by mistake to the embed path still raises rather than queueing a job with no scope.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn an_incumbent_persona_still_cannot_write_an_anchorless_job(pool: PgPool) {
    for call in [
        "SELECT workflow_job_enqueue_resource(NULL, 'embed', 'embed')",
        "SELECT workflow_job_enqueue_system('steward', 'steward', '{}'::jsonb)",
    ] {
        let err = sqlx::query(call).execute(&pool).await.unwrap_err();
        assert!(
            is_check_violation(&err, "ck_workflow_jobs_one_scope"),
            "{call}: {err}"
        );
    }
    assert_eq!(
        jobs_for(&pool, "embed").await + jobs_for(&pool, "steward").await,
        0
    );
}

/// The gate's other direction, and the one both reviews found missing. A sensitivity job carrying
/// a resource anchor would be handed out by the unscoped resource claim with a resource id on it.
/// It would also make that resource unerasable: the erasure act sets `payload = '{}'` on every job
/// of the resource, `'{}'` fails the work-order CHECK, and the act rolls back. So the row cannot be
/// written at all.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_sensitivity_job_can_never_carry_an_anchor(pool: PgPool) {
    let resource = a_resource(&pool).await;
    let err = sqlx::query("SELECT workflow_job_enqueue_resource($1, $2, $3, $4)")
        .bind(resource)
        .bind(persona())
        .bind(dispatch())
        .bind(serde_json::to_value(work_order()).unwrap())
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(
        is_check_violation(&err, "ck_workflow_jobs_one_scope"),
        "{err}"
    );
    assert_eq!(jobs_for(&pool, persona()).await, 0);
}

/// Two anchors stay refused for every persona.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn two_anchors_stay_refused(pool: PgPool) {
    let resource = a_resource(&pool).await;
    let telos = a_resource(&pool).await;
    let cogmap: Uuid = sqlx::query_scalar(
        "INSERT INTO kb_cogmaps (name, telos_resource_id) VALUES ('m', $1) RETURNING id",
    )
    .bind(telos)
    .fetch_one(&pool)
    .await
    .unwrap();
    let err = sqlx::query(
        "INSERT INTO kb_workflow_jobs (resource_id, cogmap_id, persona, dispatch_type) \
         VALUES ($1, $2, 'embed', 'embed')",
    )
    .bind(resource)
    .bind(cogmap)
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(
        is_check_violation(&err, "ck_workflow_jobs_one_scope"),
        "{err}"
    );
}
