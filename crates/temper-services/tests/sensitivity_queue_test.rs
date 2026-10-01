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
//! (anchorless completion), plus the plan's P1 guard: the zero-anchor arm of
//! `ck_workflow_jobs_one_scope` admits only the declared system personas.

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use temper_core::types::workflow_job::{DispatchType, Persona, SensitivityJobPayload};
use temper_services::services::workflow_job_service::{
    claim_system, complete_system, enqueue_system, reap,
};

const SENSITIVITY: &str = "sensitivity";

fn persona() -> &'static str {
    Persona::Sensitivity.as_str()
}

fn dispatch() -> &'static str {
    DispatchType::SensitivitySweep.as_str()
}

fn work_order() -> SensitivityJobPayload {
    SensitivityJobPayload {
        surface: "kb_block_content.content".into(),
        cursor_from: None,
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

/// The persona string the SQL guards name and the one the Rust enum writes are the same string.
/// The CHECKs key on a literal, so a renamed variant would otherwise slip past them silently.
#[test]
fn the_enum_writes_the_persona_the_checks_name() {
    assert_eq!(persona(), SENSITIVITY);
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
    assert_eq!(jobs_for(&pool, SENSITIVITY).await, 1);
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
    assert_eq!(jobs_for(&pool, SENSITIVITY).await, 2);
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_completed_job_frees_the_slot(pool: PgPool) {
    let id = enqueue_system(&pool, persona(), dispatch(), &work_order())
        .await
        .unwrap()
        .expect("first enqueue creates a row");
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
    enqueue_system(&pool, persona(), dispatch(), &work_order())
        .await
        .unwrap();
    let claimed = claim_system::<SensitivityJobPayload>(&pool, persona(), dispatch(), 10, 600)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    let done = complete_system(&pool, claimed[0].id, persona(), dispatch())
        .await
        .unwrap();
    assert_eq!(done, Some(claimed[0].id));
    assert_eq!(status_of(&pool, claimed[0].id).await, "done");
}

/// None of the three incumbent completers can complete an anchorless job, which is what makes
/// `complete_system` load-bearing rather than a duplicate. `complete` and `complete_resource` match
/// `<anchor> = p_anchor`, which is NULL for a NULL argument and so never true.
///
/// `complete_anchor` is the subtle one. It matches with `IS NOT DISTINCT FROM`, so before this
/// migration a call with both anchors NULL would have completed ANY anchorless job of the tuple: a
/// door into the system family from outside it. That door was unreachable while the CHECK forbade
/// anchorless rows. The migration that makes them legal also gives `complete_anchor` the same
/// `num_nonnulls(cogmap_id, context_id) = 1` guard its own claim already carries, and this asserts
/// the guard.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn the_incumbent_completers_cannot_complete_an_anchorless_job(pool: PgPool) {
    let id = enqueue_system(&pool, persona(), dispatch(), &work_order())
        .await
        .unwrap()
        .unwrap();
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
    assert_eq!(status_of(&pool, id).await, "pending");
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn complete_system_never_completes_another_tuples_job(pool: PgPool) {
    let id = enqueue_system(&pool, persona(), dispatch(), &work_order())
        .await
        .unwrap()
        .unwrap();
    let hit = complete_system(&pool, id, persona(), "some-other-dispatch")
        .await
        .unwrap();
    assert_eq!(hit, None, "a job id under the wrong tuple is not completed");
    assert_eq!(status_of(&pool, id).await, "pending");
}

/// The id is the handle, but not a skeleton key. An anchored job's id handed to the system door is
/// refused, so a stray id cannot complete another family's job.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn complete_system_never_completes_an_anchored_job(pool: PgPool) {
    let resource: Uuid = sqlx::query_scalar(
        "INSERT INTO kb_resources (title, origin_uri) VALUES ('doc', '') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let id: Uuid = sqlx::query_scalar("SELECT workflow_job_enqueue_resource($1, $2, $3, $4)")
        .bind(resource)
        .bind(persona())
        .bind(dispatch())
        .bind(serde_json::to_value(work_order()).unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    let hit = complete_system(&pool, id, persona(), dispatch())
        .await
        .unwrap();
    assert_eq!(hit, None);
    assert_eq!(status_of(&pool, id).await, "pending");
}

// ── The claim ──────────────────────────────────────────────────────────────────────────────────

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

/// The system claim takes anchorless rows only. A resource-anchored row under the same tuple belongs
/// to the resource family's claim, and handing it out here would give the worker a scope it does not
/// know it has.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn claim_system_never_claims_an_anchored_row(pool: PgPool) {
    let resource: Uuid = sqlx::query_scalar(
        "INSERT INTO kb_resources (title, origin_uri) VALUES ('doc', '') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("SELECT workflow_job_enqueue_resource($1, $2, $3, $4)")
        .bind(resource)
        .bind(persona())
        .bind(dispatch())
        .bind(serde_json::to_value(work_order()).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let claimed = claim_system::<SensitivityJobPayload>(&pool, persona(), dispatch(), 10, 600)
        .await
        .unwrap();
    assert!(claimed.is_empty());
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

fn is_check_violation(e: &sqlx::Error, constraint: &str) -> bool {
    matches!(e, sqlx::Error::Database(db)
        if db.code().as_deref() == Some("23514") && db.constraint() == Some(constraint))
}

/// Spec D8 constraint 1: no resource id, no hash, no category, no count. A convenience field added
/// later is rejected by the table, not caught in review.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_payload_carrying_anything_beyond_the_work_order_is_refused(pool: PgPool) {
    for extra in ["resource_id", "content_hash", "category", "new_findings"] {
        let mut payload = serde_json::to_value(work_order()).unwrap();
        payload[extra] = json!("x");
        let err = raw_enqueue(&pool, payload).await.unwrap_err();
        assert!(
            is_check_violation(&err, "ck_workflow_jobs_sensitivity_work_order"),
            "{extra}: {err}"
        );
    }
    assert_eq!(jobs_for(&pool, SENSITIVITY).await, 0);
}

#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn a_payload_missing_part_of_the_work_order_is_refused(pool: PgPool) {
    for payload in [
        json!({}),
        json!({"surface": "kb_resources.title", "budget": 10}),
        json!(["surface", "cursor_from", "budget"]),
    ] {
        let err = raw_enqueue(&pool, payload.clone()).await.unwrap_err();
        assert!(
            is_check_violation(&err, "ck_workflow_jobs_sensitivity_work_order"),
            "{payload}: {err}"
        );
    }
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
    .bind(SENSITIVITY)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(keys, vec![vec!["budget", "cursor_from", "surface"]]);
}

// ── P1: the zero-anchor arm admits only the declared system personas ───────────────────────────

/// The incumbent wrappers say an anchorless row of their family "should be unreachable"
/// (`workflow_job_service.rs`, `claim_anchor`). Widening the CHECK must not make it reachable: a NULL
/// passed by mistake to the embed path still raises rather than queueing a job with no scope.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn an_incumbent_persona_still_cannot_write_an_anchorless_job(pool: PgPool) {
    let err = sqlx::query("SELECT workflow_job_enqueue_resource(NULL, 'embed', 'embed')")
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(
        is_check_violation(&err, "ck_workflow_jobs_one_scope"),
        "{err}"
    );

    let err = sqlx::query("SELECT workflow_job_enqueue_system('steward', 'steward', '{}'::jsonb)")
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(
        is_check_violation(&err, "ck_workflow_jobs_one_scope"),
        "{err}"
    );
    assert_eq!(
        jobs_for(&pool, "embed").await + jobs_for(&pool, "steward").await,
        0
    );
}

/// The other half of "exactly one": two anchors stay refused for every persona, system ones
/// included.
#[sqlx::test(migrator = "temper_services::MIGRATOR")]
async fn two_anchors_stay_refused(pool: PgPool) {
    let resource: Uuid = sqlx::query_scalar(
        "INSERT INTO kb_resources (title, origin_uri) VALUES ('doc', '') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let telos: Uuid = sqlx::query_scalar(
        "INSERT INTO kb_resources (title, origin_uri) VALUES ('telos', '') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let cogmap: Uuid = sqlx::query_scalar(
        "INSERT INTO kb_cogmaps (name, telos_resource_id) VALUES ('m', $1) RETURNING id",
    )
    .bind(telos)
    .fetch_one(&pool)
    .await
    .unwrap();
    let err = sqlx::query(
        "INSERT INTO kb_workflow_jobs (resource_id, cogmap_id, persona, dispatch_type, payload) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(resource)
    .bind(cogmap)
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
}
