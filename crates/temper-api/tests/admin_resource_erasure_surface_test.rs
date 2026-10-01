#![cfg(feature = "test-db")]
//! Witnesses for the resource-erasure act's operator doors (resource erasure 2b, PR 2):
//!
//! * the execute door (`POST /api/admin/resources/erasure`) — an operator completes, and the
//!   targets the act records equal the survey's prediction; a non-operator is rejected AT THE
//!   WIRE (the door mints the `&SystemAdmin` proof before dispatch): 404, ZERO new events, with a
//!   bite probe that stands the gate down; an unknown id is 404; a body carrying
//!   `request_reference` is refused at the door (`deny_unknown_fields`, axum answers 422), never
//!   silently honoured. A repeat erasure renders 200 `refused` / `already_erased` with the
//!   recorded refusal's reference, and a non-operator's unknown id gets the gate's own 404 body.
//! * the survey door (`POST /api/admin/resources/erasure/survey`) — a non-operator gets the same
//!   404 and ZERO new events (a survey requests nothing).
//! * the admin ledger lists both `resource_erased` and `resource_erasure_refused`.
//!
//! No tenant axis exists: the gate is `is_system_admin` alone (ruled 2026-09-30), which is why
//! the operator here is the instance operator and nothing else.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// Resolve the profile a test JWT's `sub` provisioned.
async fn profile_of_sub(pool: &PgPool, sub: &str) -> Uuid {
    sqlx::query_scalar(
        "SELECT profile_id FROM kb_profile_auth_links WHERE auth_provider_user_id = $1",
    )
    .bind(sub)
    .fetch_one(pool)
    .await
    .expect("the provisioned profile")
}

/// Provision `sub` through a real authenticated request, then return its token and profile.
async fn provision(app: &common::TestApp, sub: &str, email: &str) -> (String, Uuid) {
    let token = common::generate_test_jwt(sub, email);
    let resp = app
        .client
        .get(app.url("/api/profile"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("provisioning request");
    assert_eq!(resp.status().as_u16(), 200, "first sign-in must provision");
    let profile = profile_of_sub(&app.pool, sub).await;
    (token, profile)
}

/// An operator: standing plus the governance row that IS `is_system_admin`.
async fn provision_operator(app: &common::TestApp, sub: &str, email: &str) -> (String, Uuid) {
    let (token, profile) = provision(app, sub, email).await;
    common::fixtures::make_test_admin(&app.pool, profile).await;
    (token, profile)
}

/// A non-operator: standing ONLY, so it reaches the gated router but fails the door's gate.
async fn provision_non_operator(app: &common::TestApp, sub: &str, email: &str) -> (String, Uuid) {
    let (token, profile) = provision(app, sub, email).await;
    common::fixtures::approve_standing(&app.pool, profile).await;
    (token, profile)
}

/// A resource made through the real create path (`POST /api/resources`), owned by a third
/// profile that is neither the operator nor the non-operator.
async fn create_resource(app: &common::TestApp) -> Uuid {
    let email = format!("resource-owner-{}@example.com", Uuid::new_v4());
    let (owner, context_id) =
        common::fixtures::create_test_profile_with_context(&app.pool, &email).await;
    let token = common::generate_test_jwt(&format!("test|{owner}"), &email);
    let created: Value = app
        .client
        .post(app.url("/api/resources"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "kb_context_id": context_id.to_string(),
            "doc_type": "research",
            "origin_uri": format!("test://erasure-door-{}", Uuid::new_v4()),
            "title": "Door Erasure Subject",
            "slug": null,
            "mimetype": "text/markdown"
        }))
        .send()
        .await
        .expect("create request")
        .json()
        .await
        .expect("create JSON");
    Uuid::parse_str(created["id"].as_str().expect("id field")).expect("resource id")
}

async fn post(app: &common::TestApp, token: &str, path: &str, body: &Value) -> reqwest::Response {
    app.client
        .post(app.url(path))
        .header("Authorization", format!("Bearer {token}"))
        .json(body)
        .send()
        .await
        .expect("the door answers")
}

const EXECUTE: &str = "/api/admin/resources/erasure";
const SURVEY: &str = "/api/admin/resources/erasure/survey";

async fn count_events(pool: &PgPool, event_type: Option<&str>) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM kb_events e JOIN kb_event_types t ON t.id = e.event_type_id \
          WHERE $1::text IS NULL OR t.name = $1",
    )
    .bind(event_type)
    .fetch_one(pool)
    .await
    .expect("event count")
}

/// The ONE event of `event_type`: its payload and correlation id.
async fn the_event(pool: &PgPool, event_type: &str) -> (Value, Uuid) {
    sqlx::query_as(
        "SELECT e.payload, e.correlation_id FROM kb_events e \
           JOIN kb_event_types t ON t.id = e.event_type_id WHERE t.name = $1",
    )
    .bind(event_type)
    .fetch_one(pool)
    .await
    .expect("the one event")
}

async fn is_erased(pool: &PgPool, resource: Uuid) -> bool {
    sqlx::query_scalar("SELECT erased_at IS NOT NULL FROM kb_resources WHERE id = $1")
        .bind(resource)
        .fetch_one(pool)
        .await
        .expect("erased_at probe")
}

// ── WITNESS: the operator completes, and the record equals the survey's prediction ───────────

/// FAILS IF the door does not reach the service, the response loses the reference the operator
/// must cite, the recorded `correlation_id` is not that reference, or the act's recorded targets
/// diverge from the survey's prediction (exact prose, exact order).
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn an_operator_completes_and_the_recorded_targets_equal_the_surveys_prediction(pool: PgPool) {
    let app = common::setup_test_app(pool).await;
    let (token, operator) = provision_operator(&app, "rx-operator", "rx-op@example.com").await;
    let resource = create_resource(&app).await;

    let surveyed = post(&app, &token, SURVEY, &json!({ "resource": resource })).await;
    assert_eq!(surveyed.status().as_u16(), 200);
    let prediction: Value = surveyed.json().await.expect("the survey body");
    let predicted = &prediction["plan"]["targets"];
    assert!(
        predicted.as_array().is_some_and(|t| !t.is_empty()),
        "the prediction carries targets (a vacuous equality proves nothing): {prediction}"
    );

    let resp = post(&app, &token, EXECUTE, &json!({ "resource": resource })).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.expect("the tagged outcome");
    assert_eq!(body["status"], "completed", "{body}");

    let (payload, correlation) = the_event(&app.pool, "resource_erased").await;
    assert_eq!(payload["actor"], Value::String(operator.to_string()));
    assert_eq!(
        body["request_reference"],
        Value::String(correlation.to_string()),
        "the reference the door returns IS the recorded correlation id"
    );
    assert_eq!(
        payload["targets"], *predicted,
        "the act's recorded targets must equal the survey's prediction"
    );
    assert_eq!(body["targets"], *predicted, "and so must the door's answer");
    assert!(is_erased(&app.pool, resource).await);
}

// ── WITNESS: the non-operator's 404 at the wire, zero events, and the bite ──────────────────

/// FAILS IF a non-operator's attempt erases anything, leaks anything but 404, or appends ANY
/// event — not even a refusal: a rejected caller is recorded only in telemetry. The same holds
/// for a body the service would refuse with a 400 (a blob listed twice): the gate answers before
/// the service ever sees the list, so the non-operator learns nothing from it. The bite: the
/// SAME caller with the gate granted completes the SAME request, so the 404 was the door gate's
/// work and not the router's.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn a_non_operator_gets_404_and_zero_new_events_until_the_gate_stands_down(pool: PgPool) {
    let app = common::setup_test_app(pool).await;
    let (token, non_admin) =
        provision_non_operator(&app, "rx-nonadmin", "rx-nonadmin@example.com").await;
    let resource = create_resource(&app).await;
    let body = json!({ "resource": resource });
    let before = count_events(&app.pool, None).await;

    let resp = post(&app, &token, EXECUTE, &body).await;
    assert_eq!(resp.status().as_u16(), 404, "the door renders ABSENT");

    // A duplicate blob list is a 400 for an operator; for a non-operator it is the same 404.
    let blob = Uuid::now_v7();
    let resp = post(
        &app,
        &token,
        EXECUTE,
        &json!({ "resource": resource, "also_strike_blobs": [blob, blob] }),
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        404,
        "the gate answers before the service validates the list"
    );

    assert_eq!(
        count_events(&app.pool, None).await,
        before,
        "a rejected caller appends NOTHING — no resource_erasure_refused, no event at all"
    );
    assert!(
        !is_erased(&app.pool, resource).await,
        "a rejected attempt erases nothing"
    );

    // THE BITE: only `is_system_admin` moves. The duplicate list now reaches the service and is
    // its 400, so the earlier 404 for it was the gate's.
    temper_services::test_support::grant_governance(&app.pool, non_admin).await;
    let resp = post(
        &app,
        &token,
        EXECUTE,
        &json!({ "resource": resource, "also_strike_blobs": [blob, blob] }),
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "past the gate, the service refuses the duplicate"
    );
    let resp = post(&app, &token, EXECUTE, &body).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "with the gate stood down it completes"
    );
    let answer: Value = resp.json().await.expect("the tagged outcome");
    assert_eq!(answer["status"], "completed", "{answer}");
    assert!(is_erased(&app.pool, resource).await);
}

// ── WITNESS: the survey's silent 404 ─────────────────────────────────────────────────────────

/// FAILS IF a non-operator's survey records anything or answers anything but the gate's 404 body,
/// for a real id and an unknown one alike (a rejected caller is recorded only in telemetry). The
/// bite: the same caller, gate granted, the same call answers 200.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn a_non_operator_survey_gets_404_and_zero_new_events_until_the_gate_stands_down(
    pool: PgPool,
) {
    let app = common::setup_test_app(pool).await;
    let (token, non_admin) =
        provision_non_operator(&app, "rx-survey-nonadmin", "rx-survey-na@example.com").await;
    let resource = create_resource(&app).await;
    let before = count_events(&app.pool, None).await;

    // A real id and an unknown one get the same gate face: the gate answers before any lookup.
    for id in [resource, Uuid::now_v7()] {
        let resp = post(&app, &token, SURVEY, &json!({ "resource": id })).await;
        assert_eq!(resp.status().as_u16(), 404);
        let body: Value = resp.json().await.expect("the 404 body");
        assert_eq!(
            body["error"]["message"], "not found",
            "the gate's face is EXACTLY \"not found\" — \"resource not found\" would betray a \
             lookup running above the gate"
        );
    }
    assert_eq!(
        count_events(&app.pool, None).await,
        before,
        "a refused survey records NOTHING"
    );

    temper_services::test_support::grant_governance(&app.pool, non_admin).await;
    let resp = post(&app, &token, SURVEY, &json!({ "resource": resource })).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "with the gate stood down it answers"
    );
}

// ── WITNESS: an unknown id is 404 on both doors ──────────────────────────────────────────────

/// FAILS IF either door answers an operator's unknown id with anything but 404 (a 500 from a
/// raised `not found`, or a recorded refusal rendered 200). The bite: the same operator and the
/// same doors answer 200 for a resource that exists, so the 404 is about the id.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn an_unknown_resource_is_404_on_both_doors(pool: PgPool) {
    let app = common::setup_test_app(pool).await;
    let (token, _) = provision_operator(&app, "rx-ghost-op", "rx-ghost-op@example.com").await;
    let ghost = Uuid::now_v7();

    let resp = post(&app, &token, SURVEY, &json!({ "resource": ghost })).await;
    assert_eq!(resp.status().as_u16(), 404, "survey of an unknown id");
    let resp = post(&app, &token, EXECUTE, &json!({ "resource": ghost })).await;
    assert_eq!(resp.status().as_u16(), 404, "execute of an unknown id");
    assert_eq!(count_events(&app.pool, Some("resource_erased")).await, 0);

    let real = create_resource(&app).await;
    let resp = post(&app, &token, SURVEY, &json!({ "resource": real })).await;
    assert_eq!(resp.status().as_u16(), 200, "an existing resource surveys");
}

// ── WITNESS: a caller-supplied request reference is refused at the door ──────────────────────

/// FAILS IF the execute body accepts a `request_reference` (the service mints it; a caller-chosen
/// one would merge two acts' replay spans). The door refuses it with axum's 422 for a
/// well-formed body carrying an unknown field, and NOTHING is erased or recorded. The bite: the
/// same body without the field completes, so the refusal is about the field alone.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn a_caller_supplied_request_reference_is_refused_at_the_door(pool: PgPool) {
    let app = common::setup_test_app(pool).await;
    let (token, _) = provision_operator(&app, "rx-ref-op", "rx-ref-op@example.com").await;
    let resource = create_resource(&app).await;
    let chosen = Uuid::now_v7();
    let before = count_events(&app.pool, None).await;

    let resp = post(
        &app,
        &token,
        EXECUTE,
        &json!({ "resource": resource, "request_reference": chosen }),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 422, "an unknown field is refused");
    assert_eq!(
        count_events(&app.pool, None).await,
        before,
        "nothing recorded"
    );
    assert!(!is_erased(&app.pool, resource).await);

    let resp = post(&app, &token, EXECUTE, &json!({ "resource": resource })).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.expect("the tagged outcome");
    assert_ne!(
        body["request_reference"],
        Value::String(chosen.to_string()),
        "the reference is the server's"
    );
}

// ── WITNESS: the admin ledger lists both resource families ───────────────────────────────────

/// FAILS IF the existing admin ledger does not list BOTH `resource_erased` and
/// `resource_erasure_refused` for an operator reading by the resource subject. Both are real:
/// the operator's act, then the operator's repeat, refused `already_erased`.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn the_admin_ledger_lists_resource_erased_and_resource_erasure_refused(pool: PgPool) {
    let app = common::setup_test_app(pool).await;
    let (token, _) = provision_operator(&app, "rx-auditor", "rx-auditor@example.com").await;
    let resource = create_resource(&app).await;

    let completed = post(&app, &token, EXECUTE, &json!({ "resource": resource })).await;
    assert_eq!(completed.status().as_u16(), 200);
    let repeat = post(&app, &token, EXECUTE, &json!({ "resource": resource })).await;
    assert_eq!(repeat.status().as_u16(), 200);
    let repeat: Value = repeat.json().await.expect("the tagged outcome");
    assert_eq!(repeat["reason"], "already_erased", "{repeat}");

    let resp = app
        .client
        .get(app.url(&format!(
            "/api/admin/ledger?subject=kb_resources:{resource}"
        )))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("the ledger answers");
    assert_eq!(resp.status().as_u16(), 200);
    let page: Value = resp.json().await.expect("the ledger page");
    let types: Vec<&str> = page["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["event_type"].as_str().expect("event_type"))
        .collect();
    assert!(types.contains(&"resource_erased"), "got {types:?}");
    assert!(types.contains(&"resource_erasure_refused"), "got {types:?}");
}

// ── WITNESS: a repeat erasure renders the recorded refusal ───────────────────────────────────

/// FAILS IF the door renders a repeat erasure as anything but 200 `{status: "refused", reason:
/// "already_erased"}`, or if the `request_reference` and `event_id` it returns are not the
/// recorded refusal's correlation id and id. The bite: the first call on the same resource
/// renders `completed`, so the arm is chosen by the outcome, not fixed.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn a_repeat_erasure_renders_refused_already_erased_with_the_recorded_reference(pool: PgPool) {
    let app = common::setup_test_app(pool).await;
    let (token, _) = provision_operator(&app, "rx-repeat-op", "rx-repeat-op@example.com").await;
    let resource = create_resource(&app).await;
    let body = json!({ "resource": resource });

    let first = post(&app, &token, EXECUTE, &body).await;
    assert_eq!(first.status().as_u16(), 200);
    let first: Value = first.json().await.expect("the tagged outcome");
    assert_eq!(first["status"], "completed", "{first}");

    let resp = post(&app, &token, EXECUTE, &body).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a recorded refusal renders 200"
    );
    let answer: Value = resp.json().await.expect("the tagged outcome");
    assert_eq!(answer["status"], "refused", "{answer}");
    assert_eq!(answer["reason"], "already_erased", "{answer}");

    let (event_id, payload, correlation): (Uuid, Value, Uuid) = sqlx::query_as(
        "SELECT e.id, e.payload, e.correlation_id FROM kb_events e \
           JOIN kb_event_types t ON t.id = e.event_type_id \
          WHERE t.name = 'resource_erasure_refused'",
    )
    .fetch_one(&app.pool)
    .await
    .expect("the one recorded refusal");
    assert_eq!(payload["reason"], "already_erased");
    assert_eq!(
        answer["request_reference"],
        Value::String(correlation.to_string()),
        "the reference the door returns IS the refusal's correlation id"
    );
    assert_eq!(answer["event_id"], Value::String(event_id.to_string()));
    assert_ne!(
        answer["request_reference"], first["request_reference"],
        "the repeat is its own attempt with its own reference"
    );
    assert_eq!(count_events(&app.pool, Some("resource_erased")).await, 1);
}

// ── WITNESS: a non-operator's unknown id ─────────────────────────────────────────────────────

/// FAILS IF a non-operator naming an id that does not exist gets anything but the 404 a real
/// id gets, or if the attempt appends anything: the gate runs before any lookup, so the body is
/// the gate's own EXACTLY "not found" for both ids. The bite: the operator's 404 for the same
/// unknown id is the lookup's "resource not found", so the non-operator's body was the gate's,
/// not the id's.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn a_non_operator_gets_the_gates_404_for_an_unknown_id_and_nothing_is_recorded(pool: PgPool) {
    let app = common::setup_test_app(pool).await;
    let (token, _) =
        provision_non_operator(&app, "rx-ghost-nonadmin", "rx-ghost-na@example.com").await;
    let (op_token, _) = provision_operator(&app, "rx-ghost-op2", "rx-ghost-op2@example.com").await;
    let real = create_resource(&app).await;
    let ghost = Uuid::now_v7();
    let before = count_events(&app.pool, None).await;

    for id in [real, ghost] {
        let resp = post(&app, &token, EXECUTE, &json!({ "resource": id })).await;
        assert_eq!(resp.status().as_u16(), 404);
        let body: Value = resp.json().await.expect("the 404 body");
        assert_eq!(
            body["error"]["message"], "not found",
            "the gate's face is the same for a real id and an unknown one"
        );
    }
    assert_eq!(
        count_events(&app.pool, None).await,
        before,
        "nothing is recorded"
    );

    let resp = post(&app, &op_token, EXECUTE, &json!({ "resource": ghost })).await;
    assert_eq!(resp.status().as_u16(), 404);
    let body: Value = resp.json().await.expect("the 404 body");
    assert_eq!(
        body["error"]["message"], "resource not found",
        "past the gate, the lookup answers"
    );
}
