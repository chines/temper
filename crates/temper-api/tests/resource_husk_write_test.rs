#![cfg(feature = "test-db")]
//! A write to an ERASED resource (a husk: `kb_resources.erased_at` set) answers `410` under
//! `RESOURCE_ERASED` to a caller who holds standing on it, and the door's uniform `403` to everyone
//! else (resource erasure spec D13, F4; the write floor, `backend::write_floor`). The population is
//! the read side's — `resource_husk_held_by`, migration `20260930000060` — so a write never answers
//! an erasure to a caller the read would not.
//!
//! Witnessed on every resource-row write door that floors on `can_modify_resource`, driven from
//! one table ([`doors`]) so a new door is one row:
//!
//! * the owner of a husk gets `410` + `RESOURCE_ERASED`;
//! * a direct read-grant holder (who could never write it) gets the same `410`;
//! * a caller with no standing gets `403`, never `410`;
//! * the owner of a tombstone (soft-deleted through the real delete door, never erased) gets
//!   `403`, never `410`.
//!
//! Plus the goal-set partial write: a PATCH that changes the title AND links a goal the caller
//! may not link is refused whole — the title does not land.
//!
//! Every state is made by a real door: the resource by `POST /api/ingest`, the grant by
//! `POST /api/resources/{id}/grants`, the husk by the operator door
//! `POST /api/admin/resources/erasure`, the tombstone by `DELETE /api/resources/{id}`. Nothing
//! writes `is_active` or `erased_at` by hand. The team, its context and the memberships are
//! fixture rows, as in `resource_husk_read_test.rs`, whose helpers these are.

mod common;

use reqwest::Method;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use temper_core::types::ingest::{pack_chunks, IngestPayload, PackedChunk};

const TITLE: &str = "Husk Write Subject Title";
const BODY: &str = "Prose the write floor must refuse to touch once erased.";

/// The code a husk answer travels under — the one constant producer and consumer share.
const RESOURCE_ERASED: &str = temper_core::error::RESOURCE_ERASED_CODE;

/// An already-embedded chunk carrying the REAL chunker hash, so the test-db tier needs no ONNX
/// (the pattern in `soft_delete_read_floor_test.rs`).
fn chunk(content: &str) -> PackedChunk {
    let c = &temper_ingest::chunk::chunk_markdown(content)[0];
    PackedChunk {
        chunk_index: 0,
        header_path: c.header_path.clone(),
        heading_depth: c.heading_depth,
        content: c.content.clone(),
        content_hash: c.content_hash.clone(),
        embedding: vec![0.5; 768],
        embedded_with: None,
    }
}

struct Caller {
    token: String,
    profile: Uuid,
}

/// A fully provisioned profile (approved standing, `<handle>@web` emitter, own context) and its JWT.
async fn caller(pool: &PgPool, label: &str) -> (Caller, Uuid) {
    let email = format!("husk-write-{label}-{}@example.com", Uuid::new_v4());
    let (profile, own_context) =
        common::fixtures::create_test_profile_with_context(pool, &email).await;
    let token = common::generate_test_jwt(&format!("test|{profile}"), &email);
    (Caller { token, profile }, own_context)
}

/// A team that owns a context, with each profile a `member` (an authoring role, so the owner may
/// write into it; every member reads it). Returns the context id.
async fn team_context(pool: &PgPool, members: &[Uuid]) -> Uuid {
    let team = Uuid::now_v7();
    let slug = format!("husk-write-team-{}", &team.simple().to_string()[..8]);
    sqlx::query("INSERT INTO kb_teams (id, slug, name) VALUES ($1, $2, $2)")
        .bind(team)
        .bind(&slug)
        .execute(pool)
        .await
        .expect("insert team");
    let context = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO kb_contexts (id, owner_table, owner_id, slug, name) \
         VALUES ($1, 'kb_teams', $2, 'husk-home', 'husk-home')",
    )
    .bind(context)
    .bind(team)
    .execute(pool)
    .await
    .expect("insert team-owned context");
    for member in members {
        sqlx::query(
            "INSERT INTO kb_team_members (team_id, profile_id, role) VALUES ($1, $2, 'member')",
        )
        .bind(team)
        .bind(member)
        .execute(pool)
        .await
        .expect("add team member");
    }
    context
}

/// A resource with a real body, made through `POST /api/ingest` by `owner` into `context`.
async fn ingest(app: &common::TestApp, owner: &Caller, context: Uuid) -> Uuid {
    let payload = IngestPayload {
        idempotency_key: None,
        segmented: None,
        title: TITLE.to_string(),
        origin_uri: format!("test://husk-write-{}", Uuid::new_v4()),
        context_ref: context.to_string(),
        home_cogmap_id: None,
        doc_type_name: "research".to_string(),
        content_hash: None,
        content: BODY.to_string(),
        metadata: None,
        managed_meta: None,
        open_meta: None,
        chunks_packed: Some(pack_chunks(&[chunk(BODY)]).expect("pack")),
        goal: None,
        act: Default::default(),
        sources: Vec::new(),
    };
    let resp = app
        .client
        .post(app.url("/api/ingest"))
        .header("Authorization", format!("Bearer {}", owner.token))
        .json(&payload)
        .send()
        .await
        .expect("ingest request");
    assert_eq!(resp.status().as_u16(), 200, "the owner ingests");
    let created: Value = resp.json().await.expect("ingest JSON");
    Uuid::parse_str(created["id"].as_str().expect("id field")).expect("resource id")
}

/// `owner` grants `grantee` read on `resource` through the real grant door.
async fn grant_read(app: &common::TestApp, owner: &Caller, resource: Uuid, grantee: Uuid) {
    let resp = app
        .client
        .post(app.url(&format!("/api/resources/{resource}/grants")))
        .header("Authorization", format!("Bearer {}", owner.token))
        .json(&json!({
            "principal_table": "kb_profiles",
            "principal_id": grantee,
            "can_read": true,
            "can_write": false,
            "can_delete": false,
            "can_grant": false,
        }))
        .send()
        .await
        .expect("grant request");
    assert_eq!(resp.status().as_u16(), 200, "the owner may grant read");
}

/// Erase `resource` through the operator door, as a fresh instance operator.
async fn erase(app: &common::TestApp, resource: Uuid) {
    let (operator, _) = caller(&app.pool, "operator").await;
    common::fixtures::make_test_admin(&app.pool, operator.profile).await;
    let resp = app
        .client
        .post(app.url("/api/admin/resources/erasure"))
        .header("Authorization", format!("Bearer {}", operator.token))
        .json(&json!({ "resource": resource }))
        .send()
        .await
        .expect("erasure request");
    assert_eq!(resp.status().as_u16(), 200, "the operator's act answers");
    let body: Value = resp.json().await.expect("the tagged outcome");
    assert_eq!(body["status"], "completed", "the act completed: {body}");
}

/// Soft-delete `resource` through the real delete door.
async fn delete(app: &common::TestApp, owner: &Caller, resource: Uuid) {
    let resp = app
        .client
        .delete(app.url(&format!("/api/resources/{resource}")))
        .header("Authorization", format!("Bearer {}", owner.token))
        .send()
        .await
        .expect("delete request");
    assert_eq!(resp.status().as_u16(), 200, "the owner deletes");
}

/// One write door under test: how to address it for one resource, with a minimal valid body.
struct Door {
    name: &'static str,
    method: Method,
    path: String,
    body: Option<Value>,
}

/// Every resource-row write door that floors on `can_modify_resource` inside its transaction.
/// Each body is valid for a live resource the caller may modify, so a refusal below is the
/// floor's, not a shape error's.
fn doors(resource: Uuid) -> Vec<Door> {
    vec![
        Door {
            name: "PATCH /api/resources/{id}",
            method: Method::PATCH,
            path: format!("/api/resources/{resource}"),
            body: Some(json!({ "title": "A title the floor must refuse" })),
        },
        Door {
            name: "PUT /api/resources/{id}/meta",
            method: Method::PUT,
            path: format!("/api/resources/{resource}/meta"),
            body: Some(json!({
                "resource_id": resource,
                "managed_meta": {},
                "open_meta": { "note": "refused" },
                "managed_hash": "",
                "open_hash": "",
            })),
        },
        Door {
            name: "PUT /api/ingest/{id}",
            method: Method::PUT,
            path: format!("/api/ingest/{resource}"),
            body: Some(
                serde_json::to_value(IngestPayload {
                    idempotency_key: None,
                    segmented: None,
                    title: TITLE.to_string(),
                    // `ingest::update` reads none of the identity fields (title, origin_uri,
                    // context_ref, doc_type_name); they are required by the payload type only.
                    origin_uri: format!("test://husk-write-update-{resource}"),
                    context_ref: String::new(),
                    home_cogmap_id: None,
                    doc_type_name: "research".to_string(),
                    content_hash: None,
                    // Empty content ⇒ no body revise; the meta half is the write.
                    content: String::new(),
                    metadata: None,
                    managed_meta: None,
                    open_meta: Some(json!({ "note": "refused" })),
                    chunks_packed: None,
                    goal: None,
                    act: Default::default(),
                    sources: Vec::new(),
                })
                .expect("ingest update body"),
            ),
        },
        Door {
            name: "DELETE /api/resources/{id}",
            method: Method::DELETE,
            path: format!("/api/resources/{resource}"),
            body: None,
        },
        Door {
            name: "POST /api/resources/{id}/provenance",
            method: Method::POST,
            path: format!("/api/resources/{resource}/provenance"),
            body: Some(json!({
                "sources": [{ "kind": "remote", "value": "https://example.com/husk-write" }],
            })),
        },
        Door {
            name: "POST /api/resources/{id}/artifacts",
            method: Method::POST,
            path: format!("/api/resources/{resource}/artifacts"),
            body: Some(json!({
                "kind": "husk-write-probe",
                "intent": "current",
                "content": { "probe": true },
            })),
        },
        Door {
            name: "POST /api/facets (resource owner)",
            method: Method::POST,
            path: "/api/facets".to_string(),
            body: Some(json!({
                "resource": resource,
                "values": { "summary": "refused" },
                "weight": 1.0,
            })),
        },
    ]
}

/// Send `door` as `who`: the status and the parsed body (`Null` when the body is not JSON).
async fn send(app: &common::TestApp, who: &Caller, door: &Door) -> (u16, Value) {
    let mut req = app
        .client
        .request(door.method.clone(), app.url(&door.path))
        .header("Authorization", format!("Bearer {}", who.token));
    if let Some(body) = &door.body {
        req = req.json(body);
    }
    let resp = req.send().await.expect("door request");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("door body");
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// Assert every door answers `who` with `410` under `RESOURCE_ERASED`, the message naming the id.
async fn assert_every_door_410(app: &common::TestApp, who: &Caller, resource: Uuid, label: &str) {
    for door in doors(resource) {
        let (status, body) = send(app, who, &door).await;
        assert_eq!(
            status, 410,
            "{label}: {} answers 410; body: {body}",
            door.name
        );
        assert_eq!(
            body["error"]["code"], RESOURCE_ERASED,
            "{label}: {} travels under RESOURCE_ERASED; body: {body}",
            door.name
        );
        assert_eq!(
            body["error"]["message"],
            format!("resource {resource} was erased"),
            "{label}: {} — the fixed message names the id and nothing else",
            door.name
        );
    }
}

/// Assert every door answers `who` with `403`, and never under `RESOURCE_ERASED`.
async fn assert_every_door_403(app: &common::TestApp, who: &Caller, resource: Uuid, label: &str) {
    for door in doors(resource) {
        let (status, body) = send(app, who, &door).await;
        assert_eq!(
            status, 403,
            "{label}: {} answers 403; body: {body}",
            door.name
        );
        assert_ne!(
            body["error"]["code"], RESOURCE_ERASED,
            "{label}: {} must never answer RESOURCE_ERASED; body: {body}",
            door.name
        );
    }
}

/// The resource's title as `who` reads it through `GET /api/resources/{id}`.
async fn title_of(app: &common::TestApp, who: &Caller, resource: Uuid) -> String {
    let resp = app
        .client
        .get(app.url(&format!("/api/resources/{resource}")))
        .header("Authorization", format!("Bearer {}", who.token))
        .send()
        .await
        .expect("read request");
    assert_eq!(resp.status().as_u16(), 200, "the owner reads the resource");
    let view: Value = resp.json().await.expect("view JSON");
    view["title"].as_str().expect("title field").to_owned()
}

// ── WITNESS: the owner of a husk gets 410 RESOURCE_ERASED on every write door ─────────────────

/// FAILS IF any write door answers the owner of an erased resource with anything but `410` under
/// `RESOURCE_ERASED`. The bite, per door: restore that door's `self.check_can_modify_next(..)`
/// pre-check (a bare `can_modify_resource` that renders every deny `Forbidden`) ahead of its
/// floor — or, for the update doors, delete the `modify_floor_fast_fail` call, whose absence lets
/// the visibility-gated `native_resource_identity` / readback answer the husk `404` first.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn the_owner_of_an_erased_resource_gets_410_on_every_write_door(pool: PgPool) {
    let app = common::setup_test_app(pool).await;
    let (owner, _) = caller(&app.pool, "owner").await;
    let home = team_context(&app.pool, &[owner.profile]).await;
    let resource = ingest(&app, &owner, home).await;

    erase(&app, resource).await;

    assert_every_door_410(&app, &owner, resource, "owner").await;
}

// ── WITNESS: a direct read-grant holder gets the same 410 ─────────────────────────────────────

/// FAILS IF a direct `can_read` grantee of an erased resource — a caller who could never have
/// written it — gets anything but the husk `410` on any write door (ruling 1: the write's
/// population is the read's). The bite: in `write_floor::erased_or_forbidden`, answer
/// `Forbidden` unconditionally, or key the classification on `can_modify_resource` standing. The
/// grantee is not a member of the home context, so the grant is its only reach.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn a_read_grant_holder_of_an_erased_resource_gets_410_on_every_write_door(pool: PgPool) {
    let app = common::setup_test_app(pool).await;
    let (owner, _) = caller(&app.pool, "owner").await;
    let (grantee, _) = caller(&app.pool, "grantee").await;
    let home = team_context(&app.pool, &[owner.profile]).await;
    let resource = ingest(&app, &owner, home).await;
    grant_read(&app, &owner, resource, grantee.profile).await;

    erase(&app, resource).await;

    assert_every_door_410(&app, &grantee, resource, "read-grant holder").await;
}

// ── WITNESS: a caller with no standing gets 403, never 410 ────────────────────────────────────

/// The oracle check. FAILS IF a caller with no standing on an erased resource gets `410` (or
/// anything but `403`) from any write door — the `410` would confirm an erasure to someone the read
/// side answers `404`. The bite: in `write_floor::erased_or_forbidden`, answer
/// `ResourceErased(resource)` whenever the row's `erased_at` is set, without asking
/// `resource_husk_held_by`. The owner's `410` in the same world shows the resource IS a husk.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn a_caller_with_no_standing_gets_403_on_every_write_door(pool: PgPool) {
    let app = common::setup_test_app(pool).await;
    let (owner, _) = caller(&app.pool, "owner").await;
    let (stranger, _) = caller(&app.pool, "stranger").await;
    let home = team_context(&app.pool, &[owner.profile]).await;
    let resource = ingest(&app, &owner, home).await;

    erase(&app, resource).await;

    assert_every_door_403(&app, &stranger, resource, "no standing").await;
    assert_every_door_410(&app, &owner, resource, "owner, same world").await;
}

// ── WITNESS: the owner of a tombstone gets 403, never 410 ─────────────────────────────────────

/// FAILS IF a soft-deleted resource that was never erased answers its owner `410` (or anything
/// but `403`) on any write door. The bite: classify on `is_active` rather than `erased_at` — e.g.
/// in `write_floor::erased_or_forbidden`, answer `ResourceErased` whenever `can_modify_resource`
/// is false for the resource's owner. The probe pins the fixture: the delete door left a tombstone
/// (`is_active` false) with `erased_at` NULL.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn the_owner_of_a_tombstone_gets_403_on_every_write_door(pool: PgPool) {
    let app = common::setup_test_app(pool).await;
    let (owner, own_context) = caller(&app.pool, "owner").await;
    let resource = ingest(&app, &owner, own_context).await;

    delete(&app, &owner, resource).await;

    let (is_active, erased): (bool, bool) =
        sqlx::query_as("SELECT is_active, erased_at IS NOT NULL FROM kb_resources WHERE id = $1")
            .bind(resource)
            .fetch_one(&app.pool)
            .await
            .expect("tombstone probe");
    assert!(!is_active, "precondition: the delete door made a tombstone");
    assert!(!erased, "precondition: a tombstone is not an erasure");

    assert_every_door_403(&app, &owner, resource, "tombstone owner").await;
}

// ── WITNESS: a refused goal-set rolls the whole update back ───────────────────────────────────

/// FAILS IF a PATCH that changes the title AND links a goal the caller may not link is refused
/// while the title change lands anyway (a partial write). The goal belongs to a stranger, in the
/// stranger's own context, so the owner cannot read it: the edge's target clause
/// (`check_endpoint_readable_in_tx`) refuses it `404`. The bite: in `update_resource`, move
/// `tx.commit()` up to directly after `writes::update_resource_in_tx(..)` and run the goal match on
/// a fresh transaction — the shape before this change, which commits the title and then refuses.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn a_refused_goal_set_leaves_the_title_unchanged(pool: PgPool) {
    let app = common::setup_test_app(pool).await;
    let (owner, own_context) = caller(&app.pool, "owner").await;
    let (stranger, stranger_context) = caller(&app.pool, "stranger").await;
    let resource = ingest(&app, &owner, own_context).await;
    let goal = ingest(&app, &stranger, stranger_context).await;

    assert_eq!(
        title_of(&app, &owner, resource).await,
        TITLE,
        "precondition: the resource carries the ingested title"
    );

    let resp = app
        .client
        .patch(app.url(&format!("/api/resources/{resource}")))
        .header("Authorization", format!("Bearer {}", owner.token))
        .json(&json!({ "title": "A title that must not land", "goal": goal }))
        .send()
        .await
        .expect("patch request");
    let status = resp.status().as_u16();
    let body = resp.text().await.expect("patch body");
    assert_eq!(
        status, 404,
        "a goal the caller cannot read is refused as absent; body: {body}"
    );

    assert_eq!(
        title_of(&app, &owner, resource).await,
        TITLE,
        "the refused goal-set rolled the whole update back — the title did not land"
    );
}
