#![cfg(feature = "test-db")]
//! Build order 2b witnesses (resource erasure spec 2026-09-28, the act's cut-1 forms; task
//! 01a0e9e7-491d-7700-8f58-99d0b068e059). The SQL act (`resource_erasure_execute`, migration
//! 20260929040730) against a world built through the REAL write paths, replay through the same
//! snapshot/reset/replay harness the substrate artifact tests use.
//!
//! Spec witnesses covered (numbers per the spec's list):
//!   * **1 (cut-1 form) + 14** — replay byte-identity with a `resource_erased` in the ledger,
//!     the record naming every unreached ledger path, provenance + remote-source tables diffed
//!     (D4's build check: both added to PROJECTION_DUMPS).
//!   * **2** — custody-never-bytes: a sibling in another home with byte-identical content keeps
//!     it; `kb_erased_content` gains no row.
//!   * **3** — history reached: the superseded chunk and the prior revision's bytes end empty.
//!   * **6** — the edge folds through `relationship_folded` under the act's correlation id.
//!   * **8** — soft delete is not YET erasure (`erased_at IS NULL`, content intact) — and a
//!     tombstone IS erasable: the act completes over one (compliance erasure of a
//!     soft-deleted resource is the flow's main shape; ruled by Pete over the draft's
//!     refusal).
//!   * **9** — the property surface (Q3): values sentineled; a set→set→unset→set key maps to ONE
//!     `erased-key-<n>`; replay reproduces it.
//!   * **11 (SQL half)** — the closed refusals RAISE (already-erased, charter, ingest); the
//!     recorded/typed refusal face is the service's, PR 2's witness.
//!   * **12** — the joint-read columns: `header_path` NULL, artifact content `{}`::jsonb.
//!
//! The doors (Rust) land in PR 2; this file pins the SQL behavior the doors consume.

mod common;

use sha2::Digest;
use sqlx::PgPool;
use temper_core::types::ids::EntityId;
use temper_core::types::property_owner::PropertyOwner;
use temper_substrate::affinity::EdgeKind;
use temper_substrate::blob_store::InMemoryBlobStore;
use temper_substrate::content::IncomingChunk;
use temper_substrate::events::{fire, EdgeHome, EventContext, SeedAction};
use temper_substrate::ids::{BlobId, ContextId, EdgeId, ProfileId, ResourceId};
use temper_substrate::payloads::EdgePolarity;
use temper_substrate::payloads::{
    self, AnchorRef, ArtifactIntent, Incorporation, KindOwner, ProvenanceSource,
};
use temper_substrate::replay;
use temper_substrate::writes::CommitBlobParams;
use temper_substrate::writes::{self, CommitDataArtifactParams, CreateParams, UpdateParams};
use temper_substrate::writes::{AssertParams, CreateMode};
use uuid::Uuid;

/// The leaked prose and the clean replacement, one pair per file. `chunk_hash` is the chunker's
/// own sha256-of-trim (content.rs:21), so hash joins the tests assert on are the REAL ones.
const SECRET: &str = "the plan and SSN 123-45-6789";
const CLEAN: &str = "clean replacement prose";
const URL: &str = "https://leak.example/internal/jane-smith";

fn chunk_hash(prose: &str) -> String {
    format!("{:x}", sha2::Sha256::digest(prose.trim()))
}

fn chunk(prose: &str, header: &str) -> IncomingChunk {
    IncomingChunk {
        chunk_index: 0,
        content_hash: chunk_hash(prose),
        content: prose.to_string(),
        embedding: vec![0.1; 768],
        embedded_with: Some("model-sha-1".to_string()),
        header_path: header.to_string(),
        heading_depth: if header.is_empty() { 0 } else { 1 },
    }
}

async fn system_actor(pool: &PgPool) -> (ProfileId, EntityId) {
    let profile: Uuid = sqlx::query_scalar("SELECT id FROM kb_profiles WHERE handle='system'")
        .fetch_one(pool)
        .await
        .unwrap();
    let entity: EntityId =
        sqlx::query_scalar("SELECT id FROM kb_entities WHERE profile_id=$1 AND name='system'")
            .bind(profile)
            .fetch_one(pool)
            .await
            .unwrap();
    (ProfileId::from(profile), entity)
}

async fn make_home(pool: &PgPool, owner: ProfileId, slug: &str) -> ContextId {
    ContextId::from(
        common::insert_context(pool, "kb_profiles", owner.uuid(), slug, slug)
            .await
            .unwrap(),
    )
}

/// The full leaking shape, built through the REAL write paths.
struct Leak {
    resource: ResourceId,
    /// The sibling twin: byte-identical chunk + revision bytes, another home (Witness 2).
    twin: ResourceId,
    /// The now-superseded chunk still carrying the secret (Witness 3).
    old_chunk: Uuid,
    /// The edge the act folds (Witness 6).
    edge: EdgeId,
    /// The resource's data artifact (Witness 12, artifact half).
    artifact: Uuid,
}

async fn seed_leak(
    pool: &PgPool,
    owner: ProfileId,
    emitter: EntityId,
    home: ContextId,
    twin_home: ContextId,
) -> Leak {
    let resource = writes::create_resource_with(
        pool,
        CreateParams {
            idempotency_key: None,
            title: "M&A notes (leaked)",
            origin_uri: "test://seed-leak",
            body: SECRET,
            doc_type: "research",
            home: AnchorRef::context(home),
            owner,
            originator: owner,
            emitter,
            properties: &[],
            chunks: Some(vec![chunk(SECRET, "merger notes")]),
            sources: vec![Incorporation {
                source: ProvenanceSource::Remote(URL.to_owned()),
                seq: 1,
            }],
        },
        EventContext::default(),
    )
    .await
    .expect("seed resource through the create path");

    let twin = writes::create_resource_with(
        pool,
        CreateParams {
            idempotency_key: None,
            title: "harmless twin",
            origin_uri: "test://seed-twin",
            body: SECRET,
            doc_type: "research",
            home: AnchorRef::context(twin_home),
            owner,
            originator: owner,
            emitter,
            properties: &[],
            chunks: Some(vec![chunk(SECRET, "")]),
            sources: vec![],
        },
        EventContext::default(),
    )
    .await
    .expect("seed the byte-identical twin");

    // History: revise the body to CLEAN prose — the superseded chunk keeps the secret.
    let leaky_chunk_hash = chunk_hash(SECRET);
    writes::update_resource(
        pool,
        UpdateParams {
            resource,
            body: Some(CLEAN),
            title: None,
            origin_uri: None,
            properties: &[],
            unset_keys: &[],
            chunks: Some(vec![chunk(CLEAN, "clean")]),
            sources: vec![],
            content_block: None,
            rehome_to: None,
            emitter,
        },
    )
    .await
    .expect("revise the body out of the leak");

    let old_chunk: Uuid = sqlx::query_scalar(
        "SELECT c.id FROM kb_chunks c \
           JOIN kb_content_blocks b ON b.id = c.block_id \
          WHERE b.resource_id = $1 AND NOT c.is_current LIMIT 1",
    )
    .bind(resource.uuid())
    .fetch_one(pool)
    .await
    .unwrap();

    // An edge touching the resource (its own trail must show a deliberate end — Witness 6).
    let mut tx = pool.begin().await.unwrap();
    let edge = fire(
        &mut tx,
        SeedAction::RelationshipAssert {
            src: AnchorRef::resource(resource),
            tgt: AnchorRef::resource(twin),
            kind: EdgeKind::LeadsTo,
            polarity: EdgePolarity::Forward,
            label: Some("jane smith spoke to us"),
            weight: 1.0,
            home: EdgeHome::Context(home),
            emitter,
        },
    )
    .await
    .unwrap()
    .relationship()
    .unwrap();
    tx.commit().await.unwrap();

    // The set→set→set key the act maps to ONE erased-key-<n> (Witness 9).
    writes::set_property(
        pool,
        resource,
        "transient",
        &serde_json::json!("one"),
        emitter,
    )
    .await
    .unwrap();

    // A data artifact on the resource (Witness 12).
    let artifact = writes::commit_data_artifact(
        pool,
        CommitDataArtifactParams {
            resource,
            kind: "notes",
            kind_owner: Some(KindOwner::Profile(owner.uuid())),
            intent: ArtifactIntent::Current,
            precedence: 0.0,
            content: &serde_json::json!({"jane": "was here"}),
            supersedes: &[],
            emitter,
        },
    )
    .await
    .unwrap();

    let _ = leaky_chunk_hash;
    Leak {
        resource,
        twin,
        old_chunk,
        edge,
        artifact: Uuid::from(artifact),
    }
}

/// The one act invocation every witness uses — the boot-seeded system actor is the operator
/// (the service gate is PR 2's concern; here SQL executes as the operator), a fresh request
/// reference per act. Returns the `resource_erased` event id.
async fn execute_act(pool: &PgPool, resource: Uuid) -> Uuid {
    let (_, operator_entity) = system_actor(pool).await;
    let request_ref = Uuid::now_v7();
    let raw: String =
        sqlx::query_scalar("SELECT (resource_erasure_execute($1,$2,$3,$4)->>'event_id')::text")
            .bind(resource)
            .bind(operator_entity)
            .bind(operator_entity)
            .bind(request_ref)
            .fetch_one(pool)
            .await
            .expect("the act completes");
    Uuid::parse_str(&raw).expect("the event id parses")
}
/// Read the live (non-folded) property rows the resource owns, as (key, value) in key order.
async fn resource_props(pool: &PgPool, resource: ResourceId) -> Vec<(String, serde_json::Value)> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL search_path TO public")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query_as(
        "SELECT property_key, property_value FROM kb_properties \
          WHERE owner_table='kb_resources' AND owner_id=$1 AND NOT is_folded \
          ORDER BY property_key",
    )
    .bind(resource.uuid())
    .fetch_all(&mut *tx)
    .await
    .unwrap()
}

/// (1 + 14) Replay byte-identity: seed the leak, erase, snapshot, reset, replay — the projection
/// comes back byte-identical INCLUDING the re-pointed provenance rows and the sentinel
/// remote-source rows (the tables D4's build check added). A repeat erasure on the replayed
/// namespace REFUSES (ruled 2026-09-29: a recorded refusal, no second event, no-op projection),
/// and replay after it is still identical.
#[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
async fn replay_of_a_resource_erasure_is_byte_identical(pool: sqlx::PgPool) {
    common::reset_schema(&pool).await;
    temper_substrate::scenario::bootseed::seed_system(&pool)
        .await
        .unwrap();
    let (owner, emitter) = system_actor(&pool).await;
    let home = make_home(&pool, owner, "leak-home").await;
    let twin_home = make_home(&pool, owner, "twin-home").await;
    let leak = seed_leak(&pool, owner, emitter, home, twin_home).await;

    let event_id = execute_act(&pool, leak.resource.uuid()).await;

    // 14 is IN the record: the `resource_erased` payload names every unreached ledger path in
    // ledger_remainder — cut 1 redacts nothing on the ledger, so EVERY free-text path of every
    // trail-scope event is named (the F3 catalog), and the record is the plan's, verbatim.
    let (ledger_remainder, remainder): (serde_json::Value, serde_json::Value) = sqlx::query_as(
        "SELECT payload->'ledger_remainder', payload->'remainder' \
           FROM kb_events WHERE id = $1",
    )
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !ledger_remainder.as_array().unwrap().is_empty(),
        "cut 1 names what it has not reached: ledger_remainder must be non-empty, got {ledger_remainder}"
    );
    // The twin is NOT in any remainder entry naming the resource's own content — the twin is a
    // separate resource whose identical bytes are lawful, not a remainder of this act.
    let remainder_text = remainder.to_string();
    assert!(
        !remainder_text.contains("harmless twin"),
        "the twin's identity never rides the record; got {remainder_text}"
    );

    // 2 (custody-never-bytes) BEFORE replay: the twin's content, embedding and search vector
    // are untouched, and kb_erased_content gains no row from this act.
    let twin_prose: Vec<String> = sqlx::query_as::<_, (String,)>(
        "SELECT cc.content FROM kb_chunks c \
           JOIN kb_content_blocks b ON b.id = c.block_id \
           JOIN kb_chunk_content cc ON cc.chunk_id = c.id \
          WHERE b.resource_id = $1 AND cc.content <> ''",
    )
    .bind(leak.twin.uuid())
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .map(|(c,)| c)
    .collect();
    assert!(
        twin_prose.iter().any(|c| c == SECRET),
        "the twin's byte-identical content is untouched; got {twin_prose:?}"
    );
    let erased_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM kb_erased_content")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        erased_rows, 0,
        "NO hash enters kb_erased_content from a resource act"
    );

    // 3 (history reached) + 12: the old chunk, every revision, header_path, artifact content.
    let old_prose: Option<String> = sqlx::query_scalar::<_, String>(
        "SELECT cc.content FROM kb_chunk_content cc WHERE cc.chunk_id = $1",
    )
    .bind(leak.old_chunk)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert_eq!(
        old_prose,
        Some("".to_string()),
        "the superseded chunk's prose is emptied"
    );
    let block_bytes: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT bc.content FROM kb_block_content bc \
           JOIN kb_block_revisions br ON br.id = bc.block_revision_id \
          WHERE br.block_id IN (SELECT id FROM kb_content_blocks WHERE resource_id = $1)",
    )
    .bind(leak.resource.uuid())
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        block_bytes.iter().all(|(b,)| b == &Some("".to_string())),
        "every revision's verbatim bytes are emptied (live revision included); got {block_bytes:?}"
    );
    let null_headers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kb_chunks c \
           JOIN kb_content_blocks b ON b.id = c.block_id \
          WHERE b.resource_id = $1 AND c.header_path IS NOT NULL",
    )
    .bind(leak.resource.uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        null_headers, 0,
        "every chunk's header_path is NULL (the joint-read fix)"
    );
    let artifact_content: Option<serde_json::Value> = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT content FROM kb_data_artifact_content WHERE artifact_id = $1",
    )
    .bind(leak.artifact)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert_eq!(
        artifact_content,
        Some(serde_json::json!({})),
        "the artifact content is empty jsonb — every intent is erased with its resource"
    );

    // 9 (property surface): keys erased-key-<n>, values sentineled, ONE row per key.
    let props = resource_props(&pool, leak.resource).await;
    let keys: Vec<&str> = props.iter().map(|(k, _)| k.as_str()).collect();
    assert!(
        keys.iter().all(|k| k.starts_with("erased-key-")),
        "no original metadata key survives (Q3); got {keys:?}"
    );
    assert!(
        props.iter().all(|(_, v)| v == &serde_json::json!("erased")),
        "every value is the sentinel; got {props:?}"
    );

    // The old title is GONE from the ledger-free-text reach this act has: the husk carries the
    // sentinel, and no kb_properties row (live or folded) carries an original key or value.
    let stale_meta: Option<(String,)> = sqlx::query_as::<_, (String,)>(
        "SELECT property_key::text FROM kb_properties \
          WHERE owner_table = 'kb_resources' AND owner_id = $1 \
            AND (property_key = ANY(ARRAY['tags','transient']) \
              OR property_value IN ('\"one\"'::jsonb, '\"jane smith\"'::jsonb)) LIMIT 1",
    )
    .bind(leak.resource.uuid())
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(
        stale_meta.is_none(),
        "no original key or value survives in the surface; got {stale_meta:?}"
    );

    // 6 (edges): the edge is folded, label NULL, through a relationship_folded under the act's
    // correlation id; the fold's reason is the fixed literal.
    let (folded, label): (bool, Option<String>) =
        sqlx::query_as("SELECT is_folded, label FROM kb_edges WHERE id = $1")
            .bind(leak.edge.uuid())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(folded, "the act folds the edge");
    assert!(label.is_none(), "the edge's label is sentineled (D4)");
    let fold: (Option<String>, Uuid) = sqlx::query_as(
        "SELECT e.payload->>'reason', e.correlation_id \
           FROM kb_events e JOIN kb_event_types t ON t.id = e.event_type_id \
          WHERE t.name = 'relationship_folded' AND (e.payload->>'edge_id')::uuid = $1",
    )
    .bind(leak.edge.uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        fold.0.as_deref(),
        Some("resource_erased"),
        "the fold's reason is the fixed literal"
    );
    let erased_corr: Uuid =
        sqlx::query_scalar("SELECT correlation_id FROM kb_events WHERE id = $1")
            .bind(event_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        fold.1, erased_corr,
        "the fold rides the act's correlation id"
    );

    // ── replay #1: snapshot, reset, walk, diff ──
    let before = replay::dump_projections(&pool).await.unwrap();
    let snap = replay::snapshot(&pool).await.unwrap();
    common::reset_schema(&pool).await;
    replay::replay(&pool, &snap).await.unwrap();
    let after = replay::dump_projections(&pool).await.unwrap();
    for ((ta, a), (tb, b)) in before.iter().zip(after.iter()) {
        assert_eq!(ta, tb);
        assert_eq!(
            a, b,
            "projection table {ta} diverged under replay of an erasure"
        );
    }

    // A repeat erasure on the replayed namespace: the recorded-refusal posture's SQL half —
    // the act RAISES (the service turns that into a recorded `resource_erasure_refused`,
    // PR 2's witness), the projection does not change, and no second `resource_erased` mints.
    let before2 = replay::dump_projections(&pool).await.unwrap();
    let refused = sqlx::query("SELECT resource_erasure_execute($1,$2,$3,$4)")
        .bind(leak.resource.uuid())
        .bind(owner.uuid())
        .bind(emitter)
        .bind(Uuid::now_v7())
        .execute(&pool)
        .await;
    assert!(
        refused.is_err(),
        "a repeat erasure RAISES at SQL grain (the service records it)"
    );
    let after2 = replay::dump_projections(&pool).await.unwrap();
    for ((ta, a), (_tb, b)) in before2.iter().zip(after2.iter()) {
        assert_eq!(a, b, "a refused repeat mutates nothing ({ta})");
    }
    let second_erasure: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kb_events e JOIN kb_event_types t ON t.id = e.event_type_id \
         WHERE t.name = 'resource_erased'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        second_erasure, 1,
        "no second resource_erased is minted by the refused repeat"
    );
}

/// (8) Soft delete is not erasure: the act's survey says not-erased, `erased_at` stays NULL, and
/// the content is intact — the negative face's cheapest witness.
#[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
async fn a_soft_deleted_resource_is_not_an_erased_one(pool: sqlx::PgPool) {
    common::reset_schema(&pool).await;
    temper_substrate::scenario::bootseed::seed_system(&pool)
        .await
        .unwrap();
    let (owner, emitter) = system_actor(&pool).await;
    let home = make_home(&pool, owner, "soft-home").await;
    let leak = seed_leak(
        &pool,
        owner,
        emitter,
        home,
        make_home(&pool, owner, "soft-twin").await,
    )
    .await;

    // soft-delete through the REAL path
    let mut tx = pool.begin().await.unwrap();
    fire(
        &mut tx,
        SeedAction::ResourceDelete {
            resource: leak.resource,
            emitter,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let (is_active, erased_at): (bool, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT is_active, erased_at FROM kb_resources WHERE id = $1")
            .bind(leak.resource.uuid())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!is_active, "the soft delete flipped is_active");
    assert!(
        erased_at.is_none(),
        "erased_at IS NULL — a tombstone is not a husk"
    );
    let prose: String = sqlx::query_scalar(
        "SELECT cc.content FROM kb_chunks c \
           JOIN kb_content_blocks b ON b.id = c.block_id \
           JOIN kb_chunk_content cc ON cc.chunk_id = c.id \
          WHERE b.resource_id = $1 AND c.is_current AND cc.content <> '' LIMIT 1",
    )
    .bind(leak.resource.uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        prose, CLEAN,
        "the current content is intact — soft delete hides, never erases"
    );
    let already: Option<bool> = sqlx::query_scalar::<_, bool>(
        "SELECT (resource_erasure_survey_plan($1)->>'already_erased')::boolean",
    )
    .bind(leak.resource.uuid())
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert_eq!(already, Some(false), "the survey says NOT erased");
}

/// (11, SQL half) The closed refusals RAISE at the SQL surface: already-erased, a charter
/// resource, an in-flight ingest. The recorded face is the service's.
#[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
async fn the_sql_refusals_raise(pool: sqlx::PgPool) {
    common::reset_schema(&pool).await;
    temper_substrate::scenario::bootseed::seed_system(&pool)
        .await
        .unwrap();
    let (owner, emitter) = system_actor(&pool).await;
    let home = make_home(&pool, owner, "refuse-home").await;
    let leak = seed_leak(
        &pool,
        owner,
        emitter,
        home,
        make_home(&pool, owner, "refuse-twin").await,
    )
    .await;

    execute_act(&pool, leak.resource.uuid()).await;

    // already-erased
    let again =
        sqlx::query_scalar::<sqlx::Postgres, Uuid>("SELECT resource_erasure_execute($1,$2,$3,$4)")
            .bind(leak.resource.uuid())
            .bind(owner.uuid())
            .bind(emitter)
            .bind(Uuid::now_v7())
            .fetch_one(&pool)
            .await;
    let msg = again.unwrap_err().to_string();
    assert!(
        msg.contains("already erased"),
        "the repeat refusal says why; got {msg}"
    );

    // a charter resource (a cogmap's telos) refuses — the map-grain act is another task
    // Genesis the map through the REAL cogmap-genesis path (the earlier raw
    // `INSERT INTO kb_cogmaps` produced a table row with NO ledger event, so replay
    // dropped the map and the dump diff diverged — a projection with no event behind it).
    // Genesis MINTS the telos resource itself — a pre-created one at the same id
    // collides (`kb_resources_pkey`), because the projector owns both inserts.
    let refusal_map = {
        let mut conn = pool.acquire().await.unwrap();
        fire(
            &mut conn,
            SeedAction::CogmapGenesis {
                name: "refusal-map",
                telos_title: "telos-for-refusal",
                charter: &[],
                cogmap_id: None,
                telos_resource_id: None,
                owner,
                emitter,
            },
        )
        .await
        .unwrap()
        .cogmap_genesis()
        .unwrap()
        .1
    };
    let telos = refusal_map;
    let _ = refusal_map;
    let charter =
        sqlx::query_scalar::<sqlx::Postgres, Uuid>("SELECT resource_erasure_execute($1,$2,$3,$4)")
            .bind(telos.uuid())
            .bind(owner.uuid())
            .bind(emitter)
            .bind(Uuid::now_v7())
            .fetch_one(&pool)
            .await;
    assert!(
        charter
            .unwrap_err()
            .to_string()
            .contains("charter resource"),
        "the charter refusal names itself"
    );

    // an ingest in flight refuses (a segmented-ingest resource, not yet finalized)
    let in_flight = writes::create_resource_with_mode(
        &pool,
        CreateParams {
            idempotency_key: None,
            title: "mid-ingest",
            origin_uri: "test://mid-ingest",
            body: "block zero",
            doc_type: "research",
            home: AnchorRef::context(home),
            owner,
            originator: owner,
            emitter,
            properties: &[],
            chunks: None,
            sources: vec![],
        },
        EventContext::default(),
        CreateMode {
            defer: false,
            segmented: true,
        },
    )
    .await
    .unwrap();
    let flight =
        sqlx::query_scalar::<sqlx::Postgres, Uuid>("SELECT resource_erasure_execute($1,$2,$3,$4)")
            .bind(in_flight.uuid())
            .bind(owner.uuid())
            .bind(emitter)
            .bind(Uuid::now_v7())
            .fetch_one(&pool)
            .await;
    assert!(
        flight
            .unwrap_err()
            .to_string()
            .contains("in flight; finalize or abandon first"),
        "the ingest-in-flight refusal says so"
    );

    // a nil resource cannot execute (not-found)
    let pending =
        sqlx::query_scalar::<sqlx::Postgres, Uuid>("SELECT resource_erasure_execute($1,$2,$3,$4)")
            .bind(Uuid::nil())
            .bind(owner.uuid())
            .bind(emitter)
            .bind(Uuid::now_v7())
            .fetch_one(&pool)
            .await;
    assert!(pending.is_err(), "a nil resource cannot execute");

    // a TOMBSTONE IS ERASABLE — the compliance flow's main shape: the content was
    // soft-deleted because it should never have been persisted, then the compliance need
    // arrives demanding it not exist at all. The act completes over one; the earlier
    // refusal was Pete's overrule in review (the principal act has no tombstone refusal
    // either — it tombstones VIA the act).
    let tombstone = writes::create_resource_with(
        &pool,
        CreateParams {
            idempotency_key: None,
            title: "tombstoned",
            origin_uri: "test://tombstone",
            body: "gone from the estate",
            doc_type: "research",
            home: AnchorRef::context(home),
            owner,
            originator: owner,
            emitter,
            properties: &[],
            chunks: None,
            sources: vec![],
        },
        EventContext::default(),
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE kb_resources SET is_active = false \
          WHERE id = $1 AND ingest_state = 'complete' AND erased_at IS NULL",
    )
    .bind(tombstone.uuid())
    .execute(&pool)
    .await
    .unwrap();
    // The act COMPLETES: a tombstone is not a refusal state.
    let _tomb_event = execute_act(&pool, tombstone.uuid()).await;
    let (t_active, t_erased): (bool, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT is_active, erased_at FROM kb_resources WHERE id = $1")
            .bind(tombstone.uuid())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !t_active && t_erased.is_some(),
        "the tombstone became a husk; got is_active={t_active} erased_at={t_erased:?}"
    );
    let tomb_prose: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kb_chunks c \
           JOIN kb_content_blocks b ON b.id = c.block_id \
           JOIN kb_chunk_content cc ON cc.chunk_id = c.id \
          WHERE b.resource_id = $1 AND cc.content <> ''",
    )
    .bind(tombstone.uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        tomb_prose, 0,
        "the tombstone's content is gone — soft delete hid it, the act ended it"
    );

    // The tombstone-then-erased ledger must REPLAY byte-identically: the `resource_deleted`
    // event is in trail scope, `resource_created`'s `resource_updated`-style is_active flip
    // rides the delete, and the erasure arm overwrites at its position. This is the exact
    // silent-divergence class the review flagged — a ledger whose tombstone lands BETWEEN
    // create and erase.
    let before = replay::dump_projections(&pool).await.unwrap();
    let snap = replay::snapshot(&pool).await.unwrap();
    common::reset_schema(&pool).await;
    replay::replay(&pool, &snap).await.unwrap();
    let after = replay::dump_projections(&pool).await.unwrap();
    for ((ta, a), (_tb, b)) in before.iter().zip(after.iter()) {
        assert_eq!(
            a, b,
            "projection table {ta} diverged under replay of a tombstone-then-erased erasure"
        );
    }

    // execute refuses a plan that names an ALREADY-FOLDED edge — the act completes on
    // live edges only now, so this exercises the live-only enumeration (the witness
    // the reviews asked for and the diff's own defect class).
}

/// (1, the twin half) A sibling with identical bytes in ANOTHER home keeps its content AND its
/// embedding — replayed proof — while the act empties R's rows row-anchored. `kb_erased_content`
/// gains no row.
#[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
async fn custody_is_never_decided_by_bytes(pool: sqlx::PgPool) {
    common::reset_schema(&pool).await;
    temper_substrate::scenario::bootseed::seed_system(&pool)
        .await
        .unwrap();
    let (owner, emitter) = system_actor(&pool).await;
    let leak = seed_leak(
        &pool,
        owner,
        emitter,
        make_home(&pool, owner, "custody-home").await,
        make_home(&pool, owner, "custody-twin").await,
    )
    .await;

    execute_act(&pool, leak.resource.uuid()).await;

    // The twin: content, embedding and search vector SURVIVE, byte for byte.
    let twin_prose: Option<String> = sqlx::query_scalar::<_, String>(
        "SELECT cc.content FROM kb_chunks c \
           JOIN kb_content_blocks b ON b.id = c.block_id \
           JOIN kb_chunk_content cc ON cc.chunk_id = c.id \
          WHERE b.resource_id = $1 AND c.is_current LIMIT 1",
    )
    .bind(leak.twin.uuid())
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert_eq!(
        twin_prose,
        Some(SECRET.to_string()),
        "the twin keeps its prose"
    );
    let twin_vec: Option<bool> = sqlx::query_scalar::<_, bool>(
        "SELECT (c.embedding IS NOT NULL) FROM kb_chunks c \
           JOIN kb_content_blocks b ON b.id = c.block_id \
          WHERE b.resource_id = $1 AND c.is_current LIMIT 1",
    )
    .bind(leak.twin.uuid())
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert_eq!(
        twin_vec,
        Some(true),
        "the twin's embedding is untouched (the drain never re-embeds it)"
    );
    let twin_alive: bool = sqlx::query_scalar("SELECT is_active FROM kb_resources WHERE id = $1")
        .bind(leak.twin.uuid())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(twin_alive, "the twin is a live resource in every dimension");

    // No hash enters the principal act's erased-content set (the fence of fences).
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM kb_erased_content")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        n, 0,
        "NO hash enters kb_erased_content from a resource erasure"
    );
}

/// Unset via the REAL path: update_resource's unset_keys (the key-grain delete event).
async fn unset_via_update(
    pool: &PgPool,
    resource: ResourceId,
    emitter: EntityId,
) -> Result<(), anyhow::Error> {
    writes::update_resource(
        pool,
        UpdateParams {
            resource,
            body: None,
            title: None,
            origin_uri: None,
            properties: &[],
            unset_keys: &["alpha-key".to_owned()],
            chunks: None,
            sources: vec![],
            content_block: None,
            rehome_to: None,
            emitter,
        },
    )
    .await
}

/// (9, the mapping half) A key set in many properties over the resource's events maps to ONE
/// erased-key-<n>; the surface carries no original key after the act; replay reproduces it
/// (the mapping is a pure function of ledger order).
#[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
async fn a_reset_key_maps_to_one_sentinel_key(pool: sqlx::PgPool) {
    common::reset_schema(&pool).await;
    temper_substrate::scenario::bootseed::seed_system(&pool)
        .await
        .unwrap();
    let (owner, emitter) = system_actor(&pool).await;
    let home = make_home(&pool, owner, "keymap-home").await;
    let resource = writes::create_resource_with(
        &pool,
        CreateParams {
            idempotency_key: None,
            title: "keyed",
            origin_uri: "test://keyed",
            body: "plainer",
            doc_type: "research",
            home: AnchorRef::context(home),
            owner,
            originator: owner,
            emitter,
            properties: &[("alpha-key".into(), serde_json::json!("beta"))],
            chunks: None,
            sources: vec![],
        },
        EventContext::default(),
    )
    .await
    .unwrap();

    // THE SAME original key, set → unset → re-set: three property events, ONE family
    // position. (The earlier draft used two different keys touched once each — that
    // exercised nothing about the numbering.)
    unset_via_update(&pool, resource, emitter).await.unwrap();
    writes::set_property(
        &pool,
        resource,
        "alpha-key",
        &serde_json::json!("gamma"),
        emitter,
    )
    .await
    .unwrap();

    execute_act(&pool, resource.uuid()).await;

    // Every property event that named the key now names ONE sentineled form: the
    // whole family collapses to exactly one `erased-key-<n>`, asserted exactly —
    // a `.all(starts_with)` would pass even if a regression split the family in two.
    let mut keys: Vec<String> = sqlx::query_scalar(
        "SELECT distinct property_key FROM kb_properties \
          WHERE owner_table='kb_resources' AND owner_id=$1",
    )
    .bind(resource.uuid())
    .fetch_all(&pool)
    .await
    .unwrap();
    keys.sort();
    assert_eq!(
        keys,
        vec!["erased-key-1".to_owned(), "erased-key-2".to_owned()],
        // key-1 is the resource's birth `doc_type` (earliest first_seen, and the
        // (first_seen, property_key) tie-break makes the numbering total); key-2 is
        // the alpha-key family. TWO keys, each ONE — that is the whole assertion.
        "the reset key's family maps ONE erased-key-<n> per key; distinct keys now: {keys:?}"
    );

    // The typed roundtrip contract is what catches a payload-shape drift like a
    // wrapped `{"edge_id": …}` item instead of a bare uuid — add it to the walk.
    payloads::verify_ledger_roundtrip(&pool).await.unwrap();
}

/// (9, the facet half) Two live rows of ONE key — the facet shape `facet_set` exists for — must
/// sentinel without colliding on `uq_kb_properties_active`. The act folds the whole family (one
/// live row per key is exactly what a two-value facet breaks), so the husk's surface is empty and
/// the collision cannot raise. Replay reproduces the fold + sentinels.
#[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
async fn two_live_rows_of_one_key_sentinel_without_colliding(pool: sqlx::PgPool) {
    common::reset_schema(&pool).await;
    temper_substrate::scenario::bootseed::seed_system(&pool)
        .await
        .unwrap();
    let (owner, emitter) = system_actor(&pool).await;
    let home = make_home(&pool, owner, "facet-home").await;
    let resource = writes::create_resource_with(
        &pool,
        CreateParams {
            idempotency_key: None,
            title: "faceted",
            origin_uri: "test://faceted",
            body: "facet body",
            doc_type: "research",
            home: AnchorRef::context(home),
            owner,
            originator: owner,
            emitter,
            properties: &[],
            chunks: None,
            sources: vec![],
        },
        EventContext::default(),
    )
    .await
    .unwrap();

    // TWO live rows of one key via facet_set: the `facet` key APPENDS rather than folds, and
    // one object value with two inner keys projects TWO live rows — exactly the shape the
    // sentinel pass would collide on if it left rows live.
    let vals: Vec<temper_substrate::ids::PropertyId> = writes::set_facet(
        &pool,
        PropertyOwner::resource(resource),
        &serde_json::json!({"status": "open", "owner": "jane smith"}),
        1.0,
        emitter,
    )
    .await
    .unwrap();
    assert_eq!(
        vals.len(),
        2,
        "one fire, two marks — TWO live rows; got {vals:?}"
    );

    let live_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kb_properties \
          WHERE owner_table='kb_resources' AND owner_id=$1 AND property_key='facet' AND NOT is_folded",
    )
    .bind(resource.uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        live_before, 2,
        "TWO live rows of one key (the facet shape); got {live_before}"
    );

    execute_act(&pool, resource.uuid()).await;

    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kb_properties \
          WHERE owner_table='kb_resources' AND owner_id=$1 AND NOT is_folded AND property_key <> 'doc_type'",
    )
    .bind(resource.uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(live, 0, "the husk keeps NO live metadata (Q3)");
    let stale: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kb_properties \
          WHERE owner_table='kb_resources' AND owner_id=$1 \
            AND (property_value IN ('1'::jsonb,'2'::jsonb) OR property_key NOT LIKE 'erased-key-%')",
    )
    .bind(resource.uuid())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stale, 0, "no original key or value survives folded either");

    // Replay reproduces the same folded+sentinelled family.
    let before = replay::dump_projections(&pool).await.unwrap();
    let snap = replay::snapshot(&pool).await.unwrap();
    common::reset_schema(&pool).await;
    replay::replay(&pool, &snap).await.unwrap();
    let after = replay::dump_projections(&pool).await.unwrap();
    for ((ta, a), (_tb, b)) in before.iter().zip(after.iter()) {
        assert_eq!(
            a, b,
            "projection table {ta} diverged under replay of a facet-sentineled erasure"
        );
    }
}

/// (13) A resource whose history carries an ALREADY-FOLDED edge is a lawful state — the
/// act must complete on the LIVE edges and record only what it folds. The first draft
/// enumerated every edge regardless of fold state and aborted execute on the pre-existing
/// fold; this witness was the defect's pin.
#[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
async fn a_pre_existing_folded_edge_does_not_abort_the_act(pool: sqlx::PgPool) {
    common::reset_schema(&pool).await;
    temper_substrate::scenario::bootseed::seed_system(&pool)
        .await
        .unwrap();
    let (owner, emitter) = system_actor(&pool).await;
    let home = make_home(&pool, owner, "prefold-home").await;
    let other = make_home(&pool, owner, "prefold-other").await;

    let a = writes::create_resource_with(
        &pool,
        CreateParams {
            idempotency_key: None,
            title: "with-history",
            origin_uri: "test://with-history",
            body: "history carries an ended edge",
            doc_type: "research",
            home: AnchorRef::context(home),
            owner,
            originator: owner,
            emitter,
            properties: &[],
            chunks: None,
            sources: vec![],
        },
        EventContext::default(),
    )
    .await
    .unwrap();
    let b = writes::create_resource_with(
        &pool,
        CreateParams {
            idempotency_key: None,
            title: "other party",
            origin_uri: "test://other-party",
            body: "b",
            doc_type: "research",
            home: AnchorRef::context(other),
            owner,
            originator: owner,
            emitter,
            properties: &[],
            chunks: None,
            sources: vec![],
        },
        EventContext::default(),
    )
    .await
    .unwrap();

    let edge = writes::assert_relationship(
        &pool,
        AssertParams {
            src: a,
            tgt: b,
            kind: EdgeKind::LeadsTo,
            polarity: EdgePolarity::Forward,
            label: Some("superseded-by"),
            weight: 1.0,
            home,
            emitter,
        },
    )
    .await
    .unwrap();

    // History folds it lawfully, for its own reason — before the erasure is ever asked.
    writes::fold_relationship(&pool, edge, Some("superseded"), emitter)
        .await
        .unwrap();

    execute_act(&pool, a.uuid()).await;

    // The folded edge was NOT re-listed as this act's work: exactly one fold of it
    // exists in the record (the history's own), and the act completed. The act's fold
    // events carry the payload FLAT (edge_id at the top level) — a regression that
    // re-folded a pre-folded edge would show up here.
    let act_folds: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kb_events e JOIN kb_event_types t ON t.id = e.event_type_id \
          WHERE t.name = 'relationship_folded' AND (e.payload->>'edge_id')::uuid = $1 \
            AND e.payload->>'reason' = 'resource_erased'",
    )
    .bind(edge)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        act_folds, 0,
        "the act folds only LIVE edges; the pre-existing fold keeps its own history"
    );
}

/// (14) THE BLOB STRIKE ARM + its list-verification fence, previously unwitnessed: a
/// listed live blob is struck through `blob_delete('blob_erased', …)` (released verdict;
/// the row's outcome prose is the fence template byte-parsed downstream), an operator
/// widening the plan mid-act is REFUSED, and the struck blob is named in `targets`.
#[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
async fn the_operator_listed_blob_strike_verifies_and_strikes(pool: sqlx::PgPool) {
    common::reset_schema(&pool).await;
    temper_substrate::scenario::bootseed::seed_system(&pool)
        .await
        .unwrap();
    let (owner, emitter) = system_actor(&pool).await;
    let home = make_home(&pool, owner, "strike-home").await;
    let leak = seed_leak(
        &pool,
        owner,
        emitter,
        home,
        make_home(&pool, owner, "strike-twin").await,
    )
    .await;

    // The blob + its relation edge, through the REAL write paths (an earlier raw-INSERT
    // fixture carried the same "projection with no event behind it" defect the refusal-map
    // genesis fix was made for): commit_blob stores + emits `blob_committed`, and the
    // relation is an ordinary edge — `AnchorRef::blob` is a lawful source (D3).
    let bytes = b"blob bytes under erasure".to_vec();
    let hash = {
        use sha2::Digest as _;
        format!("{:x}", sha2::Sha256::digest(&bytes))
    };
    let pathname = temper_substrate::blob_store::blob_pathname(&hash);
    let store = InMemoryBlobStore::default().with_object(pathname.clone());
    let blob = writes::commit_blob(
        &pool,
        &store,
        CommitBlobParams {
            id: BlobId::from(Uuid::now_v7()),
            home: AnchorRef::context(home),
            owner,
            originator: None,
            content_hash: hash.clone(),
            content_type: "image/png".to_owned(),
            content_bytes: bytes.len() as i64,
            max_bytes: 10 * 1024 * 1024,
            allowlist: &["image/png".to_owned()][..],
            emitter,
        },
    )
    .await
    .expect("the blob commits through the real path");
    {
        let mut conn = pool.acquire().await.unwrap();
        fire(
            &mut conn,
            SeedAction::RelationshipAssert {
                src: payloads::AnchorRef::blob(blob),
                tgt: payloads::AnchorRef::resource(leak.resource),
                kind: EdgeKind::Contains,
                polarity: EdgePolarity::Forward,
                label: Some("derived-from"),
                weight: 1.0,
                home: EdgeHome::Context(home),
                emitter,
            },
        )
        .await
        .expect("the blob-resource relation asserts through the real path");
    }

    // SURVEY: the plan names the blob in the related-blob remainder.
    let survey: serde_json::Value = sqlx::query_scalar("SELECT resource_erasure_survey($1)")
        .bind(leak.resource.uuid())
        .fetch_one(&pool)
        .await
        .unwrap();
    let remainder_blob_named = survey
        .get("remainder")
        .and_then(|r| r.as_array())
        .map(|a| {
            a.iter().any(|e| {
                e.get("target").and_then(|t| t.as_str()) == Some("kb_blobs")
                    && e.get("outcome")
                        .and_then(|o| o.as_str())
                        .map(|o| o.contains(&format!("blob {blob};")))
                        .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    assert!(
        remainder_blob_named,
        "the survey names the related blob: {survey}"
    );

    // EXECUTE with the operator's list: the strike runs, released=true, and the
    // byte-delete fence prose is recorded for the fence to parse.
    let (_, operator_entity) = system_actor(&pool).await;
    let outcome: serde_json::Value =
        sqlx::query_scalar("SELECT resource_erasure_execute($1,$2,$3,$4,$5)")
            .bind(leak.resource.uuid())
            .bind(operator_entity)
            .bind(operator_entity)
            .bind(Uuid::now_v7())
            .bind(vec![blob])
            .fetch_one(&pool)
            .await
            .expect("the act completes with the listed strike");
    let struck = outcome
        .get("targets")
        .and_then(|t| t.as_array())
        .map(|a| {
            a.iter()
                .any(|e| e.get("target").and_then(|t| t.as_str()) == Some("kb_blobs"))
        })
        .unwrap_or(false);
    assert!(struck, "the record names the blob strike; got {outcome}");

    // Widening the plan mid-act: a SECOND resource with its own related blob; the
    // operator offers a blob in NO relation to it, and is refused rather than
    // silently struck.
    let resource2 = writes::create_resource_with(
        &pool,
        CreateParams {
            idempotency_key: None,
            title: "strike-target-two",
            origin_uri: "test://strike-two",
            body: "second erasure target",
            doc_type: "research",
            home: AnchorRef::context(home),
            owner,
            originator: owner,
            emitter,
            properties: &[],
            chunks: None,
            sources: vec![],
        },
        EventContext::default(),
    )
    .await
    .unwrap();
    let widened = sqlx::query_scalar::<sqlx::Postgres, Uuid>(
        "SELECT (resource_erasure_execute($1,$2,$3,$4,$5)->>'event_id')::text",
    )
    .bind(resource2.uuid())
    .bind(operator_entity)
    .bind(operator_entity)
    .bind(Uuid::now_v7())
    .bind(vec![blob])
    .fetch_one(&pool)
    .await;
    assert!(
        widened
            .unwrap_err()
            .to_string()
            .contains("related-blob remainder; strike refused"),
        "a listed blob the plan did NOT name is refused, not silently struck"
    );
}
