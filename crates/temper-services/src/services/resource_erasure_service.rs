//! The resource-erasure act's service layer — execute + survey (resource erasure spec 2026-09-28,
//! build order 2b; D5, D8, D10). The principal act's service (`erasure_service`) is the template:
//! the same gate order, the same silent survey, the same wire-struct decoding of the act's jsonb.
//!
//! THE GATE IS `is_system_admin` AND NOTHING MORE (ruled 2026-09-30). "Operator + tenant" means
//! the instance: there is no tenant axis — `is_system_admin` (20260720000100) is the single
//! gating team's owner — and the act reaches a resource in any context (D5), so no per-context
//! check is added. The gate resolves before any SQL touches the resource (authz-before-writes):
//! a non-operator's execute is a RECORDED `unauthorized` refusal and its only mutation; a
//! non-operator's survey is a silent 404 that records nothing (D10: a survey requests nothing).
//! Existence is disclosed only past the gate, as [`ApiError::NotFound`], never as raise text.
//!
//! SQL commits, it does not decide legality: the plan, the folds, the strikes and the redaction
//! body live in `resource_erasure_survey_plan` / `resource_erasure_execute` /
//! `resource_erasure_refuse` (migration 20260929040730). Two things diverge from the principal
//! door ON PURPOSE:
//!
//! * **The request reference is minted here**, one `Uuid::now_v7()` per act, never taken from a
//!   caller. It is the act's correlation id, and replay finds the act's span by it (D14): a
//!   reused reference would merge two acts' spans, so it is never reused and never batched. A
//!   refusal recorded after a raised execute carries the same reference — the aborted execute
//!   appended nothing, so the reference names exactly one attempt.
//! * **The act's raises are mapped**, through a closed classifier (`classify_act_failure`).
//!   Every raise in the act is a bare `RAISE EXCEPTION` (SQLSTATE P0001, no ERRCODE, HINT or
//!   DETAIL), so the classifier matches the message on stable prefixes and suffixes, pinned by
//!   unit tests over every literal and by a test-db witness against the live SQL. A refused
//!   state (charter, already erased) becomes a recorded refusal; a deadlock (`40P01`) or a
//!   raced edge fold retries a bounded number of times; nothing the SQL says reaches a response.
//!
//! The provider bytes of a released strike are deleted AFTER the act commits (a provider call
//! cannot join the transaction), once per released strike, and only when a store is configured.
//! A failed or skipped release is not a door failure: the byte-delete fence
//! (`erasure_fence_service`) derives the same deletes from the `resource_erased` payload and
//! retries them with age alerting (derive-don't-remember). The HTTP doors call straight into
//! [`execute_resource_erasure`] / [`survey_resource_erasure`]; this module carries no HTTP types.

use std::collections::HashMap;

use sqlx::PgPool;
use uuid::Uuid;

use temper_core::types::ids::{BlobId, EdgeId, EntityId, ProfileId, PropertyId, ResourceId};
use temper_substrate::blob_store::BlobStore;
use temper_substrate::payloads::{
    ErasureTargetOutcome, RedactedEventFields, ResourceErasureRefusalReason,
};
use temper_substrate::writes::{release_blob_bytes, resolve_emitter};
use temper_workflow::operations::Surface;

use crate::error::{ApiError, ApiResult};
use crate::services::access_service;
use crate::services::erasure_fence_service::{
    classify_blob_outcome, BlobOutcomeClass, BLOB_TARGET,
};
use crate::services::erasure_service::BlobStrikeOutcome;

/// How many times one act re-runs after a retryable failure (a deadlock or a raced edge fold)
/// before it answers `Internal`. Two retries, three attempts: the byte-delete fence's bound for
/// the same deadlock class (`erasure_fence_service::drain`). The act is one statement and one
/// transaction, so a failed attempt commits nothing and each retry is a fresh statement against
/// the post-conflict state.
const MAX_ACT_RETRIES: u32 = 2;

/// The one refusal detail today: a charter resource's erasure is map-grain, filed as its own task
/// (01a0e960-0ca2-7f42-b33e-1ed19b024e6b). Fixed text, because the refusal event is an admin
/// event that is never redactable: no caller-chosen text can reach it.
pub const MAP_GRAIN_ERASURE_DETAIL: &str =
    "map-grain erasure is task 01a0e960-0ca2-7f42-b33e-1ed19b024e6b";

/// The SQLSTATE Postgres raises when it resolves a deadlock by aborting one transaction.
const DEADLOCK_DETECTED: &str = "40P01";

/// The prefix of every raise in `resource_erasure_execute` (migration 20260929040730).
const EXECUTE_RAISE_PREFIX: &str = "resource_erasure_execute: ";

/// The shape of a related-blob remainder entry the plan writes: `related blob <id>; hash …`.
const RELATED_BLOB_PREFIX: &str = "related blob ";

const RESOURCE_NOT_FOUND: &str = "resource not found";

/// The closed vocabulary of a refusal's `detail`. A type, not a `String`, so free text can never
/// reach the never-redactable refusal event (the length bound the SQL lacks is unnecessary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceErasureRefusalDetail {
    /// A charter (cogmap telos) resource: map-grain erasure is its own act and task.
    MapGrainErasureTask,
}

impl ResourceErasureRefusalDetail {
    /// The fixed text recorded on the refusal event.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MapGrainErasureTask => MAP_GRAIN_ERASURE_DETAIL,
        }
    }
}

/// One execute request. The request reference is not here: the service mints it.
#[derive(Debug, Clone, Copy)]
pub struct ResourceErasureRequest<'a> {
    pub caller: ProfileId,
    pub resource: ResourceId,
    /// The blobs the operator lists for striking (D8): each must be named in the survey's
    /// related-blob remainder, or the act refuses the whole request.
    pub also_strike_blobs: &'a [BlobId],
    /// Where the request came from; the act and any refusal are attributed through it.
    pub surface: Surface,
}

/// A completed resource erasure: ONE `resource_erased` event stands behind these values.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceErasureCompletion {
    /// The server-minted reference the act is correlated by — the operator cites it.
    pub request_reference: Uuid,
    pub event_id: Uuid,
    /// Every edge this act folded, each by its own `relationship_folded` event.
    pub folded_edges: Vec<EdgeId>,
    pub targets: Vec<ErasureTargetOutcome>,
    /// What the act names and does not touch, by design (D8).
    pub remainder: Vec<ErasureTargetOutcome>,
    /// The resource's own ledger paths the act has not reached (D12).
    pub ledger_remainder: Vec<RedactedEventFields>,
    /// The operator-listed strikes, in the operator's order, each with its strike-time verdict.
    pub blob_strikes: Vec<BlobStrikeOutcome>,
}

/// A recorded refusal: one `resource_erasure_refused` event, nothing else mutated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceErasureRefusal {
    /// The server-minted reference the refusal event is correlated by.
    pub request_reference: Uuid,
    pub event_id: Uuid,
    pub reason: ResourceErasureRefusalReason,
    pub detail: Option<ResourceErasureRefusalDetail>,
}

/// What an execute call did.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceErasureOutcome {
    Completed(ResourceErasureCompletion),
    Refused(ResourceErasureRefusal),
}

/// An edge touching the resource whose asserting principal is not the resource's owner.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OtherAuthorEdge {
    pub edge_id: EdgeId,
    /// The profile behind the entity that emitted the edge's asserting event.
    pub author: ProfileId,
    /// Already folded at survey time: the act appends no fold for it, but still nulls its label
    /// and sentinels its properties (steps 9c and 9d reach live and folded edges).
    pub folded: bool,
}

/// A property row owned by an edge touching the resource, asserted by another principal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OtherAuthorEdgeProperty {
    pub property_id: PropertyId,
    pub edge_id: EdgeId,
    pub author: ProfileId,
}

/// A related blob and the other resources that hold a live edge to it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlobCoLinks {
    pub blob_id: BlobId,
    /// Empty when no other resource links the blob.
    pub holders: Vec<ResourceId>,
}

/// The plan `resource_erasure_survey` renders, plus the display-only annotations. The act never
/// consumes the annotations (D10's fingerprint posture): they are read after the plan, in Rust.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ResourceErasurePlan {
    pub n_blocks: i64,
    pub n_revisions: i64,
    pub n_chunks: i64,
    pub n_artifacts: i64,
    pub n_edges: i64,
    /// The live edges the act would fold.
    pub edges: Vec<EdgeId>,
    pub targets: Vec<ErasureTargetOutcome>,
    /// Set when the resource is a cogmap's charter: the act would refuse.
    pub charter_of: Option<Uuid>,
    pub ingest_state: String,
    pub fingerprint_available: bool,
    /// Derivers, related blobs, cross-resource ledger text and shared remote sources (D8).
    pub remainder: Vec<ErasureTargetOutcome>,
    pub ledger_remainder: Vec<RedactedEventFields>,
    pub other_author_edges: Vec<OtherAuthorEdge>,
    pub other_author_edge_properties: Vec<OtherAuthorEdgeProperty>,
    pub blob_co_links: Vec<BlobCoLinks>,
}

/// The read-only survey. `plan` is `None` exactly when the resource was already erased when the
/// survey began (the short-circuit); `already_erased` also reads true when an act lands between
/// that read and the plan, and then the plan is present.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ResourceErasureSurvey {
    pub resource: ResourceId,
    pub already_erased: bool,
    pub plan: Option<ResourceErasurePlan>,
}

/// The jsonb `resource_erasure_execute` returns.
#[derive(Debug, serde::Deserialize)]
struct ExecuteOutcomeWire {
    event_id: Uuid,
    edges: Vec<EdgeId>,
    targets: Vec<ErasureTargetOutcome>,
    remainder: Vec<ErasureTargetOutcome>,
    ledger_remainder: Vec<RedactedEventFields>,
}

/// The jsonb `resource_erasure_survey` returns (its `resource` key is ignored: the caller named
/// it).
#[derive(Debug, serde::Deserialize)]
struct SurveyPlanWire {
    n_blocks: i64,
    n_revisions: i64,
    n_chunks: i64,
    n_artifacts: i64,
    n_edges: i64,
    edges: Vec<EdgeId>,
    targets: Vec<ErasureTargetOutcome>,
    already_erased: bool,
    charter_of: Option<Uuid>,
    ingest_state: String,
    fingerprint_available: bool,
    remainder: Vec<ErasureTargetOutcome>,
    ledger_remainder: Vec<RedactedEventFields>,
}

/// Who is attempting which act, under which reference: everything a refusal records.
#[derive(Debug, Clone, Copy)]
struct Attempt {
    caller: ProfileId,
    emitter: EntityId,
    resource: ResourceId,
    request_reference: Uuid,
}

/// How one run of the act ended, once the classifier has read any failure.
#[derive(Debug)]
enum ActVerdict {
    Completed(ExecuteOutcomeWire),
    Refused(
        ResourceErasureRefusalReason,
        Option<ResourceErasureRefusalDetail>,
    ),
}

/// The closed classification of a failed `resource_erasure_execute` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActFailure {
    Charter,
    AlreadyErased,
    NotFound,
    /// A listed blob the plan did not name; the id when the message carried a parseable one.
    BlobNotInRemainder(Option<Uuid>),
    /// A listed blob a previous act already struck.
    BlobAlreadyStruck(Option<Uuid>),
    /// A deadlock, or an edge folded between the plan and the fold loop.
    Retryable,
    Other,
}

/// Execute the resource-erasure act.
///
/// The emitter resolves first (an unattributable authority act is worse than a failed one), then
/// the `is_system_admin` gate: a non-operator's attempt is recorded as the `unauthorized`
/// refusal, attributed to the attempter, and nothing else happens. Past the gate, an unknown
/// resource is [`ApiError::NotFound`] (existence is disclosed after the gate, operator-only).
/// A charter or an already-erased resource is a recorded refusal (the effect of a repeat
/// erasure is a no-op: no second `resource_erased` is minted).
/// A listed blob the act refuses to strike is [`ApiError::BadRequest`] naming that blob; the act
/// rolled back whole, so nothing was struck.
pub async fn execute_resource_erasure(
    pool: &PgPool,
    store: Option<&dyn BlobStore>,
    request: ResourceErasureRequest<'_>,
) -> ApiResult<ResourceErasureOutcome> {
    let emitter = resolve_emitter(pool, request.caller, request.surface.marker())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let is_operator = access_service::is_system_admin(pool, request.caller).await?;
    let attempt = Attempt {
        caller: request.caller,
        emitter,
        resource: request.resource,
        request_reference: Uuid::now_v7(),
    };

    if !is_operator {
        let refusal = refuse(
            pool,
            &attempt,
            ResourceErasureRefusalReason::Unauthorized,
            None,
        )
        .await?;
        return Ok(ResourceErasureOutcome::Refused(refusal));
    }

    // Gate passed — NOW existence may be disclosed, and as an error, not a ledger row.
    if erased_state(pool, request.resource).await?.is_none() {
        return Err(ApiError::NotFound(RESOURCE_NOT_FOUND.to_string()));
    }

    let wire = match run_act(pool, &attempt, request.also_strike_blobs).await? {
        ActVerdict::Completed(wire) => wire,
        ActVerdict::Refused(reason, detail) => {
            let refusal = refuse(pool, &attempt, reason, detail).await?;
            return Ok(ResourceErasureOutcome::Refused(refusal));
        }
    };

    let blob_strikes = strike_verdicts(
        pool,
        attempt.request_reference,
        request.also_strike_blobs,
        &wire.targets,
    )
    .await?;
    if let Some(store) = store {
        release_struck_bytes(pool, store, &blob_strikes).await;
    }

    Ok(ResourceErasureOutcome::Completed(
        ResourceErasureCompletion {
            request_reference: attempt.request_reference,
            event_id: wire.event_id,
            folded_edges: wire.edges,
            targets: wire.targets,
            remainder: wire.remainder,
            ledger_remainder: wire.ledger_remainder,
            blob_strikes: blob_strikes.into_iter().map(|s| s.outcome).collect(),
        },
    ))
}

/// `None` when no such resource exists; otherwise whether it is already erased.
async fn erased_state(pool: &PgPool, resource: ResourceId) -> ApiResult<Option<bool>> {
    let erased = sqlx::query_scalar!(
        r#"SELECT erased_at IS NOT NULL AS "erased!" FROM kb_resources WHERE id = $1"#,
        resource.uuid(),
    )
    .fetch_optional(pool)
    .await?;
    Ok(erased)
}

/// Run the act, retrying a retryable failure up to [`MAX_ACT_RETRIES`] times, and map every
/// other failure through the classifier.
async fn run_act(
    pool: &PgPool,
    attempt: &Attempt,
    also_strike_blobs: &[BlobId],
) -> ApiResult<ActVerdict> {
    let blobs: Vec<Uuid> = also_strike_blobs.iter().map(|b| b.uuid()).collect();
    let mut retries = 0;
    loop {
        let result = sqlx::query_scalar!(
            r#"SELECT resource_erasure_execute($1, $2, $3, $4, $5)
                   AS "outcome: serde_json::Value""#,
            attempt.resource.uuid(),
            attempt.caller.uuid(),
            attempt.emitter.uuid(),
            attempt.request_reference,
            &blobs[..],
        )
        .fetch_one(pool)
        .await;
        let err = match result {
            Ok(raw) => return decode_completion(raw).map(ActVerdict::Completed),
            Err(err) => err,
        };
        match classify_act_error(&err) {
            ActFailure::Retryable if retries < MAX_ACT_RETRIES => retries += 1,
            failure => return verdict_for(failure, also_strike_blobs, err),
        }
    }
}

fn decode_completion(raw: Option<serde_json::Value>) -> ApiResult<ExecuteOutcomeWire> {
    let raw = raw.ok_or_else(|| {
        ApiError::Internal("resource_erasure_execute returned no row".to_string())
    })?;
    serde_json::from_value(raw)
        .map_err(|e| ApiError::Internal(format!("resource erasure outcome shape: {e}")))
}

/// What a classified failure means for the caller. Never carries the raise text: a refusal is
/// recorded vocabulary, a blob refusal is a fixed message naming the operator's own blob id, and
/// anything unexpected is a scrubbed `Internal` (logged, not rendered).
fn verdict_for(
    failure: ActFailure,
    supplied: &[BlobId],
    err: sqlx::Error,
) -> ApiResult<ActVerdict> {
    match failure {
        ActFailure::Charter => Ok(ActVerdict::Refused(
            ResourceErasureRefusalReason::CharterResource,
            Some(ResourceErasureRefusalDetail::MapGrainErasureTask),
        )),
        ActFailure::AlreadyErased => Ok(ActVerdict::Refused(
            ResourceErasureRefusalReason::AlreadyErased,
            None,
        )),
        ActFailure::NotFound => Err(ApiError::NotFound(RESOURCE_NOT_FOUND.to_string())),
        ActFailure::BlobNotInRemainder(blob) => Err(blob_refusal(
            blob,
            supplied,
            "is not a related blob of this resource (the survey's remainder names the blobs \
             that may be listed); nothing was struck",
        )),
        ActFailure::BlobAlreadyStruck(blob) => Err(blob_refusal(
            blob,
            supplied,
            "was struck by an earlier act and cannot be struck again; nothing was struck",
        )),
        ActFailure::Retryable | ActFailure::Other => Err(ApiError::internal_scrubbed(
            "resource erasure act failed",
            err,
        )),
    }
}

/// A 400 naming the blob the operator listed. The id comes from the raise only when it is one
/// of the operator's own; otherwise the message names no id.
fn blob_refusal(blob: Option<Uuid>, supplied: &[BlobId], reason: &str) -> ApiError {
    match blob.filter(|b| supplied.iter().any(|s| s.uuid() == *b)) {
        Some(blob) => ApiError::BadRequest(format!("blob {blob} {reason}")),
        None => ApiError::BadRequest(format!("a listed blob {reason}")),
    }
}

/// Classify a failed act call. A non-database error (a lost connection, a decode failure) is
/// `Other`.
fn classify_act_error(err: &sqlx::Error) -> ActFailure {
    match err.as_database_error() {
        Some(db) => classify_act_failure(db.code().as_deref(), db.message()),
        None => ActFailure::Other,
    }
}

/// The pure classifier over a database error's SQLSTATE and message. The literals it matches
/// are the act's own raises (migration 20260929040730) and `blob_delete`'s already-struck raise
/// (20260906000010); each `%` in them is an id, so each arm matches a stable prefix and suffix.
/// `p_resource is required` and `p_request_ref is required` are `Other`: the service always
/// supplies both, so either raise is a bug here, not a state of the resource.
fn classify_act_failure(code: Option<&str>, message: &str) -> ActFailure {
    if code == Some(DEADLOCK_DETECTED) {
        return ActFailure::Retryable;
    }
    if let Some(rest) = message.strip_prefix(EXECUTE_RAISE_PREFIX) {
        return classify_execute_raise(rest);
    }
    if let Some(id) = message
        .strip_prefix("blob_delete: blob ")
        .and_then(|rest| rest.split_once(" is already struck"))
        .map(|(id, _)| id)
    {
        return ActFailure::BlobAlreadyStruck(Uuid::parse_str(id).ok());
    }
    ActFailure::Other
}

/// The arms of `resource_erasure_execute`'s raises, after its prefix.
fn classify_execute_raise(rest: &str) -> ActFailure {
    if rest == "already erased" {
        ActFailure::AlreadyErased
    } else if rest.starts_with("charter resource") {
        ActFailure::Charter
    } else if let Some(id) = between(
        rest,
        "blob ",
        " is not in the survey's related-blob remainder; strike refused",
    ) {
        ActFailure::BlobNotInRemainder(Uuid::parse_str(id).ok())
    } else if between(rest, "edge ", " missing or already folded").is_some() {
        ActFailure::Retryable
    } else if between(rest, "resource ", " not found").is_some() {
        ActFailure::NotFound
    } else {
        ActFailure::Other
    }
}

fn between<'a>(s: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    s.strip_prefix(prefix)?.strip_suffix(suffix)
}

/// Record a refusal: ONE `resource_erasure_refused` event, nothing else mutated. Attributed to
/// the attempter through the request's surface, correlated by the attempt's reference.
async fn refuse(
    pool: &PgPool,
    attempt: &Attempt,
    reason: ResourceErasureRefusalReason,
    detail: Option<ResourceErasureRefusalDetail>,
) -> ApiResult<ResourceErasureRefusal> {
    let reason_str = serde_json::to_value(reason)
        .expect("a refusal reason always serializes")
        .as_str()
        .expect("a refusal reason serializes to a string")
        .to_string();

    let event_id: Uuid = sqlx::query_scalar!(
        r#"SELECT resource_erasure_refuse($1, $2, $3, $4, $5, $6) AS "event: Uuid""#,
        attempt.resource.uuid(),
        attempt.caller.uuid(),
        attempt.emitter.uuid(),
        attempt.request_reference,
        reason_str,
        detail.map(ResourceErasureRefusalDetail::as_str),
    )
    .fetch_one(pool)
    .await?
    .ok_or_else(|| ApiError::Internal("resource_erasure_refuse returned no row".to_string()))?;

    Ok(ResourceErasureRefusal {
        request_reference: attempt.request_reference,
        event_id,
        reason,
        detail,
    })
}

/// One settled strike: the outcome the caller sees, plus what a release needs.
struct SettledStrike {
    outcome: BlobStrikeOutcome,
    content_hash: String,
    /// The pathname the strike released, when it released one.
    released_pathname: Option<String>,
}

/// The strike verdicts of a completed act, in the operator's order. The act appended one
/// `kb_blobs` target per listed blob, in list order, each in the ONE strike-outcome template
/// (`blob_strike_outcome_text`); it is read through the fence's own parser, so the service
/// releases exactly what the fence would seed. The `blob_erased` events under the act's
/// correlation id pair each strike with its row, and the content hash comes from that row, never
/// from the pathname. A mismatch means the record and the ledger disagree: the act has
/// committed, so the error names its reference rather than guessing a verdict.
async fn strike_verdicts(
    pool: &PgPool,
    request_reference: Uuid,
    listed: &[BlobId],
    targets: &[ErasureTargetOutcome],
) -> ApiResult<Vec<SettledStrike>> {
    let hashes: HashMap<Uuid, String> = sqlx::query!(
        r#"
        SELECT (e.payload->>'blob_id')::uuid AS "blob_id!: Uuid",
               b.content_hash               AS "content_hash!"
          FROM kb_events e
          JOIN kb_event_types t ON t.id = e.event_type_id AND t.name = 'blob_erased'
          JOIN kb_blobs b ON b.id = (e.payload->>'blob_id')::uuid
         WHERE e.correlation_id = $1
        "#,
        request_reference,
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|r| (r.blob_id, r.content_hash))
    .collect();

    let committed_but_unreadable = || {
        ApiError::Internal(format!(
            "resource erasure {request_reference} committed, but its strike record does not \
             match the ledger"
        ))
    };
    let verdicts: Vec<&ErasureTargetOutcome> =
        targets.iter().filter(|t| t.target == BLOB_TARGET).collect();
    if verdicts.len() != listed.len() || hashes.len() != listed.len() {
        return Err(committed_but_unreadable());
    }

    listed
        .iter()
        .zip(verdicts)
        .map(|(blob, verdict)| {
            let content_hash = hashes
                .get(&blob.uuid())
                .cloned()
                .ok_or_else(committed_but_unreadable)?;
            let released_pathname = match classify_blob_outcome(&verdict.outcome) {
                BlobOutcomeClass::Released(pathname) => Some(pathname),
                BlobOutcomeClass::Known => None,
                BlobOutcomeClass::Unrecognized => return Err(committed_but_unreadable()),
            };
            Ok(SettledStrike {
                outcome: BlobStrikeOutcome {
                    blob_id: blob.uuid(),
                    released: released_pathname.is_some(),
                },
                content_hash,
                released_pathname,
            })
        })
        .collect()
}

/// The post-commit byte release, once per released strike — the `blob_service` delete door's
/// shape: `release_blob_bytes` re-derives released-ness under the hash lock and holds it across
/// the provider delete. A skip or a failure is logged, never a door failure: the fence seeds the
/// same pathname from the `resource_erased` payload and retries it with age alerting.
async fn release_struck_bytes(pool: &PgPool, store: &dyn BlobStore, strikes: &[SettledStrike]) {
    for strike in strikes {
        let Some(pathname) = strike.released_pathname.as_deref() else {
            continue;
        };
        let blob = strike.outcome.blob_id;
        match release_blob_bytes(pool, &strike.content_hash, pathname, store).await {
            Ok(true) => {}
            Ok(false) => tracing::info!(
                blob = %blob,
                "post-commit release skipped: a live row re-holds the hash — the fence \
                 resolves its seeded row re-occupied"
            ),
            Err(e) => tracing::warn!(
                blob = %blob,
                error = format!("{e:#}"),
                "post-commit provider delete failed — the byte-delete fence retries with \
                 age alerting"
            ),
        }
    }
}

/// The read-only survey: what [`execute_resource_erasure`] would do if it ran now, rendered
/// from the act's own plan (`resource_erasure_survey_plan`, D10), plus display-only annotations.
///
/// THE GATE IS FIRST AND SILENT: a non-operator gets [`ApiError::NotFound`] and nothing else —
/// no emitter resolves and no refusal is recorded (a survey attempt is not an erasure request).
/// Past the gate (the execute door's order, operator-only), an unknown resource is `NotFound`,
/// and an already-erased one short-circuits to a minimal survey with no plan: the plan still
/// counts rows on a husk, which would misstate what an act could reach.
pub async fn survey_resource_erasure(
    pool: &PgPool,
    caller: ProfileId,
    resource: ResourceId,
) -> ApiResult<ResourceErasureSurvey> {
    if !access_service::is_system_admin(pool, caller).await? {
        return Err(ApiError::NotFound("not found".to_string()));
    }

    match erased_state(pool, resource).await? {
        None => return Err(ApiError::NotFound(RESOURCE_NOT_FOUND.to_string())),
        Some(true) => {
            return Ok(ResourceErasureSurvey {
                resource,
                already_erased: true,
                plan: None,
            })
        }
        Some(false) => {}
    }

    let raw = sqlx::query_scalar!(
        r#"SELECT resource_erasure_survey($1) AS "survey: serde_json::Value""#,
        resource.uuid(),
    )
    .fetch_one(pool)
    .await?
    .ok_or_else(|| ApiError::Internal("resource_erasure_survey returned no row".to_string()))?;
    let wire: SurveyPlanWire = serde_json::from_value(raw)
        .map_err(|e| ApiError::Internal(format!("resource erasure survey shape: {e}")))?;

    let other_author_edges = other_author_edges(pool, resource).await?;
    let other_author_edge_properties = other_author_edge_properties(pool, resource).await?;
    let blob_co_links = blob_co_links(pool, resource, &wire.remainder).await?;

    Ok(ResourceErasureSurvey {
        resource,
        already_erased: wire.already_erased,
        plan: Some(ResourceErasurePlan {
            n_blocks: wire.n_blocks,
            n_revisions: wire.n_revisions,
            n_chunks: wire.n_chunks,
            n_artifacts: wire.n_artifacts,
            n_edges: wire.n_edges,
            edges: wire.edges,
            targets: wire.targets,
            charter_of: wire.charter_of,
            ingest_state: wire.ingest_state,
            fingerprint_available: wire.fingerprint_available,
            remainder: wire.remainder,
            ledger_remainder: wire.ledger_remainder,
            other_author_edges,
            other_author_edge_properties,
            blob_co_links,
        }),
    })
}

/// Every edge touching the resource — live or already folded, the reach of the act's label and
/// property steps (9c, 9d) — whose asserting principal is not the resource's owner.
///
/// Authorship is not a column on `kb_edges`: it is the emitter of the edge's asserting event
/// (`asserted_by_event_id` → `kb_events.emitter_entity_id`), the actor `element_trail_edge`
/// reports. The comparison is PROFILE to PROFILE: the owner is
/// `kb_resource_homes.owner_profile_id` and the emitting entity is resolved to its `profile_id`,
/// because an entity is one surface of a principal (`<handle>@web`, `<handle>@cli`), and the
/// owner's own edge asserted from another surface is not another principal's text.
async fn other_author_edges(
    pool: &PgPool,
    resource: ResourceId,
) -> ApiResult<Vec<OtherAuthorEdge>> {
    let rows = sqlx::query!(
        r#"
        SELECT e.id          AS "edge_id!: Uuid",
               en.profile_id AS "author!: Uuid",
               e.is_folded   AS "folded!"
          FROM kb_edges e
          JOIN kb_events ev ON ev.id = e.asserted_by_event_id
          JOIN kb_entities en ON en.id = ev.emitter_entity_id
         WHERE ((e.source_table = 'kb_resources' AND e.source_id = $1)
             OR (e.target_table = 'kb_resources' AND e.target_id = $1))
           AND en.profile_id IS DISTINCT FROM
               (SELECT h.owner_profile_id FROM kb_resource_homes h WHERE h.resource_id = $1)
         ORDER BY e.id
        "#,
        resource.uuid(),
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| OtherAuthorEdge {
            edge_id: EdgeId::from(r.edge_id),
            author: ProfileId::from(r.author),
            folded: r.folded,
        })
        .collect())
}

/// Every property row owned by an edge touching the resource (live or folded, every row step 9d
/// sentinels) whose asserting principal is not the resource's owner — the same derivation and
/// the same profile-to-profile comparison as [`other_author_edges`], over the row's own
/// `asserted_by_event_id`.
async fn other_author_edge_properties(
    pool: &PgPool,
    resource: ResourceId,
) -> ApiResult<Vec<OtherAuthorEdgeProperty>> {
    let rows = sqlx::query!(
        r#"
        SELECT p.id          AS "property_id!: Uuid",
               e.id          AS "edge_id!: Uuid",
               en.profile_id AS "author!: Uuid"
          FROM kb_properties p
          JOIN kb_edges e ON p.owner_table = 'kb_edges' AND e.id = p.owner_id
          JOIN kb_events ev ON ev.id = p.asserted_by_event_id
          JOIN kb_entities en ON en.id = ev.emitter_entity_id
         WHERE ((e.source_table = 'kb_resources' AND e.source_id = $1)
             OR (e.target_table = 'kb_resources' AND e.target_id = $1))
           AND en.profile_id IS DISTINCT FROM
               (SELECT h.owner_profile_id FROM kb_resource_homes h WHERE h.resource_id = $1)
         ORDER BY p.id
        "#,
        resource.uuid(),
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| OtherAuthorEdgeProperty {
            property_id: PropertyId::from(r.property_id),
            edge_id: EdgeId::from(r.edge_id),
            author: ProfileId::from(r.author),
        })
        .collect())
}

/// For each related blob the plan's remainder names, the other resources holding a live edge
/// to it. The blobs are the plan's own (parsed from its remainder), never re-derived.
async fn blob_co_links(
    pool: &PgPool,
    resource: ResourceId,
    remainder: &[ErasureTargetOutcome],
) -> ApiResult<Vec<BlobCoLinks>> {
    let blobs = related_blob_ids(remainder)?;
    if blobs.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query!(
        r#"
        SELECT CASE WHEN e.source_table = 'kb_blobs' THEN e.source_id ELSE e.target_id END
                   AS "blob_id!: Uuid",
               CASE WHEN e.source_table = 'kb_blobs' THEN e.target_id ELSE e.source_id END
                   AS "holder!: Uuid"
          FROM kb_edges e
         WHERE NOT e.is_folded
           AND ((e.source_table = 'kb_blobs' AND e.source_id = ANY($1)
                 AND e.target_table = 'kb_resources' AND e.target_id <> $2)
             OR (e.target_table = 'kb_blobs' AND e.target_id = ANY($1)
                 AND e.source_table = 'kb_resources' AND e.source_id <> $2))
         ORDER BY 1, 2
        "#,
        &blobs[..],
        resource.uuid(),
    )
    .fetch_all(pool)
    .await?;

    Ok(blobs
        .into_iter()
        .map(|blob| {
            let mut holders: Vec<ResourceId> = rows
                .iter()
                .filter(|r| r.blob_id == blob)
                .map(|r| ResourceId::from(r.holder))
                .collect();
            holders.dedup();
            BlobCoLinks {
                blob_id: BlobId::from(blob),
                holders,
            }
        })
        .collect())
}

/// The blob ids of the plan's related-blob remainder entries (`related blob <id>; hash …`). An
/// entry in any other shape is drift in the plan's template, and fails loud.
fn related_blob_ids(remainder: &[ErasureTargetOutcome]) -> ApiResult<Vec<Uuid>> {
    remainder
        .iter()
        .filter(|r| r.target == BLOB_TARGET)
        .map(|r| {
            r.outcome
                .strip_prefix(RELATED_BLOB_PREFIX)
                .and_then(|rest| rest.split_once(';'))
                .and_then(|(id, _)| Uuid::parse_str(id).ok())
                .ok_or_else(|| {
                    ApiError::Internal(
                        "the survey's remainder names a blob in an unrecognized shape".to_string(),
                    )
                })
        })
        .collect()
}

#[cfg(test)]
mod classifier_tests {
    //! The classifier over every literal the act raises (migration 20260929040730) and
    //! `blob_delete`'s already-struck raise (20260906000010), `%` substituted with an id. Each
    //! FAILS IF the classifier's arm for that literal drifts.
    use super::*;

    const P0001: Option<&str> = Some("P0001");

    fn id() -> Uuid {
        Uuid::parse_str("01a0e9e7-491d-7700-8f58-99d0b068e059").expect("a literal uuid")
    }

    #[test]
    fn the_required_argument_raises_are_other() {
        assert_eq!(
            classify_act_failure(P0001, "resource_erasure_execute: p_resource is required"),
            ActFailure::Other
        );
        assert_eq!(
            classify_act_failure(P0001, "resource_erasure_execute: p_request_ref is required"),
            ActFailure::Other
        );
    }

    #[test]
    fn resource_not_found_is_not_found() {
        let msg = format!("resource_erasure_execute: resource {} not found", id());
        assert_eq!(classify_act_failure(P0001, &msg), ActFailure::NotFound);
    }

    #[test]
    fn the_charter_raise_is_charter() {
        assert_eq!(
            classify_act_failure(
                P0001,
                "resource_erasure_execute: charter resource (map-grain erasure is filed task \
                 01a0e960-0ca2-7f42-b33e-1ed19b024e6b)"
            ),
            ActFailure::Charter
        );
    }

    #[test]
    fn already_erased_is_already_erased() {
        assert_eq!(
            classify_act_failure(P0001, "resource_erasure_execute: already erased"),
            ActFailure::AlreadyErased
        );
    }

    #[test]
    fn a_blob_outside_the_remainder_names_its_id() {
        let msg = format!(
            "resource_erasure_execute: blob {} is not in the survey's related-blob remainder; \
             strike refused",
            id()
        );
        assert_eq!(
            classify_act_failure(P0001, &msg),
            ActFailure::BlobNotInRemainder(Some(id()))
        );
    }

    #[test]
    fn a_raced_edge_fold_is_retryable() {
        let msg = format!(
            "resource_erasure_execute: edge {} missing or already folded",
            id()
        );
        assert_eq!(classify_act_failure(P0001, &msg), ActFailure::Retryable);
    }

    #[test]
    fn an_already_struck_blob_names_its_id() {
        let msg = format!(
            "blob_delete: blob {} is already struck — the ledger carries its emptying",
            id()
        );
        assert_eq!(
            classify_act_failure(P0001, &msg),
            ActFailure::BlobAlreadyStruck(Some(id()))
        );
    }

    #[test]
    fn a_deadlock_is_retryable_whatever_its_message() {
        assert_eq!(
            classify_act_failure(Some("40P01"), "deadlock detected"),
            ActFailure::Retryable
        );
    }

    #[test]
    fn an_unrelated_raise_is_other() {
        let msg = format!("resource {} is erased; writes are refused", id());
        assert_eq!(classify_act_failure(P0001, &msg), ActFailure::Other);
        assert_eq!(
            classify_act_failure(P0001, "resource_erasure_execute: something new"),
            ActFailure::Other
        );
    }

    // FAILS IF the charter detail stops naming the map-grain task, or starts carrying the raise.
    #[test]
    fn the_charter_detail_names_the_map_grain_task_and_not_the_raise() {
        let detail = ResourceErasureRefusalDetail::MapGrainErasureTask.as_str();
        assert!(detail.contains("01a0e960-0ca2-7f42-b33e-1ed19b024e6b"));
        assert!(!detail.contains(EXECUTE_RAISE_PREFIX));
    }

    // FAILS IF the remainder parse loses the plan's `related blob <id>; hash …` shape, or stops
    // failing loud on a drifted one.
    #[test]
    fn related_blob_ids_parse_the_plans_remainder_shape() {
        let remainder = vec![
            ErasureTargetOutcome {
                target: "kb_blobs".to_string(),
                outcome: format!(
                    "related blob {}; hash abc; live; struck only when the operator lists it",
                    id()
                ),
            },
            ErasureTargetOutcome {
                target: "deriver".to_string(),
                outcome: "resource x holds a structural lead".to_string(),
            },
        ];
        assert_eq!(related_blob_ids(&remainder).expect("parses"), vec![id()]);

        let drifted = vec![ErasureTargetOutcome {
            target: "kb_blobs".to_string(),
            outcome: format!("blob {} related", id()),
        }];
        assert!(related_blob_ids(&drifted).is_err());
    }
}

#[cfg(all(test, feature = "test-db"))]
mod tests {
    //! Service witnesses. Every test runs on a fresh database migrated by
    //! `temper_substrate::MIGRATOR` — no `reset_schema` — so every event type a migration
    //! registered is present (the substrate suite's re-registration trap does not apply).
    use sha2::Digest as _;
    use sqlx::PgPool;
    use uuid::Uuid;

    use temper_core::types::property_owner::PropertyOwner;
    use temper_substrate::affinity::EdgeKind;
    use temper_substrate::blob_store::{blob_pathname, InMemoryBlobStore};
    use temper_substrate::events::{fire, EdgeHome, EventContext, SeedAction};
    use temper_substrate::ids::ContextId;
    use temper_substrate::payloads::{AnchorRef, EdgePolarity};
    use temper_substrate::scenario::bootseed;
    use temper_substrate::writes::{
        self, AssertParams, CommitBlobParams, CreateMode, CreateParams,
    };

    use super::*;
    use crate::services::erasure_fence_service;
    use crate::test_support;

    /// The raise literals' distinctive parts: no response or error may carry any of them.
    const RAISE_FRAGMENTS: &[&str] = &[
        "resource_erasure_execute:",
        "blob_delete:",
        "related-blob remainder; strike refused",
        "missing or already folded",
        "the ledger carries its emptying",
        "map-grain erasure is filed task",
        "already erased",
    ];

    /// A principal: profile, its `<handle>@web` emitter entity, and a personal context.
    struct Principal {
        profile: ProfileId,
        handle: String,
        emitter: EntityId,
        home: ContextId,
    }

    /// The handle is the FULL id: two UUIDv7s minted in one millisecond share leading bytes, so
    /// a truncated handle collides on `kb_profiles_handle_key` (the template's rule).
    async fn principal(pool: &PgPool) -> Principal {
        let id = Uuid::now_v7();
        let handle = format!("user-{id}");
        sqlx::query("INSERT INTO kb_profiles (id, handle, display_name) VALUES ($1, $2, $2)")
            .bind(id)
            .bind(&handle)
            .execute(pool)
            .await
            .expect("seed profile");
        let emitter: Uuid = sqlx::query_scalar(
            "INSERT INTO kb_entities (profile_id, name) VALUES ($1, $2) RETURNING id",
        )
        .bind(id)
        .bind(format!("{handle}@web"))
        .fetch_one(pool)
        .await
        .expect("seed emitter entity");
        let home: Uuid = sqlx::query_scalar(
            "INSERT INTO kb_contexts (owner_table, owner_id, slug, name) \
             VALUES ('kb_profiles', $1, 'home', 'Home') RETURNING id",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("seed personal context");
        Principal {
            profile: ProfileId::from(id),
            handle,
            emitter: EntityId::from(emitter),
            home: ContextId::from(home),
        }
    }

    async fn operator(pool: &PgPool) -> ProfileId {
        let op = principal(pool).await;
        test_support::grant_governance(pool, op.profile.uuid()).await;
        op.profile
    }

    /// A resource created through the REAL create path, homed in `owner`'s context.
    async fn resource_with_mode(
        pool: &PgPool,
        owner: &Principal,
        title: &str,
        mode: CreateMode,
    ) -> ResourceId {
        let origin = format!("test://{title}-{}", Uuid::now_v7());
        writes::create_resource_with_mode(
            pool,
            CreateParams {
                idempotency_key: None,
                title,
                origin_uri: &origin,
                body: "body under erasure",
                doc_type: "research",
                home: AnchorRef::context(owner.home),
                owner: owner.profile,
                originator: owner.profile,
                emitter: owner.emitter,
                properties: &[],
                chunks: None,
                sources: vec![],
            },
            EventContext::default(),
            mode,
        )
        .await
        .expect("create resource through the real path")
    }

    async fn resource(pool: &PgPool, owner: &Principal, title: &str) -> ResourceId {
        resource_with_mode(pool, owner, title, CreateMode::default()).await
    }

    /// A live blob committed through the REAL path (its bytes pre-registered in `store`), with a
    /// relation edge from it to each of `related`. Returns the blob and its pathname.
    async fn related_blob(
        pool: &PgPool,
        store: &InMemoryBlobStore,
        owner: &Principal,
        related: &[ResourceId],
    ) -> (BlobId, String) {
        let bytes = format!("blob bytes {}", Uuid::now_v7());
        let hash = format!("{:x}", sha2::Sha256::digest(bytes.as_bytes()));
        let pathname = blob_pathname(&hash);
        store.insert(pathname.clone());
        let blob = writes::commit_blob(
            pool,
            store,
            CommitBlobParams {
                id: BlobId::from(Uuid::now_v7()),
                home: AnchorRef::context(owner.home),
                owner: owner.profile,
                originator: None,
                content_hash: hash,
                content_type: "image/png".to_owned(),
                content_bytes: bytes.len() as i64,
                max_bytes: 10 * 1024 * 1024,
                allowlist: &["image/png".to_owned()][..],
                emitter: owner.emitter,
            },
        )
        .await
        .expect("the blob commits through the real path");
        for r in related {
            let mut conn = pool.acquire().await.expect("acquire");
            fire(
                &mut conn,
                SeedAction::RelationshipAssert {
                    src: AnchorRef::blob(blob),
                    tgt: AnchorRef::resource(*r),
                    kind: EdgeKind::Contains,
                    polarity: EdgePolarity::Forward,
                    label: Some("attached"),
                    weight: 1.0,
                    home: EdgeHome::Context(owner.home),
                    emitter: owner.emitter,
                },
            )
            .await
            .expect("the blob relation asserts through the real path");
        }
        (blob, pathname)
    }

    fn request(
        caller: ProfileId,
        resource: ResourceId,
        blobs: &[BlobId],
    ) -> ResourceErasureRequest<'_> {
        ResourceErasureRequest {
            caller,
            resource,
            also_strike_blobs: blobs,
            surface: Surface::ApiHttp,
        }
    }

    async fn execute(
        pool: &PgPool,
        caller: ProfileId,
        resource: ResourceId,
    ) -> ApiResult<ResourceErasureOutcome> {
        execute_resource_erasure(pool, None, request(caller, resource, &[])).await
    }

    async fn events_of(pool: &PgPool, kind: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM kb_events e JOIN kb_event_types t ON t.id = e.event_type_id \
              WHERE t.name = $1",
        )
        .bind(kind)
        .fetch_one(pool)
        .await
        .expect("count events")
    }

    async fn erased_at(
        pool: &PgPool,
        resource: ResourceId,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        sqlx::query_scalar("SELECT erased_at FROM kb_resources WHERE id = $1")
            .bind(resource.uuid())
            .fetch_one(pool)
            .await
            .expect("resource row")
    }

    fn completed(outcome: ResourceErasureOutcome) -> ResourceErasureCompletion {
        match outcome {
            ResourceErasureOutcome::Completed(c) => c,
            other => panic!("the act must complete, got {other:?}"),
        }
    }

    fn refused(outcome: ResourceErasureOutcome) -> ResourceErasureRefusal {
        match outcome {
            ResourceErasureOutcome::Refused(r) => r,
            other => panic!("the act must be refused, got {other:?}"),
        }
    }

    fn assert_no_raise_literal(text: &str) {
        for fragment in RAISE_FRAGMENTS {
            assert!(
                !text.contains(fragment),
                "a response carries raise text {fragment:?}: {text}"
            );
        }
    }

    /// ── WITNESS: the authority gate ─────────────────────────────────────────────────────────
    /// FAILS IF a non-operator's execute mutates anything but its one refusal event, or if the
    /// refusal is not what the gate decided: granting governance makes the SAME call complete.
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn a_non_operator_execute_records_unauthorized_and_mutates_nothing(pool: PgPool) {
        let owner = principal(&pool).await;
        let caller = principal(&pool).await;
        let r = resource(&pool, &owner, "gate").await;

        let refusal = refused(
            execute(&pool, caller.profile, r)
                .await
                .expect("the door answers"),
        );
        assert_eq!(refusal.reason, ResourceErasureRefusalReason::Unauthorized);
        assert_eq!(refusal.detail, None);

        let (reason, actor, correlation): (String, Uuid, Uuid) = sqlx::query_as(
            "SELECT e.payload->>'reason', (e.payload->>'actor')::uuid, e.correlation_id \
               FROM kb_events e JOIN kb_event_types t ON t.id = e.event_type_id \
              WHERE t.name = 'resource_erasure_refused'",
        )
        .fetch_one(&pool)
        .await
        .expect("the refusal event");
        assert_eq!(events_of(&pool, "resource_erasure_refused").await, 1);
        assert_eq!(reason, "unauthorized");
        assert_eq!(actor, caller.profile.uuid(), "attributed to the attempter");
        assert_eq!(correlation, refusal.request_reference);
        assert!(erased_at(&pool, r).await.is_none(), "nothing was erased");
        assert_eq!(events_of(&pool, "resource_erased").await, 0);
        assert_eq!(events_of(&pool, "relationship_folded").await, 0);

        // The bite: the same caller, governed, completes the same call.
        test_support::grant_governance(&pool, caller.profile.uuid()).await;
        completed(
            execute(&pool, caller.profile, r)
                .await
                .expect("the act runs"),
        );
        assert!(erased_at(&pool, r).await.is_some());
    }

    /// ── WITNESS: the charter refusal ────────────────────────────────────────────────────────
    /// FAILS IF a charter resource is not refused-and-recorded, or its detail is not the fixed
    /// map-grain text.
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn a_charter_resource_is_refused_recorded_with_the_fixed_detail(pool: PgPool) {
        bootseed::seed_system(&pool).await.expect("boot seed");
        let owner = principal(&pool).await;
        let op = operator(&pool).await;
        let telos = {
            let mut conn = pool.acquire().await.expect("acquire");
            fire(
                &mut conn,
                SeedAction::CogmapGenesis {
                    name: "charter-map",
                    telos_title: "charter telos",
                    charter: &[],
                    cogmap_id: None,
                    telos_resource_id: None,
                    owner: owner.profile,
                    emitter: owner.emitter,
                },
            )
            .await
            .expect("cogmap genesis")
            .cogmap_genesis()
            .expect("genesis mints the telos")
            .1
        };

        let refusal = refused(execute(&pool, op, telos).await.expect("the door answers"));
        assert_eq!(
            refusal.reason,
            ResourceErasureRefusalReason::CharterResource
        );
        assert_eq!(
            refusal.detail,
            Some(ResourceErasureRefusalDetail::MapGrainErasureTask)
        );

        let (reason, detail, correlation): (String, String, Uuid) = sqlx::query_as(
            "SELECT payload->>'reason', payload->>'detail', correlation_id FROM kb_events \
              WHERE id = $1",
        )
        .bind(refusal.event_id)
        .fetch_one(&pool)
        .await
        .expect("the refusal is recorded");
        assert_eq!(reason, "charter_resource");
        assert_eq!(detail, MAP_GRAIN_ERASURE_DETAIL);
        assert_eq!(correlation, refusal.request_reference);
        assert!(erased_at(&pool, telos).await.is_none());
        assert_eq!(events_of(&pool, "resource_erased").await, 0);
    }

    /// ── WITNESS 11: a repeat erasure ────────────────────────────────────────────────────────
    /// FAILS IF a second execute mints a second `resource_erased`, changes any projection row,
    /// or goes unrecorded.
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn a_repeat_erasure_is_refused_already_erased_and_changes_nothing(pool: PgPool) {
        let owner = principal(&pool).await;
        let op = operator(&pool).await;
        let r = resource(&pool, &owner, "repeat").await;
        completed(execute(&pool, op, r).await.expect("the first act runs"));
        let before = temper_substrate::replay::dump_projections(&pool)
            .await
            .expect("dump");

        let refusal = refused(execute(&pool, op, r).await.expect("the door answers"));
        assert_eq!(refusal.reason, ResourceErasureRefusalReason::AlreadyErased);
        assert_eq!(refusal.detail, None);

        let after = temper_substrate::replay::dump_projections(&pool)
            .await
            .expect("dump");
        assert_eq!(before, after, "the repeat changed the projection");
        let reason: String =
            sqlx::query_scalar("SELECT payload->>'reason' FROM kb_events WHERE id = $1")
                .bind(refusal.event_id)
                .fetch_one(&pool)
                .await
                .expect("the refusal is recorded");
        assert_eq!(reason, "already_erased");
        assert_eq!(
            events_of(&pool, "resource_erased").await,
            1,
            "exactly one resource_erased"
        );
    }

    /// ── WITNESS 11: the two former refusals complete ────────────────────────────────────────
    /// FAILS IF the service refuses a tombstone (made by the real soft delete) or an in-flight
    /// ingest (a segmented create not yet finalized).
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn a_tombstone_and_an_in_flight_ingest_both_complete(pool: PgPool) {
        let owner = principal(&pool).await;
        let op = operator(&pool).await;

        let tombstone = resource(&pool, &owner, "tombstone").await;
        let mut tx = pool.begin().await.expect("begin");
        fire(
            &mut tx,
            SeedAction::ResourceDelete {
                resource: tombstone,
                emitter: owner.emitter,
            },
        )
        .await
        .expect("soft delete through the real path");
        tx.commit().await.expect("commit");
        let active: bool = sqlx::query_scalar("SELECT is_active FROM kb_resources WHERE id = $1")
            .bind(tombstone.uuid())
            .fetch_one(&pool)
            .await
            .expect("row");
        assert!(!active, "the witness needs a real tombstone");

        let in_flight = resource_with_mode(
            &pool,
            &owner,
            "in-flight",
            CreateMode {
                defer: false,
                segmented: true,
            },
        )
        .await;
        let ingest: String =
            sqlx::query_scalar("SELECT ingest_state FROM kb_resources WHERE id = $1")
                .bind(in_flight.uuid())
                .fetch_one(&pool)
                .await
                .expect("row");
        assert_eq!(
            ingest, "in_progress",
            "the witness needs an ingest in flight"
        );

        completed(
            execute(&pool, op, tombstone)
                .await
                .expect("the tombstone erases"),
        );
        let flight = completed(
            execute(&pool, op, in_flight)
                .await
                .expect("the ingest erases"),
        );
        assert!(erased_at(&pool, tombstone).await.is_some());
        assert!(erased_at(&pool, in_flight).await.is_some());
        assert!(
            flight
                .targets
                .iter()
                .any(|t| t.target == "kb_resources.ingest_state"),
            "the record names the ended ingest: {:?}",
            flight.targets
        );
        assert_eq!(events_of(&pool, "resource_erasure_refused").await, 0);
    }

    /// ── WITNESS: one reference per act ──────────────────────────────────────────────────────
    /// FAILS IF two acts share a request reference, or the returned reference is not the one
    /// the act's events are correlated by.
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn two_acts_get_two_distinct_request_references(pool: PgPool) {
        let owner = principal(&pool).await;
        let op = operator(&pool).await;
        let a = completed(
            execute(&pool, op, resource(&pool, &owner, "first").await)
                .await
                .expect("first act"),
        );
        let b = completed(
            execute(&pool, op, resource(&pool, &owner, "second").await)
                .await
                .expect("second act"),
        );
        assert_ne!(a.request_reference, b.request_reference);
        for c in [&a, &b] {
            let correlation: Uuid =
                sqlx::query_scalar("SELECT correlation_id FROM kb_events WHERE id = $1")
                    .bind(c.event_id)
                    .fetch_one(&pool)
                    .await
                    .expect("the completion event");
            assert_eq!(correlation, c.request_reference);
        }
    }

    /// ── WITNESS: no raise text reaches a caller ─────────────────────────────────────────────
    /// FAILS IF any outcome or error string carries a raise literal. Not vacuous: the charter
    /// and already-erased refusal events exist only because the SQL raised, and the two blob
    /// 400s are produced only by the classifier's arms over a raised act.
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn no_response_or_error_contains_a_raise_literal(pool: PgPool) {
        bootseed::seed_system(&pool).await.expect("boot seed");
        let owner = principal(&pool).await;
        let op = operator(&pool).await;
        let store = InMemoryBlobStore::default();
        let mut texts: Vec<String> = Vec::new();

        // Charter.
        let telos = {
            let mut conn = pool.acquire().await.expect("acquire");
            fire(
                &mut conn,
                SeedAction::CogmapGenesis {
                    name: "raise-map",
                    telos_title: "raise telos",
                    charter: &[],
                    cogmap_id: None,
                    telos_resource_id: None,
                    owner: owner.profile,
                    emitter: owner.emitter,
                },
            )
            .await
            .expect("cogmap genesis")
            .cogmap_genesis()
            .expect("telos")
            .1
        };
        texts.push(format!(
            "{:?}",
            execute(&pool, op, telos).await.expect("answers")
        ));

        // Already erased, and a blob struck once through a completed act.
        let r1 = resource(&pool, &owner, "raise-r1").await;
        let r2 = resource(&pool, &owner, "raise-r2").await;
        let r3 = resource(&pool, &owner, "raise-r3").await;
        let (blob, _) = related_blob(&pool, &store, &owner, &[r1, r2]).await;
        completed(
            execute_resource_erasure(&pool, Some(&store), request(op, r1, &[blob]))
                .await
                .expect("r1 erases, striking the blob"),
        );
        texts.push(format!(
            "{:?}",
            execute(&pool, op, r1).await.expect("answers")
        ));
        assert_eq!(
            events_of(&pool, "resource_erasure_refused").await,
            2,
            "both raised"
        );

        // The blob again, through r2 (still related, already struck) and r3 (never related).
        let struck = execute_resource_erasure(&pool, Some(&store), request(op, r2, &[blob]))
            .await
            .expect_err("an already-struck blob is refused");
        let unrelated = execute_resource_erasure(&pool, Some(&store), request(op, r3, &[blob]))
            .await
            .expect_err("an unrelated blob is refused");
        for err in [&struck, &unrelated] {
            let ApiError::BadRequest(msg) = err else {
                panic!("a blob refusal is a 400, got {err:?}");
            };
            assert!(
                msg.contains(&blob.uuid().to_string()),
                "names the blob: {msg}"
            );
            texts.push(err.to_string());
        }
        assert!(erased_at(&pool, r2).await.is_none() && erased_at(&pool, r3).await.is_none());

        // An unknown id, past the gate.
        let unknown = execute(&pool, op, ResourceId::from(Uuid::now_v7()))
            .await
            .expect_err("an unknown id is not found");
        assert!(matches!(unknown, ApiError::NotFound(_)), "got {unknown:?}");
        texts.push(unknown.to_string());

        for text in &texts {
            assert_no_raise_literal(text);
        }
    }

    /// ── WITNESS: the classifier against the live SQL ────────────────────────────────────────
    /// FAILS IF a RAISE in the act or in `blob_delete` is reworded so the classifier no longer
    /// recognizes it (it would otherwise degrade to `Internal` silently).
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn the_classifier_matches_the_live_sql_raises(pool: PgPool) {
        bootseed::seed_system(&pool).await.expect("boot seed");
        let owner = principal(&pool).await;
        let store = InMemoryBlobStore::default();
        let raw = |resource: Uuid, blobs: Vec<Uuid>| {
            let pool = pool.clone();
            let emitter = owner.emitter.uuid();
            let actor = owner.profile.uuid();
            async move {
                sqlx::query_scalar::<_, serde_json::Value>(
                    "SELECT resource_erasure_execute($1, $2, $3, $4, $5)",
                )
                .bind(resource)
                .bind(actor)
                .bind(emitter)
                .bind(Uuid::now_v7())
                .bind(blobs)
                .fetch_one(&pool)
                .await
            }
        };

        let telos = {
            let mut conn = pool.acquire().await.expect("acquire");
            fire(
                &mut conn,
                SeedAction::CogmapGenesis {
                    name: "pin-map",
                    telos_title: "pin telos",
                    charter: &[],
                    cogmap_id: None,
                    telos_resource_id: None,
                    owner: owner.profile,
                    emitter: owner.emitter,
                },
            )
            .await
            .expect("cogmap genesis")
            .cogmap_genesis()
            .expect("telos")
            .1
        };
        let err = raw(telos.uuid(), vec![]).await.expect_err("charter raises");
        assert_eq!(classify_act_error(&err), ActFailure::Charter);

        let r1 = resource(&pool, &owner, "pin-r1").await;
        let r2 = resource(&pool, &owner, "pin-r2").await;
        let r3 = resource(&pool, &owner, "pin-r3").await;
        let (blob, _) = related_blob(&pool, &store, &owner, &[r1, r2]).await;
        raw(r1.uuid(), vec![blob.uuid()]).await.expect("r1 erases");

        let err = raw(r1.uuid(), vec![]).await.expect_err("repeat raises");
        assert_eq!(classify_act_error(&err), ActFailure::AlreadyErased);

        let err = raw(r3.uuid(), vec![blob.uuid()])
            .await
            .expect_err("unrelated raises");
        assert_eq!(
            classify_act_error(&err),
            ActFailure::BlobNotInRemainder(Some(blob.uuid()))
        );

        let err = raw(r2.uuid(), vec![blob.uuid()])
            .await
            .expect_err("struck raises");
        assert_eq!(
            classify_act_error(&err),
            ActFailure::BlobAlreadyStruck(Some(blob.uuid()))
        );

        let err = raw(Uuid::now_v7(), vec![])
            .await
            .expect_err("unknown raises");
        assert_eq!(classify_act_error(&err), ActFailure::NotFound);
    }

    /// ── WITNESS: the survey gate is silent ──────────────────────────────────────────────────
    /// FAILS IF a non-operator's survey records anything or answers anything but 404 — and the
    /// bite: the same caller, governed, gets the plan (the 404 was the gate's, not the id's).
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn a_non_operator_survey_is_silent(pool: PgPool) {
        let owner = principal(&pool).await;
        let caller = principal(&pool).await;
        let r = resource(&pool, &owner, "silent").await;
        let events_before: i64 = sqlx::query_scalar("SELECT count(*) FROM kb_events")
            .fetch_one(&pool)
            .await
            .expect("count");

        let err = survey_resource_erasure(&pool, caller.profile, r)
            .await
            .expect_err("a non-operator's survey is refused");
        assert!(matches!(err, ApiError::NotFound(_)), "got {err:?}");
        let events_after: i64 = sqlx::query_scalar("SELECT count(*) FROM kb_events")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(
            events_before, events_after,
            "a refused survey records nothing"
        );

        test_support::grant_governance(&pool, caller.profile.uuid()).await;
        let survey = survey_resource_erasure(&pool, caller.profile, r)
            .await
            .expect("an operator's survey answers");
        assert!(survey.plan.is_some());
    }

    /// ── WITNESS: the husk short-circuit ─────────────────────────────────────────────────────
    /// FAILS IF the survey of an erased resource runs the plan (which still counts husk rows).
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn the_survey_short_circuits_on_a_husk(pool: PgPool) {
        let owner = principal(&pool).await;
        let op = operator(&pool).await;
        let r = resource(&pool, &owner, "husk").await;
        completed(execute(&pool, op, r).await.expect("erases"));

        let survey = survey_resource_erasure(&pool, op, r)
            .await
            .expect("answers");
        assert!(survey.already_erased);
        assert_eq!(survey.plan, None, "no plan on a husk");
    }

    /// ── WITNESS: another principal's edge is named, with its author ─────────────────────────
    /// FAILS IF an edge (or an edge-owned property) another principal asserted goes unnamed, or
    /// the owner's own edge — asserted from a SECOND surface entity — is misnamed as another
    /// principal's (the profile-to-profile comparison).
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn the_survey_names_another_principals_edge_and_its_author(pool: PgPool) {
        let owner = principal(&pool).await;
        let other = principal(&pool).await;
        let op = operator(&pool).await;
        let r = resource(&pool, &owner, "authored").await;
        let s = resource(&pool, &other, "other-notes").await;
        let t = resource(&pool, &owner, "owner-notes").await;

        let foreign = writes::assert_relationship(
            &pool,
            AssertParams {
                src: s,
                tgt: r,
                kind: EdgeKind::LeadsTo,
                polarity: EdgePolarity::Forward,
                label: Some("another principal's words"),
                weight: 1.0,
                home: other.home,
                emitter: other.emitter,
            },
        )
        .await
        .expect("the other principal's edge");
        let foreign_prop = writes::assert_keyed_property_with(
            &pool,
            PropertyOwner::edge(foreign),
            "note",
            &serde_json::json!("their text"),
            1.0,
            other.emitter,
            EventContext::default(),
        )
        .await
        .expect("the other principal's edge property");

        // The owner's own edge, from the owner's `@cli` entity: a second surface, same principal.
        let owner_cli: Uuid = sqlx::query_scalar(
            "INSERT INTO kb_entities (profile_id, name) VALUES ($1, $2) RETURNING id",
        )
        .bind(owner.profile.uuid())
        .bind(format!("{}@cli", owner.handle))
        .fetch_one(&pool)
        .await
        .expect("owner cli entity");
        let own = writes::assert_relationship(
            &pool,
            AssertParams {
                src: r,
                tgt: t,
                kind: EdgeKind::LeadsTo,
                polarity: EdgePolarity::Forward,
                label: Some("the owner's words"),
                weight: 1.0,
                home: owner.home,
                emitter: EntityId::from(owner_cli),
            },
        )
        .await
        .expect("the owner's edge");

        let plan = survey_resource_erasure(&pool, op, r)
            .await
            .expect("answers")
            .plan
            .expect("a live resource has a plan");
        assert!(plan.edges.contains(&foreign) && plan.edges.contains(&own));
        assert_eq!(
            plan.other_author_edges,
            vec![OtherAuthorEdge {
                edge_id: foreign,
                author: other.profile,
                folded: false,
            }],
            "only the other principal's edge is named"
        );
        assert_eq!(
            plan.other_author_edge_properties,
            vec![OtherAuthorEdgeProperty {
                property_id: foreign_prop,
                edge_id: foreign,
                author: other.profile,
            }]
        );
    }

    /// ── WITNESS: a blob's co-link holder is named ───────────────────────────────────────────
    /// FAILS IF the survey does not name the other resource linking a related blob, or names
    /// the surveyed resource itself as a holder.
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn the_survey_names_a_blobs_co_link_holder(pool: PgPool) {
        let owner = principal(&pool).await;
        let op = operator(&pool).await;
        let store = InMemoryBlobStore::default();
        let r = resource(&pool, &owner, "co-link-r").await;
        let holder = resource(&pool, &owner, "co-link-holder").await;
        let (shared, _) = related_blob(&pool, &store, &owner, &[r, holder]).await;
        let (alone, _) = related_blob(&pool, &store, &owner, &[r]).await;

        let plan = survey_resource_erasure(&pool, op, r)
            .await
            .expect("answers")
            .plan
            .expect("a plan");
        let mut links = plan.blob_co_links;
        links.sort_by_key(|l| l.blob_id.uuid());
        let mut expected = vec![
            BlobCoLinks {
                blob_id: shared,
                holders: vec![holder],
            },
            BlobCoLinks {
                blob_id: alone,
                holders: vec![],
            },
        ];
        expected.sort_by_key(|l| l.blob_id.uuid());
        assert_eq!(links, expected);
    }

    /// ── WITNESS: the post-commit byte release ───────────────────────────────────────────────
    /// FAILS IF a released strike's bytes survive the call (the release did not run after the
    /// commit), or if the fence, deriving the same delete from the `resource_erased` payload,
    /// fails it or leaves it outstanding — the provider delete of an absent object is a no-op.
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn a_listed_blob_strike_releases_its_bytes_and_the_fence_has_nothing_left(pool: PgPool) {
        let owner = principal(&pool).await;
        let op = operator(&pool).await;
        let store = InMemoryBlobStore::default();
        let r = resource(&pool, &owner, "strike").await;
        let (blob, pathname) = related_blob(&pool, &store, &owner, &[r]).await;
        assert!(
            store.contains(&pathname),
            "the witness needs the bytes present"
        );

        let completion = completed(
            execute_resource_erasure(&pool, Some(&store), request(op, r, &[blob]))
                .await
                .expect("the act completes"),
        );
        assert_eq!(
            completion.blob_strikes,
            vec![BlobStrikeOutcome {
                blob_id: blob.uuid(),
                released: true,
            }]
        );
        assert!(
            !store.contains(&pathname),
            "the bytes are released after the commit, before any fence tick"
        );

        let summary = erasure_fence_service::drain(&pool, &store)
            .await
            .expect("the fence drains");
        assert_eq!(summary.seeded, 1, "the fence derives the same delete");
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.unparseable_verdicts, 0);
        let outstanding: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM kb_erasure_blob_deletes \
              WHERE status IN ('pending', 'in_progress', 'waiting_for_retry', 'dead')",
        )
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(outstanding, 0, "nothing left to drain");
        let again = erasure_fence_service::drain(&pool, &store)
            .await
            .expect("drains");
        assert_eq!(again.claimed, 0);
    }

    /// ── WITNESS: the fence seeds from a `resource_erased` payload, unassisted ────────────────
    /// The act runs with NO store, so nothing releases the bytes after the commit: the only
    /// thing that can delete them is the fence deriving the delete from the `resource_erased`
    /// event's `targets`.
    /// FAILS IF the fence's seed scan drops `'resource_erased'` from its event-type `IN (...)`
    /// (nothing seeds, `seeded` is 0, the bytes stay), or if it seeds under any event other than
    /// the act's own, or if the drain does not delete the pathname.
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn the_fence_seeds_a_resource_erased_strike_and_the_drain_deletes_the_bytes(
        pool: PgPool,
    ) {
        let owner = principal(&pool).await;
        let op = operator(&pool).await;
        let store = InMemoryBlobStore::default();
        let r = resource(&pool, &owner, "fence-seed").await;
        let (blob, pathname) = related_blob(&pool, &store, &owner, &[r]).await;

        let completion = completed(
            execute_resource_erasure(&pool, None, request(op, r, &[blob]))
                .await
                .expect("the act completes"),
        );
        assert!(
            store.contains(&pathname),
            "no store was passed, so nothing released the bytes after the commit"
        );

        let summary = erasure_fence_service::drain(&pool, &store)
            .await
            .expect("the fence drains");
        assert_eq!(summary.seeded, 1, "seeded from the resource_erased payload");
        assert_eq!(summary.unparseable_verdicts, 0);
        assert_eq!(summary.deleted, 1, "the drain struck the pathname");
        assert!(!store.contains(&pathname), "the bytes are gone");

        let seeded_under: Vec<Uuid> = sqlx::query_scalar(
            "SELECT erasure_event_id FROM kb_erasure_blob_deletes WHERE pathname = $1",
        )
        .bind(&pathname)
        .fetch_all(&pool)
        .await
        .expect("fence rows");
        assert_eq!(
            seeded_under,
            vec![completion.event_id],
            "one queue row, keyed by the resource_erased event"
        );
    }

    /// ── WITNESS: a remainder-only related blob never seeds ──────────────────────────────────
    /// Two related blobs; the operator lists neither. Both stay in `remainder` (D8), so the
    /// payload's `targets` carry no blob and the fence has nothing to derive.
    /// FAILS IF the fence (or the act's payload) derives deletes from `remainder` rather than
    /// `targets`: `seeded` would be nonzero and a blob's bytes would be deleted.
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn an_unlisted_related_blob_stays_in_the_remainder_and_is_never_seeded(pool: PgPool) {
        let owner = principal(&pool).await;
        let op = operator(&pool).await;
        let store = InMemoryBlobStore::default();
        let r = resource(&pool, &owner, "fence-remainder").await;
        let (_, first) = related_blob(&pool, &store, &owner, &[r]).await;
        let (_, second) = related_blob(&pool, &store, &owner, &[r]).await;

        let completion = completed(
            execute_resource_erasure(&pool, None, request(op, r, &[]))
                .await
                .expect("the act completes"),
        );
        assert!(
            !completion.remainder.is_empty(),
            "the related blobs are named in the remainder"
        );
        assert!(
            completion.targets.iter().all(|t| t.target != "kb_blobs"),
            "an unlisted blob is never a target"
        );

        let summary = erasure_fence_service::drain(&pool, &store)
            .await
            .expect("the fence drains");
        assert_eq!(summary.seeded, 0, "nothing derives from the remainder");
        assert_eq!(summary.claimed, 0);
        assert_eq!(summary.deleted, 0);
        assert!(store.contains(&first) && store.contains(&second));
    }
}
