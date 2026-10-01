//! The resource-erasure act's HTTP doors (resource erasure spec 2026-09-28, build order 2b): the
//! operator's execute door and the read-only survey beside it. They conform to the principal
//! doors in [`crate::handlers::erasure`] and their posture is documented there.
//!
//! **Gate-free by ruling, like the principal doors.** `resource_erasure_service` resolves
//! `is_system_admin` before anything else; a door that pre-empted it would decide legality twice.
//! A non-operator's execute is a RECORDED `unauthorized` refusal rendered as 404 (never 403); a
//! non-operator's survey is the service's silent 404. Either way the refused caller learns
//! nothing about the RESOURCE: the gate answers before any lookup, so every id it is given gets
//! the same 404, which says neither that the resource exists nor that it was erased. The doors
//! themselves are discoverable, and the 404 does not claim to hide them. No tenant axis exists:
//! the gate is the instance operator and nothing more (ruled 2026-09-30).
//!
//! **No caller-supplied request reference.** The service mints the act's reference and both
//! execute answers return it. The execute body is `deny_unknown_fields`, so a body that carries
//! `request_reference` is refused at the door (axum's `Json` answers a well-formed body with an
//! unknown field as 422) instead of being silently ignored.
//!
//! Both mounted plain (`.route()`), out of the OpenAPI contract; allowlisted in
//! `.github/scripts/check-openapi-routes.sh`.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use temper_core::types::ids::{BlobId, EdgeId, ProfileId, ResourceId};
use temper_services::error::{ApiError, ApiResult};
use temper_services::services::resource_erasure_service::{
    self, ResourceErasureOutcome, ResourceErasureRequest, ResourceErasureSurvey,
};
use temper_services::state::AppState;
use temper_substrate::payloads::{
    ErasureTargetOutcome, RedactedEventFields, ResourceErasureRefusalReason,
};

use crate::handlers::erasure::BlobStrikeView;
use crate::middleware::auth::AuthUser;
use crate::middleware::surface::RequestSurface;

/// The survey door's request: the resource and nothing else (a survey requests nothing).
#[derive(Debug, Deserialize)]
pub struct ResourceErasureSurveyRequest {
    pub resource: Uuid,
}

/// The execute door's request. `deny_unknown_fields`: the act's request reference is minted by
/// the service, so a caller that sends one is refused, not ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceErasureExecuteRequest {
    pub resource: Uuid,
    /// Related blobs to strike with the resource (D8); each must be in the survey's remainder.
    pub also_strike_blobs: Option<Vec<Uuid>>,
}

/// What the execute door's act did: a completion and a refusal are different answers, so the
/// response is a tagged enum. `unauthorized` never reaches the wire (the door answers 404).
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ResourceErasureExecuteResponse {
    Completed {
        /// The server-minted reference the operator cites.
        request_reference: Uuid,
        event_id: Uuid,
        folded_edges: Vec<EdgeId>,
        targets: Vec<ErasureTargetOutcome>,
        remainder: Vec<ErasureTargetOutcome>,
        ledger_remainder: Vec<RedactedEventFields>,
        blob_strikes: Vec<BlobStrikeView>,
    },
    Refused {
        request_reference: Uuid,
        event_id: Uuid,
        reason: ResourceErasureRefusalReason,
        detail: Option<String>,
    },
}

/// `POST /api/admin/resources/erasure` — the operator's execute door.
pub async fn execute(
    State(state): State<AppState>,
    auth: AuthUser,
    RequestSurface(surface): RequestSurface,
    Json(body): Json<ResourceErasureExecuteRequest>,
) -> ApiResult<Json<ResourceErasureExecuteResponse>> {
    let blobs: Vec<BlobId> = body
        .also_strike_blobs
        .unwrap_or_default()
        .into_iter()
        .map(BlobId::from)
        .collect();
    let outcome = resource_erasure_service::execute_resource_erasure(
        &state.pool,
        state.blob_store.as_deref(),
        ResourceErasureRequest {
            caller: ProfileId::from(auth.0.profile().id),
            resource: ResourceId::from(body.resource),
            also_strike_blobs: &blobs,
            surface,
        },
    )
    .await?;

    match outcome {
        // The gate's refusal face: absent (404), never 403. The refusal is already recorded.
        ResourceErasureOutcome::Refused(r)
            if r.reason == ResourceErasureRefusalReason::Unauthorized =>
        {
            Err(ApiError::NotFound("not found".to_string()))
        }
        ResourceErasureOutcome::Refused(r) => Ok(Json(ResourceErasureExecuteResponse::Refused {
            request_reference: r.request_reference,
            event_id: r.event_id,
            reason: r.reason,
            detail: r.detail.map(|d| d.as_str().to_string()),
        })),
        ResourceErasureOutcome::Completed(c) => {
            Ok(Json(ResourceErasureExecuteResponse::Completed {
                request_reference: c.request_reference,
                event_id: c.event_id,
                folded_edges: c.folded_edges,
                targets: c.targets,
                remainder: c.remainder,
                ledger_remainder: c.ledger_remainder,
                blob_strikes: c
                    .blob_strikes
                    .into_iter()
                    .map(|s| BlobStrikeView {
                        blob_id: s.blob_id,
                        released: s.released,
                    })
                    .collect(),
            }))
        }
    }
}

/// `POST /api/admin/resources/erasure/survey` — the read-only survey. The service's gate answers
/// a non-operator with a silent 404 (nothing recorded); an unknown id past the gate is a 404 too.
/// The service's survey types serialize as-is (`Serialize` derived on them), so the door mirrors
/// nothing field by field.
pub async fn survey(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ResourceErasureSurveyRequest>,
) -> ApiResult<Json<ResourceErasureSurvey>> {
    let survey = resource_erasure_service::survey_resource_erasure(
        &state.pool,
        ProfileId::from(auth.0.profile().id),
        ResourceId::from(body.resource),
    )
    .await?;
    Ok(Json(survey))
}
