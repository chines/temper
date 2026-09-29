//! Unauthenticated routes. Documented.

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::handlers;
use temper_services::state::AppState;

pub(super) fn public_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(handlers::health::health_check))
}
