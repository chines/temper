//! The browser-facing Slack link callback — the registered `redirect_uri`.
//!
//! Ungated by design: it is the IdP's redirect target, so it carries no bearer and no
//! signature. Its authentication is the PKCE code exchange plus the single-use state nonce
//! it burns, and it renders HTML rather than JSON because a human is looking at it.
//! `create_app` only — the internal function never serves a browser. Excluded from the
//! OpenAPI contract entirely.

use axum::routing::get;
use axum::Router;

use crate::handlers;
use temper_services::state::AppState;

pub(super) fn slack_link_public_routes() -> Router<AppState> {
    Router::new().route(
        "/api/auth/slack/callback",
        get(handlers::slack_link::callback),
    )
}
