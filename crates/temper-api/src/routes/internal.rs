//! The three internal HMAC-gated groups — server-to-server only, one scheme, three
//! secrets, three routers. Each carries its signature middleware via the table's
//! `InternalHmac` tier; the layer is applied at the mount so the route can never be
//! mounted ungated.

use axum::routing::post;
use axum::Router;

use crate::handlers;
use temper_services::state::AppState;

/// Internal, server-to-server only — gated by a shared secret, NOT `require_auth`.
/// Called by the co-deployed SAML Authorization Server before it mints a token.
/// Excluded from the OpenAPI contract entirely.
pub(super) fn internal_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/internal/saml/reconcile",
            post(handlers::internal_saml::reconcile),
        )
        // Same caller and the SAME key as its neighbour, which is why it belongs on this router
        // rather than one of its own: the AS asks who a `sub` resolves to so it can record an owner
        // on the refresh chain it is about to mint.
        .route(
            "/internal/principal/resolve",
            post(handlers::internal_saml::resolve_principal),
        )
}

/// Internal, server-to-server only — gated by `require_slack_link_signature`, NOT
/// `require_auth`. Called by the Slack mention agent on every mention to ask what to say to
/// the mentioning user: already linked, or here is a fresh authorize URL.
///
/// A router of its own rather than a route on `internal_routes` because the two carry
/// different keys: `internal_routes` is layered with `require_internal_signature`
/// (`INTERNAL_RECONCILE_SECRET`), and gating this route on the reconcile secret would let
/// either principal forge the other's calls. One scheme, two secrets, two routers — the
/// layer is applied by the table's `InternalHmac` tier, so the route can never be
/// mounted ungated.
/// Excluded from the OpenAPI contract entirely.
pub(super) fn slack_link_internal_routes() -> Router<AppState> {
    Router::new().route(
        "/internal/slack/link-state",
        post(handlers::slack_link::slack_link_state),
    )
}

/// Internal, server-to-server only — gated by `require_slack_mint_signature`, NOT `require_auth`
/// and NOT the link-state gate. Called by the Slack mention agent to obtain an
/// act-as-the-human access token for a mentioning user.
///
/// A **third** router rather than a second route on `slack_link_internal_routes`, even though
/// the caller is the same agent, because the keys must differ. Link-state answers a question
/// ("is this principal linked?"); this vends a credential carrying that human's entire reach.
/// Sharing one key would make compromise of the cheap capability yield the expensive one — the
/// same reasoning that already separates `internal_routes` from `slack_link_internal_routes`,
/// applied where the stakes are highest. One scheme, three secrets, three routers — the layer is
/// applied by the table's `InternalHmac` tier, so the route can never be mounted
/// ungated.
/// Excluded from the OpenAPI contract entirely.
pub(super) fn slack_mint_internal_routes() -> Router<AppState> {
    Router::new().route(
        "/internal/slack/mint",
        post(handlers::slack_mint::slack_mint),
    )
}
