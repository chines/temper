//! Authenticated AND system-access-gated — default-deny for all data routes.
//! Documented, except the operator-only `/api/access/admin/*` surface which is
//! mounted with plain `.route()` (no `#[utoipa::path]`) so it stays out of the
//! public contract.

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::handlers;
use temper_services::state::AppState;

pub(super) fn gated_routes() -> OpenApiRouter<AppState> {
    use axum::routing::{get, patch, post};

    OpenApiRouter::new()
        .routes(routes!(
            handlers::resources::list,
            handlers::resources::create
        ))
        .routes(routes!(
            handlers::resources::get,
            handlers::resources::update,
            handlers::resources::delete
        ))
        .routes(routes!(handlers::resources::get_content))
        .routes(routes!(handlers::data_artifacts::list))
        .routes(routes!(handlers::data_artifacts::get))
        .routes(routes!(handlers::data_artifacts::commit))
        // The flat artifact read — the MCP `get_data_artifact` tool's wire twin (the tool
        // takes only the artifact id; the nested route's REST parent is a field its
        // declaration cannot grow). Route-first for the beat G4 door crossing.
        .routes(routes!(handlers::data_artifacts::get_by_id))
        // `blobs::commit` and `blobs::append_segment` are NOT mounted here: they are the
        // two doors whose legal body sizes exceed axum's inherited default, so they merge
        // through `blob_commit_routes` / `blob_segment_routes` with limits sized from
        // the config and the plan numbers (see those functions, merged in [`create_app`]).
        .routes(routes!(handlers::blobs::get))
        .routes(routes!(handlers::blobs::delete))
        // One `.routes()` per handler: the multi-handler form is for same-path method
        // grouping (the ingest blocks GET+POST shape); distinct paths in one call mangle
        // the mounted patterns into overlaps.
        .routes(routes!(handlers::blobs::begin_upload))
        .routes(routes!(handlers::blobs::upload_progress))
        .routes(routes!(handlers::blobs::finalize_upload))
        .routes(routes!(handlers::blobs::list))
        .routes(routes!(handlers::blobs::relate))
        .routes(routes!(handlers::blobs::relations))
        .routes(routes!(handlers::data_artifact_shapes::list_shapes))
        .routes(routes!(handlers::data_artifact_shapes::get_shape))
        .routes(routes!(handlers::data_artifact_shapes::declare_shape))
        // The cogmap-home shapes pair — the MCP `list_data_artifact_shapes` /
        // `declare_data_artifact_shape` tools admit a cogmap `home_type` and the
        // substrate read/write are home-generic, but only the context arm had a wire
        // door. Route-first for the beat G4 door crossing.
        .routes(routes!(handlers::data_artifact_shapes::list_cogmap_shapes))
        .routes(routes!(
            handlers::data_artifact_shapes::declare_cogmap_shape
        ))
        .routes(routes!(
            handlers::resources::provenance,
            handlers::resources::annotate
        ))
        .routes(routes!(handlers::resources::read_block))
        // Corpus adoption — one bounded, resumable, per-row-gated re-block step per call,
        // dispatched to the Backend's `reblock_resources` command. Documented (unlike the
        // admin-enclosed `/api/embed/admin/reembed` trigger): the gate is the backend seam —
        // the deployment-wide arm is SystemAdmin-checked there, the resource/context arms ride
        // the caller's own visibility — and the contract is the receipt.
        .routes(routes!(handlers::reblock::reblock))
        .routes(routes!(handlers::reassign::reassign_resource))
        .routes(routes!(handlers::edges::list))
        .routes(routes!(handlers::edges::list_connections))
        .routes(routes!(handlers::evidence::evidence))
        // Both methods on `/api/resources/{id}/citation-audits` — one `routes!` group, as with the
        // resource CRUD trio above, so the path is declared once.
        .routes(routes!(
            handlers::citation_audits::record,
            handlers::citation_audits::list
        ))
        // The block-addressed audit write — same gate, same command, no finding in the address.
        .routes(routes!(handlers::citation_audits::record_for_block))
        .routes(routes!(handlers::edges::lineage))
        .routes(routes!(handlers::edges::assert))
        .routes(routes!(handlers::edges::retype))
        .routes(routes!(handlers::edges::reweight))
        .routes(routes!(handlers::edges::fold))
        .routes(routes!(handlers::facets::set_facet))
        .routes(routes!(handlers::facets::list_resource_facets))
        .routes(routes!(
            handlers::facets::set_edge_facet,
            handlers::facets::list_edge_facets,
            handlers::facets::retract_edge_facet
        ))
        .routes(routes!(handlers::graph::cogmap_neighborhood_slice))
        .routes(routes!(handlers::graph::region_composition))
        .routes(routes!(handlers::graph::context_panorama))
        .routes(routes!(handlers::graph::context_composition))
        .routes(routes!(handlers::graph::entry))
        .routes(routes!(handlers::graph::traverse))
        .routes(routes!(handlers::graph::atlas_home))
        .routes(routes!(handlers::graph::cogmap_panorama))
        .routes(routes!(
            handlers::meta::get_meta,
            handlers::meta::update_meta
        ))
        .routes(routes!(
            handlers::resources::grant,
            handlers::resources::revoke
        ))
        .routes(routes!(
            handlers::contexts::list,
            handlers::contexts::create
        ))
        .routes(routes!(handlers::contexts::get, handlers::contexts::delete))
        .routes(routes!(handlers::contexts::restore))
        .routes(routes!(handlers::contexts::share_team))
        .routes(routes!(handlers::contexts::unshare_team))
        .routes(routes!(handlers::contexts::reassign))
        .routes(routes!(handlers::contexts::rename))
        // Context orientation reads (T8) — the peers of the five cognitive-map orientation reads
        // below (shape, materialize-delta, materialize, region-metrics, analytics).
        .routes(routes!(handlers::contexts::shape))
        .routes(routes!(handlers::contexts::region_metrics))
        .routes(routes!(handlers::contexts::materialize_delta))
        .routes(routes!(handlers::contexts::materialize))
        .routes(routes!(handlers::contexts::analytics))
        .routes(routes!(handlers::teams::list, handlers::teams::create))
        .routes(routes!(handlers::teams::add_member))
        .routes(routes!(handlers::invitations::create))
        .routes(routes!(handlers::invitations::list))
        .routes(routes!(handlers::invitations::revoke))
        .routes(routes!(handlers::reassign::reassign_team))
        .routes(routes!(
            handlers::teams::detail,
            handlers::teams::update,
            handlers::teams::delete
        ))
        .routes(routes!(
            handlers::teams::remove_member,
            handlers::teams::change_role
        ))
        .routes(routes!(handlers::ingest::create))
        .routes(routes!(handlers::ingest::update))
        .routes(routes!(
            handlers::segments::list_blocks_handler,
            handlers::segments::append_block_handler
        ))
        .routes(routes!(handlers::segments::finalize_handler))
        .routes(routes!(
            handlers::cognitive_maps::genesis,
            handlers::cognitive_maps::list
        ))
        .routes(routes!(
            handlers::cognitive_maps::reconcile,
            handlers::cognitive_maps::show
        ))
        .routes(routes!(handlers::cognitive_maps::shape))
        .routes(routes!(handlers::cognitive_maps::materialize_delta))
        .routes(routes!(handlers::cognitive_maps::materialize))
        .routes(routes!(handlers::cognitive_maps::region_metrics))
        .routes(routes!(handlers::cognitive_maps::analytics))
        .routes(routes!(handlers::cognitive_maps::bind_team))
        .routes(routes!(handlers::cognitive_maps::unbind_team))
        .routes(routes!(
            handlers::cognitive_maps::grant,
            handlers::cognitive_maps::revoke
        ))
        .routes(routes!(
            handlers::invocations::open,
            handlers::invocations::list
        ))
        .routes(routes!(handlers::invocations::show))
        .routes(routes!(handlers::invocations::close))
        .routes(routes!(handlers::steward::delta))
        .routes(routes!(handlers::steward::advance))
        .routes(routes!(handlers::steward::sweep))
        .routes(routes!(handlers::steward::candidates))
        .routes(routes!(handlers::steward::dispatch))
        .routes(routes!(handlers::auditor::sweep))
        .routes(routes!(handlers::auditor::dispatch))
        .routes(routes!(handlers::auditor::complete))
        .routes(routes!(handlers::events::cursor))
        .routes(routes!(handlers::events::element_trail))
        // The vocabularies each kind of work carries. Caller-independent answers over the
        // embedded schemas — still on the gated surface, because caller-independence is a
        // property of the answer and not a reason to publish it.
        .routes(routes!(handlers::schema::list_doc_types))
        .routes(routes!(handlers::schema::describe_doc_type))
        .routes(routes!(handlers::schema::describe_open_meta))
        .routes(routes!(handlers::search::search))
        .merge(super::query::query_routes())
        .routes(routes!(handlers::slack_disconnect::admin_disconnect))
        // Operator-only re-embed trigger: enqueue embed jobs for chunks whose vector was produced by
        // a model that is no longer the one we embed with. The per-minute drain does the work; this is
        // only the trigger. Admin-gated on the caller's own identity, so an operator uses their normal
        // login rather than holding the drain's deploy secret.
        .route("/api/embed/admin/reembed", post(handlers::embed::reembed))
        // Operator-only access-gate admin surface — deliberately UNDOCUMENTED.
        // These handlers carry no `#[utoipa::path]`; plain `.route()` mounts them
        // without adding them to the OpenAPI contract.
        .route(
            "/api/access/admin/requests",
            get(handlers::access::list_pending),
        )
        // The counting siblings of the two queue reads. Static `/count` beats the `{id}`
        // pattern in the router, and they are GET while `{id}` is PATCH, so neither shadows
        // the other. Same undocumented posture as the lists they count.
        .route(
            "/api/access/admin/requests/count",
            get(handlers::access::count_pending),
        )
        .route(
            "/api/access/admin/requests/{id}",
            patch(handlers::access::review_request),
        )
        // Same posture, same reason: the D15 reconsideration inbox is read and closed by an
        // operator, never by a library caller administering their own access.
        .route(
            "/api/access/admin/reviews",
            get(handlers::access::list_reviews),
        )
        .route(
            "/api/access/admin/reviews/count",
            get(handlers::access::count_reviews),
        )
        .route(
            "/api/access/admin/reviews/{id}",
            patch(handlers::access::close_review),
        )
        .route(
            "/api/access/admin/settings",
            get(handlers::access::get_admin_settings).patch(handlers::access::update_settings),
        )
        .route(
            "/api/access/admin/promote",
            post(handlers::access::promote_admin),
        )
        .route(
            "/api/access/admin/demote",
            post(handlers::access::demote_admin),
        )
        // The admin standing acts (Task 13). Same operator-only convention as their neighbours:
        // plain `.route()`, out of the OpenAPI contract, allowlisted in
        // `.github/scripts/check-openapi-routes.sh`. The admin gate is in each handler.
        .route(
            "/api/access/admin/principals/{id}/approve",
            post(handlers::access::approve_principal),
        )
        .route(
            "/api/access/admin/principals/{id}/revoke",
            post(handlers::access::revoke_principal),
        )
        .route(
            "/api/access/admin/principals/{id}/deactivate",
            post(handlers::access::deactivate_principal),
        )
        .route(
            "/api/access/admin/principals/{id}/reactivate",
            post(handlers::access::reactivate_principal),
        )
        // The auto-join roster repair: converge every `auto_join_role` team to the
        // standing-approved population and report what it added. Same operator-only
        // convention: plain `.route()`, out of the OpenAPI contract, allowlisted.
        .route(
            "/api/access/admin/auto-join/reconcile",
            post(handlers::access::reconcile_auto_join),
        )
        // The operator directory (admin-operator-directory spec §5/§6). Same operator-only
        // convention as every neighbour above: plain `.route()`, out of the OpenAPI contract,
        // allowlisted in `.github/scripts/check-openapi-routes.sh`. Both handlers mint the
        // sealed `&SystemAdmin` here and dispatch immediately — the gate is the service
        // signature, and it runs before any existence lookup, so absence never leaks to a
        // non-admin. `?email=` on the list route is an identity-resolution act (exact,
        // ambiguity-refusing) that answers a state card, not a page.
        .route(
            "/api/access/admin/profiles",
            get(handlers::admin_directory::list_profiles),
        )
        .route(
            "/api/access/admin/profiles/{profile_id}",
            get(handlers::admin_directory::show_profile),
        )
        // The admin ledger's read surface — operator-only, so plain `.route()` and OUT of the
        // OpenAPI contract like its neighbours above. Authorization is in
        // `admin_ledger_service`, which gates per act family rather than with a prelude, and
        // denies with 404 so a refusal discloses nothing about the subject.
        .route("/api/admin/ledger", get(handlers::admin_ledger::list))
        // The erasure act's doors (task 01a0577c Beat 4; the survey is task 01a09628 item 2).
        // Same operator-only posture as `/api/admin/ledger`: plain `.route()`, out of the
        // contract, allowlisted. Each handler mints the sealed `&SystemAdmin` proof before it
        // dispatches (the services take it), and a caller who is not a system admin is rejected
        // there: 404, never 403, one telemetry line, and no ledger event of any kind (ruled
        // 2026-09-30).
        .route("/api/admin/erasure", post(handlers::erasure::execute))
        .route("/api/admin/erasure/survey", post(handlers::erasure::survey))
        // The resource-erasure pair: plain `.route()`, allowlisted, the same wire gate over
        // `resource_erasure_service`. The 404 means a rejected caller learns nothing about the
        // RESOURCE (not whether it exists, not whether it was erased). The doors themselves are
        // discoverable; the 404 does not hide them.
        .route(
            "/api/admin/resources/erasure",
            post(handlers::resource_erasure::execute),
        )
        .route(
            "/api/admin/resources/erasure/survey",
            post(handlers::resource_erasure::survey),
        )
        // Machine-principal registration (G3 Phase A). Mounted with plain `.route()`, like
        // `/api/access/admin/*` above, so it stays OUT of the OpenAPI contract. Its paths are
        // allowlisted in `.github/scripts/check-openapi-routes.sh`.
        //
        // NOT admin-only, despite sitting among the admin mounts. The gate is
        // `is_system_admin OR owner of the machine's owning team` (`machine_authz::authorize`),
        // so any authenticated profile that owns any team can reach `provision`, `issue`, and
        // `apply_reach`. Only `rebind` is admin-only (`machine_registration_service::rebind`).
        //
        // The gate lives in the SERVICES, not in these handlers — the handlers are gate-free by
        // design, as `handlers::machine_clients`' module doc explains. Treat it as load-bearing,
        // not defense-in-depth: how much the router's `require_system_access` layer actually
        // excludes is an operational setting an instance can change at any time, so the service
        // check is the only guarantee that does not move. Do not relax it on the strength of a
        // configuration value read at some past moment.
        .route(
            "/api/machine-clients",
            get(handlers::machine_clients::list).post(handlers::machine_clients::provision),
        )
        .route(
            "/api/machine-clients/{id}",
            get(handlers::machine_clients::get).delete(handlers::machine_clients::revoke),
        )
        .route(
            "/api/machine-clients/{id}/rebind",
            post(handlers::machine_clients::rebind),
        )
        .route(
            "/api/machine-clients/issue",
            post(handlers::machine_clients::issue),
        )
        .route(
            "/api/machine-clients/{id}/rotate-secret",
            post(handlers::machine_clients::rotate_secret),
        )
        // Operator-only connection provisioning (external systems as subscribed emitters, S1).
        // Same shape as machine-clients above and for the same reasons: plain `.route()`, out of
        // the OpenAPI contract, allowlisted in `.github/scripts/check-openapi-routes.sh`, and
        // gated inside the service (`machine_authz::authorize`, verbatim — a connection is a
        // machine principal wearing an integration's clothes).
        .route(
            "/api/connections",
            get(handlers::connections::list).post(handlers::connections::provision),
        )
        .route(
            "/api/connections/{id}",
            get(handlers::connections::get).delete(handlers::connections::revoke),
        )
        // The credential and the two capability tiers, each its own endpoint. They are separately
        // provisioned and both explicit — folding them into one PATCH would let a caller grant
        // reach while believing they were only registering a webhook.
        .route(
            "/api/connections/{id}/credential",
            post(handlers::connections::attach_credential),
        )
        .route(
            "/api/connections/{id}/webhook-events",
            post(handlers::connections::set_webhook_events),
        )
        .route(
            "/api/connections/{id}/tool-manifest",
            post(handlers::connections::set_tool_manifest),
        )
        // A team's read-reach on the connection, its own endpoint (a `kb_access_grants` write, not
        // a connection-row mutation). Owning ≠ reaching, so this is separate from provisioning.
        // Grant and revoke share the path — POST adds, DELETE removes — both carrying the team.
        .route(
            "/api/connections/{id}/reach",
            post(handlers::connections::grant_reach).delete(handlers::connections::revoke_reach),
        )
        // Operator-only subscription management (external systems as subscribed emitters, S2).
        // Same shape as connections above: plain .route(), out of the OpenAPI contract, gated
        // inside the service (require_manage_on_team + kb_access_grants reach-grant read).
        .route(
            "/api/subscriptions",
            get(handlers::subscriptions::list).post(handlers::subscriptions::create),
        )
        .route(
            "/api/subscriptions/{id}",
            get(handlers::subscriptions::get).delete(handlers::subscriptions::revoke),
        )
}
