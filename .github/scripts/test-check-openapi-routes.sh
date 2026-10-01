#!/usr/bin/env bash
# .github/scripts/test-check-openapi-routes.sh
#
# Test harness for check-openapi-routes.sh. Runs the checker against the real
# routes.rs and against synthetic fixtures, asserting the exit code.
#   bash .github/scripts/test-check-openapi-routes.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECK_SCRIPT="${SCRIPT_DIR}/check-openapi-routes.sh"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REAL_ROUTES="${REPO_ROOT}/crates/temper-api/src/routes"
PASS=0
FAIL=0

FIXTURE_DIR="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

# run_test NAME ROUTES_FILE EXPECTED_EXIT
run_test() {
    local test_name="$1"
    local routes_file="$2"
    local expected_exit="$3"

    local output actual_exit
    set +e
    output="$(bash "$CHECK_SCRIPT" "$routes_file" 2>&1)"
    actual_exit=$?
    set -e

    if [ "$actual_exit" -eq "$expected_exit" ]; then
        echo "  PASS: ${test_name}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: ${test_name}"
        echo "    expected exit=${expected_exit} actual exit=${actual_exit}"
        echo "    output: ${output}"
        FAIL=$((FAIL + 1))
    fi
}

echo "Running check-openapi-routes.sh tests..."
echo ""

# --- (a) the real routes module passes (only allowlisted plain .route() mounts).
# The real case runs with NO argument — the checker's default is the whole routes
# module directory, which is exactly what CI scans. ---
run_test "real routes module: passes" "" 0

# --- (b) an off-allowlist plain .route() fails ---
OFF_ALLOWLIST="${FIXTURE_DIR}/off_allowlist.rs"
cat > "$OFF_ALLOWLIST" <<'EOF'
fn gated_routes() -> OpenApiRouter<AppState> {
    use axum::routing::{get, post};

    OpenApiRouter::new()
        .routes(routes!(handlers::resources::list))
        // Allowlisted server-to-server surface — fine.
        .route("/api/embed/dispatch", post(handlers::embed::dispatch))
        // Undocumented public route — MUST fail the gate.
        .route("/api/secret", get(handlers::secret::leak))
}
EOF
run_test "off-allowlist plain .route(): fails" "$OFF_ALLOWLIST" 1

# --- (c) a router using only .routes(routes!(…)) passes (no plain .route()) ---
ROUTES_ONLY="${FIXTURE_DIR}/routes_only.rs"
cat > "$ROUTES_ONLY" <<'EOF'
fn gated_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(handlers::resources::list, handlers::resources::create))
        .routes(routes!(handlers::teams::list))
        .routes(routes!(handlers::ingest::create))
}
EOF
run_test "only .routes(routes!()): passes" "$ROUTES_ONLY" 0

# --- multiline plain .route() with the path literal on the next line ---
MULTILINE="${FIXTURE_DIR}/multiline.rs"
cat > "$MULTILINE" <<'EOF'
fn gated_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .route(
            "/api/secret",
            get(handlers::secret::leak),
        )
}
EOF
run_test "off-allowlist multiline plain .route(): fails" "$MULTILINE" 1

# --- every allowlisted path, each on its own plain .route(), passes ---
ALL_ALLOWED="${FIXTURE_DIR}/all_allowed.rs"
cat > "$ALL_ALLOWED" <<'EOF'
fn gated_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .route("/internal/saml/reconcile", post(a))
        .route("/internal/principal/resolve", post(b))
        .route("/api/auth/slack/callback", get(c))
        .route("/api/intake/webhook", post(d))
        .route("/api/embed/dispatch", get(g).post(g))
}
EOF
run_test "all allowlisted plain .route()s: passes" "$ALL_ALLOWED" 0

# --- the system-admin surface is documented, never allowlisted: a plain mount of one of its
# paths is a regression to the undocumented posture and MUST fail ---
ADMIN_PLAIN="${FIXTURE_DIR}/admin_plain.rs"
cat > "$ADMIN_PLAIN" <<'EOF'
fn admin_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .route("/api/access/admin/promote", post(handlers::access::promote_admin))
}
EOF
run_test "system-admin path mounted plain: fails" "$ADMIN_PLAIN" 1

# --- the scoped operator families are documented too (a team owner or the actor reaches them):
# a plain mount of any of their paths is a regression to the undocumented posture and MUST fail.
# Every formerly allowlisted path gets its own fixture, so re-adding any one of them to the
# allowlist fails here rather than hiding behind its siblings. ---
for scoped in \
    "/api/admin/ledger" \
    "/api/machine-clients" \
    "/api/machine-clients/{id}" \
    "/api/machine-clients/issue" \
    "/api/machine-clients/{id}/rotate-secret" \
    "/api/connections" \
    "/api/connections/{id}" \
    "/api/connections/{id}/credential" \
    "/api/connections/{id}/webhook-events" \
    "/api/connections/{id}/tool-manifest" \
    "/api/connections/{id}/reach" \
    "/api/subscriptions" \
    "/api/subscriptions/{id}"; do
    SCOPED_PLAIN="${FIXTURE_DIR}/scoped_plain.rs"
    printf 'fn gated_routes() -> OpenApiRouter<AppState> {\n    OpenApiRouter::new()\n        .route("%s", get(handlers::scoped::handler))\n}\n' "$scoped" > "$SCOPED_PLAIN"
    run_test "scoped operator path ${scoped} mounted plain: fails" "$SCOPED_PLAIN" 1
done

# --- a fixture with no .route( at all passes (nothing to check) ---
EMPTY="${FIXTURE_DIR}/empty.rs"
cat > "$EMPTY" <<'EOF'
fn create_app(state: AppState) -> Router {
    Router::new().with_state(state)
}
EOF
run_test "no plain .route() at all: passes" "$EMPTY" 0

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed (total: $((PASS + FAIL)))"
[ "$FAIL" -eq 0 ]
