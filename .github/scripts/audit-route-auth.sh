#!/usr/bin/env bash
# audit-route-auth.sh — pin the auth posture of every temper-api route.
#
# WHY THIS EXISTS
# ---------------
# temper-api's routes live in per-group files under crates/temper-api/src/routes/, and the route
# TABLE in that module's mod.rs maps every group to its auth tier; the tier's middleware stack is
# applied in exactly one place (apply_tier). The table's rows are data, and this script asserts
# them — the group set and each row's tier:
#
#   GROUP                        TIER                          POSTURE
#   ---------------------------  ----------------------------  --------------------------------------------------------------
#   auth_only_routes             AuthOnly                      require_auth                          (JWT — authenticated)
#   gated_routes                 Gated                         require_auth + require_system_access  (JWT + system access)
#   public_routes                Public                        (none)                                by-design public: /health
#   blob_commit_routes           Gated (+ inner body limit)    same stack as gated_routes
#   blob_segment_routes          Gated (+ inner body limit)    same stack as gated_routes
#   embed_internal_routes        SelfGated                     (none)                                self-gated: EMBED_DISPATCH_SECRET
#   internal_routes              InternalHmac(Reconcile)       require_internal_signature            HMAC (INTERNAL_RECONCILE_SECRET)
#   slack_link_internal_routes   InternalHmac(SlackLink)       require_slack_link_signature          HMAC (SLACK_LINK_SECRET)
#   slack_mint_internal_routes   InternalHmac(SlackMint)       require_slack_mint_signature          HMAC (SLACK_MINT_SECRET)
#   slack_link_public_routes     SelfGated                     (none)                                by-design public: PKCE+state callback
#   webhook_intake_routes        SelfGated                     (none)                                self-gated: broker RS256 attestation
#
# On webhook_intake_routes: the caller is Vercel Connect forwarding a third-party system's event.
# It is not a temper principal, holds no temper token, and never will -- require_auth is not a
# tightening available here, it is a category error. Its compensating control is inside the
# handler: CredentialBroker::verify_inbound performs RS256-over-JWKS with set_required_spec_claims,
# asserts issuer/audience, asserts the anti-decoy client_id ("api-connex"), and reads the connector
# from the SIGNED trigger claim rather than the unsigned x-trigger-* mirror headers. The anti-decoy
# assertion is load-bearing and non-obvious: the attestation is claim-for-claim identical to the
# deployment's OWN ambient x-vercel-oidc-token except for client_id and trigger, and that ambient
# token rides on every inbound request -- so a verifier that stops at "valid Vercel OIDC token
# naming our project" accepts the deployment's own identity as a forged webhook.
#
# It is a group of its own rather than a route on embed_internal_routes because the controls are
# different in kind, not merely in key: that group compares a shared secret temper issued, this one
# verifies a third party's signature against a remote JWKS. The baseline's job is that each entry
# names the control it actually carries, and one shared group would blur exactly that.
#
# NOTE it gets no tier-stack assertion below, and that is not an omission -- SelfGated applies no
# middleware. Like embed_internal_routes, its gate is inside the handler, so the baseline diff (c)
# is the whole of its protection here: a second route added to this group fails until reviewed.
#
# On slack_mint_internal_routes specifically: it is a THIRD signature group rather than a route on
# slack_link_internal_routes because the keys must differ. Link-state answers "is this principal
# linked?"; the mint route vends an act-as-the-human access token carrying that human's FULL reach
# (resources_visible_to takes a profile and nothing else — there is no narrowing behind it). One
# shared key would make compromise of the cheap capability yield the expensive one. Its signature
# gate is ALSO the only thing enforcing "naming a principal must not be sufficient to mint its
# token" — mint_access_token authorizes nothing itself — so a lost layer here is not a downgrade
# to authenticated-but-broad, it is act-as-any-user.
#
# A route added to auth_only/gated is authenticated by construction — safe, no review needed.
# A route added to any of the OTHER groups is unauthenticated-at-the-middleware (public, a
# self-checked secret, or a signature the handler trusts) and MUST be reviewed: does it really
# self-gate / carry its own compensating control? This script freezes the set of routes in those
# review-required groups, and asserts the table's rows and tier stacks are still present, so:
#   - a new unauthenticated/self-gated/signature route FAILS until acknowledged,
#   - a silently deleted auth layer FAILS immediately,
#   - a group's tier quietly changed FAILS immediately.
# Auth-covered routes (auth_only/gated) grow freely and never trip this.
# See internal/development/security-audit-playbook.md § 1.
#
# USAGE
#   .github/scripts/audit-route-auth.sh          # verify (CI mode)
#   .github/scripts/audit-route-auth.sh --list   # print current review-required routes
#   UPDATE_BASELINE=1 .github/scripts/audit-route-auth.sh   # rewrite baseline after review
#
# ROUTES_FILE may be overridden to point at a single file OR a directory of them (a fixture copy
# of the routes module — see test-audit-route-auth.sh). Under a fixture the baseline diff (c) will
# of course disagree, which is why the test harness asserts on the FAIL MESSAGE, not just the exit
# code.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

ROUTES="${ROUTES_FILE:-crates/temper-api/src/routes}"

# Resolve ROUTES to the list of .rs files to scan: a directory's *.rs (sorted, so group
# attribution is deterministic), or the one file named.
if [ -d "$ROUTES" ]; then
  ROUTES_FILES="$(find "$ROUTES" -maxdepth 1 -name '*.rs' | sort)"
elif [ -f "$ROUTES" ]; then
  ROUTES_FILES="$ROUTES"
else
  echo "audit-route-auth: FAIL — routes source not found: $ROUTES" >&2
  exit 1
fi

# The app builders in routes/mod.rs, and which of them must mount the table. Every
# signature-gated group is served by BOTH builders (see create_internal_app's doc comment: the
# split exists only for Vercel's per-function maxDuration), so both mounts are load-bearing.
APP_BUILDERS='create_app create_internal_app'

# Groups whose routes are authenticated by construction (a require_auth layer). They grow freely.
# `query_routes` is auth-covered NOT by carrying the layers itself but by being MERGED into
# `gated_routes` — it is a sub-router of one only so that its `DefaultBodyLimit` binds to `/api/query`
# and to nothing else. That indirection is exactly what makes a bare AUTH_COVERED entry too weak
# here: the entry asserts a posture, and the posture is a property of where the merge lands. The
# merge-landing assertion below is what closes that, and it is why this name may sit here at all.
AUTH_COVERED='auth_only_routes|gated_routes|query_routes|blob_segment_routes|blob_commit_routes'
# Groups whose routes are NOT behind require_auth — every entry is a reviewed compensating control.
REVIEW_GROUPS='public_routes|embed_internal_routes|internal_routes|slack_link_internal_routes|slack_mint_internal_routes|slack_link_public_routes|webhook_intake_routes'

# Reviewed baseline: <group>\t<handler> for every route in a REVIEW group. Each is unauthenticated
# at the middleware and carries its own control (see the table above). A change here means a new or
# removed unauthenticated/self-gated/signature route — confirm the control, then UPDATE_BASELINE=1.
read -r -d '' BASELINE <<'EOF' || true
embed_internal_routes	handlers::as_reap::reap_as_tables
embed_internal_routes	handlers::embed::dispatch
embed_internal_routes	handlers::embed::warm
embed_internal_routes	handlers::erasure::drain
embed_internal_routes	handlers::internal_call_health::check_internal_calls
embed_internal_routes	handlers::region::dispatch
embed_internal_routes	handlers::slack_disconnect::reap_intents
internal_routes	handlers::internal_saml::reconcile
internal_routes	handlers::internal_saml::resolve_principal
public_routes	handlers::health::health_check
slack_link_internal_routes	handlers::slack_link::slack_link_state
slack_mint_internal_routes	handlers::slack_mint::slack_mint
slack_link_public_routes	handlers::slack_link::callback
webhook_intake_routes	handlers::webhook_intake::receive
EOF

# Every (sub-router group, handler) pair declared in the routes module, keyed on the handler ident
# (stable across single-line and multi-line `.route(` / `routes!(` forms). Each group fn lives in
# its own file with its comments, so attribution is per-file and exact.
extract() {
  awk '
    function grpname(s,   r){ if (match(s,/fn [a-z_]+_routes\(/)){ r=substr(s,RSTART+3); sub(/\(.*/,"",r); return r } return "" }
    { g=grpname($0); if(g!=""){grp=g; next} }
    /^(pub )?fn (create_app|create_internal_app|openapi_spec|apply_transport_layers|cors_layer|fallback_handler|apply_tier|mount_group|route_table)/ { grp="_x_"; next }
    grp=="_x_" || grp=="" { next }
    { s=$0; while (match(s,/handlers::[a-z_]+::[a-z_]+/)) { print grp"\t"substr(s,RSTART,RLENGTH); s=substr(s,RSTART+RLENGTH) } }
  ' $ROUTES_FILES | sort -u
}

ALL="$(extract)"
REVIEW_CURRENT="$(printf '%s\n' "$ALL" | grep -E "^($REVIEW_GROUPS)"$'\t' || true)"

if [[ "${1:-}" == "--list" ]]; then
  printf '%s\n' "$REVIEW_CURRENT"
  exit 0
fi

fail=0

# (a) An unknown sub-router group = a group with no known posture. Fail: its layer wiring is unreviewed.
UNKNOWN_GROUPS="$(printf '%s\n' "$ALL" | cut -f1 | sort -u | grep -Ev "^($AUTH_COVERED|$REVIEW_GROUPS)$" || true)"
if [[ -n "$UNKNOWN_GROUPS" ]]; then
  echo "audit-route-auth: FAIL — sub-router group(s) with UNKNOWN auth posture:" >&2
  printf '  %s\n' $UNKNOWN_GROUPS >&2
  echo "  Add a table row for it in routes/mod.rs (with a tier), then add it to AUTH_COVERED" >&2
  echo "  or REVIEW_GROUPS here after confirming the tier." >&2
  fail=1
fi

# (b) The table's rows and tier stacks must still be present — guards against a silently deleted
#     auth layer or a quietly changed tier.
#
# The pre-table form of this check grepped each app builder's body for each layer's name, sliced
# per builder, because the layers were mounted SEPARATELY in create_app and create_internal_app and
# deleting one mount left the name present elsewhere. The table made that regression structurally
# impossible — both builders mount the same rows through the same apply_tier — and moved the
# surface: now a layer can be lost from a TIER stack, a tier can be changed on a ROW, or a builder
# can stop consuming the table. Each is asserted explicitly.

# Print the body of function NAME from the routes module: its signature line through the closing
# brace at column 0. Handles bare `fn`, `pub fn` and `pub(super)`/`pub(crate)` spellings.
# Bash 3.2 compatible (no assoc arrays) — recomputed per call, the files are small.
fn_body() {
  awk -v fname="$1" '
    $0 ~ "^(pub(\\([a-z]+\\))? )?fn "fname"\\(" { inside=1 }
    inside { print }
    inside && /^\}/ { exit }
  ' $ROUTES_FILES
}

# require_tier GROUP TIER_SPELLING — the row asserting GROUP must exist with exactly TIER_SPELLING.
require_tier() {
  local group="$1" tier="$2"
  grep -Eq "key: \"$group\", tier: $tier" $ROUTES_FILES || {
    echo "audit-route-auth: FAIL — table row changed: no row 'key: \"$group\", tier: $tier'" >&2
    echo "  A group's tier is its reviewed auth posture. If the change is intentional it must be" >&2
    echo "  reviewed and this assertion updated together with routes/mod.rs." >&2
    fail=1
  }
}

require_tier 'public_routes'              'Tier::Public'
require_tier 'auth_only_routes'           'Tier::AuthOnly'
require_tier 'gated_routes'               'Tier::Gated'
require_tier 'blob_commit_routes'         'Tier::Gated'
require_tier 'blob_segment_routes'        'Tier::Gated'
require_tier 'internal_routes'            'Tier::InternalHmac\(SignatureKind::Reconcile\)'
require_tier 'slack_link_internal_routes' 'Tier::InternalHmac\(SignatureKind::SlackLink\)'
require_tier 'slack_mint_internal_routes' 'Tier::InternalHmac\(SignatureKind::SlackMint\)'
require_tier 'slack_link_public_routes'   'Tier::SelfGated'
require_tier 'embed_internal_routes'      'Tier::SelfGated'
require_tier 'webhook_intake_routes'      'Tier::SelfGated'

# The tier stacks: apply_tier is the one place a middleware stack is spelled. Every middleware
# name the postures promise must appear in its body — a name dropped here un-gates every group
# whose tier names it. (Bodies are captured and matched as strings, never piped to `grep -q`:
# under `set -o pipefail`, grep's early exit on match SIGPIPEs the producer mid-stream and turns
# a MATCH into a pipeline failure.)
TIER_BODY="$(fn_body apply_tier)"
assert_in_body() {
  local layer="$1"; shift
  [[ "$TIER_BODY" == *"$layer"* ]] || {
    echo "audit-route-auth: FAIL — missing auth wiring: '$layer' not applied by apply_tier in $ROUTES" >&2
    echo "  A tier's stack is applied exactly once; a middleware name missing from it serves every" >&2
    echo "  group of that tier unauthenticated (or unlimited, for the rate seam)." >&2
    fail=1
  }
}
assert_in_body 'auth::require_auth'
assert_in_body 'require_system_access'
assert_in_body 'require_relay_trust'
assert_in_body 'require_route_rate_limit'
assert_in_body 'require_internal_signature'
assert_in_body 'require_slack_link_signature'
assert_in_body 'require_slack_mint_signature'

# Both builders must mount FROM the table. A builder that stops consuming it (e.g. re-derives its
# own router) is a second, drift-prone wiring path — the exact thing the table exists to prevent.
for app in $APP_BUILDERS; do
  fn_body "$app" | grep -q 'mount_group' || {
    echo "audit-route-auth: FAIL — app builder '$app' does not mount from the route table" >&2
    echo "  Both builders must consume route_table() via mount_group; a builder assembling its" >&2
    echo "  own router is a parallel wiring path the posture assertions cannot see." >&2
    fail=1
  }
done

# A merged sub-router inherits its posture from the group it lands in, so the LANDING is the wiring.
# `query_routes` carries no auth layer of its own — it exists to scope a body limit — and is
# auth-covered only for as long as `gated_routes` is where it is merged.
GATED_BODY="$(fn_body gated_routes)"
[[ "$GATED_BODY" == *'query_routes()'* ]] || {
  echo "audit-route-auth: FAIL — missing merge: 'query_routes()' not merged into gated_routes()" >&2
  echo "  The query door is auth-covered only for as long as it merges into the gated group." >&2
  fail=1
}

# (c) The review-required route set must match the reviewed baseline.
NORM_BASELINE="$(printf '%s\n' "$BASELINE" | sort -u)"
if [[ "${UPDATE_BASELINE:-}" == "1" ]]; then
  printf '%s\n' "$REVIEW_CURRENT"
  echo "^^^ copy into BASELINE after confirming each route is intentionally unauthenticated and self-gates." >&2
  exit 0
fi
if ! diff <(printf '%s\n' "$NORM_BASELINE") <(printf '%s\n' "$REVIEW_CURRENT") >/tmp/route-auth.diff 2>&1; then
  echo "audit-route-auth: FAIL — the set of unauthenticated/self-gated/signature routes changed." >&2
  echo "A route NOT behind require_auth must carry its own compensating control (secret, signature, PKCE)." >&2
  echo "diff (baseline -> current):" >&2
  cat /tmp/route-auth.diff >&2
  echo "If reviewed and correct: UPDATE_BASELINE=1 .github/scripts/audit-route-auth.sh" >&2
  fail=1
fi

if [[ "$fail" == "0" ]]; then
  echo "audit-route-auth: OK — $(printf '%s\n' "$REVIEW_CURRENT" | grep -c .) reviewed unauth routes; $(printf '%s\n' "$ALL" | grep -Ec "^($AUTH_COVERED)"$'\t') auth-covered; table rows and wiring present."
fi
exit "$fail"
