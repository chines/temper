-- Give kb_workflow_jobs a fourth family: SYSTEM-scoped jobs with no anchor at all, for the
-- sensitivity sweep.
--
-- Goal 01a0e9e6-959b-7780-af70-25ceb0f632e3 ("Personal data that lands in the corpus by accident is
-- found"). Sensitivity-sweep spec (temper-artifacts specs/2026-09-28-sensitivity-sweep-design.md),
-- R5 and D8. Plan: plans/2026-10-01-sensitivity-sweep-3a-core.md, PR A.
--
-- ── Why this queue, and not a table of its own ──────────────────────────────────────────────────
-- R5: one dispatch mechanism, so that whoever is troubleshooting at 2am has one table to look in,
-- one reaper and one backoff ladder. 20260909000040 gave the erasure fence its own table instead,
-- for reasons that do not carry over to the sweep:
--   * the fence's idempotence grain is a content-addressed pathname, where the sweep's is
--     (persona, dispatch_type);
--   * the fence's clock is an event's occurred_at, where the sweep's is enqueue time.
-- The one cost the fence named that does apply here is amending a shared table. This migration pays
-- it once, and the four changes are below.
--
-- ── 1 · The CHECK widens, and only for the declared system personas ─────────────────────────────
-- ck_workflow_jobs_one_scope demanded exactly one anchor, so a system-wide job was unrepresentable.
-- The zero-anchor arm is gated by persona rather than opened to everyone. The incumbent wrappers
-- rely on an anchorless row of THEIR family being impossible ("ck_workflow_jobs_one_scope should
-- make this unreachable", workflow_job_service.rs, claim_anchor). A bare `<= 1` would quietly turn a
-- NULL passed by mistake to the embed path into a queued job that has no scope.
--
-- The gate also runs the other way: a system persona is anchorless ONLY. A sensitivity row
-- carrying a resource_id would be handed out by the unscoped claim_resource with a resource id on
-- it, which contradicts constraint 3 below. Worse, it would make the erasure act raise: step 8 of
-- _resource_erasure_apply_redaction (20260929040730) sets payload = '{}' on every job of the erased
-- resource, '{}' fails the work-order CHECK, and the act rolls back. One stray row would make one
-- resource unerasable. Both reviews of this migration reproduced that.
--
-- The next system persona joins by adding itself to BOTH lists: one additive line, written on
-- purpose.
--
-- ── 2 · Single-flight for anchorless rows ───────────────────────────────────────────────────────
-- uq_workflow_jobs_in_flight is keyed on cogmap_id, and a unique index treats NULLs as distinct, so
-- an anchorless row conflicts with nothing. Without an index of its own, two sweep jobs would both
-- run, double-scanning and racing each other's cursor (spec F7.3). The resource and context families
-- each closed this same hole with their own partial unique index; this is the fourth. It is keyed on
-- the anchors being ABSENT rather than on the persona, so the next system persona gets single-flight
-- without rediscovering the hole.
--
-- ── 3 · The payload is a work order, held by the table ──────────────────────────────────────────
-- Spec D8, constraint 1. A sensitivity job's payload is {surface, budget} and nothing else: no
-- resource id, hash, category, count, or cursor. That is what keeps the unscoped claim safe.
-- 20260724000130 narrowed the cogmap claim because claim_audit handed out cross-tenant ids IN ITS
-- PAYLOAD; a payload with no ids in it has nothing to steal. The rule is enforced here, structurally,
-- rather than by review, because kb_workflow_jobs is in public and is the one table outside the
-- sweep's guarded store that the sweep writes to.
--
-- The VALUES are held too, not only the keys. If the keys alone were fixed, any jsonb could sit
-- under them, including the content the sweep exists to find; the security review enqueued an SSN
-- as a budget. So:
--   * surface is a `kb_<table>.<column>` identifier. Every scan-manifest surface is a kb_ table, so
--     the prefix narrows what can travel without refusing a real surface. It is still a shape, not
--     membership: `kb_jane.doe` passes. Checking the value against the manifest needs the guarded
--     store, and lands with it (build order 3a PR B);
--   * budget is a row count from 1 to 100000. Six digits cannot carry a nine-digit identifier, and
--     a re-review showed an SSN with its dashes stripped passing the earlier int-sized bound.
--
-- No cursor travels in the payload. That is a ruling (2026-10-02), amending the spec's
-- {surface, cursor_from, budget}. On every append-only surface, a watermark is the v7 id of the last
-- row read: a row id from some tenant's content, which also encodes when it was written. A payload
-- carrying one would contradict the "no ids" argument above, and the claim that hands it out is
-- unscoped. The watermark lives in the sweep's guarded store, keyed per (surface, detector,
-- version) as D4 already keys it, and the tick reads it there. Both reviews of this migration
-- named the contradiction; it was settled here, before ship, rather than carried.
--
-- ── 4 · Two incumbent doors stop reaching outside their families ───────────────────────────────────────
-- complete_anchor matches with IS NOT DISTINCT FROM, so a call with both anchors NULL would complete
-- ANY anchorless job of the tuple. That was unreachable while no anchorless row could exist; this
-- migration makes such rows exist, so this migration closes the door. It does so with the same
-- num_nonnulls(cogmap_id, context_id) = 1 guard that workflow_job_claim_anchor has carried since
-- 20260802000020. Every caller passes exactly one anchor (HomeAnchor is a closed two-variant enum),
-- so no existing call changes outcome. Before this migration, the same both-NULL call also matched
-- any resource-anchored row of the tuple; the guard closes that pre-existing gap as well.
--
-- workflow_job_claim, the cogmap claim, has no anchor predicate at all. With p_principal NULL, its
-- documented unscoped default, it would hand out an anchorless job, as it already hands out
-- resource- and context-anchored rows of a matching tuple. It gains `cogmap_id IS NOT NULL`. Both
-- Rust callers pass a principal, whose steward_candidate_cogmaps filter never matches a NULL cogmap,
-- and hard-code cogmap personas, so no existing call changes outcome.
--
-- ADDITIVE, additive-only-on-`main`, on the argument 20260802000020 made for its own widening:
--   * the rewritten one-scope CHECK accepts every row the current one accepts EXCEPT an anchored
--     row of persona 'sensitivity', which no deployed binary writes; every existing row satisfies
--     it;
--   * the work-order CHECK constrains only a persona no deployed binary writes;
--   * the new index covers only rows no deployed binary creates;
--   * the three new functions are unreachable by old code;
--   * complete_anchor and workflow_job_claim keep their signatures, and change outcome only for
--     calls no caller makes.

ALTER TABLE kb_workflow_jobs DROP CONSTRAINT ck_workflow_jobs_one_scope;
ALTER TABLE kb_workflow_jobs
    ADD CONSTRAINT ck_workflow_jobs_one_scope
    CHECK (
        (num_nonnulls(cogmap_id, resource_id, context_id) = 1 AND persona NOT IN ('sensitivity'))
        OR (num_nonnulls(cogmap_id, resource_id, context_id) = 0 AND persona IN ('sensitivity'))
    );

-- The key set is checked in both directions. `?&` requires each key to be present, and subtracting
-- the two must leave an empty object; an array also fails that second test. Each value is then held
-- to its shape (see 3 above). `->>` of a jsonb number is its normalised text form, so the digit
-- pattern refuses fractions and negatives, and it guards the cast that follows it. Postgres does not
-- guarantee the evaluation order of AND, so the cast sits in a CASE, which it does honour. jsonb
-- normalises `1e2` to `100` before the CHECK sees it, which is harmless: the stored form is the plain
-- integer.
ALTER TABLE kb_workflow_jobs
    ADD CONSTRAINT ck_workflow_jobs_sensitivity_work_order
    CHECK (
        persona <> 'sensitivity'
        OR (
            jsonb_typeof(payload) = 'object'
            AND payload ?& ARRAY['surface', 'budget']
            AND payload - ARRAY['surface', 'budget'] = '{}'::jsonb
            AND jsonb_typeof(payload -> 'surface') = 'string'
            AND payload ->> 'surface' ~ '^kb_[a-z0-9_]{1,60}\.[a-z][a-z0-9_]{0,62}$'
            AND jsonb_typeof(payload -> 'budget') = 'number'
            AND CASE WHEN payload ->> 'budget' ~ '^[0-9]{1,6}$'
                     THEN (payload ->> 'budget')::int BETWEEN 1 AND 100000
                     ELSE false
                END
        )
    );

COMMENT ON CONSTRAINT ck_workflow_jobs_sensitivity_work_order ON kb_workflow_jobs IS
    'A sensitivity job''s payload is a work order: exactly {surface, budget}, each held to its '
    'shape. Never a resource id, hash, category, count, cursor or excerpt. Findings and watermarks '
    'live in the sweep''s own store, and the queue row '
    'never learns what was found (sensitivity-sweep spec D8, constraint 1). If you are here to add a '
    'field, read that section first.';

CREATE UNIQUE INDEX uq_workflow_jobs_in_flight_system
    ON kb_workflow_jobs (persona, dispatch_type)
    WHERE cogmap_id IS NULL AND resource_id IS NULL AND context_id IS NULL
      AND status IN ('pending', 'in_progress', 'waiting_for_retry');

-- ── System-scoped enqueue / claim / complete ────────────────────────────────────────────────────

-- Enqueue: idempotent within a band, like its three twins. Returns NULL when a job for the tuple is
-- already in flight. The caller reads that as "already queued", never as an error.
CREATE FUNCTION workflow_job_enqueue_system(
    p_persona text, p_dispatch_type text, p_payload jsonb
) RETURNS uuid LANGUAGE sql AS $$
    INSERT INTO kb_workflow_jobs (persona, dispatch_type, payload)
    VALUES (p_persona, p_dispatch_type, p_payload)
    ON CONFLICT DO NOTHING
    RETURNING id;
$$;

-- Claim anchorless jobs: the same FOR UPDATE SKIP LOCKED claim, flip and increment as the anchor
-- twin, with FIFO order and the lease set. It takes no principal, as the resource and anchor claims
-- take none; what makes that safe for this persona is the work-order CHECK above, not a scope.
-- The num_nonnulls(...) = 0 guard keeps this claim disjoint from every anchored family. A row of
-- the same tuple that carries an anchor belongs to that family's claim.
CREATE FUNCTION workflow_job_claim_system(
    p_persona text, p_dispatch_type text, p_limit int, p_lease_seconds int
) RETURNS TABLE(id uuid, attempts int, payload jsonb)
LANGUAGE sql AS $$
    UPDATE kb_workflow_jobs j
       SET status = 'in_progress',
           leased_at = now(),
           lease_expires_at = now() + make_interval(secs => p_lease_seconds),
           attempts = j.attempts + 1
     WHERE j.id IN (
         SELECT c.id
           FROM kb_workflow_jobs c
          WHERE c.persona = p_persona
            AND c.dispatch_type = p_dispatch_type
            AND num_nonnulls(c.cogmap_id, c.resource_id, c.context_id) = 0
            AND c.status IN ('pending', 'waiting_for_retry')
            AND c.next_visible_at <= now()
          ORDER BY c.enqueued_at
          LIMIT p_limit
          FOR UPDATE SKIP LOCKED
     )
    RETURNING j.id, j.attempts, j.payload;
$$;

-- Complete by JOB ID. Every incumbent completer matches on its anchor column, and for an anchorless
-- row that predicate is `NULL = NULL`, which is never true. The job id is the only handle an
-- anchorless row has, which is why this cannot be done by passing NULLs to the existing functions.
-- The persona, dispatch type and anchorless guards keep a stray id from completing another family's
-- job. Only an IN-PROGRESS job completes, the narrowing workflow_job_complete_claimed made in
-- 20260724000130 for the same reason: completing a pending job would cancel work that was never
-- dispatched. Here that is the next sweep tick, and nothing would record it.
CREATE FUNCTION workflow_job_complete_system(
    p_job uuid, p_persona text, p_dispatch_type text
) RETURNS uuid LANGUAGE sql AS $$
    UPDATE kb_workflow_jobs
       SET status = 'done', completed_at = now()
     WHERE id = p_job
       AND persona = p_persona
       AND dispatch_type = p_dispatch_type
       AND num_nonnulls(cogmap_id, resource_id, context_id) = 0
       AND status = 'in_progress'
    RETURNING id;
$$;

-- ── complete_anchor, guarded to its own family (see 4 above) ────────────────────────────────────
CREATE OR REPLACE FUNCTION workflow_job_complete_anchor(
    p_cogmap uuid, p_context uuid, p_persona text, p_dispatch_type text
) RETURNS uuid LANGUAGE sql AS $$
    UPDATE kb_workflow_jobs
       SET status = 'done', completed_at = now()
     WHERE cogmap_id IS NOT DISTINCT FROM p_cogmap
       AND context_id IS NOT DISTINCT FROM p_context
       AND num_nonnulls(cogmap_id, context_id) = 1
       AND persona = p_persona
       AND dispatch_type = p_dispatch_type
       AND status IN ('pending', 'in_progress', 'waiting_for_retry')
    RETURNING id;
$$;

-- ── workflow_job_claim, guarded to cogmap rows (see 4 above) ─────────────────────────────────────
-- The body is 20260724000130's, verbatim, plus `c.cogmap_id IS NOT NULL`.
CREATE OR REPLACE FUNCTION workflow_job_claim(
    p_persona text, p_dispatch_type text, p_limit int, p_lease_seconds int,
    p_correlation uuid DEFAULT NULL, p_principal uuid DEFAULT NULL
) RETURNS TABLE(id uuid, cogmap_id uuid, attempts int, payload jsonb)
LANGUAGE sql AS $$
    UPDATE kb_workflow_jobs j
       SET status = 'in_progress',
           leased_at = now(),
           lease_expires_at = now() + make_interval(secs => p_lease_seconds),
           attempts = j.attempts + 1,
           correlation_id = p_correlation,
           claimed_by_profile_id = p_principal
     WHERE j.id IN (
         SELECT c.id
           FROM kb_workflow_jobs c
          WHERE c.persona = p_persona
            AND c.dispatch_type = p_dispatch_type
            AND c.cogmap_id IS NOT NULL
            AND c.status IN ('pending', 'waiting_for_retry')
            AND c.next_visible_at <= now()
            -- The reach constraint. `steward_candidate_cogmaps` is the SAME predicate the sweep above
            -- gates on, so a principal can only ever claim work over cogmaps its own sweep could have
            -- enqueued. NULL means "unscoped", preserving the pre-Set-5 behavior for callers that
            -- pass no principal.
            AND (p_principal IS NULL
                 OR c.cogmap_id IN (SELECT m.cogmap_id FROM steward_candidate_cogmaps(p_principal) m))
          ORDER BY c.enqueued_at
          LIMIT p_limit
          FOR UPDATE SKIP LOCKED
     )
    RETURNING j.id, j.cogmap_id, j.attempts, j.payload;
$$;

SELECT declare_migration(
    20261001213010,
    'additive',
    'kb_workflow_jobs gains a fourth, SYSTEM scope for the sensitivity sweep (sensitivity-sweep spec R5, D8). ck_workflow_jobs_one_scope is rewritten so the declared system personas (sensitivity) are anchorless-only and every other persona stays exactly-one-anchor; ck_workflow_jobs_sensitivity_work_order holds that persona''s payload to exactly {surface, budget}, each value shape-checked, with no cursor (the watermark lives in the sweep''s guarded store); uq_workflow_jobs_in_flight_system gives anchorless rows single-flight on (persona, dispatch_type); workflow_job_enqueue_system / claim_system / complete_system (complete by job id, in_progress only) are new; workflow_job_complete_anchor gains num_nonnulls(cogmap_id, context_id) = 1 and workflow_job_claim gains cogmap_id IS NOT NULL, so neither reaches outside its family. Additive: the rewritten CHECK refuses only an anchored sensitivity row, which no deployed binary writes, and every existing row satisfies it; the work-order CHECK and the new index touch only a persona and rows no deployed binary writes; the new functions are unreachable by old code; the two amended functions keep their signatures and change outcome only for calls no caller makes.'
);
