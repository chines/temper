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
-- The next system persona joins by widening this list: one additive line, written on purpose.
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
-- Spec D8, constraint 1. A sensitivity job's payload is {surface, cursor_from, budget} and nothing
-- else: no resource id, hash, category or count. That is what keeps the unscoped claim safe.
-- 20260724000130 narrowed the cogmap claim because claim_audit handed out cross-tenant ids IN ITS
-- PAYLOAD; a payload with no ids in it has nothing to steal. The rule is enforced here, structurally,
-- rather than by review, because kb_workflow_jobs is in public and is the one table outside the
-- sweep's guarded store that the sweep writes to.
--
-- ── 4 · complete_anchor stops reaching outside its family ───────────────────────────────────────
-- complete_anchor matches with IS NOT DISTINCT FROM, so a call with both anchors NULL would complete
-- ANY anchorless job of the tuple. That was unreachable while no anchorless row could exist; this
-- migration makes such rows exist, so this migration closes the door. It does so with the same
-- num_nonnulls(cogmap_id, context_id) = 1 guard that workflow_job_claim_anchor has carried since
-- 20260802000020. Every caller passes exactly one anchor (HomeAnchor is a closed two-variant enum),
-- so no existing call changes outcome.
--
-- ADDITIVE, additive-only-on-`main`, on the argument 20260802000020 made for its own widening:
--   * the widened CHECK accepts a strict superset of the current one, and every existing row
--     already satisfies it;
--   * the work-order CHECK constrains only a persona no deployed binary writes;
--   * the new index covers only rows no deployed binary creates;
--   * the three new functions are unreachable by old code;
--   * complete_anchor keeps its signature, and changes outcome only for an argument pair no caller
--     passes.

ALTER TABLE kb_workflow_jobs DROP CONSTRAINT ck_workflow_jobs_one_scope;
ALTER TABLE kb_workflow_jobs
    ADD CONSTRAINT ck_workflow_jobs_one_scope
    CHECK (
        num_nonnulls(cogmap_id, resource_id, context_id) = 1
        OR (num_nonnulls(cogmap_id, resource_id, context_id) = 0 AND persona IN ('sensitivity'))
    );

-- The key set is checked in both directions. `?&` requires each key to be present, and subtracting
-- the three must leave an empty object; an array also fails that second test. The keys' VALUES are
-- the worker's business, and nothing here constrains them.
ALTER TABLE kb_workflow_jobs
    ADD CONSTRAINT ck_workflow_jobs_sensitivity_work_order
    CHECK (
        persona <> 'sensitivity'
        OR (
            jsonb_typeof(payload) = 'object'
            AND payload ?& ARRAY['surface', 'cursor_from', 'budget']
            AND payload - ARRAY['surface', 'cursor_from', 'budget'] = '{}'::jsonb
        )
    );

COMMENT ON CONSTRAINT ck_workflow_jobs_sensitivity_work_order ON kb_workflow_jobs IS
    'A sensitivity job''s payload is a work order: exactly {surface, cursor_from, budget}. Never a '
    'resource id, hash, category or count. Findings go to the sweep''s own store and the queue row '
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
-- job.
CREATE FUNCTION workflow_job_complete_system(
    p_job uuid, p_persona text, p_dispatch_type text
) RETURNS uuid LANGUAGE sql AS $$
    UPDATE kb_workflow_jobs
       SET status = 'done', completed_at = now()
     WHERE id = p_job
       AND persona = p_persona
       AND dispatch_type = p_dispatch_type
       AND num_nonnulls(cogmap_id, resource_id, context_id) = 0
       AND status IN ('pending', 'in_progress', 'waiting_for_retry')
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

SELECT declare_migration(
    20261001213010,
    'additive',
    'kb_workflow_jobs gains a fourth, SYSTEM scope for the sensitivity sweep (sensitivity-sweep spec R5, D8). ck_workflow_jobs_one_scope widens to admit zero anchors for the declared system personas only (sensitivity); ck_workflow_jobs_sensitivity_work_order holds that persona''s payload to exactly {surface, cursor_from, budget}; uq_workflow_jobs_in_flight_system gives anchorless rows single-flight on (persona, dispatch_type); workflow_job_enqueue_system / claim_system / complete_system (complete by job id) are new; and workflow_job_complete_anchor gains the num_nonnulls(cogmap_id, context_id) = 1 guard its claim already carries, so it cannot complete an anchorless job. Additive: the widened CHECK accepts a strict superset and every existing row satisfies it; the work-order CHECK and the new index touch only a persona and rows no deployed binary writes; the new functions are unreachable by old code; complete_anchor keeps its signature and changes outcome only for a both-NULL argument pair no caller passes.'
);
