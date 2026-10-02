-- A SYSTEM scope for kb_workflow_jobs: anchorless jobs, for the sensitivity sweep (spec R5, D8).
-- Rationale and review history: temper-artifacts plans/2026-10-01-sensitivity-sweep-3a-core.md.

-- System personas are anchorless ONLY, and every other persona keeps exactly one anchor. Both
-- directions are load-bearing. An anchorless embed or region job would be a mis-passed NULL. An
-- anchored sensitivity job makes the erasure act roll back: it sets payload = '{}' on the erased
-- resource's jobs, which fails the work-order CHECK below. A new system persona joins both lists.
ALTER TABLE kb_workflow_jobs DROP CONSTRAINT ck_workflow_jobs_one_scope;
ALTER TABLE kb_workflow_jobs
    ADD CONSTRAINT ck_workflow_jobs_one_scope
    CHECK (
        (num_nonnulls(cogmap_id, resource_id, context_id) = 1 AND persona NOT IN ('sensitivity'))
        OR (num_nonnulls(cogmap_id, resource_id, context_id) = 0 AND persona IN ('sensitivity'))
    );

-- The payload is a work order: {surface, budget}, no ids and no cursor (spec D8, Q14). The
-- unscoped claim is safe only because of that. Values are bounded, not just keys: an unbounded
-- budget held a dash-stripped SSN. The cast sits in a CASE: Postgres does not order AND.
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
    'A work order only: {surface, budget}. Never an id, cursor or excerpt. Read spec D8 before '
    'adding a field.';

-- Keyed on the anchors being absent, not on persona: NULLs are distinct in a unique index, so no
-- incumbent single-flight index sees an anchorless row.
CREATE UNIQUE INDEX uq_workflow_jobs_in_flight_system
    ON kb_workflow_jobs (persona, dispatch_type)
    WHERE cogmap_id IS NULL AND resource_id IS NULL AND context_id IS NULL
      AND status IN ('pending', 'in_progress', 'waiting_for_retry');

CREATE FUNCTION workflow_job_enqueue_system(
    p_persona text, p_dispatch_type text, p_payload jsonb
) RETURNS uuid LANGUAGE sql AS $$
    INSERT INTO kb_workflow_jobs (persona, dispatch_type, payload)
    VALUES (p_persona, p_dispatch_type, p_payload)
    ON CONFLICT DO NOTHING
    RETURNING id;
$$;

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

-- By job id: an incumbent completer's `anchor = p_anchor` never matches NULL. In-progress only,
-- as workflow_job_complete_claimed (20260724000130): completing a pending job cancels a tick.
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

-- Its IS NOT DISTINCT FROM would match an anchorless row on a both-NULL call. Prior body + guard.
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

-- Unscoped (NULL principal) it would hand out an anchorless job. 20260724000130's body + guard.
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
    'System-scoped (anchorless) jobs for the sensitivity sweep: the one-scope CHECK admits zero anchors for system personas only, a work-order CHECK on their payload, a single-flight index, and enqueue/claim/complete_system. complete_anchor and workflow_job_claim gain one guard each. Additive: the rewritten CHECK refuses only anchored sensitivity rows, which no deployed binary writes; everything else is new or unchanged for every existing caller.'
);
