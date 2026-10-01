-- resource_erasure_execute: lock each edge before the fold loop reads it (spec 2026-09-28 D1, D13).
--
-- 20260929040730's fold loop read `SELECT id INTO v_id FROM kb_edges WHERE id = v_eid AND NOT
-- is_folded` with no lock, and `_project_relationship_folded` (newest: 20260727000030) updates
-- with no `is_folded` predicate. A principal's fold uncommitted when the act read the edge let
-- the act append its own fold, wait on the projector's UPDATE, then succeed: two
-- `relationship_folded` events for one edge, `folded_edges` overclaiming, and the principal's
-- free-text reason in R's trail outside `ledger_remainder`.
--
-- The body below is 20260929040730's, copied verbatim; the ONLY change is `FOR UPDATE` on that
-- SELECT. Under READ COMMITTED the WHERE is re-checked after the wait, so a fold that commits
-- first leaves no row and the existing `edge % missing or already folded` raise fires;
-- resource_erasure_service classifies it as retryable and re-plans, and the new plan leaves the
-- folded edge out. What a later edit must not break:
--   * the lock and the `NOT is_folded` test stay ONE statement, so the re-check reads the
--     committed fold;
--   * the raise text is the service's classifier input (resource_erasure_service.rs).
-- The function COMMENT is re-issued with one sentence added. The same migration adds a
-- deployment caution to _resource_write_guard's COMMENT: `temper.replaying` bypasses the guard,
-- so it must only ever be set transaction-local by the replay walk.

CREATE OR REPLACE FUNCTION resource_erasure_execute(
    p_resource    uuid,
    p_operator    uuid,
    p_emitter     uuid,
    p_request_ref uuid,
    p_also_strike_blobs uuid[] DEFAULT '{}'::uuid[]
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
    v_plan    jsonb;
    v_charter uuid;
    v_ingest  text;
    v_erased  boolean;
    v_erased_ts timestamptz;
    v_found   boolean;
    v_id      uuid;
    v_ev      uuid;
    v_targets jsonb;
    v_remainder jsonb;
    v_edges   jsonb;
    v_i       integer;
    v_eid     uuid;
    v_bid     uuid; v_rel boolean; v_path text;
    v_ledger  jsonb := '[]'::jsonb;
BEGIN
    IF p_resource IS NULL THEN
        RAISE EXCEPTION 'resource_erasure_execute: p_resource is required';
    END IF;
    -- The request reference is the act's correlation id: every event the act appends carries
    -- it, and replay finds the act's span by it (D14). Without one, _event_append correlates
    -- each event to itself and the span is lost.
    IF p_request_ref IS NULL THEN
        RAISE EXCEPTION 'resource_erasure_execute: p_request_ref is required';
    END IF;

    -- ── THE REFUSAL VERDICTS, read PRE-act (D5). A refusal here RAISES — the Rust caller
    --    catches the typed message and records it through resource_erasure_refuse, so the SQL
    --    never silently widens the negative face to a partial act (and never appends a refusal
    --    event itself: _event_append's emitter is the OPERATOR and a refused attempt at SQL
    --    grain would attribute wrongly). The verdict reads happen before anything mutates, and
    --    under R's row lock (D13), taken right after the existence check: FOR UPDATE waits out
    --    every writer already holding the row (their FK KEY SHARE, the write guard's KEY SHARE,
    --    the body-hash recompute's NO KEY UPDATE) so the plan, the folds and the body all see one
    --    settled state, and a writer arriving after it waits on the lock, then refuses at the
    --    write guard (Section W). The same lock serializes a second execute: its verdict read
    --    runs after the first commits, sees `erased_at`, and raises `already erased` rather than
    --    both passing the reads and double-completing.
    --    PR 2's service parses these strings into refusal vocabulary. Two states are NOT
    --    refusals (D5): an in-flight ingest (below, where `targets` names it) and a tombstone
    --    (the paragraph after the verdicts). ──
    SELECT count(*) > 0 INTO v_found FROM kb_resources r WHERE r.id = p_resource;
    IF NOT v_found THEN
        RAISE EXCEPTION 'resource_erasure_execute: resource % not found', p_resource;
    END IF;
    PERFORM 1 FROM kb_resources WHERE id = p_resource FOR UPDATE;
    -- R's captured original remote sources, locked BEFORE the plan reads them, in uuid order (the
    -- order step (9e) locks them in, so two acts sharing originals cannot deadlock). A citer whose
    -- _upsert_remote_source already holds one of these rows makes the act wait for its commit, so
    -- the plan's shared/exclusive split and step (9e)'s delete decision read the same citers; a
    -- citer arriving later waits on the act, and if the act deleted the row, its upsert inserts
    -- the URL as a fresh row.
    PERFORM 1 FROM kb_remote_sources rs
     WHERE rs.id IN (SELECT o.source_id FROM _resource_erasure_remote_originals(p_resource) o)
     ORDER BY rs.id
       FOR UPDATE;
    SELECT c.telos_resource_id INTO v_charter FROM kb_cogmaps c WHERE c.telos_resource_id = p_resource;
    SELECT r.erased_at INTO v_erased_ts
      FROM kb_resources r WHERE r.id = p_resource;
    v_erased := v_erased_ts IS NOT NULL;

    IF v_charter IS NOT NULL THEN
        RAISE EXCEPTION 'resource_erasure_execute: charter resource (map-grain erasure is filed task 01a0e960-0ca2-7f42-b33e-1ed19b024e6b)';
    END IF;
    IF v_erased THEN
        RAISE EXCEPTION 'resource_erasure_execute: already erased';
    END IF;
    -- A TOMBSTONE IS ERASABLE: a soft-deleted resource is not a refusal. It is arguably the
    -- flow's most common shape — the content was soft-deleted, and the compliance need then
    -- arrives that demands it not exist at all. The principal act has no tombstone refusal
    -- (it tombstones VIA the act, 20260909000025), F4's write floor makes is_active=false
    -- already permanent, and no restore verb exists (the spec's F4 — "un-modifiable on every
    -- axis"), so erasure is the only way out of a tombstone. The act completes over one
    -- mechanically: is_active is already false, the CHECK is satisfied, and COALESCE keeps
    -- erased_at stable. D6's rule ("a soft-deleted resource must never be mistaken for an
    -- erased one") is a PROJECTION honesty rule — erased_at is NULL until this act sets it. ──

    -- ── The ONE computation (D10). No re-enumeration of the remainder, block counts, artifact
    --    counts or edges happens below — the plan computed them once. The would_strike entries
    --    the principal plan's shape used do not exist here: the survey names related blobs via
    --    the remainder, and the operator's `also_strike_blobs` arrives AT THE ACT (D8), where
    --    the strike loop below consumes it. ──────────────────────────────────────────────────
    v_plan := resource_erasure_survey_plan(p_resource);
    v_targets := v_plan->'targets';
    v_ingest := v_plan->>'ingest_state';

    -- ── The operator-listed blob strikes, through the wrapper, PER ROW (D8: a blob is struck
    --    ONLY when the operator listed it; the act never infers a strike from a relation). Each
    --    strike carries the wrapper's verdict at ITS OWN moment — the byte-delete fence runs
    --    inside — and its prose template is the ONE the fence parses by exact prefix. The plan
    --    itself predicts nothing here, because the operator's list arrives at the act, not at
    --    the survey (the survey names related blobs; the operator answers with the subset to
    --    strike).
    --
    --    A listed blob the plan did NOT name is refused, not silently struck: the survey is the
    --    reviewed record of what the act may reach, and an operator widening it mid-act is a
    --    drift the fence exists to catch. ─────────────────────────────────────────────────────
    FOR v_i IN 0 .. coalesce(array_upper(p_also_strike_blobs, 1), 0) - 1 LOOP
        v_bid := p_also_strike_blobs[v_i + 1];
        IF NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(v_plan->'remainder') rem
             WHERE rem->>'target' = 'kb_blobs'
               AND rem->>'outcome' LIKE '%blob ' || v_bid::text || ';%') THEN
            RAISE EXCEPTION 'resource_erasure_execute: blob % is not in the survey''s related-blob remainder; strike refused', v_bid;
        END IF;
        SELECT blob_id, released, pathname
          INTO v_bid, v_rel, v_path
          FROM blob_delete('blob_erased',
                           jsonb_build_object('blob_id', v_bid),
                           p_emitter,
                           p_correlation => p_request_ref);
        v_targets := v_targets || jsonb_build_array(jsonb_build_object(
            'target',  'kb_blobs',
            'outcome', blob_strike_outcome_text(v_rel, v_path)));
    END LOOP;

    -- ── Ingest state is not a refusal (D5): a partial or in-flight ingest ends with the
    --    erasure. The husk keeps its ingest_state; erased_at is authoritative, and the write
    --    floor (Section W) refuses any later attempt to continue the ingest. The record names
    --    the ingest the act ended. ─────────────────────────────────────────────────────────
    IF v_ingest <> 'complete' THEN
        v_targets := v_targets || jsonb_build_array(jsonb_build_object(
            'target',  'kb_resources.ingest_state',
            'outcome', 'ingest ' || v_ingest || '; ended by erasure; erased_at is authoritative'));
    END IF;

    -- ── Per-edge folds: ONE relationship_folded per edge touching R (D1 — the incumbent verb,
    --    its OWN trail shows who ended it and why, another principal's view reads as
    --    deliberately ended; replay folds through the existing projector). reason is a FIXED
    --    literal 'resource_erased', never operator prose. Each event carries the act's
    --    correlation id (the request reference), so the act's pairing is a fact, not a
    --    convention. Edges are folded FIRST (the projected is_folded) so the plan's edge arm and
    --    the fold events agree in the same transaction.
    v_edges := v_plan->'edges';
    FOR v_i IN 0 .. jsonb_array_length(v_edges) - 1 LOOP
        v_eid := (v_edges->>v_i)::uuid;
        SELECT id INTO v_id FROM kb_edges WHERE id = v_eid AND NOT is_folded FOR UPDATE;
        IF v_id IS NULL THEN
            RAISE EXCEPTION 'resource_erasure_execute: edge % missing or already folded', v_eid;
        END IF;
        v_ev := _event_append('relationship_folded', p_emitter,
                              (SELECT home_anchor_table FROM kb_edges WHERE id = v_eid),
                              (SELECT home_anchor_id FROM kb_edges WHERE id = v_eid),
                              jsonb_build_object(
                                  'edge_id', v_eid,
                                  'reason', 'resource_erased'),
                              p_correlation => p_request_ref);
        PERFORM _project_relationship_folded(v_ev, jsonb_build_object(
            'edge_id', v_eid,
            'reason', 'resource_erased'));
    END LOOP;

    -- ── Projection-side sentinels + the content sweep — THE one body, at the act's event
    --    position. No events inside; the appended event below is the record. ─────────────────
    v_ev := _event_append(
        'resource_erased', p_emitter, NULL, NULL,
        jsonb_build_object(
            'subject_table', 'kb_resources',
            'subject_id', p_resource,
            'actor', p_operator,
            'redacted_fields', '[]'::jsonb,
            'folded_edges', v_edges,
            'targets', v_targets,
            'remainder', v_plan->'remainder',
            'ledger_remainder', v_plan->'ledger_remainder',
            'propagated_to_clients', false),
        p_references => jsonb_build_array(
            jsonb_build_object('rel','subject',
                'target', jsonb_build_object('kind','kb_resources','id', p_resource)),
            jsonb_build_object('rel','request',
                'target', jsonb_build_object('kind','kb_events','id', p_request_ref))),
        p_correlation => p_request_ref);

    PERFORM _resource_erasure_apply_redaction(p_resource, v_ev);

    RETURN jsonb_build_object(
        'event_id',        v_ev,
        'edges',           v_edges,
        'targets',         v_targets,
        'remainder',       v_plan->'remainder',
        'ledger_remainder', v_plan->'ledger_remainder');
END;
$$;

COMMENT ON FUNCTION resource_erasure_execute(uuid, uuid, uuid, uuid, uuid[]) IS
'the resource-erasure act (spec 2026-09-28 D1/D2/D5/D8/D12; build order 2b): consumes
resource_erasure_survey_plan (ONE computation per act), folds every edge touching the resource
through its own relationship_folded event (fixed reason ''resource_erased'', the act''s correlation
id), strikes ONLY the operator-listed blobs through blob_delete(''blob_erased'', …), appends the ONE
NULL-anchored resource_erased event (references carry the subject + the request reference;
targets, remainder, ledger_remainder, folded_edges read straight off the plan — targets extended
by each blob strike and, when ingest_state is not complete, the ingest the erasure ended, which
is not a refusal), then calls _resource_erasure_apply_redaction — all one transaction. A refused
state (charter resource, already erased) RAISES here and appends nothing; the Rust service catches
it and records the refusal through resource_erasure_refuse. Legality is the Rust caller''s
is_system_admin gate, never SQL''s. No hash enters kb_erased_content.
Since 20260930000070 the fold loop locks each edge FOR UPDATE before it reads is_folded, so a fold
committed under the act raises ''edge % missing or already folded'' instead of folding twice.';

COMMENT ON FUNCTION _resource_write_guard(uuid) IS
'the write guard (spec 2026-09-28 D13): FOR KEY SHARE on the kb_resources row, then RAISE
''resource % is erased; writes are refused'' when erased_at IS NOT NULL. Conflicts only with the
erasure act''s FOR UPDATE. Reads erased_at, never is_active, so replay of historical writes to a
soft-deleted resource never trips it. Returns at once when the transaction-local setting
temper.replaying is ''on'', which the replay walk sets around each event it projects: a lawful write
whose event committed before the act can sort after the act''s events in walk order (event ids are
uuidv7, unordered across transactions within a millisecond on PG17), and replay must then diverge
(D14) rather than abort. The bypass is not an authorization boundary: the guard is a state floor
for the write paths, and a raw SQL session can write the tables directly with or without it.
temper.replaying must only ever be set transaction-local by the replay walk, never at session or
role level, because it bypasses this guard and the guard is not an authorization boundary.';

SELECT declare_migration(
    20260930000070,
    'additive',
    'CREATE OR REPLACE of resource_erasure_execute with the same signature and return shape; the one change is a row lock in the edge-fold loop, which turns a raced fold from a duplicate relationship_folded into the edge-missing-or-already-folded raise the function already had. The return shape and the raise vocabulary are unchanged. Two COMMENT texts gain a sentence. No table, column, constraint or grant changes.'
);
