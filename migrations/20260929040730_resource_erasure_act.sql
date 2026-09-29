-- Resource erasure's ACT (spec 2026-09-28, temper-artifacts/specs/2026-09-28-resource-erasure-design.md,
-- D1/D2/D4/D5/D8/D10/D12; task 01a0e9e7-491d-7700-8f58-99d0b068e059, build order 2b). The act itself:
-- row-anchored redaction keyed by resource id (never by hash), the survey plan that owns the
-- computation once, the survey door's render, and the executor that consumes the plan.
--
-- THE CONSTRAINTS A LATER EDIT MUST NOT BREAK:
--
--   * REDACTION IS ROW-ANCHORED, NEVER BY HASH (D2, the custody-never-bytes ruling of 2026-09-10).
--     _erasure_apply_redaction empties by `content_hash = ANY(p_hashes)`; it REACHES byte-identical
--     rows in every other resource. This act empties by join on `resource_id` alone, and NO hash
--     enters kb_erased_content — that table is the principal act's hash-keyed record, and feeding it
--     from a resource act would re-create exactly the defect 01a09c45 is cleaning up.
--   * THE ONE REDACTION DEFINITION HAS A SCOPE (D11): `_resource_erasure_apply_redaction` takes a
--     scope parameter that either names the whole resource or narrows to a block set with
--     keep-current. Cut 1 (this migration) only ever calls the whole-resource form; the block
--     history scrub (build order 2e, `block_history_scrubbed`) narrows THIS definition rather than
--     forking it. A second body of erasure is two definitions that drift.
--   * THE ACT AND THE SURVEY SHARE ONE COMPUTATION (D10, the 20260913000010 precedent): the plan is
--     the act's scope machinery moved whole out of the act, so the act consumes it and nothing
--     re-enumerates. A preview that can disagree with the act is worse than no preview.
--   * CUT 1 DOES NOT TOUCH THE LEDGER (D12). No event payload is rewritten; the append-only trigger
--     is unamended; kb_event_field_redactions does not exist yet. Every free-text path the act does
--     NOT reach is computed into `ledger_remainder` by (event, path) — D12's shape, exactly what
--     cut 2's completion pass reads. Replay stays byte-identical because step 9 applies the
--     PROJECTION-side sentinels at the event's ledger position.
--   * REFUSALS ARE RECORDED (ruled 2026-09-29): `resource_erasure_refused` is appended for a
--     non-operator, a charter resource, an in-flight ingest — and for already-erased (the attempt
--     and its refusal are part of the record; the effect is a no-op — nothing in the projection
--     changes, no second `resource_erased` is minted).
--
-- Additive: new functions only — no existing column, constraint or function is altered, and an old
-- binary reads every pre-existing row unchanged.

-- ---------------------------------------------------------------------------
-- Section 0. The one redaction body (D2), given a scope. Event-free by design:
-- the replay arm runs this beside the walk; only `resource_erasure_execute`
-- appends events around it.
--
-- The scope is spelled with four parameters rather than a jsonb blob: p_whole
-- true = the whole resource (cut 1's only form today; anything else is REFUSED —
-- the narrowed form is the block history scrub's, 2e, and half-building it here
-- would be a scope that lies about its completeness). p_resource keys every
-- join; p_event supplies occurred_at for the replay-stable stamps.
-- ---------------------------------------------------------------------------
CREATE FUNCTION _resource_erasure_apply_redaction(p_resource uuid, p_event uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_occurred timestamptz := (SELECT occurred_at FROM kb_events WHERE id = p_event);
    v_key text;
BEGIN
    -- ── (1) Chunk prose emptied BY ROW JOIN, hash kept (D2 step 1, and the joint-read fix:
    --     header_path rides the same chunks — authored heading prose, scanned by the sweep).
    --     Current AND superseded. The CAS retention rule never fires: fold/supersede affect
    --     visibility, not existence, and emptied rows stay rows. ─────────────────────────────
    UPDATE kb_chunk_content cc
       SET content = ''
      FROM kb_chunks c
     WHERE cc.chunk_id = c.id
       AND c.resource_id = p_resource
       AND cc.content <> '';

    UPDATE kb_chunks
       SET header_path = NULL
     WHERE resource_id = p_resource
       AND header_path IS NOT NULL;

    -- ── (2) Verbatim block bytes: every revision of every block, live and folded (D2 step 2, F1:
    --     kb_block_revisions → kb_content_blocks.resource_id reaches them all with NO hash in the
    --     join). ───────────────────────────────────────────────────────────────────────────────
    UPDATE kb_block_content bc
       SET content = ''
     WHERE bc.block_revision_id IN (
           SELECT br.id FROM kb_block_revisions br
             JOIN kb_content_blocks b ON b.id = br.block_id
            WHERE b.resource_id = p_resource)
       AND bc.content <> '';

    -- ── (3) Embeddings and provenance nulled TOGETHER — `embedding IS NULL` and `embedded_with IS
    --     NULL` can never disagree (20260713000040:84-87), the coherence rule the principal act's
    --     step (4) carries (D2 step 3). The embed drain skips inactive resources
    --     (embed_service.rs:163,225), so nothing re-embeds (F4). ────────────────────────────────
    UPDATE kb_chunks
       SET embedding = NULL,
           embedded_with = NULL
     WHERE resource_id = p_resource
       AND embedding IS NOT NULL;

    -- ── (4) Search vector emptied: the vector folds title+body+meta, so a partial redaction would
    --     leave redacted terms searchable (D2 step 4). ────────────────────────────────────────
    UPDATE kb_resource_search_index si
       SET search_vector = ''
      WHERE si.resource_id = p_resource
        AND si.search_vector <> '';

    -- ── (5) Data artifacts: EVERY artifact of the resource — every kind owner (kb_profiles,
    --     kb_teams), every intent (current, member, pinned), folded/superseded included. Ruled
    --     2026-09-28: artifacts are bound to their resource and do not exist independently of it;
    --     that is the cost of security. Content '{}'::jsonb — the column is JSONB NOT NULL
    --     (20260820000020:48); the principal act's own value and the sweep's closure signal. Hashes
    --     and ids kept; artifact SHAPES are homed in a context or cogmap, not in the resource, and
    --     are untouched. NO hash enters kb_erased_content from here, ever (D12 rule 0). ────────
    UPDATE kb_data_artifact_content dac
       SET content = '{}'::jsonb
     WHERE dac.artifact_id IN (
           SELECT da.id FROM kb_data_artifacts da WHERE da.resource_id = p_resource)
       AND dac.content <> '{}'::jsonb;

    -- ── (6) The citation audits PROJECTED from R's blocks' events: the projected column the sweep
    --     scans (20260724000110:29), reached SEPARATELY from the ledger half, which cut 1 does NOT
    --     touch (D2 step 8's joint-read fix; D3 redacts the event's reason at cut 2). Audits by
    --     other findings that CITE R's blocks are listed-only (Q1) and unreached — they are
    --     anchored on other findings' blocks, outside the resource join. ──────────────────────
    UPDATE kb_citation_audits ca
       SET reason = NULL
     WHERE ca.block_id IN (
           SELECT b.id FROM kb_content_blocks b WHERE b.resource_id = p_resource)
       AND ca.reason IS NOT NULL;

    -- ── (7) Formation watermarks nulled (D2 step 6, the principal act's rule UNCHANGED): the
    --     resource's home context and any cogmap holding it as a region member, so the next
    --     materialize recomputes centroids from survivors. Nulling in LEDGER ORDER (the walk arm
    --     re-applies at the event's position; the later of the two events' stamps is what replay
    --     leaves — an idempotent no-op either way, since replay also runs this body). ──────────
    UPDATE kb_contexts c
       SET shape_materialized_event_id = NULL
     WHERE c.shape_materialized_event_id IS NOT NULL
       AND c.id = (SELECT h.anchor_id FROM kb_resource_homes h
                    WHERE h.resource_id = p_resource AND h.anchor_table = 'kb_contexts');
    UPDATE kb_cogmaps m
       SET shape_materialized_event_id = NULL
     WHERE m.shape_materialized_event_id IS NOT NULL
       AND m.id IN (
           SELECT r.home_anchor_id FROM kb_cogmap_regions r
             JOIN kb_cogmap_region_members mem ON mem.region_id = r.id
            WHERE r.home_anchor_table = 'kb_cogmaps' AND NOT r.is_folded
              AND mem.member_table = 'kb_resources' AND mem.member_id = p_resource);

    -- ── (8) Workflow jobs scoped to the resource (D2 step 7): pending rows cancelled, payload
    --     excerpts emptied. Not replay inputs; excerpt carriers on the personal-data surface. ───
    UPDATE kb_workflow_jobs j
       SET status     = 'dead',
           payload    = '{}'::jsonb,
           last_error = NULL
     WHERE j.resource_id = p_resource
       AND j.status IN ('pending', 'waiting_for_retry');

    -- ── (9) PROJECTION-SIDE SENTINELS, applied inside the same body at the caller's event
    --     position (D2 step 9, D4's projection side). Before cut 2 ships, step (9a) is what keeps
    --     replay byte-identical: the walk projects the original title from resource_created, then
    --     the resource_erased arm reaches here and overwrites at its position — "apply at the
    --     event's position", the reconciliation the PrincipalErased arm documents in replay.rs.
    --     After cut 2 ships, the redacted payloads already project these values from genesis and
    --     this step becomes an idempotent no-op. ──────────────────────────────────────────────

    -- (9a) The husk: is_active cleared and erased_at set in the SAME UPDATE — the CHECK
    --      kb_resources_erased_is_inactive (20260929000010) raises on any in-between state, so the
    --      order is a constraint, not policy. erased_at = the event's occurred_at (never now(),
    --      the replay-stable rule, D6). Title and origin_uri: D4 sentinels, projector-reproducible
    --      constants, never operator input. `updated` rides occurred_at like every projector.
    UPDATE kb_resources r
       SET is_active      = false,
           erased_at      = COALESCE(r.erased_at, v_occurred),
           title          = 'erased-' || r.id::text,
           origin_uri     = 'erased:' || r.id::text,
           updated        = v_occurred
     WHERE r.id = p_resource;

    -- (9b) The resource's properties: keys AND values sentineled (Q3, ruled 2026-09-28 — an
    --      operator does not tell a resource apart from its metadata; the husk keeps no metadata
    --      at all; doc_type, tags and facets are inside the property surface and go with it).
    --      Keys map erased-key-<n> by LEDGER ORDER of first appearance (D4): the mapping derives
    --      from ledger order, never from key text, so it reveals nothing; property_unset stays
    --      consistent because the same original key maps to the same n across property_set,
    --      property_asserted and property_unset events, which replay reproduces (the mapping is
    --      a pure function of (owner, key) under a total ledger order of first-assertion
    --      timestamps). EVERY family row — live and folded — is folded by this pass: the husk
    --      keeps NO metadata (Q3), and folding avoids a UNIQUE-index collision the sentinel
    --      values would otherwise raise — uq_kb_properties_active is partial on NOT is_folded
    --      over (owner, key, value); two live rows of ONE key in the facet shape (several live
    --      rows per key is what facet_set IS) would both map to (erased-key-n, "erased") and
    --      violate it. Folding is also what replay reproduces: the act's later, folded rows came
    --      from events that are themselves behind the erasure event in ledger order, so the
    --      arm at the event's position sees the same family state the live act sees.
    --
    --      The key-grain projection: first appearance = the minimum occurred_at across the
    --      property's asserted_by_event_id over the row's family. A key set → unset → re-set maps
    --      to one n: the DISTINCT-on-key pass numbers each original key ONCE for the whole
    --      family. last_event_id points at the erasure event (the property fold rides the act
    --      — the trail records which event retired the property, the 20260727000030 shape).
    WITH family AS (
        SELECT DISTINCT p.property_key,
               (SELECT min(e.occurred_at) FROM kb_events e
                 WHERE e.id IN (
                     SELECT pr.asserted_by_event_id FROM kb_properties pr
                      WHERE pr.owner_table = 'kb_resources' AND pr.owner_id = p_resource
                        AND pr.property_key = p.property_key)) AS first_seen
          FROM kb_properties p
         WHERE p.owner_table = 'kb_resources' AND p.owner_id = p_resource
    ), ranked AS (
        SELECT property_key, row_number() OVER (ORDER BY first_seen) AS n FROM family
    )
    UPDATE kb_properties p
       SET property_key   = 'erased-key-' || ranked.n::text,
           property_value = '"erased"'::jsonb,
           is_folded      = true,
           last_event_id  = COALESCE(p_event, p.last_event_id)
      FROM ranked
     WHERE ranked.property_key = p.property_key
       AND p.owner_table = 'kb_resources' AND p.owner_id = p_resource;

    -- (9c) Edge labels: NULL on every edge at either end (D4 — kind and polarity survive; they
    --      are the structure; the "system vocabulary" alternative was rejected in the spec — no
    --      registry exists, and the edge is folded anyway at the act level).
    UPDATE kb_edges e
       SET label = NULL
     WHERE (e.source_table = 'kb_resources' AND e.source_id = p_resource)
        OR (e.target_table = 'kb_resources' AND e.target_id = p_resource);

    -- (9d) Edge-owned property rows cascade-folded with their edges (the edge-owned-properties
    --      discipline): the resource erasure does NOT redact edge-owned property VALUES' keys in
    --      place — the fold event (`relationship_folded`, one per edge, emitted by the act under
    --      its correlation id) carries the fold to the properties through the incumbent
    --      _project_relationship_folded. No separate pass here: the fold is the edge's own
    --      lifecycle event, and step (9b)'s resource-owned surface is the only surface this body
    --      sentinels in place.

    -- (9e) The remote-source re-pointing (D4): every remote provenance row of R's blocks re-points
    --      to the SAME sentinel row replay's redacted incorporated[*].source.value would upsert —
    --      sentinel URI 'erased:<block_id>:<seq>', constant per class. Upsert-then-update: mint or
    --      find the sentinel row, then UPDATE the provenance rows to point at it. The ORIGINAL
    --      remote row either has another live citer and stays (the remainder names it), or has
    --      none and is dropped-by-replay — the act deletes it when nothing else cites it, because
    --      replay of the redacted ledger never mints it.
    FOR v_key IN
        SELECT DISTINCT 'erased:' || v_b.block_id::text || ':' || v_b.accretion_seq
          FROM (SELECT b.id AS block_id, v_bp.accretion_seq
                  FROM kb_content_blocks b
                  JOIN kb_block_provenance v_bp ON v_bp.block_id = b.id
                 WHERE b.resource_id = p_resource
                   AND v_bp.source_kind = 'remote') v_b
    LOOP
        PERFORM _upsert_remote_source(v_key);
    END LOOP;

    UPDATE kb_block_provenance bp
       SET source_id = sentinel.id
      FROM kb_remote_sources sentinel
     WHERE sentinel.uri = 'erased:' || bp.block_id::text || ':' || bp.accretion_seq
       AND bp.source_kind = 'remote'
       AND EXISTS (SELECT 1 FROM kb_content_blocks b
                    WHERE b.id = bp.block_id AND b.resource_id = p_resource);

    -- The original remote rows R exclusively cited: deleted ONLY when nothing else cites them —
    -- replay of the redacted payloads never mints them, and a deleted row is the exact
    -- projection replay lands on. A row with another live citer STAYS, and the remainder names it
    -- (D4, D8: "a URL others cite"). The upsert-then-update above made replay and the live act
    -- agree on the destination before this sweep.
    -- After the re-pointing UPDATE above, R's blocks' provenance rows no longer point at the
    -- originals; a row is deleted ONLY when NOTHING cites it any more — replay of the redacted
    -- payloads never mints it, and a dropped row is the exact projection replay lands on. A row
    -- with another live citer STAYS, and the remainder names it (D4, D8: "a URL others cite").
    DELETE FROM kb_remote_sources r
     WHERE NOT EXISTS (SELECT 1 FROM kb_block_provenance q WHERE q.source_kind = 'remote' AND q.source_id = r.id);

    RETURN;
END;
$$;

COMMENT ON FUNCTION _resource_erasure_apply_redaction(uuid, uuid) IS
'THE ONE row-anchored redaction body for resource erasure (spec 2026-09-28 D2, D4): chunk prose,
header_path, block revision bytes, embeddings+embedded_with, search vector, data artifact content
({}::jsonb, EVERY artifact of the resource whatever its kind owner, intent or supersession — ruled
2026-09-28), citation-audit projected reasons, formation watermark nulls, workflow-job scoping, and
the projection-side sentinels (husk title/origin_uri, property keys erased-key-<n> by ledger order
of first appearance, values ''erased''::jsonb, edge labels NULL, remote-source re-pointing to the
sentinel rows replay mints). ROW-ANCHORED: every join is on resource id, never a content hash —
another resource''s byte-identical content is NEVER reached (the custody-never-bytes ruling), and
no hash enters kb_erased_content from this body. Cut 1 (2026-09-29): scope is whole-resource; the
block-set form with keep-current is the block history scrub''s (2e) and narrows THIS body, never
forks it. Event-free: the replay arm (replay.rs ResourceErased) calls it at the event''s ledger
position; only resource_erasure_execute appends events around it.';

-- ---------------------------------------------------------------------------
-- Section 0b. THE trail-scope predicate (F2): "the resource's events" — the
-- union the element-trail reader (20260912000020) already spells, PLUS the one
-- arm the trail lacks: property events owned by an EDGE that touches R. The
-- survey's ledger remainder, cut 2's completion pass, and any operator audit
-- all walk the SAME definition; re-deriving it separately is a second
-- definition that drifts from the trail.
-- ---------------------------------------------------------------------------
CREATE FUNCTION _resource_erasure_trail_scope(p_resource uuid)
RETURNS TABLE (event_id uuid, event_type text) LANGUAGE sql STABLE AS $$
    SELECT ev.id, et.name
      FROM kb_events ev
      JOIN kb_event_types et ON et.id = ev.event_type_id
     WHERE et.category = 'domain'
       AND (
            (ev.payload ->> 'resource_id')::uuid = p_resource
         OR ((ev.payload #>> '{owner,table}') = 'kb_resources'
             AND (ev.payload #>> '{owner,id}')::uuid = p_resource)
         OR EXISTS (SELECT 1 FROM kb_content_blocks b
                     WHERE b.id = (ev.payload ->> 'block_id')::uuid
                       AND b.resource_id = p_resource)
         OR EXISTS (SELECT 1 FROM kb_edges ee
                     WHERE ee.id = (ev.payload ->> 'edge_id')::uuid
                       AND ((ee.source_table = 'kb_resources' AND ee.source_id = p_resource)
                         OR (ee.target_table = 'kb_resources' AND ee.target_id = p_resource)))
         OR ((ev.payload #>> '{owner,table}') = 'kb_edges'
             AND (ev.payload #>> '{owner,id}')::uuid IN (
                 SELECT ee2.id FROM kb_edges ee2
                  WHERE (ee2.source_table = 'kb_resources' AND ee2.source_id = p_resource)
                     OR (ee2.target_table = 'kb_resources' AND ee2.target_id = p_resource)))
       );
$$;

COMMENT ON FUNCTION _resource_erasure_trail_scope(uuid) IS
'the ONE scope predicate for "a resource''s own ledger events" (spec 2026-09-28 F2): the
element-trail read''s own predicate (payload->>''resource_id''; property events owner-keyed to the
resource; block events through the block join; events carrying a touched edge''s edge_id) PLUS the
one arm the trail lacks — property events whose owner IS an edge touching the resource (edge-owned
properties ride the 20260727000030 edge-facet shape, and the trail''s edge_id arm does not reach
owner-shaped payloads). Every consumer — the survey''s ledger remainder, cut 2''s completion pass,
any operator audit — walks THIS predicate, never a second derivation.';

-- ---------------------------------------------------------------------------
-- Section 1. THE shared computation (D10): blocks, revisions, chunks, artifacts,
-- edges, the refusal verdict, and both remainders. The act consumes it; the
-- survey door renders it; nothing re-enumerates.
-- ---------------------------------------------------------------------------
CREATE FUNCTION resource_erasure_survey_plan(p_resource uuid)
RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
    v_exists        uuid;
    v_n_blocks      integer;
    v_n_revisions   integer;
    v_n_chunks      integer;
    v_n_artifacts   integer;
    v_n_edges       integer;
    v_edges         jsonb := '[]'::jsonb;
    v_charter_of    uuid;
    v_ingest        text;
    v_ledger        jsonb := '[]'::jsonb;
    v_remainder     jsonb := '[]'::jsonb;
    v_row           record;
    v_fingerprint   text;
BEGIN
    SELECT id INTO v_exists FROM kb_resources WHERE id = p_resource;
    IF v_exists IS NULL THEN
        RAISE EXCEPTION 'resource_erasure_execute: resource % not found', p_resource;
    END IF;

    -- ── Scope counts, PRE-redaction state (the same discipline the principal plan's per-target
    --    arms hold: the reads only report what the act will find). ────────────────────────────
    SELECT count(*) INTO v_n_blocks FROM kb_content_blocks WHERE resource_id = p_resource;
    SELECT count(*) INTO v_n_revisions FROM kb_block_revisions br
      JOIN kb_content_blocks b ON b.id = br.block_id
     WHERE b.resource_id = p_resource;
    SELECT count(*) INTO v_n_chunks FROM kb_chunks WHERE resource_id = p_resource;
    SELECT count(*) INTO v_n_artifacts FROM kb_data_artifacts WHERE resource_id = p_resource;
    SELECT count(*) INTO v_n_edges FROM kb_edges e
     WHERE (e.source_table = 'kb_resources' AND e.source_id = p_resource)
        OR (e.target_table = 'kb_resources' AND e.target_id = p_resource);

    -- ── The edges the act folds, each listed so the record's `folded_edges` and the per-edge
    --     events agree. ──────────────────────────────────────────────────────────────────────
    FOR v_row IN
        SELECT e.id, e.label, e.edge_kind
          FROM kb_edges e
         WHERE (e.source_table = 'kb_resources' AND e.source_id = p_resource)
            OR (e.target_table = 'kb_resources' AND e.target_id = p_resource)
         ORDER BY e.id
    LOOP
        v_edges := v_edges || jsonb_build_object('edge_id', v_row.id, 'kind', v_row.edge_kind);
    END LOOP;

    -- ── THE REFUSAL FACE (D5), computed here so execute consumes the verdict rather than
    -- re-deriving it: a charter resource (Q2 — the map-grain act is another task, named), an
    -- in-flight ingest, an already-erased resource. ──────────────────────────────────────────
    SELECT c.telos_resource_id INTO v_charter_of FROM kb_cogmaps c WHERE c.telos_resource_id = p_resource;
    SELECT r.ingest_state INTO v_ingest FROM kb_resources r WHERE r.id = p_resource;

    -- ── THE REMAINDER (D8). Each entry is the named, never-struck part. The four shapes: ─────

    -- 1. Blobs related to the resource, live or struck, through a relation edge. The act folds
    --    their edges and names each blob; it strikes ONLY what the operator listed
    --    (also_strike_blobs), per row through blob_delete('blob_erased', …) and the byte-delete
    --    fence. It never infers a strike from a relation.
    FOR v_row IN
        SELECT DISTINCT b.id, b.content_hash, b.blob_pathname,
               EXISTS (SELECT 1 FROM kb_blobs live
                        WHERE live.id = b.id AND live.content_type IS NOT NULL) AS is_live
          FROM kb_blobs b
          JOIN kb_edges e ON NOT e.is_folded
               AND ((e.source_table = 'kb_blobs' AND e.source_id = b.id
                      AND e.target_table = 'kb_resources' AND e.target_id = p_resource)
                 OR (e.target_table = 'kb_blobs' AND e.target_id = b.id
                      AND e.source_table = 'kb_resources' AND e.source_id = p_resource))
         ORDER BY b.id
    LOOP
        v_remainder := v_remainder || jsonb_build_object(
            'target', 'kb_blobs',
            'outcome', 'related blob ' || v_row.id::text || '; hash ' || v_row.content_hash
                       || '; hash ' || CASE WHEN v_row.is_live THEN 'live; struck only when the operator lists it'
                                            ELSE 'already struck' END);
    END LOOP;

    -- 2. Derivers: resources with a live `derived_from` edge INTO R, or block provenance citing R.
    --    Named by id, never touched; their citing provenance rows are ids only (no text).
    FOR v_row IN
        SELECT DISTINCT e.source_id AS deriver_id
          FROM kb_edges e
         WHERE e.is_folded = false AND e.edge_kind = 'leads_to'
           AND e.label = 'derived_from'
           AND e.target_table = 'kb_resources' AND e.target_id = p_resource
           AND e.source_table = 'kb_resources'
        UNION
        SELECT DISTINCT b.resource_id
          FROM kb_block_provenance q
          JOIN kb_content_blocks b ON b.id = q.block_id
         WHERE q.source_kind = 'resource' AND q.source_id = p_resource
     LOOP
        v_remainder := v_remainder || jsonb_build_object(
            'target', 'deriver',
            'outcome', 'resource ' || v_row.deriver_id::text
                       || ' holds a structural lead (' ||
                       CASE WHEN EXISTS (SELECT 1 FROM kb_edges e
                                          WHERE e.is_folded = false AND e.edge_kind = 'leads_to'
                                            AND e.label = 'derived_from'
                                            AND e.target_table = 'kb_resources' AND e.target_id = p_resource
                                            AND e.source_table = 'kb_resources' AND e.source_id = v_row.deriver_id)
                            THEN 'derived_from edge'
                            ELSE 'provenance citation' END
                       || '); never touched; discovery-bound');
    END LOOP;

    -- 3. Cross-resource ledger text that quotes R (Q1, listed only): events of a quoting type
    --    whose payload text names R's id AND whose subject arm is NOT R's own. A
    --    citation_audited event ON one of R's blocks is R's own trail (step (6) reached its
    --    projected column; its ledger reason rides R's ledger remainder below) — this arm is
    --    only the events anchored elsewhere. Structurally: the payload text contains R's id,
    --    and no block of R carries the payload's block_id. Named by event id, never redacted —
    --    the exception never crosses the resource boundary (Q1).
    FOR v_row IN
        SELECT DISTINCT ev.id, et.name
          FROM kb_events ev
          JOIN kb_event_types et ON et.id = ev.event_type_id
         WHERE et.name IN ('citation_audited', 'subscription_delivery_disposed',
                           'invocation_closed')
           AND ev.payload::text LIKE '%' || p_resource::text || '%'
           AND NOT EXISTS (
               SELECT 1 FROM kb_content_blocks b
                WHERE b.resource_id = p_resource
                  AND b.id = (ev.payload->>'block_id')::uuid)
           AND NOT EXISTS (
               SELECT 1
                 FROM _resource_erasure_trail_scope(p_resource) t
                WHERE t.event_id = ev.id)
    LOOP
        v_remainder := v_remainder || jsonb_build_object(
            'target', 'cross-resource ledger text',
            'outcome', 'event ' || v_row.id::text || ' (' || v_row.name
                       || ') may quote the resource; listed only (Q1), never redacted');
    END LOOP;

    -- 4. Shared remote-source URLs: kb_remote_sources rows R's blocks cite that ANOTHER
    --    resource's block also cites (live or folded — the row is shared either way). A URL
    --    R exclusively cites is NOT here: the act's re-pointing sweep (2·(9e)) deletes it, and
    --    replay of the redacted payloads never mints it, so the projection agrees by
    --    construction. A shared one stays and is named (D4, D8: "a URL others cite").
    FOR v_row IN
        SELECT DISTINCT rs.uri
          FROM kb_remote_sources rs
          JOIN kb_block_provenance q ON q.source_kind = 'remote' AND q.source_id = rs.id
          JOIN kb_content_blocks b ON b.id = q.block_id
         WHERE b.resource_id = p_resource
           AND EXISTS (
               SELECT 1 FROM kb_block_provenance other
                 JOIN kb_content_blocks ob ON ob.id = other.block_id
                WHERE other.source_kind = 'remote' AND other.source_id = rs.id
                  AND ob.resource_id <> p_resource)
    LOOP
        v_remainder := v_remainder || jsonb_build_object(
            'target', 'kb_remote_sources.uri',
            'outcome', 'shared URL ' || v_row.uri
                       || ' ; another resource''s block still cites it; named, kept');
    END LOOP;

    -- ── THE LEDGER REMAINDER (D12): the resource's OWN ledger free-text paths the act has not
    --    reached, in exactly the shape `RedactedEventFields` uses — {event, paths} — so the
    --    cut-2 completion pass reads this list directly, no translation. The scope is the ONE
    --    trail-scope definition (see _resource_erasure_trail_scope, F2); every free-text path
    --    per F3's catalog, spelled explicitly per event type so a new payload field is caught
    --    by the fence (D9, build order 2d) rather than drifting silent here. Ids of EXISTING
    --    events only — no id is minted; paths only, never values (a redaction record must not
    --    carry what it would redact). `metadata` authorship prose (F3's last row: reasoning /
    --    rationale) rides each event's own list when the metadata carries those keys.
    SELECT coalesce(jsonb_agg(jsonb_build_object('event', s.event_id, 'paths', s.paths)
                               ORDER BY s.event_id), '[]'::jsonb)
      INTO v_ledger
      FROM (
        SELECT t.event_id,
               CASE t.event_type
                   WHEN 'resource_created'           THEN '["title","origin_uri"]'::jsonb
                   WHEN 'resource_updated'           THEN '["title","origin_uri"]'::jsonb
                   WHEN 'block_folded'               THEN '["reason"]'::jsonb
                   WHEN 'citation_audited'           THEN '["reason"]'::jsonb
                   WHEN 'relationship_asserted'      THEN '["label"]'::jsonb
                   WHEN 'relationship_folded'        THEN '["reason"]'::jsonb
                   WHEN 'relationship_corrected'     THEN '["scar"]'::jsonb
                   WHEN 'block_provenance_corrected' THEN '["scar","source.value"]'::jsonb
                   WHEN 'property_set'               THEN '["property_key","value"]'::jsonb
                   WHEN 'property_asserted'          THEN '["property_key","value"]'::jsonb
                   WHEN 'property_unset'             THEN '["property_key"]'::jsonb
                   WHEN 'block_provenance_annotated' THEN '["incorporated[*].source.value"]'::jsonb
                   WHEN 'resource_reblocked'         THEN '["created[*].attribution[*].source.value","kept[*].attribution[*].source.value"]'::jsonb
                   ELSE '[]'::jsonb
               END
             || (CASE WHEN EXISTS (
                       SELECT 1 FROM jsonb_object_keys(t.metadata) k
                        WHERE k = 'reasoning' OR k = 'rationale')
                      THEN '["metadata.reasoning","metadata.rationale"]'::jsonb
                      ELSE '[]'::jsonb END) AS paths
          FROM (
            SELECT s.event_id, s.event_type, ev.metadata
              FROM _resource_erasure_trail_scope(p_resource) s
              JOIN kb_events ev ON ev.id = s.event_id
          ) t
       ) s;

    RETURN jsonb_build_object(
        'resource',        p_resource,
        'n_blocks',        v_n_blocks,
        'n_revisions',     v_n_revisions,
        'n_chunks',        v_n_chunks,
        'n_artifacts',     v_n_artifacts,
        'n_edges',         v_n_edges,
        'edges',           v_edges,
        'targets',         '[]'::jsonb,
        'already_erased',  (SELECT r.erased_at IS NOT NULL FROM kb_resources r WHERE r.id = p_resource),
        'charter_of',      v_charter_of,
        'ingest_state',    v_ingest,
        'fingerprint_available',
            to_regproc('sensitivity.deriver_fingerprint_matches') IS NOT NULL,
        'remainder',       v_remainder,
        'ledger_remainder', v_ledger);
END;
$$;
-- ---------------------------------------------------------------------------
-- Section 2. The survey door's render: the plan + nothing else (the principal
-- survey's precedent — a refused survey records nothing; a survey attempt is
-- not an erasure request).
-- ---------------------------------------------------------------------------
CREATE FUNCTION resource_erasure_survey(p_resource uuid)
RETURNS jsonb LANGUAGE plpgsql AS $$
BEGIN
    RETURN resource_erasure_survey_plan(p_resource);
END;
$$;

COMMENT ON FUNCTION resource_erasure_survey(uuid) IS
'the survey door''s answer: the ONE plan, rendered. Read-only; appends nothing; a non-operator
at this door reaches nothing (the Rust gate answers the silent 404, and a survey attempt is not
an erasure request — the principal act''s 2026-09-12 ruling, carried).';

-- ---------------------------------------------------------------------------
-- Section 3. THE REFUSAL (D5): one `resource_erasure_refused` event, closed
-- reason vocabulary, nothing else mutated. Same NULL-anchored shape as the
-- completion; the request reference rides references + correlation exactly as
-- the principal act's refusal does. A repeat erasure is a recorded refusal, not
-- a silent no-op (ruled 2026-09-29): the attempt and its refusal are part of
-- the record.
-- ---------------------------------------------------------------------------
CREATE FUNCTION resource_erasure_refuse(
    p_resource     uuid,
    p_attempted_by uuid,
    p_emitter      uuid,
    p_request_ref  uuid,
    p_reason       text,
    p_detail       text DEFAULT NULL
) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE v_ev uuid;
BEGIN
    IF p_reason NOT IN ('unauthorized','charter_resource','ingest_in_flight','already_erased') THEN
        RAISE EXCEPTION 'resource_erasure_refuse: % is not a resource-erasure refusal reason',
                        p_reason;
    END IF;

    v_ev := _event_append(
        'resource_erasure_refused', p_emitter, NULL, NULL,
        jsonb_strip_nulls(jsonb_build_object(
            'subject_table', 'kb_resources',
            'subject_id',    p_resource,
            'actor',         p_attempted_by,
            'reason',        p_reason,
            'detail',        p_detail)),
        p_references => jsonb_build_array(
            jsonb_build_object('rel','subject',
                'target', jsonb_build_object('kind','kb_resources','id', p_resource)),
            jsonb_build_object('rel','request',
                'target', jsonb_build_object('kind','kb_events','id', p_request_ref))),
        p_correlation => p_request_ref);

    RETURN v_ev;
END;
$$;

COMMENT ON FUNCTION resource_erasure_refuse(uuid, uuid, uuid, uuid, text, text) IS
'the resource-erasure act''s negative face (spec D5; the closed refusal vocabulary ruled
2026-09-29): unauthorized | charter_resource | ingest_in_flight | already_erased — one recorded
event, nothing else mutated. A repeat erasure is a recorded refusal, not a silent no-op: nothing
in the projection changes and no second resource_erased is minted, but the attempt is part of the
record, the same as every other refusal.';

-- ---------------------------------------------------------------------------
-- Section 4. THE ACT (D1/D5): consumes the ONE plan, refuses or completes, all
-- one transaction. Emits ONE resource_erased admin event and ONE
-- relationship_folded per edge touching R (correlation = the request reference,
-- reason = 'resource_erased' — a fixed literal, never operator prose), strikes
-- only the operator-listed blobs through blob_delete('blob_erased', …) and the
-- byte-delete fence, then calls _resource_erasure_apply_redaction at the
-- completion event's position.
--
-- Legality does NOT live here: is_system_admin is the Rust caller's gate,
-- resolved before any mutation (the 20260720000030 rule); the SQL does not
-- decide it, and the refuse function is the recorded negative face.
--
-- The already-erased face is NOT an idempotent re-erase here: ruled
-- 2026-09-29, a repeat erasure is a recorded REFUSAL (already_erased) whose
-- effect is a no-op. The caller (resource_erasure_service) decides which face
-- it renders, but the RECORD is this function's job: SQL never appends the
-- refused event, so the gate decides refusal-or-execute BEFORE either door is
-- reached.
-- ---------------------------------------------------------------------------
CREATE FUNCTION resource_erasure_execute(
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

    -- ── THE REFUSAL VERDICTS, read PRE-act (D5). A refusal here RAISES — the Rust caller
    --    catches the typed message and records it through resource_erasure_refuse, so the SQL
    --    never silently widens the negative face to a partial act (and never appends a refusal
    --    event itself: _event_append's emitter is the OPERATOR and a refused attempt at SQL
    --    grain would attribute wrongly). The verdict reads happen before anything mutates. ──
    SELECT c.telos_resource_id INTO v_charter FROM kb_cogmaps c WHERE c.telos_resource_id = p_resource;
    SELECT r.ingest_state, r.erased_at IS NOT NULL
      INTO v_ingest, v_erased
      FROM kb_resources r WHERE r.id = p_resource;
    SELECT count(*) > 0 INTO v_found FROM kb_resources r WHERE r.id = p_resource AND r.is_active;

    IF v_charter IS NOT NULL THEN
        RAISE EXCEPTION 'resource_erasure_execute: charter resource (map-grain erasure is filed task 01a0e960-0ca2-7f42-b33e-1ed19b024e6b)';
    END IF;
    IF v_ingest <> 'complete' THEN
        RAISE EXCEPTION 'resource_erasure_execute: ingest % in flight; finalize or abandon first', v_ingest;
    END IF;
    IF v_erased THEN
        RAISE EXCEPTION 'resource_erasure_execute: already erased';
    END IF;
    IF NOT v_found THEN
        RAISE EXCEPTION 'resource_erasure_execute: resource % not found', p_resource;
    END IF;


    -- ── The ONE computation (D10). No re-enumeration of the remainder, block counts, artifact
    --    counts or edges happens below — the plan computed them once. The would_strike entries
    --    the principal plan's shape used do not exist here: the survey names related blobs via
    --    the remainder, and the operator's `also_strike_blobs` arrives AT THE ACT (D8), where
    --    the strike loop below consumes it. ──────────────────────────────────────────────────
    v_plan := resource_erasure_survey_plan(p_resource);
    v_targets := v_plan->'targets';

    -- ── The operator-listed blob strikes, through the wrapper, PER ROW (D8: a blob is struck
    --    ONLY when the operator listed it; the act never infers a strike from a relation). Each
    --    strike carries the wrapper's verdict at ITS OWN moment — the byte-delete fence runs
    --    inside — and its prose template is the ONE the fence parses by exact prefix. The plan's
    --    would_strike rows are the scope; the plan itself predicts nothing here, because the
    --    operator's list arrives at the act, not at the survey (the survey names related blobs;
    --    the operator answers with the subset to strike).
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

    -- ── Per-edge folds: ONE relationship_folded per edge touching R (D1 — the incumbent verb,
    --    its OWN trail shows who ended it and why, another principal's view reads as
    --    deliberately ended; replay folds through the existing projector). reason is a FIXED
    --    literal 'resource_erased', never operator prose. Each event carries the act's
    --    correlation id (the request reference), so the act's pairing is a fact, not a
    --    convention. Edges are folded FIRST (the projected is_folded) so the plan's edge arm and
    --    the fold events agree in the same transaction.
    v_edges := v_plan->'edges';
    FOR v_i IN 0 .. jsonb_array_length(v_edges) - 1 LOOP
        v_eid := (v_edges->v_i->>'edge_id')::uuid;
        SELECT id INTO v_id FROM kb_edges WHERE id = v_eid AND NOT is_folded;
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
remainder, ledger_remainder, folded_edges read straight off the plan), then calls
_resource_erasure_apply_redaction — all one transaction. Refusals RAISE here and the Rust caller
records them through resource_erasure_refuse BEFORE reaching this function; legality is the Rust
caller''s is_system_admin gate, never SQL''s. No hash enters kb_erased_content.';

SELECT declare_migration(
    20260929040730,
    'additive',
    'The resource-erasure act (spec 2026-09-28, build order 2b, task 01a0e9e7-491d): the ONE
row-anchored redaction body (_resource_erasure_apply_redaction — chunk prose + header_path, block
revision bytes, embeddings+embedded_with, search vector, data artifact content emptied to
''{}''::jsonb for EVERY artifact of the resource, projected citation-audit reasons, formation
watermark nulls, workflow-job scoping, and the projection-side sentinels: husk title/origin_uri
''erased-<id>''/''erased:<id>'', property keys erased-key-<n> by ledger order of first appearance,
property values erased::jsonb, edge labels NULL, remote-source re-pointing to the sentinel
rows replay mints — ROW-ANCHORED on resource id, never a content hash; another resource''s
byte-identical content is never reached, and NO hash enters kb_erased_content) and the ONE
trail-scope predicate (_resource_erasure_trail_scope — the element-trail read''s predicate plus the
edge-owned-properties arm), so the survey, the act and cut 2''s completion pass share one
derivation; resource_erasure_survey_plan computes scope, refusals, remainder and ledger_remainder
once per act and the survey door renders it; resource_erasure_execute consumes the plan — folds
every edge through its own relationship_folded (fixed reason ''resource_erased'', the act''s
correlation id), strikes only operator-listed blobs through blob_delete(''blob_erased'', …), appends
the ONE NULL-anchored resource_erased event (references carry the subject + request reference;
redacted_fields is EMPTY in cut 1, every unreached ledger path lives in ledger_remainder by (event,
path) in the RedactedEventFields shape), then calls the ONE redaction body at the event''s ledger
position; resource_erasure_refuse records the closed refusal vocabulary (unauthorized |
charter_resource | ingest_in_flight | already_erased) — a repeat erasure is a recorded refusal, not
a silent no-op (ruled 2026-09-29). CUT 1 DOES NOT TOUCH THE LEDGER (D12): the append-only trigger
is unamended; replay stays byte-identical through the projection-side sentinels applied at the
event''s position. Additive: new functions only.'
);
