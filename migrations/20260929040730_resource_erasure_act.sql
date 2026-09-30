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
--     scope parameter, `p_blocks uuid[] DEFAULT NULL`: NULL names the whole resource; a block-id
--     array narrows to that block set with keep-current. Cut 1 (this migration) only accepts NULL
--     and RAISES on a non-NULL array; the block history scrub (build order 2e,
--     `block_history_scrubbed`) narrows THIS definition rather than forking it. A second body of erasure is two definitions that drift.
--   * THE ACT AND THE SURVEY SHARE ONE COMPUTATION (D10, the 20260913000010 precedent): the plan is
--     the act's scope machinery moved whole out of the act, so the act consumes it and nothing
--     re-enumerates. A preview that can disagree with the act is worse than no preview.
--   * CUT 1 DOES NOT TOUCH THE LEDGER (D12). No event payload is rewritten; the append-only trigger
--     is unamended; kb_event_field_redactions does not exist yet. Every free-text path the act does
--     NOT reach is computed into `ledger_remainder` by (event, path) — D12's shape, exactly what
--     cut 2's completion pass reads. Replay stays byte-identical because step 9 applies the
--     PROJECTION-side sentinels at the event's ledger position.
--   * REFUSALS ARE RECORDED (ruled 2026-09-29): `resource_erasure_refused` is appended for a
--     non-operator, a charter resource — and for already-erased (the attempt and its refusal are
--     part of the record; the effect is a no-op — nothing in the projection changes, no second
--     `resource_erased` is minted). Ingest state is NOT a refusal (D5): an in-flight ingest ends
--     with the erasure, and the record's `targets` names it.
--   * `targets` ATTESTS WHAT THE ACT DID (D8): one {target, outcome} per reached target, counts
--     and verbs only, never content; the plan counts them pre-act, execute carries them.
--
--   * THE ACT IS SERIALIZED AGAINST EVERY WRITER (D13): the act takes FOR UPDATE on R's row before
--     the plan; every content-bearing write re-checks `erased_at` under FOR KEY SHARE inside its own
--     transaction (Section W). A racing write lands before the act and is erased, or refuses after.
--
-- Additive: no existing column or constraint is altered. Section W re-creates seven incumbent
-- functions, each verbatim plus guard calls that raise only for an erased resource — a state an
-- old binary cannot produce — so an old binary reads and writes every pre-existing row unchanged.

-- ---------------------------------------------------------------------------
-- Section W. THE WRITE GUARD (D13): a write that races the act either lands
-- before it, and is erased, or refuses after it; none lands on the husk.
--
-- The act takes FOR UPDATE on R's kb_resources row before it computes the plan
-- (Section 4). Every content-bearing write calls `_resource_write_guard` inside
-- its own transaction: FOR KEY SHARE on the same row, then a RAISE when
-- `erased_at IS NOT NULL`. FOR KEY SHARE conflicts only with FOR UPDATE, so
-- writers never block one another on it; a writer that already holds the row
-- makes the act wait for its commit, and a writer that arrives while the act
-- holds the row waits, then re-reads the committed row and refuses.
--
-- The guard reads `erased_at`, never `is_active`: replaying a historical ledger
-- walks old writes to soft-deleted resources, and those must still project.
-- It guards a state floor, not an authorization decision.
--
-- The incumbents re-created below are each their live definition verbatim
-- plus the guard call (two for relationship assert, one per endpoint) as the
-- body's first statement — nothing else changes:
--   * `_recompute_resource_body_hash` — the tail of block mutate, segment
--     append, finalize and reblock (`_project_block_mutated`, `_project_blocks`,
--     `_project_resource_reblocked` all call it);
--   * the non-content projectors: property set and assert (by owner),
--     relationship assert (both endpoints), block provenance annotate (by
--     block), `resource_updated`, data-artifact commit.
-- `_project_relationship_folded` and `_project_resource_deleted` are NOT
-- guarded: a fold or a tombstone writes no content, and the act itself folds.
-- The Rust projectors `project_property_unset` / `project_property_retracted`
-- (events.rs) and the embed drain's write-backs (embed.rs) carry the same
-- guard on their side.
-- ---------------------------------------------------------------------------
CREATE FUNCTION _resource_write_guard(p_resource uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_erased timestamptz;
BEGIN
    -- One statement, so a wait on the act's FOR UPDATE re-reads the row version the act
    -- committed (READ COMMITTED re-check) and sees its erased_at. No row → nothing to guard;
    -- the caller's own write reports a missing resource on its own terms.
    SELECT r.erased_at INTO v_erased FROM kb_resources r WHERE r.id = p_resource FOR KEY SHARE;
    IF v_erased IS NOT NULL THEN
        RAISE EXCEPTION 'resource % is erased; writes are refused', p_resource;
    END IF;
END;
$$;

COMMENT ON FUNCTION _resource_write_guard(uuid) IS
'the write guard (spec 2026-09-28 D13): FOR KEY SHARE on the kb_resources row, then RAISE
''resource % is erased; writes are refused'' when erased_at IS NOT NULL. Conflicts only with the
erasure act''s FOR UPDATE. Reads erased_at, never is_active, so replay of historical writes to a
soft-deleted resource never trips it.';

CREATE FUNCTION _resource_write_guard_owner(p_table text, p_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_resource uuid;
BEGIN
    -- The owner tables kb_properties admits (kb_properties_owner_table_check) and the edge
    -- endpoint tables (kb_edges_{source,target}_table_check). kb_cogmaps and kb_blobs write
    -- into no resource, so they fall through unguarded.
    IF p_table = 'kb_resources' THEN
        PERFORM _resource_write_guard(p_id);
    ELSIF p_table = 'kb_edges' THEN
        FOR v_resource IN
            SELECT e.source_id FROM kb_edges e
             WHERE e.id = p_id AND e.source_table = 'kb_resources'
            UNION
            SELECT e.target_id FROM kb_edges e
             WHERE e.id = p_id AND e.target_table = 'kb_resources'
            ORDER BY 1
        LOOP
            PERFORM _resource_write_guard(v_resource);
        END LOOP;
    ELSIF p_table = 'kb_content_blocks' THEN
        PERFORM _resource_write_guard(
            (SELECT b.resource_id FROM kb_content_blocks b WHERE b.id = p_id));
    END IF;
END;
$$;

COMMENT ON FUNCTION _resource_write_guard_owner(text, uuid) IS
'the write guard by owner (spec 2026-09-28 D13): resolves an owner to the resource or resources it
writes into and guards each — kb_resources itself; kb_edges each endpoint whose table is
kb_resources; kb_content_blocks the block''s resource_id; kb_cogmaps (and a kb_blobs endpoint)
nothing.';

-- _recompute_resource_body_hash: its live definition (last defined by 20260712000110), verbatim, plus the guard.
CREATE OR REPLACE FUNCTION public._recompute_resource_body_hash(p_resource uuid, p_occurred timestamp with time zone)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
DECLARE v_resource_hashes text;
BEGIN
    PERFORM _resource_write_guard(p_resource);
    -- Serialize the recompute tail: wait out any concurrent same-resource append still in flight, so
    -- the aggregate SELECT below (a fresh READ COMMITTED snapshot) sees the settled, committed block set.
    -- FOR NO KEY UPDATE (not FOR UPDATE) so it does not conflict with the FK-induced KEY SHARE locks the
    -- concurrent append already holds — see the header note; FOR UPDATE deadlocks here.
    PERFORM 1 FROM kb_resources WHERE id = p_resource FOR NO KEY UPDATE;
    SELECT string_agg(bh, '' ORDER BY seq) INTO v_resource_hashes FROM (
        SELECT b.seq,
               encode(sha256(convert_to(string_agg(ch.content_hash, '' ORDER BY ch.chunk_index), 'UTF8')),
                      'hex') AS bh
        FROM kb_content_blocks b
        JOIN kb_chunks ch ON ch.block_id = b.id AND ch.is_current
        WHERE b.resource_id = p_resource AND NOT b.is_folded
        GROUP BY b.seq
    ) per_block;
    UPDATE kb_resources
        SET body_hash = encode(sha256(convert_to(coalesce(v_resource_hashes, ''), 'UTF8')), 'hex'),
            updated = p_occurred
        WHERE id = p_resource;
END;
$function$;

-- _project_property_set: its live definition (last defined by 20260815000030), verbatim, plus the guard.
CREATE OR REPLACE FUNCTION public._project_property_set(p_event uuid, p_payload jsonb)
 RETURNS uuid[]
 LANGUAGE plpgsql
AS $function$
DECLARE v_prop uuid := (p_payload->>'property_id')::uuid;
        v_occurred timestamptz := (SELECT occurred_at FROM kb_events WHERE id = p_event);
        v_owner_tbl text := p_payload#>>'{owner,table}';
        v_owner uuid := (p_payload#>>'{owner,id}')::uuid;
        v_key text := p_payload->>'property_key';
        v_value jsonb := _property_value_normalized(p_payload->>'property_key',
                                                    p_payload->'value');
        v_weight double precision := (p_payload->>'weight')::double precision;
        v_ids uuid[] := '{}';
        v_mark record;
        v_id uuid;
BEGIN
    PERFORM _resource_write_guard_owner(p_payload#>>'{owner,table}', (p_payload#>>'{owner,id}')::uuid);
    -- Replace semantics, unchanged for every key: fold the whole live set for this key first.
    UPDATE kb_properties SET is_folded = true, last_event_id = p_event
        WHERE owner_table = v_owner_tbl AND owner_id = v_owner
          AND property_key = v_key AND NOT is_folded;

    IF v_key = 'facet' THEN
        FOR v_mark IN SELECT * FROM _facet_marks(v_value) LOOP
            v_id := uuid_generate_v7();
            INSERT INTO kb_properties (id, owner_table, owner_id, property_key, property_value,
                                       weight, asserted_by_event_id, last_event_id, created)
            VALUES (v_id, v_owner_tbl, v_owner, 'facet',
                    CASE WHEN v_mark.inner_key IS NULL
                         THEN v_mark.inner_value
                         ELSE jsonb_build_object(v_mark.inner_key, v_mark.inner_value) END,
                    v_weight, p_event, p_event, v_occurred);
            v_ids := v_ids || v_id;
        END LOOP;
    ELSE
        INSERT INTO kb_properties (id, owner_table, owner_id, property_key, property_value, weight,
                                   asserted_by_event_id, last_event_id, created)
        VALUES (v_prop, v_owner_tbl, v_owner, v_key, v_value, v_weight,
                p_event, p_event, v_occurred);
        v_ids := ARRAY[v_prop];
    END IF;

    -- Carried verbatim from 20260711000060: the FTS vector is gated on the indexed open_meta keys.
    IF v_owner_tbl = 'kb_resources' AND v_key IN ('keywords', 'descriptor', 'tags') THEN
        PERFORM _rebuild_resource_search_vector(v_owner);
    END IF;
    RETURN v_ids;
END;
$function$;

-- _project_property_asserted: its live definition (last defined by 20260815000030), verbatim, plus the guard.
CREATE OR REPLACE FUNCTION public._project_property_asserted(p_event uuid, p_payload jsonb)
 RETURNS uuid[]
 LANGUAGE plpgsql
AS $function$
DECLARE v_prop uuid := (p_payload->>'property_id')::uuid;
        v_occurred timestamptz := (SELECT occurred_at FROM kb_events WHERE id = p_event);
        v_owner_tbl text := p_payload#>>'{owner,table}';
        v_owner uuid := (p_payload#>>'{owner,id}')::uuid;
        v_key text := p_payload->>'property_key';
        v_value jsonb := _property_value_normalized(p_payload->>'property_key',
                                                    p_payload->'value');
        v_weight double precision := (p_payload->>'weight')::double precision;
        v_ids uuid[] := '{}';
        v_mark record;
        v_id uuid;
BEGIN
    PERFORM _resource_write_guard_owner(p_payload#>>'{owner,table}', (p_payload#>>'{owner,id}')::uuid);
    IF v_key <> 'facet' THEN
        INSERT INTO kb_properties (id, owner_table, owner_id, property_key, property_value, weight,
                                   asserted_by_event_id, last_event_id, created)
        VALUES (v_prop, v_owner_tbl, v_owner, v_key, v_value, v_weight,
                p_event, p_event, v_occurred);
        RETURN ARRAY[v_prop];
    END IF;

    FOR v_mark IN SELECT * FROM _facet_marks(v_value) LOOP
        -- A mark is stored as a ONE-KEY OBJECT — {"status": "open"} — never an envelope around the
        -- key and value: `expand_facets` explodes `property_value`'s top-level keys straight into
        -- `Facet { path, value }`, so a wrapper would surface its own field names as facet paths.
        --
        -- Fold the prior live mark for THIS inner key only — never a sibling.
        IF v_mark.inner_key IS NULL THEN
            UPDATE kb_properties
               SET is_folded = true, last_event_id = p_event
             WHERE owner_table = v_owner_tbl AND owner_id = v_owner
               AND property_key = 'facet' AND NOT is_folded
               AND jsonb_typeof(property_value) <> 'object';
        ELSE
            UPDATE kb_properties
               SET is_folded = true, last_event_id = p_event
             WHERE owner_table = v_owner_tbl AND owner_id = v_owner
               AND property_key = 'facet' AND NOT is_folded
               AND jsonb_typeof(property_value) = 'object'
               AND jsonb_exists(property_value, v_mark.inner_key);
        END IF;

        v_id := uuid_generate_v7();
        INSERT INTO kb_properties (id, owner_table, owner_id, property_key, property_value, weight,
                                   asserted_by_event_id, last_event_id, created)
        VALUES (v_id, v_owner_tbl, v_owner, 'facet',
                CASE WHEN v_mark.inner_key IS NULL
                     THEN v_mark.inner_value
                     ELSE jsonb_build_object(v_mark.inner_key, v_mark.inner_value) END,
                v_weight, p_event, p_event, v_occurred);
        v_ids := v_ids || v_id;
    END LOOP;

    RETURN v_ids;
END;
$function$;

-- _project_relationship_asserted: its live definition (last defined by 20260624000002), verbatim, plus the guard.
CREATE OR REPLACE FUNCTION public._project_relationship_asserted(p_event uuid, p_payload jsonb)
 RETURNS uuid
 LANGUAGE plpgsql
AS $function$
DECLARE v_edge uuid := (p_payload->>'edge_id')::uuid;
        v_occurred timestamptz := (SELECT occurred_at FROM kb_events WHERE id = p_event);
BEGIN
    PERFORM _resource_write_guard_owner(p_payload#>>'{source,table}', (p_payload#>>'{source,id}')::uuid);
    PERFORM _resource_write_guard_owner(p_payload#>>'{target,table}', (p_payload#>>'{target,id}')::uuid);
    INSERT INTO kb_edges (id, source_table, source_id, target_table, target_id,
                          edge_kind, polarity, label, weight,
                          home_anchor_table, home_anchor_id,
                          asserted_by_event_id, last_event_id, created)
    VALUES (v_edge,
            p_payload#>>'{source,table}', (p_payload#>>'{source,id}')::uuid,
            p_payload#>>'{target,table}', (p_payload#>>'{target,id}')::uuid,
            (p_payload->>'edge_kind')::edge_kind,
            COALESCE(p_payload->>'polarity', 'forward')::edge_polarity,
            p_payload->>'label',
            (p_payload->>'weight')::double precision,
            p_payload#>>'{home,table}', (p_payload#>>'{home,id}')::uuid,
            p_event, p_event, v_occurred)
    -- Idempotent on the active-edge invariant (uq_kb_edges_assertion): re-asserting the same active
    -- relationship updates the existing edge's weight (+ last_event_id) and returns ITS id rather than
    -- creating a duplicate active edge. asserted_by_event_id is left on the original assertion. The
    -- ON CONFLICT inference clause mirrors uq_kb_edges_assertion's columns + partial predicate exactly.
    ON CONFLICT (source_table, source_id, target_table, target_id, edge_kind, COALESCE(label, ''),
                 home_anchor_table, home_anchor_id) WHERE NOT is_folded
        DO UPDATE SET weight = EXCLUDED.weight, last_event_id = EXCLUDED.last_event_id
    RETURNING id INTO v_edge;
    RETURN v_edge;
END;
$function$;

-- _project_block_annotated: its live definition (last defined by 20260710000001), verbatim, plus the guard.
CREATE OR REPLACE FUNCTION public._project_block_annotated(p_event uuid, p_payload jsonb)
 RETURNS uuid
 LANGUAGE plpgsql
AS $function$
DECLARE v_block uuid := (p_payload->>'block_id')::uuid;
BEGIN
    PERFORM _resource_write_guard_owner('kb_content_blocks', v_block);
    IF NOT EXISTS (SELECT 1 FROM kb_content_blocks WHERE id = v_block) THEN
        RAISE EXCEPTION '_project_block_annotated: block % not found', v_block;
    END IF;
    PERFORM _insert_block_provenance(v_block, p_event, p_payload->'incorporated');
    RETURN v_block;
END;
$function$;

-- _project_resource_updated: its live definition (last defined by 20260626000001), verbatim, plus the guard.
CREATE OR REPLACE FUNCTION public._project_resource_updated(p_event uuid, p_payload jsonb)
 RETURNS uuid
 LANGUAGE plpgsql
AS $function$
DECLARE v_resource uuid := (p_payload->>'resource_id')::uuid;
BEGIN
    PERFORM _resource_write_guard(v_resource);
    UPDATE kb_resources SET
        title      = COALESCE(p_payload->>'title', title),
        origin_uri = COALESCE(p_payload->>'origin_uri', origin_uri),
        updated    = (SELECT occurred_at FROM kb_events WHERE id = p_event)
        WHERE id = v_resource;
    IF NOT FOUND THEN RAISE EXCEPTION 'resource_update: resource % not found', v_resource; END IF;
    IF p_payload ? 'title' THEN                            -- ← Beat 1 (origin_uri is not in the FTS vector)
        PERFORM _rebuild_resource_search_vector(v_resource);
    END IF;
    RETURN v_resource;
END;
$function$;

-- _project_data_artifact_committed: its live definition (last defined by 20260820000020), verbatim, plus the guard.
CREATE OR REPLACE FUNCTION public._project_data_artifact_committed(p_event uuid, p_payload jsonb, p_content jsonb)
 RETURNS uuid[]
 LANGUAGE plpgsql
AS $function$
DECLARE v_id       uuid := (p_payload->>'artifact_id')::uuid;
        v_occurred timestamptz := (SELECT occurred_at FROM kb_events WHERE id = p_event);
        v_resource uuid := (p_payload->>'resource_id')::uuid;
        v_kind     text := p_payload->>'artifact_kind';
        v_kind_tbl text := p_payload->>'kind_owner_table';
        v_kind_own uuid := (p_payload->>'kind_owner_id')::uuid;
        v_intent   text := p_payload->>'intent';
        v_prec     double precision := COALESCE((p_payload->>'precedence')::double precision, 0.0);
        v_hash     text := p_payload->>'content_hash';
        v_bytes    bigint := (p_payload->>'content_bytes')::bigint;

        v_supersedes uuid[] := COALESCE(
            (SELECT array_agg(x::uuid) FROM jsonb_array_elements_text(
                 COALESCE(p_payload->'supersedes', '[]'::jsonb)) x), '{}');
BEGIN
    PERFORM _resource_write_guard(v_resource);
    -- Fold ONLY what the writer explicitly named. There is no "fold everything live of this kind"
    -- sweep here, and that absence is the whole point: see the A2 comment. An empty `supersedes`
    -- means this artifact replaces nothing, which is the common case for `member`.
    IF array_length(v_supersedes, 1) IS NOT NULL THEN
        UPDATE kb_data_artifacts SET is_folded = true, last_event_id = p_event
         WHERE id = ANY(v_supersedes)
           AND resource_id = v_resource      -- a writer may only fold artifacts of the resource it
           AND NOT is_folded;                -- is writing to; cross-resource folds are not a thing
    END IF;

    INSERT INTO kb_data_artifacts (id, resource_id, kind_owner_table, kind_owner_id, artifact_kind,
                                   intent, precedence, content_hash, content_bytes,
                                   asserted_by_event_id, last_event_id, created)
    VALUES (v_id, v_resource, v_kind_tbl, v_kind_own, v_kind, v_intent, v_prec, v_hash, v_bytes,
            p_event, p_event, v_occurred);

    -- The bytes arrive as a SEPARATE ARGUMENT, never inside p_payload — the same split
    -- resource_create/_project_resource_created uses. This is what makes "the payload carries the
    -- hash, never the body" true of the stored event rather than merely of the design doc: whatever
    -- is in p_payload is what _event_append wrote to kb_events.
    IF p_content IS NOT NULL AND jsonb_typeof(p_content) <> 'null' THEN
        INSERT INTO kb_data_artifact_content (artifact_id, content, content_hash)
        VALUES (v_id, p_content, v_hash);
    END IF;

    RETURN ARRAY[v_id];
END;
$function$;

-- ---------------------------------------------------------------------------
-- Section 0. The one redaction body (D2), given a scope. Event-free by design:
-- the replay arm runs this beside the walk; only `resource_erasure_execute`
-- appends events around it.
--
-- The scope is the third parameter, `p_blocks uuid[] DEFAULT NULL`: NULL = the
-- whole resource (cut 1's only form today); a non-NULL array is REFUSED — the
-- narrowed form is the block history scrub's, 2e, and half-building it here
-- would be a scope that lies about its completeness. There is exactly one
-- function: an overload beside a DEFAULTed parameter would make every
-- two-argument call ambiguous. p_resource keys every join; p_event supplies
-- occurred_at for the replay-stable stamps.
-- ---------------------------------------------------------------------------
CREATE FUNCTION _resource_erasure_apply_redaction(p_resource uuid, p_event uuid, p_blocks uuid[] DEFAULT NULL)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_occurred      timestamptz := (SELECT occurred_at FROM kb_events WHERE id = p_event);
    v_orig_blocks   uuid[];
    v_orig_sources  uuid[];
    v_orig_ns       integer[];
    v_i             integer;
    v_sentinel      uuid;
    v_source        uuid;
    v_parked        jsonb;
BEGIN
    IF p_blocks IS NOT NULL THEN
        RAISE EXCEPTION '_resource_erasure_apply_redaction: a block-set scope lands with build order 2e (block history scrub); cut 1 accepts only the whole resource (p_blocks NULL)';
    END IF;

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

    -- ── (8) Workflow jobs scoped to the resource (D2 step 7). Every row, in EVERY status, loses
    --     its payload and last_error: the excerpt is the carrier, not the job's state, so a
    --     `done` or `dead` row keeps its status but not its excerpts. Rows not yet finished
    --     (`pending`, `waiting_for_retry`, `in_progress`) are also cancelled to `dead`;
    --     `in_progress` is reached deliberately: a leased job would otherwise run on against the
    --     husk until lease expiry. Not replay inputs; excerpt carriers on the personal-data
    --     surface. ────────────────────────────────────────────────────────────────────────────
    UPDATE kb_workflow_jobs j
       SET payload    = '{}'::jsonb,
           last_error = NULL
     WHERE j.resource_id = p_resource
       AND (j.payload <> '{}'::jsonb OR j.last_error IS NOT NULL);

    UPDATE kb_workflow_jobs j
       SET status = 'dead'
     WHERE j.resource_id = p_resource
       AND j.status IN ('pending', 'waiting_for_retry', 'in_progress');

    -- ── (8a) The ingestion record and the artifact verdicts (D2 step 7a), both reachable by
    --     foreign key from the resource. `kb_ingestion_records.source_uri` takes the origin_uri
    --     class sentinel 'erased:<resource_id>' (the column is NOT NULL, and it carries the same
    --     shape of text origin_uri does); `source_hash` is kept, like every hash. A verdict's
    --     `detail` carries validator messages that quote instance values and keys, so it is
    --     nulled on every verdict of every artifact of the resource. ─────────────────────────
    UPDATE kb_ingestion_records ir
       SET source_uri = 'erased:' || p_resource::text
     WHERE ir.resource_id = p_resource
       AND ir.source_uri <> 'erased:' || p_resource::text;

    UPDATE kb_data_artifact_verdicts v
       SET detail = NULL
     WHERE v.artifact_id IN (
           SELECT da.id FROM kb_data_artifacts da WHERE da.resource_id = p_resource)
       AND v.detail IS NOT NULL;

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
    --      a pure function of (owner, key) under the total order of each key's first-asserting
    --      event: its occurred_at, then its id — keys asserted in one transaction share
    --      occurred_at and the event id decides; the key text never does). The numbering is
    --      _resource_erasure_key_numbers (Section 0d), the ONE definition this step and step
    --      (9d) share. EVERY family row — live and folded — is folded by this pass: the husk
    --      keeps NO metadata (Q3), and folding avoids a UNIQUE-index collision the sentinel
    --      values would otherwise raise — uq_kb_properties_active is partial on NOT is_folded
    --      over (owner, key, value); two live rows of ONE key in the facet shape (several live
    --      rows per key is what facet_set IS) would both map to (erased-key-n, "erased") and
    --      violate it. Folding is also what replay reproduces: the act's later, folded rows came
    --      from events that are themselves behind the erasure event in ledger order, so the
    --      arm at the event's position sees the same family state the live act sees.
    --
    --      A key set → unset → re-set maps to one n: the numbering is per original key over the
    --      whole family, live and folded rows alike. last_event_id points at the erasure event
    --      (the property fold rides the act — the trail records which event retired the
    --      property, the 20260727000030 shape).
    WITH ranked AS (
        SELECT k.property_key, k.n
          FROM _resource_erasure_key_numbers('kb_resources', p_resource) k
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
    --      Goal §8: an edge touching R is R's surface whoever authored it — its structure and its
    --      fold event stay, all of its content goes.
    UPDATE kb_edges e
       SET label = NULL
     WHERE (e.source_table = 'kb_resources' AND e.source_id = p_resource)
        OR (e.target_table = 'kb_resources' AND e.target_id = p_resource);

    -- (9d) Edge-owned properties: keys AND values sentineled, the (9b) pass applied per edge
    --      (D2 step 9; D4 "numbered per edge … whoever authored them", goal §8). Every edge with R
    --      at either end — live or already folded — and every kb_edges-owned row of it, whoever
    --      asserted it: keys map erased-key-<n> numbered WITHIN EACH EDGE by the same
    --      ledger-identity order (_resource_erasure_key_numbers), values '"erased"'::jsonb, every
    --      row folded (the same uq_kb_properties_active collision reason as (9b)), last_event_id
    --      the erasure event. It runs after the act's relationship_folded events, whose projector
    --      has already folded the live edges' rows; the fold only folds, so the key and value
    --      text are this pass's to replace.
    UPDATE kb_properties p
       SET property_key   = 'erased-key-' || k.n::text,
           property_value = '"erased"'::jsonb,
           is_folded      = true,
           last_event_id  = COALESCE(p_event, p.last_event_id)
      FROM kb_edges e
     CROSS JOIN LATERAL _resource_erasure_key_numbers('kb_edges', e.id) k
     WHERE ((e.source_table = 'kb_resources' AND e.source_id = p_resource)
         OR (e.target_table = 'kb_resources' AND e.target_id = p_resource))
       AND p.owner_table = 'kb_edges' AND p.owner_id = e.id
       AND p.property_key = k.property_key;

    -- (9e) The remote-source re-pointing (D4). Every remote provenance row of R's blocks
    --      re-points to the sentinel row replay's redacted incorporated[*].source.value upserts:
    --      'erased:<block_id>:<n>', where n numbers the distinct original remote sources on
    --      that block in ledger order of first appearance. The key is unique per (block,
    --      original source), so two sources cited in one event at one accretion seq never share
    --      a sentinel and the provenance unique key (block_id, source_kind, source_id,
    --      contributed_by_event_id) cannot collide. It carries nothing of the URL.
    --
    --      Capture: R's original remote sources, numbered, read ONCE through
    --      _resource_erasure_remote_originals (Section 0c, the same capture the survey reads)
    --      before anything below changes a provenance row. The captured ids are the whole of
    --      what the delete at the end may consider.
    SELECT coalesce(array_agg(o.block_id  ORDER BY o.block_id, o.n), '{}'),
           coalesce(array_agg(o.source_id ORDER BY o.block_id, o.n), '{}'),
           coalesce(array_agg(o.n         ORDER BY o.block_id, o.n), '{}')
      INTO v_orig_blocks, v_orig_sources, v_orig_ns
      FROM _resource_erasure_remote_originals(p_resource) o;

    --      Upsert, then re-point BY THE ID the upsert returns. _upsert_remote_source deduplicates
    --      on uri_normalized and keeps the first writer's spelling, so the row it returns may be
    --      a look-alike someone minted first (' erased:<block>:1', leading space); matching on
    --      `uri` text would miss it and leave the provenance on the original URL.
    --
    --      The re-point runs in two passes, park then place. The returned sentinel row can
    --      itself be one of the block's originals: a block that cites the literal
    --      'erased:<block>:1' beside a URL numbered 1 gets that literal's row back as the URL's
    --      sentinel, while the literal, numbered 2, moves on to 'erased:<block>:2'. Moving the
    --      URL's row first would duplicate the literal's row on the provenance unique key
    --      (block_id, source_kind, source_id, contributed_by_event_id) before the literal's row
    --      moves away, and a non-deferrable unique check raises on that intermediate state. So
    --      the park pass sets each captured row's source_id to the row's own id, which no other
    --      row holds, and records row id → sentinel id. The place pass then sets every parked row
    --      to its sentinel in one statement. The final state cannot collide: each original on a
    --      block has its own n, distinct n give distinct uri_normalized and so distinct sentinel
    --      rows, and an event contributes at most one row per original per block. It is the
    --      state replay of the redacted payloads lands on, one row per original per event,
    --      each on its own sentinel.
    v_parked := '{}'::jsonb;
    FOR v_i IN 1 .. coalesce(array_length(v_orig_blocks, 1), 0) LOOP
        v_sentinel := _upsert_remote_source(
            'erased:' || v_orig_blocks[v_i]::text || ':' || v_orig_ns[v_i]::text);
        WITH parked AS (
            UPDATE kb_block_provenance bp
               SET source_id = bp.id
             WHERE bp.block_id = v_orig_blocks[v_i]
               AND bp.source_kind = 'remote'
               AND bp.source_id = v_orig_sources[v_i]
            RETURNING bp.id)
        SELECT v_parked || coalesce(jsonb_object_agg(parked.id::text, v_sentinel), '{}'::jsonb)
          INTO v_parked
          FROM parked;
    END LOOP;

    UPDATE kb_block_provenance bp
       SET source_id = (v_parked ->> bp.id::text)::uuid
     WHERE bp.block_id = ANY(v_orig_blocks)
       AND v_parked ? bp.id::text;

    --      Delete, scoped and locked. A captured original that nothing cites any more is deleted:
    --      replay of the redacted payloads never mints it. One that another resource's block
    --      still cites stays, and the survey names it by id (D8). Only the captured originals
    --      are considered — the act never deletes a remote source it did not orphan. Each one
    --      is locked FOR UPDATE in its own
    --      statement, and "does anything still cite it?" is asked in a SEPARATE, later
    --      statement. Under READ COMMITTED each statement of this VOLATILE function reads a
    --      fresh snapshot, and a concurrent citer's _upsert_remote_source holds this row's lock
    --      (ON CONFLICT DO UPDATE) until it commits. So the lock waits for that citer, and the
    --      existence check that follows sees its committed provenance row and keeps the source.
    --      A single `DELETE … WHERE NOT EXISTS (…)` evaluates its subquery against the
    --      statement's own snapshot, taken before the lock wait, and would delete a row a
    --      citer committed during that wait. A citer that arrives after the lock waits on it;
    --      if the row is deleted, its upsert re-inserts the URL as a fresh row. Ids are locked
    --      in uuid order, so two acts whose resources share originals take those locks in one
    --      order and cannot deadlock on them.
    FOR v_source IN
        SELECT DISTINCT s.id FROM unnest(v_orig_sources) AS s(id) ORDER BY s.id
    LOOP
        PERFORM 1 FROM kb_remote_sources r WHERE r.id = v_source FOR UPDATE;
        IF NOT EXISTS (SELECT 1 FROM kb_block_provenance q
                        WHERE q.source_kind = 'remote' AND q.source_id = v_source) THEN
            DELETE FROM kb_remote_sources r WHERE r.id = v_source;
        END IF;
    END LOOP;

    RETURN;
END;
$$;

COMMENT ON FUNCTION _resource_erasure_apply_redaction(uuid, uuid, uuid[]) IS
'THE ONE row-anchored redaction body for resource erasure (spec 2026-09-28 D2, D4): chunk prose,
header_path, block revision bytes, embeddings+embedded_with, search vector, data artifact content
({}::jsonb, EVERY artifact of the resource whatever its kind owner, intent or supersession — ruled
2026-09-28), citation-audit projected reasons, formation watermark nulls, workflow-job payloads and
last_errors in every status (unfinished rows cancelled to dead), the ingestion record''s source_uri
(erased:<id>, hash kept) and artifact verdict details (NULL), and
the projection-side sentinels (husk title/origin_uri, property keys erased-key-<n> by ledger order
of first appearance — the resource''s, and each touching edge''s numbered per edge whoever authored
them — values ''erased''::jsonb, edge labels NULL, remote-source re-pointing to the
sentinel rows replay mints). ROW-ANCHORED: every join is on resource id, never a content hash —
another resource''s byte-identical content is NEVER reached (the custody-never-bytes ruling), and
no hash enters kb_erased_content from this body. Cut 1 (2026-09-29): scope is p_blocks, and only NULL (the whole resource) is accepted — a
non-NULL array raises; the block-set form with keep-current is the block history scrub''s (2e) and narrows THIS body, never
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
-- Section 0c. R's original remote sources, numbered (D4): one row per (block,
-- original remote source) R's blocks cite, with the sentinel number n and
-- whether another resource's block also cites that source. The redaction
-- body's step (9e) re-points and deletes from it; the survey plan names the
-- shared ones and counts from it. n is computed here and nowhere else.
--
-- n numbers a block's distinct original sources in ledger order of first
-- appearance: the first contributing event's (occurred_at, id), then the
-- element's seq (kb_block_provenance.accretion_seq, which _insert_block_provenance
-- copies from the element's `seq`), then the element's position in that
-- event's list for this block. The list lives at a per-event-type path:
--   * `incorporated` — block_mutated, block_provenance_annotated;
--   * `block.incorporated` — block_created;
--   * `blocks[*].incorporated`, the entry whose block_id is this block — resource_created;
--   * `created[*].attribution` / `kept[*].attribution`, the entry whose block_id
--     is this block — resource_reblocked.
-- Position is needed because reblock carries sources forward with their
-- original seq, so two elements of one list can share it. The element is
-- matched to the source row by normalize_remote_uri(source.value) =
-- uri_normalized — the same normalization _upsert_remote_source keyed the
-- row on. The URL text is never an ordering term. cogmap_seeded and
-- charter_set also project blocks with provenance, but only onto a charter
-- resource, which the act refuses (D5); their lists are not read here.
-- ---------------------------------------------------------------------------
CREATE FUNCTION _resource_erasure_remote_originals(p_resource uuid)
RETURNS TABLE (block_id uuid, source_id uuid, n integer, shared boolean)
LANGUAGE sql STABLE AS $$
    WITH cited AS (
        SELECT bp.block_id, bp.source_id, bp.accretion_seq,
               ev.occurred_at, ev.id AS event_id, et.name AS event_type, ev.payload,
               rs.uri_normalized
          FROM kb_block_provenance bp
          JOIN kb_content_blocks b ON b.id = bp.block_id
          JOIN kb_events ev ON ev.id = bp.contributed_by_event_id
          JOIN kb_event_types et ON et.id = ev.event_type_id
          LEFT JOIN kb_remote_sources rs ON rs.id = bp.source_id
         WHERE b.resource_id = p_resource
           AND bp.source_kind = 'remote'
    ), first_appearance AS (
        SELECT DISTINCT ON (c.block_id, c.source_id)
               c.block_id, c.source_id, c.occurred_at, c.event_id, c.accretion_seq,
               (SELECT min(el.ord)
                  FROM jsonb_array_elements(
                         CASE c.event_type
                           WHEN 'block_mutated'              THEN c.payload -> 'incorporated'
                           WHEN 'block_provenance_annotated' THEN c.payload -> 'incorporated'
                           WHEN 'block_created'              THEN c.payload #> '{block,incorporated}'
                           WHEN 'resource_created' THEN
                               (SELECT x -> 'incorporated'
                                  FROM jsonb_array_elements(c.payload -> 'blocks') x
                                 WHERE (x ->> 'block_id')::uuid = c.block_id)
                           WHEN 'resource_reblocked' THEN
                               (SELECT x -> 'attribution'
                                  FROM jsonb_array_elements(coalesce(c.payload -> 'created', '[]'::jsonb)
                                                            || coalesce(c.payload -> 'kept', '[]'::jsonb)) x
                                 WHERE (x ->> 'block_id')::uuid = c.block_id)
                         END) WITH ORDINALITY AS el(v, ord)
                 WHERE el.v #>> '{source,kind}' = 'remote'
                   AND normalize_remote_uri(el.v #>> '{source,value}') = c.uri_normalized) AS pos
          FROM cited c
         ORDER BY c.block_id, c.source_id, c.occurred_at, c.event_id
    )
    SELECT f.block_id, f.source_id,
           (row_number() OVER (PARTITION BY f.block_id
                                   ORDER BY f.occurred_at, f.event_id, f.accretion_seq, f.pos))::integer,
           EXISTS (SELECT 1 FROM kb_block_provenance o
                     JOIN kb_content_blocks ob ON ob.id = o.block_id
                    WHERE o.source_kind = 'remote' AND o.source_id = f.source_id
                      AND ob.resource_id <> p_resource)
      FROM first_appearance f;
$$;

COMMENT ON FUNCTION _resource_erasure_remote_originals(uuid) IS
'R''s original remote sources, numbered (spec 2026-09-28 D4): one row per (block_id, source_id)
R''s blocks cite with source_kind remote; n is the block''s sentinel number erased:<block_id>:<n>
in ledger order of first appearance (first contributing event''s occurred_at and id, the
element''s seq, the element''s position in that event''s per-type list); shared is true when
another resource''s block also cites source_id. The ONE capture: the redaction body''s step (9e)
re-points and deletes from it, and the survey plan names shared sources by id and counts from it.';

-- ---------------------------------------------------------------------------
-- Section 0d. The property-key sentinel numbering (D4): one row per distinct
-- original key an owner's property rows carry (live and folded), with n for its
-- sentinel erased-key-<n>. The redaction body's steps (9b) (the resource) and
-- (9d) (each edge touching it) both read it; n is computed here and nowhere else.
--
-- n numbers the owner's keys in ledger order of first appearance: the
-- first-asserting event's occurred_at, then that event's id. Every property
-- event names exactly one key — _project_property_set and
-- _project_property_asserted insert rows of p_payload->>'property_key' only,
-- and _project_resource_created / _project_cogmap_seeded insert only doc_type —
-- so two distinct keys of one owner never share a first-asserting event and the
-- pair is total. Keys asserted in one transaction share occurred_at; the event
-- id decides between them. The key text is never an ordering term.
-- ---------------------------------------------------------------------------
CREATE FUNCTION _resource_erasure_key_numbers(p_owner_table text, p_owner_id uuid)
RETURNS TABLE (property_key text, n integer)
LANGUAGE sql STABLE AS $$
    WITH first_appearance AS (
        SELECT DISTINCT ON (p.property_key)
               p.property_key, ev.occurred_at, ev.id AS event_id
          FROM kb_properties p
          JOIN kb_events ev ON ev.id = p.asserted_by_event_id
         WHERE p.owner_table = p_owner_table AND p.owner_id = p_owner_id
         ORDER BY p.property_key, ev.occurred_at, ev.id
    )
    SELECT f.property_key,
           (row_number() OVER (ORDER BY f.occurred_at, f.event_id))::integer
      FROM first_appearance f;
$$;

COMMENT ON FUNCTION _resource_erasure_key_numbers(text, uuid) IS
'The property-key sentinel numbering (spec 2026-09-28 D4): one row per distinct original key the
owner''s kb_properties rows carry, live and folded, with n for erased-key-<n>, in ledger order of
first appearance (the first-asserting event''s occurred_at, then its id; never the key text). The
ONE definition: the redaction body''s step (9b) numbers the resource with it and step (9d) numbers
each edge touching the resource with it.';

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
    v_targets       jsonb := '[]'::jsonb;
    v_a             bigint;
    v_b             bigint;
    v_c             bigint;
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
      WHERE NOT e.is_folded
        AND ((e.source_table = 'kb_resources' AND e.source_id = p_resource)
          OR (e.target_table = 'kb_resources' AND e.target_id = p_resource));

    -- ── The edges the act folds, each listed so the record's `folded_edges` and the per-edge
    --     events agree. LIVE edges only: an edge already folded by history is the fold's
    --     business, not this act's — enumerating it would abort execute against a lawful
    --     state. Folded edges stay in `folded_edges`? No — only what THIS act folds is
    --     listed; the pre-existing fold already carries its own event. ──────────────────
    FOR v_row IN
        SELECT e.id
          FROM kb_edges e
          WHERE NOT e.is_folded
            AND ((e.source_table = 'kb_resources' AND e.source_id = p_resource)
              OR (e.target_table = 'kb_resources' AND e.target_id = p_resource))
          ORDER BY e.id
    LOOP
        v_edges := v_edges || to_jsonb(v_row.id);
    END LOOP;

    -- ── THE TARGETS (D8): what the act will reach, one {target, outcome} per D2 step that
    --    reaches something, counted PRE-act here because the resource_erased payload is
    --    appended before the redaction body runs and the act never computes twice (D10). Each
    --    count reads the row set its step in _resource_erasure_apply_redaction updates, by the
    --    same predicate. The outcome text is counts and verbs only: never a title, URL, key,
    --    value or any other content (goal §8 — the record never repeats what it erased). A
    --    table the act reaches nothing in is not claimed; the husk is always reached. execute
    --    appends the blob strikes and the ended ingest to this list. ─────────────────────────
    -- D2 step 1: chunk prose and heading trails.
    SELECT count(*) INTO v_a FROM kb_chunk_content cc
      JOIN kb_chunks c ON c.id = cc.chunk_id
     WHERE c.resource_id = p_resource AND cc.content <> '';
    SELECT count(*) INTO v_b FROM kb_chunks
     WHERE resource_id = p_resource AND header_path IS NOT NULL;
    IF v_a + v_b > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'kb_chunk_content',
            'outcome', v_a || ' chunk bodies emptied, hashes kept; '
                       || v_b || ' heading paths nulled');
    END IF;
    -- D2 step 2: every revision's bytes.
    SELECT count(*) INTO v_a FROM kb_block_content bc
     WHERE bc.block_revision_id IN (
           SELECT br.id FROM kb_block_revisions br
             JOIN kb_content_blocks b ON b.id = br.block_id
            WHERE b.resource_id = p_resource)
       AND bc.content <> '';
    IF v_a > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'kb_block_content',
            'outcome', v_a || ' block revision bodies emptied, hashes kept');
    END IF;
    -- D2 step 3: embeddings with their provenance.
    SELECT count(*) INTO v_a FROM kb_chunks
     WHERE resource_id = p_resource AND embedding IS NOT NULL;
    IF v_a > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'kb_chunks.embedding',
            'outcome', v_a || ' embeddings nulled with embedded_with');
    END IF;
    -- D2 step 4: the search vector.
    SELECT count(*) INTO v_a FROM kb_resource_search_index
     WHERE resource_id = p_resource AND search_vector <> '';
    IF v_a > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'kb_resource_search_index',
            'outcome', v_a || ' search vector emptied');
    END IF;
    -- D2 step 5: every artifact's content.
    SELECT count(*) INTO v_a FROM kb_data_artifact_content dac
     WHERE dac.artifact_id IN (
           SELECT da.id FROM kb_data_artifacts da WHERE da.resource_id = p_resource)
       AND dac.content <> '{}'::jsonb;
    IF v_a > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'kb_data_artifact_content',
            'outcome', v_a || ' artifact bodies emptied to {}, hashes kept');
    END IF;
    -- D2 step 6: formation watermarks.
    SELECT count(*) INTO v_a FROM kb_contexts c
     WHERE c.shape_materialized_event_id IS NOT NULL
       AND c.id = (SELECT h.anchor_id FROM kb_resource_homes h
                    WHERE h.resource_id = p_resource AND h.anchor_table = 'kb_contexts');
    SELECT count(*) INTO v_b FROM kb_cogmaps m
     WHERE m.shape_materialized_event_id IS NOT NULL
       AND m.id IN (
           SELECT r.home_anchor_id FROM kb_cogmap_regions r
             JOIN kb_cogmap_region_members mem ON mem.region_id = r.id
            WHERE r.home_anchor_table = 'kb_cogmaps' AND NOT r.is_folded
              AND mem.member_table = 'kb_resources' AND mem.member_id = p_resource);
    IF v_a + v_b > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'formation watermarks',
            'outcome', v_a || ' context and ' || v_b
                       || ' cogmap shape_materialized_event_id nulled');
    END IF;
    -- D2 step 7: workflow jobs, every status.
    SELECT count(*) FILTER (WHERE j.payload <> '{}'::jsonb OR j.last_error IS NOT NULL),
           count(*) FILTER (WHERE j.status IN ('pending', 'waiting_for_retry', 'in_progress'))
      INTO v_a, v_b
      FROM kb_workflow_jobs j WHERE j.resource_id = p_resource;
    IF v_a + v_b > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'kb_workflow_jobs',
            'outcome', v_a || ' jobs emptied of payload and last_error; '
                       || v_b || ' unfinished jobs cancelled to dead');
    END IF;
    -- D2 step 7a: the ingestion record and the verdicts.
    SELECT count(*) INTO v_a FROM kb_ingestion_records ir
     WHERE ir.resource_id = p_resource AND ir.source_uri <> 'erased:' || p_resource::text;
    IF v_a > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'kb_ingestion_records.source_uri',
            'outcome', v_a || ' ingestion record source_uri sentineled, source_hash kept');
    END IF;
    SELECT count(*) INTO v_a FROM kb_data_artifact_verdicts v
     WHERE v.artifact_id IN (
           SELECT da.id FROM kb_data_artifacts da WHERE da.resource_id = p_resource)
       AND v.detail IS NOT NULL;
    IF v_a > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'kb_data_artifact_verdicts.detail',
            'outcome', v_a || ' verdict details nulled');
    END IF;
    -- D2 step 8: projected citation-audit reasons.
    SELECT count(*) INTO v_a FROM kb_citation_audits ca
     WHERE ca.block_id IN (
           SELECT b.id FROM kb_content_blocks b WHERE b.resource_id = p_resource)
       AND ca.reason IS NOT NULL;
    IF v_a > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'kb_citation_audits.reason',
            'outcome', v_a || ' audit reasons nulled');
    END IF;
    -- D2 step 9: the husk (always), the property sentinels, the edges, the remote sources.
    v_targets := v_targets || jsonb_build_object('target', 'kb_resources',
        'outcome', '1 husk: title and origin_uri sentineled, is_active cleared, erased_at set');
    SELECT count(*) INTO v_a FROM kb_properties p
      JOIN _resource_erasure_key_numbers('kb_resources', p_resource) k
        ON k.property_key = p.property_key
     WHERE p.owner_table = 'kb_resources' AND p.owner_id = p_resource;
    SELECT count(*) INTO v_b
      FROM kb_edges e
     CROSS JOIN LATERAL _resource_erasure_key_numbers('kb_edges', e.id) k
      JOIN kb_properties p
        ON p.owner_table = 'kb_edges' AND p.owner_id = e.id AND p.property_key = k.property_key
     WHERE (e.source_table = 'kb_resources' AND e.source_id = p_resource)
        OR (e.target_table = 'kb_resources' AND e.target_id = p_resource);
    IF v_a + v_b > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'kb_properties',
            'outcome', v_a || ' resource-owned and ' || v_b
                       || ' edge-owned rows: keys erased-key-<n>, values erased, folded');
    END IF;
    SELECT count(*) INTO v_b FROM kb_edges e
     WHERE e.label IS NOT NULL
       AND ((e.source_table = 'kb_resources' AND e.source_id = p_resource)
         OR (e.target_table = 'kb_resources' AND e.target_id = p_resource));
    IF v_n_edges + v_b > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'kb_edges',
            'outcome', v_n_edges || ' edges folded by this act; ' || v_b || ' labels nulled');
    END IF;
    --    The remote sources, from the ONE capture step (9e) reads
    --    (_resource_erasure_remote_originals): the provenance rows it re-points, the exclusive
    --    originals it deletes, the shared ones it keeps. An exclusive original that is itself
    --    some captured (block, n)'s sentinel row is re-pointed onto, so it stays cited and is
    --    not deleted; the count leaves it out for that reason.
    WITH o AS MATERIALIZED (
        SELECT * FROM _resource_erasure_remote_originals(p_resource)
    )
    SELECT (SELECT count(*) FROM kb_block_provenance bp
              JOIN o ON o.block_id = bp.block_id AND o.source_id = bp.source_id
             WHERE bp.source_kind = 'remote'),
           (SELECT count(DISTINCT o1.source_id) FROM o o1
              JOIN kb_remote_sources rs ON rs.id = o1.source_id
             WHERE NOT o1.shared
               AND NOT EXISTS (
                   SELECT 1 FROM o o2
                    WHERE normalize_remote_uri('erased:' || o2.block_id::text || ':' || o2.n::text)
                          = rs.uri_normalized)),
           (SELECT count(DISTINCT o1.source_id) FROM o o1 WHERE o1.shared)
      INTO v_c, v_a, v_b;
    IF v_c > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'kb_block_provenance',
            'outcome', v_c || ' remote provenance rows re-pointed to erased:<block_id>:<n> sentinels');
    END IF;
    IF v_a + v_b > 0 THEN
        v_targets := v_targets || jsonb_build_object('target', 'kb_remote_sources',
            'outcome', v_a || ' exclusive remote sources deleted; '
                       || v_b || ' shared remote sources kept, named in the remainder');
    END IF;

    -- ── THE REFUSAL FACE (D5), computed here so execute consumes the verdict rather than
    -- re-deriving it: a charter resource (Q2 — the map-grain act is another task, named), an
    -- already-erased resource. The ingest state is reported, not refused: an in-flight ingest
    -- ends with the erasure and execute names it in `targets`. ─────────────────────────────
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

    -- 4. Shared remote sources: kb_remote_sources rows R's blocks cite that ANOTHER
    --    resource's block also cites (live or folded — the row is shared either way), read from
    --    the ONE capture the act's step (9e) re-points from (_resource_erasure_remote_originals).
    --    A source R exclusively cites is NOT here: step (9e) deletes it, and replay of the
    --    redacted payloads never mints it, so the projection agrees by construction. A shared
    --    one stays and is named by its kb_remote_sources id, never by its URL (D4, D8): the
    --    record is an admin event outside the trail scope, so nothing could ever redact a URL
    --    written into it.
    FOR v_row IN
        SELECT DISTINCT o.source_id
          FROM _resource_erasure_remote_originals(p_resource) o
         WHERE o.shared
         ORDER BY o.source_id
    LOOP
        v_remainder := v_remainder || jsonb_build_object(
            'target', 'kb_remote_sources.id',
            'outcome', 'shared remote source ' || v_row.source_id::text
                       || '; another resource''s block still cites it; named, kept');
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
                   WHEN 'resource_created'           THEN '["title","origin_uri","blocks[*].incorporated[*].source.value"]'::jsonb
                   WHEN 'resource_updated'           THEN '["title","origin_uri"]'::jsonb
                   WHEN 'block_created'              THEN '["block.incorporated[*].source.value"]'::jsonb
                   WHEN 'block_mutated'              THEN '["incorporated[*].source.value"]'::jsonb
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
        'targets',         v_targets,
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
event, nothing else mutated. ingest_in_flight is RETIRED (D5, ruled 2026-09-29: ingest state is
not a refusal; an in-flight ingest ends with the erasure): no path raises it, and it stays
accepted because removing a value from a closed vocabulary is not additive. A repeat erasure is
a recorded refusal, not a silent no-op: nothing in the projection changes and no second
resource_erased is minted, but the attempt is part of the record, the same as every other
refusal.';

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
    -- A TOMBSTONE IS ERASABLE — arguably the flow's most common shape: the content was
    -- soft-deleted ("realized I shouldn't have persisted this"), and then the compliance
    -- need arrives that demands it not exist at all. The principal act has no tombstone
    -- refusal (it tombstones VIA the act, 20260909000025), F4's write floor makes
    -- is_active=false already permanent, and no restore verb exists (the spec's F4 —
    -- "un-modifiable on every axis"), so the only escape from a tombstone was always
    -- erasure. The act completes over one mechanically: is_active is already false, the
    -- CHECK is satisfied, and COALESCE keeps erased_at stable. D6's ruling ("a
    -- soft-deleted resource must never be mistaken for an erased one") is a PROJECTION
    -- honesty rule — erased_at is NULL until this act sets it — not a refusal on the
    -- negative face. An earlier draft refused tombstones here; Pete overruled (compliance
    -- erasure of soft-deleted resources is the PII-audit flow's main use). ──


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
targets, remainder, ledger_remainder, folded_edges read straight off the plan — targets extended
by each blob strike and, when ingest_state is not complete, the ingest the erasure ended, which
is not a refusal), then calls _resource_erasure_apply_redaction — all one transaction. Refusals RAISE here and the Rust caller
records them through resource_erasure_refuse BEFORE reaching this function; legality is the Rust
caller''s is_system_admin gate, never SQL''s. No hash enters kb_erased_content.';

SELECT declare_migration(
    20260929040730,
    'additive',
    'The resource-erasure act (spec 2026-09-28, build order 2b, task 01a0e9e7-491d): the ONE
row-anchored redaction body (_resource_erasure_apply_redaction — chunk prose + header_path, block
revision bytes, embeddings+embedded_with, search vector, data artifact content emptied to
''{}''::jsonb for EVERY artifact of the resource, projected citation-audit reasons, formation
watermark nulls, workflow-job payloads and last_errors in every status (unfinished rows cancelled
to dead), the ingestion record''s source_uri (erased:<id>) and artifact verdict details, and the
projection-side sentinels: husk title/origin_uri
''erased-<id>''/''erased:<id>'', property keys erased-key-<n> by ledger order of first appearance
(_resource_erasure_key_numbers — the resource''s, and each touching edge''s numbered per edge),
property values erased::jsonb, edge labels NULL, remote-source re-pointing to the sentinel
rows replay mints — ROW-ANCHORED on resource id, never a content hash; another resource''s
byte-identical content is never reached, and NO hash enters kb_erased_content) and the ONE
trail-scope predicate (_resource_erasure_trail_scope — the element-trail read''s predicate plus the
edge-owned-properties arm), so the survey, the act and cut 2''s completion pass share one
derivation; resource_erasure_survey_plan computes scope, refusals, targets (pre-act counts per
reached target, never content), remainder and ledger_remainder once per act and the survey door renders it; resource_erasure_execute consumes the plan — folds
every edge through its own relationship_folded (fixed reason ''resource_erased'', the act''s
correlation id), strikes only operator-listed blobs through blob_delete(''blob_erased'', …), appends
the ONE NULL-anchored resource_erased event (references carry the subject + request reference;
redacted_fields is EMPTY in cut 1, every unreached ledger path lives in ledger_remainder by (event,
path) in the RedactedEventFields shape), then calls the ONE redaction body at the event''s ledger
position; resource_erasure_refuse records the closed refusal vocabulary (unauthorized |
charter_resource | ingest_in_flight (retired: an in-flight ingest ends with the erasure and
targets names it) | already_erased) — a repeat erasure is a recorded refusal, not a silent no-op
(ruled 2026-09-29). CUT 1 DOES NOT TOUCH THE LEDGER (D12): the append-only trigger
is unamended; replay stays byte-identical through the projection-side sentinels applied at the
event''s position. THE ACT IS SERIALIZED AGAINST EVERY WRITER (D13): resource_erasure_execute takes
FOR UPDATE on the resource row before the plan, and _resource_write_guard (FOR KEY SHARE, RAISE when
erased_at IS NOT NULL) with its owner-resolving companion _resource_write_guard_owner is called as
the first statement of seven re-created incumbents — _recompute_resource_body_hash,
_project_property_set, _project_property_asserted, _project_relationship_asserted,
_project_block_annotated, _project_resource_updated, _project_data_artifact_committed — each
otherwise verbatim. Additive: no column or constraint is altered, and the guard raises only for an
erased resource, a state an old binary cannot produce.'
);
