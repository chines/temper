-- The sensitivity sweep's scan over its text surfaces (spec D2, D4, D5, D8, D11; Q28-Q33).
-- Rationale and grounding: temper-artifacts plans/2026-10-01-sensitivity-sweep-3a-core.md, PR C1.

-- Q28, Q33: one finding per place; its fingerprints are children that carry no state.
ALTER TABLE sensitivity.findings
    DROP COLUMN fingerprint,
    ADD COLUMN fingerprint_state text NOT NULL DEFAULT 'unsalted'
        CHECK (fingerprint_state IN ('complete', 'truncated', 'unsalted'));

CREATE TABLE sensitivity.finding_fingerprints (
    finding_id  uuid NOT NULL REFERENCES sensitivity.findings (id),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    PRIMARY KEY (finding_id, fingerprint)
);

-- D4 rule 2: a hash scanned by a detector version is not scanned again. Zero is remembered too.
CREATE TABLE sensitivity.memo (
    content_hash     text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    detector_id      text NOT NULL,
    detector_version int NOT NULL,
    match_count      int NOT NULL CHECK (match_count BETWEEN 0 AND 100000),
    PRIMARY KEY (content_hash, detector_id, detector_version),
    FOREIGN KEY (detector_id, detector_version)
        REFERENCES sensitivity.detector_versions (detector_id, version)
);

-- Q29: the last hash each mutable place was read with, so a re-read is told from a recurrence.
CREATE TABLE sensitivity.place_observations (
    surface      text NOT NULL REFERENCES sensitivity.surfaces (surface),
    target_id    uuid NOT NULL,
    content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    observed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (surface, target_id)
);

-- outcome NULL with no finished_at is a tick that never finished: the claim committed first.
ALTER TABLE sensitivity.runs
    ADD COLUMN outcome text CHECK (outcome IN ('scanned', 'idle', 'failed')),
    ADD COLUMN units_oversize int NOT NULL DEFAULT 0 CHECK (units_oversize BETWEEN 0 AND 100000),
    ADD COLUMN head_holdback_seconds int NOT NULL DEFAULT 0 CHECK (head_holdback_seconds BETWEEN 0 AND 100000);

CREATE INDEX finding_fingerprints_by_fingerprint ON sensitivity.finding_fingerprints (fingerprint);
CREATE INDEX findings_by_resource ON sensitivity.findings (resource_id);
CREATE INDEX findings_by_value ON sensitivity.findings (content_hash, detector_id, detector_version);
CREATE INDEX runs_by_surface ON sensitivity.runs (surface, id DESC);
CREATE INDEX runs_by_finish ON sensitivity.runs (finished_at);
CREATE INDEX dispositions_latest ON sensitivity.dispositions (finding_id, decided_at DESC, id DESC);
CREATE INDEX idx_kb_resources_updated_id ON kb_resources (updated, id);

-- Q32: a sensitivity job's error is a code or reap's text, never a message that could quote a row.
ALTER TABLE kb_workflow_jobs
    ADD CONSTRAINT ck_workflow_jobs_sensitivity_last_error_coded
    CHECK (persona <> 'sensitivity' OR last_error IS NULL
           OR last_error IN ('scan_failed', 'statement_timeout', 'detector_pattern_invalid',
                             'store_constraint')
           OR last_error ~ '^([a-z]{1,16} ){0,2}lease expired$');

CREATE FUNCTION workflow_job_fail_system(p_job uuid, p_persona text, p_dispatch_type text, p_code text)
RETURNS uuid LANGUAGE sql AS $$
    UPDATE kb_workflow_jobs
       SET status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'waiting_for_retry' END,
           last_error = p_code,
           lease_expires_at = NULL,
           completed_at = CASE WHEN attempts >= max_attempts THEN now() ELSE NULL END,
           next_visible_at = CASE WHEN attempts >= max_attempts THEN next_visible_at
                                  ELSE now() + make_interval(secs => least(300 * power(2, attempts - 1), 3600)) END
     WHERE id = p_job AND persona = p_persona AND dispatch_type = p_dispatch_type
       AND num_nonnulls(cogmap_id, resource_id, context_id) = 0 AND status = 'in_progress'
    RETURNING id;
$$;

-- The smallest v7 id stamped at p_at: the head's bound is built, never extracted (PG 17 reads v1 only).
CREATE FUNCTION sensitivity.v7_floor(p_at timestamptz) RETURNS uuid
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT (lpad(to_hex(floor(extract(epoch FROM p_at) * 1000)::bigint), 12, '0') || '00000000000000000000')::uuid;
$$;

CREATE FUNCTION sensitivity.unit_hash(p_text text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT encode(sha256(convert_to(p_text, 'UTF8')), 'hex');
$$;

-- The one evaluation of a detector, now yielding its matches; detector_match_count counts them.
CREATE FUNCTION sensitivity.detector_matches(p_detector text, p_text text) RETURNS SETOF text
LANGUAGE sql STABLE STRICT AS $$
    SELECT m[1]
      FROM sensitivity.detectors d,
           LATERAL regexp_matches(p_text, '(' || d.pattern || ')', 'g') m
     WHERE d.id = p_detector
       AND p_text ~ d.prefilter
       AND m[1] <> ''
       AND CASE d.validator
               WHEN 'ssn_valid'         THEN sensitivity.ssn_valid(m[1])
               WHEN 'luhn_valid'        THEN sensitivity.luhn_valid(m[1])
               WHEN 'aba_routing_valid' THEN sensitivity.aba_routing_valid(m[1])
               ELSE true
           END
     LIMIT 100000;
$$;

CREATE OR REPLACE FUNCTION sensitivity.detector_match_count(p_detector text, p_text text) RETURNS int
LANGUAGE sql STABLE STRICT AS $$
    SELECT CASE WHEN EXISTS (SELECT 1 FROM sensitivity.detectors WHERE id = p_detector)
                THEN (SELECT count(*)::int FROM sensitivity.detector_matches(p_detector, p_text)) END;
$$;

-- One source per enabled text surface, all one shape: (target_id, order_at, unit, content_hash,
-- resource_id). order_at is NULL on an append_only_v7 surface, whose order is the id.
CREATE VIEW sensitivity.src_kb_block_content__content AS
    SELECT bc.block_revision_id AS target_id, NULL::timestamptz AS order_at, bc.content AS unit,
           coalesce(CASE WHEN bc.content_hash ~ '^[0-9a-f]{64}$' THEN bc.content_hash END,
                    sensitivity.unit_hash(bc.content)) AS content_hash, b.resource_id
      FROM kb_block_content bc
      JOIN kb_block_revisions br ON br.id = bc.block_revision_id
      JOIN kb_content_blocks b ON b.id = br.block_id;

CREATE VIEW sensitivity.src_kb_chunk_content__content AS
    SELECT cc.chunk_id AS target_id, NULL::timestamptz AS order_at, cc.content AS unit,
           coalesce(CASE WHEN c.content_hash ~ '^[0-9a-f]{64}$' THEN c.content_hash END,
                    sensitivity.unit_hash(cc.content)) AS content_hash, c.resource_id
      FROM kb_chunk_content cc JOIN kb_chunks c ON c.id = cc.chunk_id;

CREATE VIEW sensitivity.src_kb_chunks__header_path AS
    SELECT id AS target_id, NULL::timestamptz AS order_at, header_path AS unit,
           sensitivity.unit_hash(header_path) AS content_hash, resource_id
      FROM kb_chunks WHERE header_path IS NOT NULL;

CREATE VIEW sensitivity.src_kb_resources__title AS
    SELECT id AS target_id, updated AS order_at, title AS unit,
           sensitivity.unit_hash(title) AS content_hash, id AS resource_id
      FROM kb_resources;

CREATE VIEW sensitivity.src_kb_resources__origin_uri AS
    SELECT id AS target_id, updated AS order_at, origin_uri AS unit,
           sensitivity.unit_hash(coalesce(origin_uri, '')) AS content_hash, id AS resource_id
      FROM kb_resources;

CREATE VIEW sensitivity.src_kb_properties__property_key AS
    SELECT p.id AS target_id, NULL::timestamptz AS order_at, p.property_key AS unit,
           sensitivity.unit_hash(p.property_key) AS content_hash,
           CASE p.owner_table WHEN 'kb_resources' THEN p.owner_id ELSE b.resource_id END AS resource_id
      FROM kb_properties p
      LEFT JOIN kb_content_blocks b ON p.owner_table = 'kb_content_blocks' AND b.id = p.owner_id;

CREATE VIEW sensitivity.src_kb_edges__label AS
    SELECT id AS target_id, NULL::timestamptz AS order_at, label AS unit,
           sensitivity.unit_hash(label) AS content_hash,
           CASE WHEN source_table = 'kb_resources' THEN source_id END AS resource_id
      FROM kb_edges WHERE label IS NOT NULL;

CREATE VIEW sensitivity.src_kb_citation_audits__reason AS
    SELECT a.id AS target_id, NULL::timestamptz AS order_at, a.reason AS unit,
           sensitivity.unit_hash(a.reason) AS content_hash, b.resource_id
      FROM kb_citation_audits a JOIN kb_content_blocks b ON b.id = a.block_id
     WHERE a.reason IS NOT NULL;

CREATE VIEW sensitivity.src_kb_remote_sources__uri AS
    SELECT id AS target_id, NULL::timestamptz AS order_at, uri AS unit,
           sensitivity.unit_hash(uri) AS content_hash, NULL::uuid AS resource_id
      FROM kb_remote_sources;

-- Write this place's finding for one unit and one detector version: from the memo when the hash is
-- known, otherwise by running the detector. Returns whether a new finding was written.
CREATE FUNCTION sensitivity.scan_unit(
    p_surface text, p_target uuid, p_resource uuid, p_unit text, p_hash text,
    p_detector text, p_version int, p_salt bytea, INOUT p_memo_hit boolean DEFAULT false,
    OUT p_new boolean
) LANGUAGE plpgsql AS $$
DECLARE
    v_count   int;
    v_prints  bytea[];
    v_state   text;
    v_sibling uuid;
    v_id      uuid;
    v_d       sensitivity.detectors;
    v_cat     text;
BEGIN
    p_new := false;
    SELECT m.match_count INTO v_count FROM sensitivity.memo m
     WHERE m.content_hash = p_hash AND m.detector_id = p_detector AND m.detector_version = p_version;
    p_memo_hit := FOUND;
    IF p_memo_hit AND v_count > 0 THEN
        SELECT f.id, f.fingerprint_state INTO v_sibling, v_state FROM sensitivity.findings f
         WHERE f.content_hash = p_hash AND f.detector_id = p_detector AND f.detector_version = p_version
         LIMIT 1;
        SELECT array_agg(fp.fingerprint) INTO v_prints
          FROM sensitivity.finding_fingerprints fp WHERE fp.finding_id = v_sibling;
    ELSIF NOT p_memo_hit THEN
        SELECT d.* INTO v_d FROM sensitivity.detectors d WHERE d.id = p_detector;
        SELECT count(*)::int,
               array_agg(DISTINCT sha256(p_salt || convert_to(
                   CASE WHEN v_d.validator IS NULL THEN m ELSE regexp_replace(m, '[^0-9]', '', 'g') END,
                   'UTF8'))) FILTER (WHERE p_salt IS NOT NULL)
          INTO v_count, v_prints
          FROM sensitivity.detector_matches(p_detector, p_unit) m;
        v_state := CASE WHEN p_salt IS NULL THEN 'unsalted'
                        WHEN cardinality(v_prints) > 64 THEN 'truncated' ELSE 'complete' END;
        INSERT INTO sensitivity.memo (content_hash, detector_id, detector_version, match_count)
        VALUES (p_hash, p_detector, p_version, v_count);
    END IF;
    IF v_count = 0 THEN
        RETURN;
    END IF;

    SELECT category INTO v_cat FROM sensitivity.detector_versions
     WHERE detector_id = p_detector AND version = p_version;
    -- Q29: a bump's re-detection inherits its predecessor's sightings, unless the category moved (Q27).
    INSERT INTO sensitivity.findings (surface, target_table, target_id, resource_id, content_hash,
        detector_id, detector_version, category, severity, match_count, fingerprint_state,
        first_seen, last_seen)
    SELECT p_surface, split_part(p_surface, '.', 1), p_target, p_resource, p_hash, p_detector,
           p_version, v_cat, d.severity, v_count, v_state,
           coalesce(prior.first_seen, now()), coalesce(prior.last_seen, now())
      FROM sensitivity.detectors d
      LEFT JOIN LATERAL (
          SELECT f.first_seen, f.last_seen FROM sensitivity.findings f
            JOIN sensitivity.detector_versions dv
              ON dv.detector_id = f.detector_id AND dv.version = f.detector_version
           WHERE f.surface = p_surface AND f.target_id = p_target AND f.path IS NULL
             AND f.content_hash = p_hash AND f.detector_id = p_detector
             AND f.detector_version < p_version AND dv.category = v_cat
           ORDER BY f.detector_version DESC LIMIT 1) prior ON true
     WHERE d.id = p_detector
    ON CONFLICT DO NOTHING
    RETURNING id INTO v_id;
    IF v_id IS NULL THEN
        RETURN;
    END IF;
    p_new := true;
    INSERT INTO sensitivity.finding_fingerprints (finding_id, fingerprint)
    SELECT v_id, fp FROM unnest(v_prints) fp ORDER BY fp LIMIT 64;
END;
$$;

-- Read one lane of one surface within budget, evaluating each enabled detector version only on the
-- rows past its own watermark, so one read serves every cursor. Returns rows read and whether the
-- source ran out before the budget did.
CREATE FUNCTION sensitivity.scan_lane(
    p_run uuid, p_surface sensitivity.surfaces, p_lane text, p_salt bytea,
    p_bound_at timestamptz, p_bound_id uuid, p_budget int, p_deadline timestamptz,
    OUT p_rows int, OUT p_exhausted boolean
) LANGUAGE plpgsql AS $$
DECLARE
    v_mutable boolean := p_surface.cursor_kind = 'mutable_timestamp';
    v_head    boolean := p_lane = 'head';
    v_ids text[]; v_vers int[]; v_cats text[]; v_at timestamptz[]; v_id uuid[]; v_incl boolean[];
    v_lo_at timestamptz; v_lo_id uuid;
    v_last_at timestamptz; v_last_id uuid;
    v_sql text;
    r record;
    v_prior text;
    v_hit boolean; v_new boolean;
    v_scanned int := 0; v_hits int := 0; v_found int := 0; v_oversize int := 0;
    v_bycat jsonb := '{}';
BEGIN
    p_rows := 0; p_exhausted := false;
    -- A backfill cursor not yet started reads from its floor, inclusive.
    SELECT array_agg(c.detector_id ORDER BY c.detector_id), array_agg(c.detector_version ORDER BY c.detector_id),
           array_agg(dv.category ORDER BY c.detector_id),
           array_agg(CASE WHEN v_head OR c.watermark_id IS NOT NULL THEN c.watermark_at ELSE c.backfill_floor_at END ORDER BY c.detector_id),
           array_agg(coalesce(c.watermark_id, c.backfill_floor_id) ORDER BY c.detector_id),
           array_agg(NOT v_head AND c.watermark_id IS NULL ORDER BY c.detector_id)
      INTO v_ids, v_vers, v_cats, v_at, v_id, v_incl
      FROM sensitivity.cursors c
      JOIN sensitivity.detectors d ON d.id = c.detector_id AND d.version = c.detector_version AND d.enabled
      JOIN sensitivity.detector_versions dv ON dv.detector_id = c.detector_id AND dv.version = c.detector_version
     WHERE c.surface = p_surface.surface AND c.lane = p_lane
       AND (v_head OR c.backfill_completed_at IS NULL);
    IF v_ids IS NULL OR p_budget <= 0 THEN
        RETURN;
    END IF;
    -- The head reads from its lowest watermark up; the backfill from its highest down (Q30).
    SELECT x.a, x.i INTO v_lo_at, v_lo_id FROM unnest(v_at, v_id) x(a, i)
     ORDER BY CASE WHEN v_head THEN x.a END, CASE WHEN v_head THEN x.i END,
              x.a DESC, x.i DESC LIMIT 1;
    v_sql := format('SELECT target_id, order_at, unit, content_hash, resource_id FROM sensitivity.%I WHERE ',
                    'src_' || replace(p_surface.surface, '.', '__'))
          || CASE WHEN v_mutable AND v_head THEN '(order_at, target_id) > ($1, $2) AND order_at < $3 ORDER BY order_at, target_id'
                  WHEN v_mutable THEN '(order_at, target_id) <= ($1, $2) ORDER BY order_at DESC, target_id DESC'
                  WHEN v_head THEN 'target_id > $2 AND target_id < $4 ORDER BY target_id'
                  ELSE 'target_id <= $2 ORDER BY target_id DESC' END
          || ' LIMIT $5';
    FOR r IN EXECUTE v_sql USING v_lo_at, v_lo_id, p_bound_at, p_bound_id, p_budget LOOP
        EXIT WHEN clock_timestamp() > p_deadline;
        p_rows := p_rows + 1;
        v_last_at := r.order_at; v_last_id := r.target_id;
        IF v_mutable THEN
            -- Q29: content that changed since this place was last read and now matches an older
            -- finding is a recurrence; the same content read again is not.
            SELECT o.content_hash INTO v_prior FROM sensitivity.place_observations o
             WHERE o.surface = p_surface.surface AND o.target_id = r.target_id;
            IF FOUND AND v_prior <> r.content_hash THEN
                UPDATE sensitivity.findings SET last_seen = now()
                 WHERE surface = p_surface.surface AND target_id = r.target_id AND path IS NULL
                   AND content_hash = r.content_hash;
            END IF;
            INSERT INTO sensitivity.place_observations (surface, target_id, content_hash)
            VALUES (p_surface.surface, r.target_id, r.content_hash)
            ON CONFLICT (surface, target_id) DO UPDATE
               SET content_hash = EXCLUDED.content_hash, observed_at = now()
             WHERE sensitivity.place_observations.content_hash <> EXCLUDED.content_hash;
        END IF;
        CONTINUE WHEN r.unit IS NULL OR r.unit = '';
        IF octet_length(r.unit) > 1048576 THEN
            v_oversize := v_oversize + 1;
            CONTINUE;
        END IF;
        FOR k IN 1 .. cardinality(v_ids) LOOP
            CONTINUE WHEN CASE WHEN v_head
                THEN (coalesce(r.order_at, '-infinity'), r.target_id) <= (coalesce(v_at[k], '-infinity'), v_id[k])
                ELSE (coalesce(r.order_at, '-infinity'), r.target_id) > (coalesce(v_at[k], '-infinity'), v_id[k])
                  OR ((coalesce(r.order_at, '-infinity'), r.target_id) = (coalesce(v_at[k], '-infinity'), v_id[k])
                      AND NOT v_incl[k]) END;
            SELECT u.p_memo_hit, u.p_new INTO v_hit, v_new FROM sensitivity.scan_unit(
                p_surface.surface, r.target_id, r.resource_id, r.unit, r.content_hash,
                v_ids[k], v_vers[k], p_salt) u;
            IF v_hit THEN v_hits := v_hits + 1; ELSE v_scanned := v_scanned + 1; END IF;
            IF v_new THEN
                v_found := v_found + 1;
                v_bycat := jsonb_set(v_bycat, ARRAY[v_cats[k]],
                                     to_jsonb(least(coalesce((v_bycat ->> v_cats[k])::int, 0) + 1, 100000)));
            END IF;
        END LOOP;
    END LOOP;
    p_exhausted := p_rows < p_budget AND clock_timestamp() <= p_deadline;

    IF v_last_id IS NOT NULL THEN
        UPDATE sensitivity.cursors c
           SET watermark_at = v_last_at, watermark_id = v_last_id, updated = now()
         WHERE c.surface = p_surface.surface AND c.lane = p_lane
           AND (c.detector_id, c.detector_version) IN (SELECT * FROM unnest(v_ids, v_vers))
           AND CASE WHEN v_head
                    THEN (coalesce(c.watermark_at, '-infinity'), c.watermark_id) < (coalesce(v_last_at, '-infinity'), v_last_id)
                    ELSE (coalesce(coalesce(c.watermark_at, c.backfill_floor_at), '-infinity'),
                          coalesce(c.watermark_id, c.backfill_floor_id)) >= (coalesce(v_last_at, '-infinity'), v_last_id) END;
    END IF;
    IF NOT v_head AND p_exhausted THEN
        UPDATE sensitivity.cursors c SET backfill_completed_at = now(), updated = now()
         WHERE c.surface = p_surface.surface AND c.lane = 'backfill'
           AND (c.detector_id, c.detector_version) IN (SELECT * FROM unnest(v_ids, v_vers));
    END IF;

    UPDATE sensitivity.runs u
       SET rows_examined   = least(u.rows_examined + p_rows, 100000),
           hashes_examined = least(u.hashes_examined + v_scanned, 100000),
           cache_hits      = least(u.cache_hits + v_hits, 100000),
           new_findings    = least(u.new_findings + v_found, 100000),
           units_oversize  = least(u.units_oversize + v_oversize, 100000),
           cursor_advances = least(u.cursor_advances + CASE WHEN v_last_id IS NULL THEN 0 ELSE 1 END, 100000),
           by_category     = (SELECT coalesce(jsonb_object_agg(k, least(coalesce((u.by_category ->> k)::int, 0)
                                                                 + coalesce((v_bycat ->> k)::int, 0), 100000)), '{}')
                                FROM (SELECT jsonb_object_keys(u.by_category || v_bycat) k) ks)
     WHERE u.id = p_run;
END;
$$;

-- Phase 1, its own transaction: pick the least recently run text surface, enqueue it unless a job
-- is in flight, claim one work order and record the run. Committing here is what lets a tick that
-- dies in phase 2 keep its attempt, and leave a run with no outcome behind as the record of it.
CREATE FUNCTION sensitivity_sweep_claim(p_budget_rows int DEFAULT 2000, p_lease_seconds int DEFAULT 330)
RETURNS TABLE (run_id uuid, job_id uuid)
LANGUAGE plpgsql AS $$
DECLARE
    v_pick text;
    v_job  record;
BEGIN
    SELECT s.surface INTO v_pick FROM sensitivity.surfaces s
     WHERE s.enabled AND s.shape = 'text'
     ORDER BY (SELECT r.id FROM sensitivity.runs r WHERE r.surface = s.surface ORDER BY r.id DESC LIMIT 1)
              NULLS FIRST, s.surface
     LIMIT 1;
    IF v_pick IS NOT NULL THEN
        PERFORM workflow_job_enqueue_system('sensitivity', 'sensitivity-sweep',
            jsonb_build_object('surface', v_pick, 'budget', p_budget_rows));
    END IF;
    SELECT c.id, c.payload INTO v_job
      FROM workflow_job_claim_system('sensitivity', 'sensitivity-sweep', 1, p_lease_seconds) c;
    IF v_job.id IS NULL THEN
        RETURN;
    END IF;
    INSERT INTO sensitivity.runs (surface) VALUES (v_job.payload ->> 'surface') RETURNING id INTO run_id;
    job_id := v_job.id;
    RETURN NEXT;
END;
$$;

-- Phase 2: scan the claimed work order and finish the job. The deadline is checked before every
-- unit and a unit is at most 1 MiB, so a tick ends well inside the function's 300 s. Counts and ids
-- only cross the wire (D8).
CREATE FUNCTION sensitivity_sweep_tick(
    p_run uuid, p_job uuid, p_salt bytea, p_lag interval DEFAULT '5 minutes', p_budget_ms int DEFAULT 20000
) RETURNS TABLE (rows_examined int, hashes_examined int, cache_hits int, new_findings int,
                 cursor_advances int, units_oversize int, failed boolean)
LANGUAGE plpgsql AS $$
DECLARE
    v_job      record;
    v_surface  sensitivity.surfaces;
    v_deadline timestamptz := clock_timestamp() + make_interval(secs => p_budget_ms / 1000.0);
    v_bound_at timestamptz;
    v_bound_id uuid;
    v_budget   int;
    v_lane     record;
    v_code     text;
BEGIN
    SELECT j.payload INTO v_job FROM kb_workflow_jobs j
     WHERE j.id = p_job AND j.persona = 'sensitivity' AND j.status = 'in_progress';
    IF NOT FOUND OR NOT EXISTS (SELECT 1 FROM sensitivity.runs r WHERE r.id = p_run AND r.outcome IS NULL
                                   AND r.surface = v_job.payload ->> 'surface') THEN
        RETURN;
    END IF;
    SELECT s.* INTO v_surface FROM sensitivity.surfaces s WHERE s.surface = v_job.payload ->> 'surface';
    failed := false;
    IF NOT v_surface.enabled OR v_surface.shape <> 'text' THEN
        UPDATE sensitivity.runs SET outcome = 'idle', finished_at = clock_timestamp() WHERE id = p_run;
    ELSE
        BEGIN
            -- D4 rule 1: never past now() - lag, nor past the oldest transaction here that has
            -- written, whose rows may yet commit beneath the watermark (Witness 5). A reader holds
            -- nothing back; a writer's hold is recorded, so a stalled head never reads as quiet.
            SELECT least(now(), coalesce(min(a.xact_start), now())) - p_lag INTO v_bound_at
              FROM pg_stat_activity a
             WHERE a.datname = current_database() AND a.pid <> pg_backend_pid()
               AND a.backend_xid IS NOT NULL;
            v_bound_id := sensitivity.v7_floor(v_bound_at);
            UPDATE sensitivity.runs
               SET head_holdback_seconds = least(ceil(extract(epoch FROM (now() - p_lag) - v_bound_at)), 100000)
             WHERE id = p_run;
            -- A new detector version starts both lanes at the bound: its head goes forward, its
            -- backfill goes down from the same point (D4 rule 2).
            INSERT INTO sensitivity.cursors (surface, cursor_kind, detector_id, detector_version, lane,
                watermark_at, watermark_id, backfill_floor_at, backfill_floor_id)
            SELECT v_surface.surface, v_surface.cursor_kind, d.id, d.version, l.lane,
                   CASE WHEN l.lane = 'head' AND v_surface.cursor_kind = 'mutable_timestamp' THEN v_bound_at END,
                   CASE WHEN l.lane = 'head' THEN m.floor_id END,
                   CASE WHEN l.lane = 'backfill' AND v_surface.cursor_kind = 'mutable_timestamp' THEN v_bound_at END,
                   CASE WHEN l.lane = 'backfill' THEN m.floor_id END
              FROM sensitivity.detectors d
             CROSS JOIN (VALUES ('head'), ('backfill')) l(lane)
             CROSS JOIN (SELECT CASE WHEN v_surface.cursor_kind = 'mutable_timestamp'
                                     THEN 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid ELSE v_bound_id END) m(floor_id)
             WHERE d.enabled
            ON CONFLICT DO NOTHING;
            v_budget := least((v_job.payload ->> 'budget')::int, 100000);
            FOR v_lane IN SELECT * FROM sensitivity.scan_lane(p_run, v_surface, 'head', p_salt,
                                                             v_bound_at, v_bound_id, v_budget, v_deadline) LOOP
                v_budget := v_budget - v_lane.p_rows;
            END LOOP;
            PERFORM sensitivity.scan_lane(p_run, v_surface, 'backfill', p_salt,
                                          v_bound_at, v_bound_id, v_budget, v_deadline);
            UPDATE sensitivity.runs SET outcome = 'scanned', finished_at = clock_timestamp() WHERE id = p_run;
        EXCEPTION
            -- Never SQLERRM: a message can quote the row that raised it (D8 constraint 2). OTHERS
            -- does not match query_canceled, so the timeout is caught by name.
            WHEN query_canceled THEN
                v_code := 'statement_timeout';
            WHEN OTHERS THEN
                v_code := CASE WHEN SQLSTATE = '2201B' THEN 'detector_pattern_invalid'
                               WHEN SQLSTATE LIKE '23%' THEN 'store_constraint'
                               ELSE 'scan_failed' END;
        END;
    END IF;
    IF v_code IS NOT NULL THEN
        UPDATE sensitivity.runs SET outcome = 'failed', finished_at = clock_timestamp() WHERE id = p_run;
        PERFORM workflow_job_fail_system(p_job, 'sensitivity', 'sensitivity-sweep', v_code);
        failed := true;
    ELSE
        PERFORM workflow_job_complete_system(p_job, 'sensitivity', 'sensitivity-sweep');
    END IF;
    SELECT r.rows_examined, r.hashes_examined, r.cache_hits, r.new_findings, r.cursor_advances, r.units_oversize
      INTO rows_examined, hashes_examined, cache_hits, new_findings, cursor_advances, units_oversize
      FROM sensitivity.runs r WHERE r.id = p_run;
    RETURN NEXT;
END;
$$;

SELECT declare_migration(
    20261002200000,
    'additive',
    'The sensitivity sweep scan over its text surfaces: a two-phase tick (sensitivity_sweep_claim, then sensitivity_sweep_tick), a version-keyed memo, per-place observations for the mutable surfaces, fingerprints as children of a finding, and workflow_job_fail_system. Additive: findings.fingerprint is dropped, but no deployed binary names the sensitivity schema (the grep gate holds it); the new last_error CHECK constrains only the sensitivity persona, whose jobs no deployed binary runs; idx_kb_resources_updated_id and everything else is new.'
);
