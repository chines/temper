-- The sensitivity sweep's guarded store, detectors and validators (spec D1, D3-D7, Q15-Q21).
-- Rationale: temper-artifacts plans/2026-10-01-sensitivity-sweep-3a-core.md, PR B.

-- A deliberate exception to the baseline's namespace-free rule (20260624000001:14). The findings are
-- a cross-tenant enumeration oracle; no application query may name this schema, and a grep gate in
-- temper-services/tests holds that. One role migrates and serves, so it owns the schema and only
-- PUBLIC can be revoked (Q17).
CREATE SCHEMA sensitivity;

DO $$
BEGIN
    REVOKE ALL ON SCHEMA sensitivity FROM PUBLIC;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'REVOKE on schema sensitivity failed (%); the grep gate still holds.', SQLERRM;
END;
$$;

CREATE FUNCTION sensitivity.is_category(p text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT p IN ('national_id', 'payment_card', 'credential', 'contact', 'financial', 'health',
                 'secret_material', 'identifier');
$$;

CREATE FUNCTION sensitivity.is_category_tally(p jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT jsonb_typeof(p) = 'object'
       AND NOT EXISTS (
           SELECT 1 FROM jsonb_each(p) e
            WHERE NOT sensitivity.is_category(e.key)
               OR jsonb_typeof(e.value) <> 'number'
               OR e.value::text !~ '^[0-9]{1,6}$');
$$;

-- A detector's regexes must compile and must not match the empty string, which would count every
-- position. An invalid regex raises here, at write time, rather than mid-scan.
CREATE FUNCTION sensitivity.is_usable_pattern(p text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT '' !~ p;
$$;

CREATE TABLE sensitivity.surfaces (
    surface     text PRIMARY KEY CHECK (surface ~ '^kb_[a-z0-9_]{1,60}\.[a-z][a-z0-9_]{0,62}$'),
    cursor_kind text CHECK (cursor_kind IN ('append_only_v7', 'mutable_timestamp')),
    enabled     boolean NOT NULL DEFAULT false,
    CONSTRAINT surfaces_enabled_needs_cursor CHECK (NOT enabled OR cursor_kind IS NOT NULL),
    UNIQUE (surface, cursor_kind)
);

CREATE TABLE sensitivity.detectors (
    id        text PRIMARY KEY CHECK (id ~ '^[a-z][a-z0-9_]{1,62}$'),
    version   int NOT NULL DEFAULT 1 CHECK (version >= 1),
    category  text NOT NULL CHECK (sensitivity.is_category(category)),
    severity  smallint NOT NULL CHECK (severity BETWEEN 1 AND 4),
    prefilter text NOT NULL,
    pattern   text NOT NULL,
    validator text CHECK (validator IN ('ssn_valid', 'luhn_valid', 'aba_routing_valid')),
    enabled   boolean NOT NULL DEFAULT true,
    note      text NOT NULL,
    CONSTRAINT detectors_patterns_usable
        CHECK (sensitivity.is_usable_pattern(prefilter) AND sensitivity.is_usable_pattern(pattern))
);

-- One row per value, per detector version, per place (Q22): a decision about one place never
-- silences another. Text columns are held to non-prose shapes and counts to six digits; a hex hash,
-- a fingerprint or a uuid can still carry digits if a writer mis-binds, which is the writer's contract.
CREATE TABLE sensitivity.findings (
    id               uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    surface          text NOT NULL REFERENCES sensitivity.surfaces (surface),
    target_table     text NOT NULL CHECK (target_table ~ '^kb_[a-z0-9_]{1,60}$'),
    target_id        uuid NOT NULL,
    resource_id      uuid,
    content_hash     text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    detector_id      text NOT NULL REFERENCES sensitivity.detectors (id),
    detector_version int NOT NULL CHECK (detector_version >= 1),
    category         text NOT NULL CHECK (sensitivity.is_category(category)),
    severity         smallint NOT NULL CHECK (severity BETWEEN 1 AND 4),
    match_count      int NOT NULL CHECK (match_count BETWEEN 1 AND 100000),
    fingerprint      bytea CHECK (octet_length(fingerprint) = 32),
    first_seen       timestamptz NOT NULL DEFAULT now(),
    last_seen        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (surface, target_id, content_hash, detector_id, detector_version)
);

COMMENT ON TABLE sensitivity.findings IS
    'Pointers and categories, never content: no excerpt, sample, offset or window. A byte range plus '
    'read access is an extraction primitive, and the reviewer already has the resource id. A test '
    'asserts this exact column set; read spec D1 before adding a column.';

-- A mutable_timestamp watermark is the tuple (updated, id): updated alone skips rows that share a
-- timestamp across a LIMIT boundary (Q20). The composite FK keeps cursor_kind equal to the surface's.
CREATE TABLE sensitivity.cursors (
    surface               text NOT NULL,
    cursor_kind           text NOT NULL,
    detector_id           text NOT NULL REFERENCES sensitivity.detectors (id),
    detector_version      int NOT NULL CHECK (detector_version >= 1),
    lane                  text NOT NULL CHECK (lane IN ('head', 'backfill')),
    watermark_at          timestamptz,
    watermark_id          uuid,
    backfill_floor_at     timestamptz,
    backfill_floor_id     uuid,
    backfill_completed_at timestamptz,
    updated               timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (surface, detector_id, detector_version, lane),
    FOREIGN KEY (surface, cursor_kind) REFERENCES sensitivity.surfaces (surface, cursor_kind),
    CONSTRAINT cursors_watermark_shape CHECK (CASE cursor_kind
        WHEN 'mutable_timestamp' THEN num_nonnulls(watermark_at, watermark_id) IN (0, 2)
                                  AND num_nonnulls(backfill_floor_at, backfill_floor_id) IN (0, 2)
        ELSE watermark_at IS NULL AND backfill_floor_at IS NULL
    END),
    CONSTRAINT cursors_backfill_lane_only CHECK (
        lane = 'backfill'
        OR num_nonnulls(backfill_floor_at, backfill_floor_id, backfill_completed_at) = 0)
);

CREATE TABLE sensitivity.runs (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    surface         text NOT NULL REFERENCES sensitivity.surfaces (surface),
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz CHECK (finished_at >= started_at),
    rows_examined   int NOT NULL DEFAULT 0 CHECK (rows_examined BETWEEN 0 AND 100000),
    hashes_examined int NOT NULL DEFAULT 0 CHECK (hashes_examined BETWEEN 0 AND 100000),
    cache_hits      int NOT NULL DEFAULT 0 CHECK (cache_hits BETWEEN 0 AND 100000),
    new_findings    int NOT NULL DEFAULT 0 CHECK (new_findings BETWEEN 0 AND 100000),
    cursor_advances int NOT NULL DEFAULT 0 CHECK (cursor_advances BETWEEN 0 AND 100000),
    by_category     jsonb NOT NULL DEFAULT '{}' CHECK (sensitivity.is_category_tally(by_category))
);

-- Append-only; "open" is the absence of a row (Q21). A false positive names the matched value by
-- fingerprint or content hash, so one ruling clears it everywhere; every other state names a finding.
CREATE TABLE sensitivity.dispositions (
    id           uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    state        text NOT NULL
                 CHECK (state IN ('acknowledged', 'actioned', 'accepted_risk', 'false_positive')),
    finding_id   uuid REFERENCES sensitivity.findings (id),
    detector_id  text REFERENCES sensitivity.detectors (id),
    fingerprint  bytea CHECK (octet_length(fingerprint) = 32),
    content_hash text CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    expires_at   timestamptz,
    decided_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT dispositions_expiry_iff_accepted_risk
        CHECK ((state = 'accepted_risk') = (expires_at IS NOT NULL)),
    CONSTRAINT dispositions_subject CHECK (CASE state
        WHEN 'false_positive' THEN finding_id IS NULL AND detector_id IS NOT NULL
                               AND num_nonnulls(fingerprint, content_hash) = 1
        ELSE finding_id IS NOT NULL AND num_nonnulls(detector_id, fingerprint, content_hash) = 0
    END)
);

CREATE FUNCTION sensitivity.dispositions_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'sensitivity.dispositions is append-only';
END;
$$;

CREATE TRIGGER dispositions_append_only
    BEFORE DELETE OR UPDATE ON sensitivity.dispositions
    FOR EACH ROW EXECUTE FUNCTION sensitivity.dispositions_append_only();

-- Validators take the whole match and read only its digits. The pattern nominates; these adjudicate.
CREATE FUNCTION sensitivity.ssn_valid(p_match text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT d ~ '^[0-9]{9}$'
       AND left(d, 3) NOT IN ('000', '666') AND left(d, 1) <> '9'
       AND substr(d, 4, 2) <> '00' AND right(d, 4) <> '0000'
       AND d NOT IN ('078051120', '219099999', '123456789')
      FROM (SELECT regexp_replace(p_match, '[^0-9]', '', 'g') AS d) m;
$$;

CREATE FUNCTION sensitivity.luhn_valid(p_match text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE
    d   text := regexp_replace(p_match, '[^0-9]', '', 'g');
    n   int;
    sum int := 0;
BEGIN
    IF length(d) NOT BETWEEN 13 AND 19 OR d ~ '^0+$' THEN
        RETURN false;
    END IF;
    FOR i IN 1 .. length(d) LOOP
        n := substr(d, length(d) - i + 1, 1)::int;
        IF i % 2 = 0 THEN
            n := CASE WHEN n * 2 > 9 THEN n * 2 - 9 ELSE n * 2 END;
        END IF;
        sum := sum + n;
    END LOOP;
    RETURN sum % 10 = 0;
END;
$$;

CREATE FUNCTION sensitivity.aba_routing_valid(p_match text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT CASE WHEN d !~ '^[0-9]{9}$' OR d = '000000000' THEN false ELSE
           (3 * (substr(d, 1, 1)::int + substr(d, 4, 1)::int + substr(d, 7, 1)::int)
          + 7 * (substr(d, 2, 1)::int + substr(d, 5, 1)::int + substr(d, 8, 1)::int)
          +     (substr(d, 3, 1)::int + substr(d, 6, 1)::int + substr(d, 9, 1)::int)) % 10 = 0
           END
      FROM (SELECT regexp_replace(p_match, '[^0-9]', '', 'g') AS d) m;
$$;

-- One evaluation of a detector over a text, returning a count and nothing else: the tick and the
-- witnesses share it. The pattern is wrapped in a group so m[1] is the whole match.
CREATE FUNCTION sensitivity.detector_match_count(p_detector text, p_text text) RETURNS int
LANGUAGE sql STABLE STRICT AS $$
    SELECT CASE WHEN p_text !~ d.prefilter THEN 0 ELSE (
        SELECT count(*)::int
          FROM regexp_matches(p_text, '(' || d.pattern || ')', 'g') m
         WHERE CASE d.validator
                   WHEN 'ssn_valid'         THEN sensitivity.ssn_valid(m[1])
                   WHEN 'luhn_valid'        THEN sensitivity.luhn_valid(m[1])
                   WHEN 'aba_routing_valid' THEN sensitivity.aba_routing_valid(m[1])
                   ELSE true
               END)
    END
      FROM sensitivity.detectors d
     WHERE d.id = p_detector;
$$;

-- Every `scan` line of scripts/sensitivity-scan-surface.txt (a test holds the two equal). Enabled:
-- D3's first cut, less kb_blobs.blob_pathname (declared structural) and kb_workflow_jobs.last_error
-- (reap rewrites it on old ids, so no append-only cursor can see it).
INSERT INTO sensitivity.surfaces (surface, cursor_kind, enabled) VALUES
    ('kb_block_content.content',                   'append_only_v7',    true),
    ('kb_chunk_content.content',                   'append_only_v7',    true),
    ('kb_chunks.header_path',                      'append_only_v7',    true),
    ('kb_resources.title',                         'mutable_timestamp', true),
    ('kb_resources.origin_uri',                    'mutable_timestamp', true),
    ('kb_properties.property_key',                 'append_only_v7',    true),
    ('kb_edges.label',                             'append_only_v7',    true),
    ('kb_citation_audits.reason',                  'append_only_v7',    true),
    ('kb_remote_sources.uri',                      'append_only_v7',    true),
    ('kb_ingestion_records.source_uri',            NULL,                false),
    ('kb_workflow_jobs.last_error',                NULL,                false),
    ('kb_teams.description',                       NULL,                false),
    ('kb_contexts.name',                           NULL,                false),
    ('kb_cogmaps.name',                            NULL,                false),
    ('kb_cogmap_lenses.name',                      NULL,                false),
    ('kb_cogmap_regions.label',                    NULL,                false),
    ('kb_join_requests.message',                   NULL,                false),
    ('kb_join_requests.decision_note',             NULL,                false),
    ('kb_principal_review_requests.message',       NULL,                false),
    ('kb_principal_review_requests.decision_note', NULL,                false),
    ('kb_principal_standing_events.reason',        NULL,                false),
    ('kb_subscription_deliveries.rationale',       NULL,                false),
    ('kb_subscription_deliveries.scope_reason',    NULL,                false),
    ('kb_connections.reach_affirmation',           NULL,                false);

-- Cut 1's corpus (D5, Q18). No `contact` detector: email is deferred (Q16).
-- Cards match whole groupings: a loose `[ -]?` lets the longest match absorb an adjacent CVV or
-- expiry, Luhn then rejects the whole run, and no shorter match is tried.
INSERT INTO sensitivity.detectors (id, category, severity, prefilter, pattern, validator, note) VALUES
    ('private_key_block', 'secret_material', 4, 'PRIVATE KEY',
     '-----BEGIN [A-Z ]*PRIVATE KEY-----', NULL, 'PEM private key header'),
    ('cloud_saas_key', 'credential', 4, 'AKIA|gh[pos]_|xox[baprs]-|sk_live_|sk-ant-',
     'AKIA[0-9A-Z]{16}|gh[pos]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{16,}|sk-ant-[A-Za-z0-9_-]{20,}',
     NULL, 'provider-prefixed keys: AWS, GitHub, Slack, Stripe, Anthropic'),
    ('connection_string_password', 'credential', 4, '://',
     '[A-Za-z][A-Za-z0-9+.-]*://[^:/@[:space:]]+:[^@/[:space:]]+@', NULL,
     'a URL carrying user:password@'),
    ('jwt', 'credential', 3, 'eyJ',
     'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', NULL,
     'three base64url segments, JSON header'),
    ('payment_card', 'payment_card', 4, '[0-9]{4}',
     '(?<![0-9])([0-9]{13,19}|[0-9]{4}( [0-9]{4}){3}|[0-9]{4}(-[0-9]{4}){3}|[0-9]{4} [0-9]{6} [0-9]{4,5}|[0-9]{4}-[0-9]{6}-[0-9]{4,5})(?![0-9])',
     'luhn_valid', 'contiguous, or in card groupings with one separator, behind Luhn'),
    ('aba_routing', 'financial', 3, '[Rr][Oo][Uu][Tt][Ii][Nn][Gg]|ABA|aba|RTN|rtn',
     '([Rr][Oo][Uu][Tt][Ii][Nn][Gg]|(?<![A-Za-z])(ABA|aba|RTN|rtn)(?![A-Za-z]))[^0-9]{0,20}(?<![0-9])[0-9]{9}(?![0-9])',
     'aba_routing_valid', 'nine digits after a routing keyword, ABA mod-10'),
    ('us_ssn_delimited', 'national_id', 4, '[0-9]{3}[- ][0-9]{2}[- ][0-9]{4}',
     '(?<![0-9-])([0-9]{3}-[0-9]{2}-[0-9]{4}|[0-9]{3} [0-9]{2} [0-9]{4})(?![0-9-])', 'ssn_valid',
     'NNN-NN-NNNN or NNN NN NNNN; the delimiter is what makes default-on tolerable'),
    ('us_ssn_contextual', 'national_id', 4, '[Ss][Ss][Nn]|[Ss]ocial [Ss]ecurity',
     '([Ss][Ss][Nn]|[Ss]ocial [Ss]ecurity)[^0-9]{0,20}(?<![0-9])[0-9]{9}(?![0-9])', 'ssn_valid',
     'nine bare digits within 20 characters after an SSN keyword'),
    ('local_path_username', 'identifier', 1, '/Users/|/home/|:\\Users\\',
     '(/Users/|/home/|[A-Za-z]:\\Users\\)[A-Za-z0-9._-]+', NULL,
     'a home directory naming its user');

-- Q19: the SQL enqueue refuses a sensitivity surface that is not enabled. It checks AFTER the insert,
-- so the work-order CHECK still answers first for a malformed payload. Prior body: 20261001213010.
CREATE OR REPLACE FUNCTION workflow_job_enqueue_system(
    p_persona text, p_dispatch_type text, p_payload jsonb
) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE
    v_id uuid;
BEGIN
    INSERT INTO kb_workflow_jobs (persona, dispatch_type, payload)
    VALUES (p_persona, p_dispatch_type, p_payload)
    ON CONFLICT DO NOTHING
    RETURNING id INTO v_id;
    IF p_persona = 'sensitivity' AND NOT EXISTS (
        SELECT 1 FROM sensitivity.surfaces s
         WHERE s.surface = p_payload ->> 'surface' AND s.enabled
    ) THEN
        RAISE EXCEPTION 'sensitivity surface is not enabled' USING ERRCODE = 'check_violation';
    END IF;
    RETURN v_id;
END;
$$;

SELECT declare_migration(
    20261002160000,
    'additive',
    'The sensitivity sweep''s store: schema sensitivity with surfaces, detectors, findings, cursors, runs and append-only dispositions; nine seeded detectors; the ssn/luhn/aba validators and detector_match_count. workflow_job_enqueue_system now refuses a sensitivity surface that is not enabled. Additive: everything else is new, and no deployed binary enqueues a sensitivity job.'
);
