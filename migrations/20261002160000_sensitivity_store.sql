-- The sensitivity sweep's guarded store, detectors and validators (spec D1, D3-D7, Q15-Q27).
-- Rationale: temper-artifacts plans/2026-10-01-sensitivity-sweep-3a-core.md, PR B.

-- An exception to the namespace-free baseline (20260624000001:14): the findings are a cross-tenant
-- enumeration oracle, so no application code names this schema (a grep gate holds it). One role
-- migrates and serves, so only PUBLIC can be revoked (Q17).
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
               OR e.value::text !~ '^[0-9]{1,6}$'
               OR e.value::text::int > 100000);
$$;

-- Compiled bare (the prefilter's form) and wrapped in a group (the scan's), so a bad regex raises at
-- write time. A backreference is refused: the wrapping group renumbers it.
CREATE FUNCTION sensitivity.is_usable_pattern(p text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT CASE WHEN p ~ '\\[1-9]' THEN false
                ELSE '' !~ p AND '' !~ ('(' || p || ')') END;
$$;

CREATE FUNCTION sensitivity.append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'sensitivity.% is append-only', TG_TABLE_NAME;
END;
$$;

-- shape: a jsonb surface's findings carry a path into the document (Q26).
CREATE TABLE sensitivity.surfaces (
    surface     text PRIMARY KEY CHECK (surface ~ '^kb_[a-z0-9_]{1,60}\.[a-z][a-z0-9_]{0,62}$'),
    shape       text NOT NULL CHECK (shape IN ('text', 'jsonb')),
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

-- A finding names the version that produced it (Q27). A validator's body is invisible to the
-- trigger: a migration that edits one must bump every detector naming it.
CREATE TABLE sensitivity.detector_versions (
    detector_id text NOT NULL REFERENCES sensitivity.detectors (id),
    version     int NOT NULL CHECK (version >= 1),
    category    text NOT NULL,
    prefilter   text NOT NULL,
    pattern     text NOT NULL,
    validator   text,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (detector_id, version)
);

CREATE TRIGGER detector_versions_append_only
    BEFORE DELETE OR UPDATE ON sensitivity.detector_versions
    FOR EACH ROW EXECUTE FUNCTION sensitivity.append_only();

CREATE FUNCTION sensitivity.detectors_versioned() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.version < OLD.version
           OR (NEW.version = OLD.version
               AND (NEW.category, NEW.prefilter, NEW.pattern, NEW.validator)
                   IS DISTINCT FROM (OLD.category, OLD.prefilter, OLD.pattern, OLD.validator)) THEN
            RAISE EXCEPTION 'a detector''s category, prefilter, pattern or validator changes only with a version bump'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.version = OLD.version THEN
            RETURN NEW;
        END IF;
    END IF;
    INSERT INTO sensitivity.detector_versions (detector_id, version, category, prefilter, pattern, validator)
    VALUES (NEW.id, NEW.version, NEW.category, NEW.prefilter, NEW.pattern, NEW.validator);
    RETURN NEW;
END;
$$;

CREATE TRIGGER detectors_versioned
    AFTER INSERT OR UPDATE ON sensitivity.detectors
    FOR EACH ROW EXECUTE FUNCTION sensitivity.detectors_versioned();

-- One row per scanned unit, per detector version, per place: (surface, target_id, path) (Q22, Q26).
-- A hash, fingerprint or uuid can still carry digits if a writer mis-binds, and a key from a
-- user-authored map must be written `?`: both are the writer's contract.
CREATE TABLE sensitivity.findings (
    id               uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    surface          text NOT NULL REFERENCES sensitivity.surfaces (surface),
    target_table     text NOT NULL CHECK (target_table ~ '^kb_[a-z0-9_]{1,60}$'),
    target_id        uuid NOT NULL,
    path             text CHECK (path ~ '^(/([a-z_]{1,63}|\*|\?)){1,16}$'),
    resource_id      uuid,
    content_hash     text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    detector_id      text NOT NULL,
    detector_version int NOT NULL CHECK (detector_version >= 1),
    category         text NOT NULL CHECK (sensitivity.is_category(category)),
    severity         smallint NOT NULL CHECK (severity BETWEEN 1 AND 4),
    match_count      int NOT NULL CHECK (match_count BETWEEN 1 AND 100000),
    fingerprint      bytea CHECK (octet_length(fingerprint) = 32),
    first_seen       timestamptz NOT NULL DEFAULT now(),
    last_seen        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (detector_id, detector_version)
        REFERENCES sensitivity.detector_versions (detector_id, version),
    CONSTRAINT findings_target_table_is_the_surfaces CHECK (target_table = split_part(surface, '.', 1)),
    UNIQUE NULLS NOT DISTINCT (surface, target_id, path, content_hash, detector_id, detector_version)
);

-- A CHECK cannot read surfaces; an unknown surface is left to the foreign key.
CREATE FUNCTION sensitivity.findings_path_fits_shape() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM sensitivity.surfaces s
                WHERE s.surface = NEW.surface AND (s.shape = 'jsonb') <> (NEW.path IS NOT NULL)) THEN
        RAISE EXCEPTION 'a finding carries a path exactly when its surface is jsonb'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'findings_path_fits_shape';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER findings_path_fits_shape
    BEFORE INSERT OR UPDATE ON sensitivity.findings
    FOR EACH ROW EXECUTE FUNCTION sensitivity.findings_path_fits_shape();

COMMENT ON TABLE sensitivity.findings IS
    'Pointers and categories, never content: no excerpt, sample, offset or window. A byte range plus '
    'read access is an extraction primitive, and the reviewer already has the resource id. A test '
    'asserts this exact column set; read spec D1 before adding a column.';

-- A mutable_timestamp watermark is the tuple (updated, id) (Q20). backfill_floor_* is where this
-- detector version's history stops: the head lane's start.
CREATE TABLE sensitivity.cursors (
    surface               text NOT NULL,
    cursor_kind           text NOT NULL,
    detector_id           text NOT NULL,
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
    FOREIGN KEY (detector_id, detector_version)
        REFERENCES sensitivity.detector_versions (detector_id, version),
    CONSTRAINT cursors_watermark_shape CHECK (CASE cursor_kind
        WHEN 'mutable_timestamp' THEN num_nonnulls(watermark_at, watermark_id) IN (0, 2)
                                  AND num_nonnulls(backfill_floor_at, backfill_floor_id) IN (0, 2)
        WHEN 'append_only_v7' THEN watermark_at IS NULL AND backfill_floor_at IS NULL
        ELSE false
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

-- Append-only; "open" is the absence of a row (Q21). Every state is about one finding (Q25): a value
-- benign everywhere is a versioned detector change, not a disposition.
CREATE TABLE sensitivity.dispositions (
    id         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    finding_id uuid NOT NULL REFERENCES sensitivity.findings (id),
    state      text NOT NULL
               CHECK (state IN ('acknowledged', 'actioned', 'accepted_risk', 'false_positive')),
    expires_at timestamptz,
    decided_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT dispositions_expiry_iff_accepted_risk
        CHECK ((state = 'accepted_risk') = (expires_at IS NOT NULL)),
    CONSTRAINT dispositions_expiry_after_decision CHECK (expires_at > decided_at)
);

CREATE TRIGGER dispositions_append_only
    BEFORE DELETE OR UPDATE ON sensitivity.dispositions
    FOR EACH ROW EXECUTE FUNCTION sensitivity.append_only();

-- A writer's future decided_at would silence a finding for good under Q22's coverage rule.
CREATE FUNCTION sensitivity.dispositions_decided_now() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.decided_at := now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER dispositions_decided_now
    BEFORE INSERT ON sensitivity.dispositions
    FOR EACH ROW EXECUTE FUNCTION sensitivity.dispositions_decided_now();

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

-- The one evaluation of a detector, shared by the tick and the witnesses. An empty match is not a
-- match, and the count stops at the store's ceiling so one huge row cannot wedge a tick.
CREATE FUNCTION sensitivity.detector_match_count(p_detector text, p_text text) RETURNS int
LANGUAGE sql STABLE STRICT AS $$
    SELECT CASE WHEN p_text !~ d.prefilter THEN 0 ELSE (
        SELECT least(count(*), 100000)::int
          FROM regexp_matches(p_text, '(' || d.pattern || ')', 'g') m
         WHERE m[1] <> ''
           AND CASE d.validator
                   WHEN 'ssn_valid'         THEN sensitivity.ssn_valid(m[1])
                   WHEN 'luhn_valid'        THEN sensitivity.luhn_valid(m[1])
                   WHEN 'aba_routing_valid' THEN sensitivity.aba_routing_valid(m[1])
                   ELSE true
               END)
    END
      FROM sensitivity.detectors d
     WHERE d.id = p_detector;
$$;

-- Every scan line (text) and incidental line (jsonb) of the two manifests (Q19, Q26). Enabled: D3's
-- first cut and its three documents, less kb_blobs.blob_pathname (structural) and
-- kb_workflow_jobs.last_error (reap rewrites old ids, Q24).
INSERT INTO sensitivity.surfaces (surface, shape, cursor_kind, enabled) VALUES
    ('kb_block_content.content',                   'text',  'append_only_v7',    true),
    ('kb_chunk_content.content',                   'text',  'append_only_v7',    true),
    ('kb_chunks.header_path',                      'text',  'append_only_v7',    true),
    ('kb_resources.title',                         'text',  'mutable_timestamp', true),
    ('kb_resources.origin_uri',                    'text',  'mutable_timestamp', true),
    ('kb_properties.property_key',                 'text',  'append_only_v7',    true),
    ('kb_edges.label',                             'text',  'append_only_v7',    true),
    ('kb_citation_audits.reason',                  'text',  'append_only_v7',    true),
    ('kb_remote_sources.uri',                      'text',  'append_only_v7',    true),
    ('kb_ingestion_records.source_uri',            'text',  NULL,                false),
    ('kb_workflow_jobs.last_error',                'text',  NULL,                false),
    ('kb_teams.description',                       'text',  NULL,                false),
    ('kb_contexts.name',                           'text',  NULL,                false),
    ('kb_cogmaps.name',                            'text',  NULL,                false),
    ('kb_cogmap_lenses.name',                      'text',  NULL,                false),
    ('kb_cogmap_regions.label',                    'text',  NULL,                false),
    ('kb_join_requests.message',                   'text',  NULL,                false),
    ('kb_join_requests.decision_note',             'text',  NULL,                false),
    ('kb_principal_review_requests.message',       'text',  NULL,                false),
    ('kb_principal_review_requests.decision_note', 'text',  NULL,                false),
    ('kb_principal_standing_events.reason',        'text',  NULL,                false),
    ('kb_subscription_deliveries.rationale',       'text',  NULL,                false),
    ('kb_subscription_deliveries.scope_reason',    'text',  NULL,                false),
    ('kb_connections.reach_affirmation',           'text',  NULL,                false),
    ('kb_events.payload',                          'jsonb', 'append_only_v7',    true),
    ('kb_events.metadata',                         'jsonb', 'append_only_v7',    true),
    ('kb_properties.property_value',               'jsonb', 'append_only_v7',    true),
    ('kb_profiles.preferences',                    'jsonb', NULL,                false),
    ('kb_entities.metadata',                       'jsonb', NULL,                false),
    ('kb_workflow_jobs.payload',                   'jsonb', NULL,                false),
    ('kb_invocations.outcome',                     'jsonb', NULL,                false),
    ('kb_connections.credential',                  'jsonb', NULL,                false),
    ('kb_connections.observed_reach',              'jsonb', NULL,                false),
    ('kb_data_artifact_verdicts.detail',           'jsonb', NULL,                false);

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
    'Store for the sensitivity sweep: schema sensitivity with surfaces, detectors and their versions, findings, cursors, runs and append-only dispositions; nine seeded detectors; the ssn/luhn/aba validators and detector_match_count. workflow_job_enqueue_system now refuses a sensitivity surface that is not enabled. Additive: everything else is new, and no deployed binary enqueues a sensitivity job.'
);
