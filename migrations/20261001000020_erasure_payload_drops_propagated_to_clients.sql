-- The principal_erased and resource_erased payloads drop `propagated_to_clients` (ruled
-- 2026-10-01). The key named a client-propagation mechanism that does not exist and that no
-- design plans; no code read it. An event already carrying it stays valid against the
-- re-registered schemas (point 1).
--
-- 1. The principal_erased and resource_erased payload_schemas (registered by 20260909000015
--    and 20260929000010) are re-registered without the property. Each literal below is the
--    registered one with only that property removed, and equals, as JSON, its committed
--    fixture (`principal_erased.v1.schema.json`, then `resource_erased.v1.schema.json`);
--    `payload_schema::the_migration_literal_matches_the_committed_fixture` pins both, in this
--    order. The property was never required and neither schema sets additionalProperties, so
--    the version stays 1.
-- 2. principal_erasure_execute (body: 20260913000010) and resource_erasure_execute (body:
--    20260930000070) are re-created verbatim, except that each completion payload's
--    jsonb_build_object no longer writes the key, and principal_erasure_execute's comment
--    sentence about it is gone. Neither function COMMENT names the key, so both stand.

UPDATE kb_event_types
   SET payload_schema = $JS$
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "PrincipalErased",
  "description": "`principal_erased` — the ONE admin event of a completed erasure (erasure spec D1).\n\nONE TYPE for identity erasure and content erasure: the distinction rides the per-target\noutcomes as data, never the type boundary — two types would cost the pairing (one request,\none operator, one reference) and double registration for no additional guarantee. The\nsubject is the PSEUDONYM the act itself broke; the event never re-identifies — no name, no\nemail, no case description. The request reference does not ride here: it lives on\n`kb_events.\"references\"`, the apparatus this act owns.\n\nThe redacted set is keyed on CONTENT HASH (D2) — never row ids, which would collide with\nthe trail functions' join-key shapes. The erased-content set (D4) rebuilds from these\npayloads alone.",
  "type": "object",
  "properties": {
    "actor": {
      "description": "The acting operator, distinguishable from the subject — self-serve vs administrative\nis a comparison the auditor needs. `None` only where no actor exists to name; inventing\none would put a fabricated attribution on the ledger (the standing-event precedent).",
      "anyOf": [
        {
          "$ref": "#/$defs/ProfileId"
        },
        {
          "type": "null"
        }
      ]
    },
    "redacted_hashes": {
      "description": "The redacted set (D2): bare sha256 hex, exactly as `content_hash` carries it — the key\nevery reader already shares and no trail join-key shape can match.",
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "subject_id": {
      "description": "The pseudonym — `kb_profiles.id`. It survives; its identifying power does not (D5).",
      "type": "string",
      "format": "uuid"
    },
    "subject_table": {
      "$ref": "#/$defs/AnchorTable"
    },
    "targets": {
      "description": "Per-target outcomes and the named remainder (D6's accepted-in-part arm): anything\nunhonourable is named here. Partial completion is data, never a silent success.",
      "type": "array",
      "items": {
        "$ref": "#/$defs/ErasureTargetOutcome"
      }
    }
  },
  "required": [
    "subject_table",
    "subject_id"
  ],
  "$defs": {
    "AnchorTable": {
      "description": "A polymorphic anchor/endpoint reference. Serializes table names exactly as the DDL spells them.",
      "type": "string",
      "enum": [
        "kb_contexts",
        "kb_cogmaps",
        "kb_resources",
        "kb_edges",
        "kb_content_blocks",
        "kb_teams",
        "kb_profiles",
        "kb_connections",
        "kb_machine_clients",
        "kb_blobs",
        "kb_events"
      ]
    },
    "ErasureTargetOutcome": {
      "description": "One target of a completed erasure and what happened to it (erasure spec, \"per-target\noutcomes\"). The target names itself the way the personal-data manifest does — `table` or\n`table.column`; the outcome is the act's own record of what redaction applied. Deliberately\nopen-textured in v1: ceilings are DATA, not types (D1), and the per-target vocabulary is the\nexecution build's to pin. `unhonourable_scope` outcomes land here, never silent.",
      "type": "object",
      "properties": {
        "outcome": {
          "description": "What the act did to it (erased / sentinel-scrubbed / accepted-in-part / …).",
          "type": "string"
        },
        "target": {
          "description": "Manifest identity of the target (`kb_profiles.display_name`, `kb_teams.slug`, …).",
          "type": "string"
        }
      },
      "required": [
        "target",
        "outcome"
      ]
    },
    "ProfileId": {
      "description": "A `kb_profiles.id` value.",
      "type": "string",
      "format": "uuid"
    }
  }
}
$JS$::jsonb
 WHERE name = 'principal_erased';

UPDATE kb_event_types
   SET payload_schema = $JS$
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ResourceErased",
  "description": "`resource_erased` — the ONE admin event of a completed resource erasure (resource erasure\nspec D1).\n\nThe subject is keyed `subject_table` / `subject_id`, NEVER `resource_id`:\n`element_trail_node` joins on `payload->>'resource_id'`, and an admin payload never carries a\ntrail join-key shape, so the category firewall is not the only layer. The same rule keys\n`folded_edges` (not `edge_id`) and `RedactedEventFields::event` (not `event_id`).\n\nTwo remainders, deliberately separate: `remainder` names what the act leaves untouched by\ndesign (related blobs, derivers, cross-resource ledger text, shared remote-source URLs — D8),\nand `ledger_remainder` names the resource's OWN ledger paths the act has not yet reached (D12:\nevery one of them before sanctioned field redaction ships, none after it). The completion pass\nreads `ledger_remainder`, never `remainder`.",
  "type": "object",
  "properties": {
    "actor": {
      "description": "The acting system admin. `None` only where no actor exists to name.",
      "anyOf": [
        {
          "$ref": "#/$defs/ProfileId"
        },
        {
          "type": "null"
        }
      ]
    },
    "folded_edges": {
      "description": "The edges this act ended, each by its own `relationship_folded` event under the act's\ncorrelation id (D1).",
      "type": "array",
      "items": {
        "$ref": "#/$defs/EdgeId"
      }
    },
    "ledger_remainder": {
      "description": "The resource's own ledger paths the act has not reached yet (D12), in exactly the shape\n`redacted_fields` uses. The completion pass re-derives against the live ledger rather than\ntrusting this list blindly.",
      "type": "array",
      "items": {
        "$ref": "#/$defs/RedactedEventFields"
      }
    },
    "redacted_fields": {
      "description": "The ledger paths this act redacted to their sentinels (D3). Empty until sanctioned field\nredaction ships (D12).",
      "type": "array",
      "items": {
        "$ref": "#/$defs/RedactedEventFields"
      }
    },
    "remainder": {
      "description": "What the act names but does not touch, by design (D8). Never silent.",
      "type": "array",
      "items": {
        "$ref": "#/$defs/ErasureTargetOutcome"
      }
    },
    "subject_id": {
      "type": "string",
      "format": "uuid"
    },
    "subject_table": {
      "description": "Always `kb_resources`.",
      "$ref": "#/$defs/AnchorTable"
    },
    "targets": {
      "description": "Per-target outcomes, the principal act's template.",
      "type": "array",
      "items": {
        "$ref": "#/$defs/ErasureTargetOutcome"
      }
    }
  },
  "required": [
    "subject_table",
    "subject_id"
  ],
  "$defs": {
    "AnchorTable": {
      "description": "A polymorphic anchor/endpoint reference. Serializes table names exactly as the DDL spells them.",
      "type": "string",
      "enum": [
        "kb_contexts",
        "kb_cogmaps",
        "kb_resources",
        "kb_edges",
        "kb_content_blocks",
        "kb_teams",
        "kb_profiles",
        "kb_connections",
        "kb_machine_clients",
        "kb_blobs",
        "kb_events"
      ]
    },
    "EdgeId": {
      "description": "A `kb_edges.id` value — a declared relationship assertion.\n\nReturned by `Backend::assert_relationship` and fed back into\nretype/reweight/fold. Post-WS6-flip there is a single substrate-backed\nbackend, so this is always a real `kb_edges` row id (not a backend-opaque\ncorrelation handle).",
      "type": "string",
      "format": "uuid"
    },
    "ErasureTargetOutcome": {
      "description": "One target of a completed erasure and what happened to it (erasure spec, \"per-target\noutcomes\"). The target names itself the way the personal-data manifest does — `table` or\n`table.column`; the outcome is the act's own record of what redaction applied. Deliberately\nopen-textured in v1: ceilings are DATA, not types (D1), and the per-target vocabulary is the\nexecution build's to pin. `unhonourable_scope` outcomes land here, never silent.",
      "type": "object",
      "properties": {
        "outcome": {
          "description": "What the act did to it (erased / sentinel-scrubbed / accepted-in-part / …).",
          "type": "string"
        },
        "target": {
          "description": "Manifest identity of the target (`kb_profiles.display_name`, `kb_teams.slug`, …).",
          "type": "string"
        }
      },
      "required": [
        "target",
        "outcome"
      ]
    },
    "EventId": {
      "description": "A `kb_events.id` value. Always UUIDv7 (time-sortable).",
      "type": "string",
      "format": "uuid"
    },
    "ProfileId": {
      "description": "A `kb_profiles.id` value.",
      "type": "string",
      "format": "uuid"
    },
    "RedactedEventFields": {
      "description": "The ledger paths of one event: redacted (`redacted_fields`) or named-and-unreached\n(`ledger_remainder`). ONE shape for both, so the cut-2 completion pass derives what it redacts\nfrom what cut 1 recorded without translating (resource erasure spec D12). The event is keyed\n`event`, never `event_id` — no trail join-key shape rides an admin payload (D1). Paths only,\nnever values: the record of a redaction must not carry what was redacted.",
      "type": "object",
      "properties": {
        "event": {
          "$ref": "#/$defs/EventId"
        },
        "paths": {
          "description": "JSON paths within that event's `payload` (or `metadata`), e.g. `title`, `origin_uri`.",
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "required": [
        "event",
        "paths"
      ]
    }
  }
}
$JS$::jsonb
 WHERE name = 'resource_erased';

CREATE OR REPLACE FUNCTION principal_erasure_execute(
    p_subject     uuid,
    p_operator    uuid,
    p_emitter     uuid,
    p_request_ref uuid
) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
    v_plan    jsonb;
    v_targets jsonb;
    v_hashes  text[] := '{}';
    v_row     jsonb;
    v_bid uuid; v_rel boolean; v_path text;
    v_i    integer;
    v_ev   uuid;
BEGIN
    -- ONE computation per act. The existence RAISE lives in the plan (its message keeps the
    -- act's voice); the Rust gate resolves existence before either door is reached.
    v_plan := principal_erasure_survey_plan(p_subject);
    v_targets := v_plan->'targets';
    -- The plan's hash array comes back out IN ORDER (ORDINALITY makes the order load-bearing,
    -- not incidental): it is the redacted set the event carries, byte-identical to the
    -- pre-survey act's v_hashes assembly.
    v_hashes := (SELECT coalesce(array_agg(h ORDER BY ord), '{}')
                   FROM jsonb_array_elements_text(v_plan->'redacted_hashes')
                        WITH ORDINALITY AS t(h, ord));

    -- ── The strike loop: the plan's would-strike rows, IN ORDER, through the wrapper —
    -- per-row blob_delete('blob_erased', …) events exactly as before (the pairing with the
    -- completion is a fact, D1). Each structured entry is replaced IN PLACE with the prose
    -- built from the WRAPPER'S verdict — authoritative at strike time; the plan's
    -- released_would_be was a prediction and is discarded here.
    FOR v_i IN 0 .. jsonb_array_length(v_targets) - 1 LOOP
        v_row := v_targets->v_i->'would_strike';
        IF v_row IS NOT NULL THEN
            SELECT blob_id, released, pathname
              INTO v_bid, v_rel, v_path
              FROM blob_delete('blob_erased',
                               jsonb_build_object('blob_id', (v_row->>'blob_id')::uuid),
                               p_emitter,
                               p_correlation => p_request_ref);
            v_targets := jsonb_set(v_targets, ARRAY[v_i::text],
                jsonb_build_object(
                    'target',  'kb_blobs',
                    'outcome', blob_strike_outcome_text(v_rel, v_path)));
        END IF;
    END LOOP;

    -- ── The ONE completion event (D1). NULL-anchored (admin); emitter = the OPERATOR;
    -- references carry the subject (the precedent) and the request reference (rel
    -- `request`); the correlation id is the request reference — the pairing of this event
    -- with its per-row strikes is a FACT, not a convention (D1).
    v_ev := _event_append(
        'principal_erased', p_emitter, NULL, NULL,
        jsonb_build_object(
            'subject_table',        'kb_profiles',
            'subject_id',           p_subject,
            'actor',                p_operator,
            'redacted_hashes',      to_jsonb(v_hashes),
            'targets',              v_targets),
        p_references => jsonb_build_array(
            jsonb_build_object('rel','subject',
                'target', jsonb_build_object('kind','kb_profiles','id', p_subject)),
            jsonb_build_object('rel','request',
                'target', jsonb_build_object('kind','kb_events','id', p_request_ref))),
        p_correlation => p_request_ref);

    -- ── The tombstone machinery, the ONE definition ─────────────────────────────────────
    PERFORM _erasure_apply_redaction(p_subject, v_hashes, v_ev);

    RETURN jsonb_build_object(
        'event_id',        v_ev,
        'redacted_hashes', to_jsonb(v_hashes),
        'targets',         v_targets,
        'already_erased',  (v_plan->>'already_erased')::boolean);
END;
$$;

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
            'ledger_remainder', v_plan->'ledger_remainder'),
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

SELECT declare_migration(
    20261001000020,
    'additive',
    'Re-registers the principal_erased and resource_erased payload_schemas without the propagated_to_clients property (never required; neither schema sets additionalProperties, so every payload valid before stays valid), and CREATE OR REPLACEs principal_erasure_execute and resource_erasure_execute with the same signatures and return shapes, their completion payloads no longer writing the key. A binary without this change reads a payload lacking the key through serde(default); no reader consults it. No table, column, constraint, grant or COMMENT changes.'
);
