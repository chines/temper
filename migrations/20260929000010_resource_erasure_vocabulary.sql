-- Resource erasure's vocabulary and husk (spec 2026-09-28, temper-artifacts/specs/
-- 2026-09-28-resource-erasure-design.md, D1/D5/D6/D11; task 01a0e9e7-072b-7390-8700-3b4367b3bab6,
-- build order 2a). Registers the three event types and adds the husk marker. The act itself
-- lands with the next build; this migration only makes the vocabulary and the marker EXIST.
--
-- THE CONSTRAINTS A LATER EDIT MUST NOT BREAK:
--
--   * CATEGORY IS SPELLED HERE, ONCE. `kb_events_category_matches_type` is ON UPDATE RESTRICT
--     and the append-only trigger refuses reclassification (the 20260909000015 precedent). All
--     three types are `admin`, NULL-anchored by `kb_events_admin_is_unanchored`, the cognition
--     firewall: an authority act over a resource has no cognition home. One shot.
--   * NO TRAIL JOIN-KEY SHAPE IN ANY PAYLOAD (D1). `element_trail_node` joins on
--     `payload->>'resource_id'` / `'block_id'`, so the subjects are keyed `subject_table` /
--     `subject_id(s)`, the per-edge list `folded_edges`, and the per-event list `event`. The
--     category filter must not be the only layer.
--   * erased_at IS AN ACT MARKER, NOT A REDACTION (D6), the `kb_profiles.tombstoned_at`
--     precedent. It records WHEN the resource was erased, set by the act's projector to the
--     event's `occurred_at` (never now(), the replay-stable rule). It is what tells an erased
--     resource from a soft-deleted one, which `is_active` alone cannot.
--   * THE INVARIANT IS A CHECK, NOT A CONVENTION: erased_at IS NOT NULL ⇒ NOT is_active. Every
--     read that surfaces a member title from a region (anchor_shape, graph_cogmap_territories,
--     graph_region_territories, and the member/orphan reads) already joins `r.is_active`, so this
--     constraint is what keeps an erased resource's sentinel title out of a region's fallback
--     label (D6, Witness 19). It also keeps an erased resource from being reactivated.
--
-- The payload JSON below is GENERATED, NOT AUTHORED — copied byte-for-byte from
-- crates/temper-substrate/tests/fixtures/payloads/*.v1.schema.json, emitted by
-- `UPDATE_SCHEMA=1 cargo make test-schema` (package-scoped -p temper-substrate). The pairing test
-- (payload_schema.rs::the_migration_literal_matches_the_committed_fixture) pins the seam.
--
-- Additive: new registry rows, a nullable column, and a CHECK that every existing row satisfies
-- (the column is NULL everywhere). No existing column, constraint or function is altered, and an
-- old binary reads and writes kb_resources unchanged.

INSERT INTO kb_event_types (name, payload_schema, schema_version, category) VALUES
  ('resource_erased', $JS$
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
    "propagated_to_clients": {
      "description": "`true` iff the `410 resource_erased` signal exists for clients (D7): the signal exists,\nnot that every client obeyed it.",
      "type": "boolean",
      "default": false
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
$JS$::jsonb, 1, 'admin'),
  ('resource_erasure_refused', $JS$
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ResourceErasureRefused",
  "description": "`resource_erasure_refused` — the negative face of resource erasure and of the block history\nscrub (resource erasure spec D5, D11). Keyed on the resource, spelled as [`ResourceErased`]\nspells it: every reason is a fact about the resource, whichever act was refused.",
  "type": "object",
  "properties": {
    "actor": {
      "description": "Who attempted the act.",
      "anyOf": [
        {
          "$ref": "#/$defs/ProfileId"
        },
        {
          "type": "null"
        }
      ]
    },
    "detail": {
      "description": "The reason's evidence, e.g. the task that owns map-grain charter erasure.",
      "type": [
        "string",
        "null"
      ]
    },
    "reason": {
      "$ref": "#/$defs/ResourceErasureRefusalReason"
    },
    "subject_id": {
      "type": "string",
      "format": "uuid"
    },
    "subject_table": {
      "description": "Always `kb_resources`.",
      "$ref": "#/$defs/AnchorTable"
    }
  },
  "required": [
    "subject_table",
    "subject_id",
    "reason"
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
    "ProfileId": {
      "description": "A `kb_profiles.id` value.",
      "type": "string",
      "format": "uuid"
    },
    "ResourceErasureRefusalReason": {
      "description": "The closed refusal vocabulary for `resource_erasure_refused` (resource erasure spec D5, D11).",
      "oneOf": [
        {
          "description": "The caller is not a system admin.",
          "type": "string",
          "const": "unauthorized"
        },
        {
          "description": "A cogmap's telos/charter resource: map-grain erasure is its own act, named in `detail`.",
          "type": "string",
          "const": "charter_resource"
        },
        {
          "description": "`ingest_state` is not `complete`: finalize or abandon the ingest first.",
          "type": "string",
          "const": "ingest_in_flight"
        },
        {
          "description": "The resource is already erased. Recorded by the block history scrub, which has nothing to\nscrub on an erased resource; the erasure act itself answers an already-erased resource\nidempotently and records nothing.",
          "type": "string",
          "const": "already_erased"
        }
      ]
    }
  }
}
$JS$::jsonb, 1, 'admin'),
  ('block_history_scrubbed', $JS$
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "BlockHistoryScrubbed",
  "description": "`block_history_scrubbed` — the remedy lighter than erasure (resource erasure spec D11): every\nrevision of each block but its current one, and every non-current chunk, emptied, on a LIVE\nresource. CAS-only; it touches no ledger payload.\n\nKeyed `subject_table` (`kb_content_blocks`) / `subject_ids`, never `block_id`:\n`element_trail_node` joins on `payload->>'block_id'` (the D1 join-key rule).",
  "type": "object",
  "properties": {
    "actor": {
      "description": "The acting system admin.",
      "anyOf": [
        {
          "$ref": "#/$defs/ProfileId"
        },
        {
          "type": "null"
        }
      ]
    },
    "subject_ids": {
      "type": "array",
      "items": {
        "type": "string",
        "format": "uuid"
      }
    },
    "subject_table": {
      "description": "Always `kb_content_blocks`.",
      "$ref": "#/$defs/AnchorTable"
    },
    "targets": {
      "description": "Per-block outcomes (revisions and chunks emptied).",
      "type": "array",
      "items": {
        "$ref": "#/$defs/ErasureTargetOutcome"
      }
    }
  },
  "required": [
    "subject_table",
    "subject_ids"
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
$JS$::jsonb, 1, 'admin')
ON CONFLICT (name) DO UPDATE
  SET payload_schema = EXCLUDED.payload_schema,
      schema_version = EXCLUDED.schema_version,
      category       = EXCLUDED.category;

-- The husk marker (spec D6). Set by the resource_erased projector, never by a door.
ALTER TABLE kb_resources ADD COLUMN erased_at TIMESTAMPTZ;

ALTER TABLE kb_resources
    ADD CONSTRAINT kb_resources_erased_is_inactive CHECK (erased_at IS NULL OR NOT is_active);

COMMENT ON COLUMN kb_resources.erased_at IS
'Resource erasure act marker (spec 2026-09-28 D6, added 20260929000010): the resource_erased
event''s occurred_at, set by its projector. Distinguishes an erased resource from a soft-deleted
one, which is_active alone cannot. Not the redaction itself: the content emptying happens in the
same act. CHECK kb_resources_erased_is_inactive holds erased_at IS NOT NULL => NOT is_active, which
is what keeps an erased resource out of every is_active-gated read, the region-label fallback
included.';

SELECT declare_migration(
    20260929000010,
    'additive',
    'Resource erasure vocabulary and husk (spec 2026-09-28, build order 2a, task 01a0e9e7-072b): registers resource_erased, resource_erasure_refused and block_history_scrubbed (category admin, NULL-anchored — the cognition firewall) with their generated payload schemas, one shot at category per the RESTRICT/append-only precedent; adds kb_resources.erased_at, the act marker (D6 — set by the later act''s projector from the event''s occurred_at), and CHECK kb_resources_erased_is_inactive (erased_at IS NOT NULL => NOT is_active), which every existing row satisfies. Additive: new registry rows, a nullable column, a CHECK no existing row violates; nothing existing is altered.'
);
