-- Present-truth wording for the erasure registry texts. Data and comments only.
--
-- 1. `resource_erasure_refused`'s published payload_schema (registered by 20260929000010) still
--    described `ingest_in_flight` as a live refusal and `already_erased` as an act that "records
--    nothing", both as they stood before the 2026-09-29 rulings.
-- 2. Both refusal schemas described `unauthorized` as a live reason. A non-admin is now refused
--    at the wire with no event (ruled 2026-09-30), so no path raises it; the value stays
--    registered, retired, because removing one from a closed vocabulary is not additive. No door
--    raises any principal refusal, and that schema now says so. The `principal_erasure_refused`
--    literal registered by 20260909000015 is superseded here.
-- 3. `kb_erasure_blob_deletes`' COMMENT (20260909000040) named principal_erased as its only seed.
--    The fence derives from both erasure record types, and the blob delete door seeds it too.
--
-- Every reason's wire constant is unchanged; only descriptions move. Each payload_schema literal below is
-- equal, as JSON, to its committed fixture (`resource_erasure_refused.v1.schema.json`, then
-- `principal_erasure_refused.v1.schema.json`), and
-- `payload_schema::the_migration_literal_matches_the_committed_fixture` pins both, in this order.
-- A superseded literal is never edited; the next re-registration supersedes this one.

UPDATE kb_event_types
   SET payload_schema = $JS$
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
          "description": "Retired: no path raises it. A non-admin is refused at the wire with no event. The value\nstays registered because removing one from a closed vocabulary is not additive.",
          "type": "string",
          "const": "unauthorized"
        },
        {
          "description": "A cogmap's telos/charter resource: map-grain erasure is its own act, named in `detail`.",
          "type": "string",
          "const": "charter_resource"
        },
        {
          "description": "Retired: no path raises it. Ingest state does not refuse an erasure; an in-flight ingest\nends with it (spec D5). The value stays registered because removing one from a closed\nvocabulary is not additive.",
          "type": "string",
          "const": "ingest_in_flight"
        },
        {
          "description": "The resource is already erased. Recorded by the erasure act on a repeat request and by\nthe block history scrub, which has nothing to scrub on an erased resource. Nothing in the\nprojection changes and no second `resource_erased` is minted.",
          "type": "string",
          "const": "already_erased"
        }
      ]
    }
  }
}
$JS$::jsonb
 WHERE name = 'resource_erasure_refused';

UPDATE kb_event_types
   SET payload_schema = $JS$
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "PrincipalErasureRefused",
  "description": "`principal_erasure_refused` — the negative face of the erasure act (erasure spec D6). No door\nraises it today; the type stays registered so a ledger that holds one still reads and replays.\n\nSame subject spelling as [`PrincipalErased`] (`subject_table` / `subject_id`, never the\ntrail's join-key shapes); the operator is distinguishable from the subject exactly as\nthere. One type with a reason code — three outcomes, not three types.",
  "type": "object",
  "properties": {
    "actor": {
      "description": "Who ATTEMPTED the erasure — an attempt leaves a trail too.",
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
      "description": "The named unhonourable part, or the obligation held — the reason's evidence.",
      "type": [
        "string",
        "null"
      ]
    },
    "reason": {
      "$ref": "#/$defs/ErasureRefusalReason"
    },
    "subject_id": {
      "type": "string",
      "format": "uuid"
    },
    "subject_table": {
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
    "ErasureRefusalReason": {
      "description": "The closed refusal vocabulary for `principal_erasure_refused` (erasure spec D6). No door\nraises any principal refusal today: a non-admin is refused at the wire with no event, and a\nre-erase is a no-op completion. The vocabulary stays registered because removing a value from\na closed vocabulary is not additive, and a ledger may already hold one.",
      "oneOf": [
        {
          "description": "Retired: no path raises it. A non-admin is refused at the wire with no event. The value\nstays registered because removing one from a closed vocabulary is not additive.",
          "type": "string",
          "const": "unauthorized"
        },
        {
          "description": "The scope cannot be honoured in full; the unhonourable part is named in `detail`\n(accepted-in-part lands here, never silent).",
          "type": "string",
          "const": "unhonourable_scope"
        },
        {
          "description": "The system holds the data under an obligation, named in `detail`.",
          "type": "string",
          "const": "independent_obligation"
        }
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
 WHERE name = 'principal_erasure_refused';

COMMENT ON TABLE kb_erasure_blob_deletes IS
    'The erasure byte-delete fence: one durable retry state per strike-derived provider delete, '
    'seeded from the released blob strikes recorded in principal_erased and resource_erased '
    'targets, and by the blob delete door, drained through BlobStore::delete.';

SELECT declare_migration(
    20260930000050,
    'additive',
    'Re-registers the resource_erasure_refused and principal_erasure_refused payload_schemas with present-truth descriptions (unauthorized retired, a non-admin refused at the wire with no event; every wire constant unchanged, so the closed vocabularies and the SQL refuse allowlists still accept every value) and corrects the kb_erasure_blob_deletes table COMMENT. Registry data and a comment only: no DDL, signature or grant changes.'
);
