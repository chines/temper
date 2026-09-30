-- Present-truth wording for two resource-erasure registry texts. Data and comments only.
--
-- 1. `resource_erasure_refused`'s published payload_schema (registered by 20260929000010) still
--    described two reasons as they stood before the 2026-09-29 rulings: `ingest_in_flight` as a
--    live refusal ("finalize or abandon the ingest first"), and `already_erased` as an act that
--    "records nothing". Both reasons stay; only their descriptions change. The literal below is
--    the committed fixture `resource_erasure_refused.v1.schema.json`, pasted byte for byte, and
--    `payload_schema::the_migration_literal_matches_the_committed_fixture` pins it here — the
--    20260929000010 literal for this type is superseded, never edited.
-- 2. `kb_erasure_blob_deletes`' COMMENT (20260909000040) named principal_erased as its only seed.
--    The fence derives from both erasure record types, and the blob delete door seeds it too.

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

COMMENT ON TABLE kb_erasure_blob_deletes IS
    'The erasure byte-delete fence: one durable retry state per strike-derived provider delete, '
    'seeded from the released blob strikes recorded in principal_erased and resource_erased '
    'targets, and by the blob delete door, drained through BlobStore::delete.';

SELECT declare_migration(
    20260930000050,
    'additive',
    'Re-registers resource_erasure_refused payload_schema with present-truth descriptions (the wire constants are unchanged) and corrects the kb_erasure_blob_deletes table COMMENT. Registry data and a comment only: no DDL, signature or grant changes.'
);
