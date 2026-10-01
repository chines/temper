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
-- 3. The COMMENTs on resource_erasure_refuse (20260929040730), principal_erasure_execute (newest
--    restatement 20260913000030) and principal_erasure_refuse (20260909000025) described
--    `unauthorized` as live. Each is restated verbatim, with only that clause made present-truth.
-- 4. `kb_erasure_blob_deletes`' COMMENT (20260909000040) named principal_erased as its only seed.
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

COMMENT ON FUNCTION resource_erasure_refuse(uuid, uuid, uuid, uuid, text, text) IS
'the resource-erasure act''s negative face (spec D5; the closed refusal vocabulary ruled
2026-09-29): unauthorized | charter_resource | ingest_in_flight | already_erased — one recorded
event, nothing else mutated. ingest_in_flight is RETIRED (D5, ruled 2026-09-29: ingest state is
not a refusal; an in-flight ingest ends with the erasure): no path raises it, and it stays
accepted because removing a value from a closed vocabulary is not additive. unauthorized is
RETIRED too (ruled 2026-09-30): a non-admin is refused at the wire with no event, so no path
raises it, and it stays accepted for the same reason. A repeat erasure is
a recorded refusal, not a silent no-op: nothing in the projection changes and no second
resource_erased is minted, but the attempt is part of the record, the same as every other
refusal.';

COMMENT ON FUNCTION principal_erasure_execute(uuid, uuid, uuid, uuid) IS
'the erasure act (spec 2026-08-31, "The act, end to end" §3; Beat 2; outcome reads
governed-scoped 20260911000000; home-pure scope per the 2026-09-11 scope-of-engagement
ruling; the blob arm HOME-PURE since 20260913000020 — every live governed-home blob row is
struck with the estate, whoever committed it, the 2026-09-12 ruling; SHARES THE COMPUTATION
with principal_erasure_survey_plan since 20260913000010 — the plan is computed ONCE per act
and the strike loop consumes its rows by id, so the act and the survey cannot drift): scope
(every resource homed in a governed personal context), per-row governed-home blob strikes
through blob_delete(''blob_erased'', …) — the wrapper''s verdict authoritative at strike
time — the ONE NULL-anchored principal_erased event with the request reference on
kb_events."references" + correlation, then _erasure_apply_redaction — all one transaction.
The record names no retention the act does not make: every governed-home blob row is either
struck or already-struck, and only the subject''s team/map-homed rows ride the named
remainder (disposition iii). The per-target outcome reads scope to governed homes with the
redaction''s own predicate, so the record never reports "erased" for a row the act
deliberately leaves standing. Custody, not admission (the corrected arm-13 posture,
20260913000020): retiring the governed contexts floors the read/author arms into the estate
— but the estate''s resource rows stay live (D3), kb_erased_content refuses no write
(20260911000000), and a re-commit of identical bytes into a retired home mints a fresh live
row that a later erasure of the same estate strikes again; the estate is guarded by the tombstone and the custody floor, never by
an impossibility of re-admission. The record also names the subject''s ATTRIBUTED text in
shared spaces (20260913000030, the attribution ruling on the 2026-09-06 team-remainder
clause): content blocks whose genesis event the subject''s entity emitted, in homes outside
the governed estate — team and map alike — named with count and hashes for audit, never
struck, never in the redacted set; attribution, never a deletion claim. Does NOT decide legality (is_system_admin is the Rust
caller''s gate, resolved before any mutation); a non-admin is refused at the wire with no
event, so no unauthorized refusal is recorded (the unauthorized reason is retired, ruled
2026-09-30).';

COMMENT ON FUNCTION principal_erasure_refuse(uuid, uuid, uuid, uuid, text, text) IS
'the erasure act''s negative face (spec D6; Beat 2): records principal_erasure_refused —
one event with the closed reason vocabulary (unauthorized | unhonourable_scope |
independent_obligation) — and mutates NOTHING else. unauthorized is RETIRED (ruled
2026-09-30): a non-admin is refused at the wire with no event, so no path raises it; it stays
accepted because removing a value from a closed vocabulary is not additive. Accepted-in-part is NOT this event:
a completion with a named remainder is principal_erasure_execute''s payload data.';

COMMENT ON TABLE kb_erasure_blob_deletes IS
    'The erasure byte-delete fence: one durable retry state per strike-derived provider delete, '
    'seeded from the released blob strikes recorded in principal_erased and resource_erased '
    'targets, and by the blob delete door, drained through BlobStore::delete.';

SELECT declare_migration(
    20260930000050,
    'additive',
    'Re-registers the resource_erasure_refused and principal_erasure_refused payload_schemas with present-truth descriptions (unauthorized retired, a non-admin refused at the wire with no event; every wire constant unchanged, so the closed vocabularies and the SQL refuse allowlists still accept every value) restates the resource_erasure_refuse, principal_erasure_execute and principal_erasure_refuse function COMMENTs with the unauthorized clause made present-truth, and corrects the kb_erasure_blob_deletes table COMMENT. Registry data and comments only: no DDL, signature or grant changes.'
);
