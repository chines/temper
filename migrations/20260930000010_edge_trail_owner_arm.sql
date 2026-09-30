-- The edge trail reads its edge's own property events.
--
-- `element_trail_edge` matched events by `payload ->> 'edge_id'` alone. That is the key the
-- relationship lifecycle events carry (asserted / reweighted / retyped / folded), but an
-- edge's PROPERTY events — `property_asserted`, `property_set`, `property_retracted`,
-- `property_unset`, written by `facet_set target=edge` (including the keyed `anchored-at`
-- row) and `facet_retract` — identify their subject as `payload -> 'owner'`
-- (`{"table": "kb_edges", "id": …}`) and carry no `edge_id`. So every facet and span
-- qualification on an edge was invisible in that edge's trail, while `element_trail_node`
-- has read the resource half of the same shape (its `owner` arm) all along.
--
-- Fix: the node trail's shape — an `ev_ids` UNION of the two keys, each arm pruned by
-- `producing_anchor_table IS NOT NULL` inside its index scan
-- (`idx_kb_events_payload_edge_id`, `idx_kb_events_payload_owner_id`). Everything else is
-- re-emitted verbatim from `20260912000020`: the return type, the `category = 'domain'`
-- firewall, and the three visibility predicates. The return type is unchanged, so
-- `CREATE OR REPLACE` applies.

CREATE OR REPLACE FUNCTION element_trail_edge(
    p_profile uuid,
    p_edge uuid
) RETURNS TABLE (
    event_id uuid,
    kind text,
    actor_entity_id uuid,
    occurred_at timestamptz,
    metadata jsonb,
    payload jsonb,
    actor_name text,
    correlation_id uuid
) LANGUAGE sql STABLE AS $$
    WITH ev_ids AS (
        SELECT ev.id FROM kb_events ev
         WHERE (ev.payload ->> 'edge_id')::uuid = p_edge
           AND ev.producing_anchor_table IS NOT NULL
        UNION
        SELECT ev.id FROM kb_events ev
         WHERE ev.payload -> 'owner' ->> 'table' = 'kb_edges'
           AND (ev.payload -> 'owner' ->> 'id')::uuid = p_edge
           AND ev.producing_anchor_table IS NOT NULL
    )
    SELECT ev.id, et.name, ev.emitter_entity_id, ev.occurred_at, ev.metadata, ev.payload, en.name,
           ev.correlation_id
    FROM kb_edges edg
    JOIN ev_ids ON TRUE
    JOIN kb_events ev ON ev.id = ev_ids.id
    JOIN kb_event_types et ON et.id = ev.event_type_id
    JOIN kb_entities en ON en.id = ev.emitter_entity_id
    WHERE edg.id = p_edge
      AND et.category = 'domain'
      AND anchor_readable_by_profile(p_profile, edg.home_anchor_table, edg.home_anchor_id)
      AND endpoint_readable_by_profile(p_profile, edg.source_table, edg.source_id)
      AND endpoint_readable_by_profile(p_profile, edg.target_table, edg.target_id)
    ORDER BY ev.id;
$$;

SELECT declare_migration(
    20260930000010,
    'additive',
    'element_trail_edge gains an owner arm so an edge''s own property events (payload.owner = kb_edges) surface in its trail. CREATE OR REPLACE with an unchanged signature and return type; the running binary decodes the same row shape and only sees more rows for edges that carry properties.'
);
