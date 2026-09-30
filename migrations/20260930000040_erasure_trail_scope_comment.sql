-- Resource erasure's scope predicate (`20260929040730`) names the edge-owned property arm as the
-- one "the trail lacks". `20260930000010` gave element_trail_edge that arm for a single edge; the
-- scope still unions it across every edge touching the resource, so only its comment changes.

COMMENT ON FUNCTION _resource_erasure_trail_scope(uuid) IS
'the ONE scope predicate for "a resource''s own ledger events" (spec 2026-09-28 F2): the
element-trail read''s own predicate (payload->>''resource_id''; property events owner-keyed to the
resource; block events through the block join; events carrying a touched edge''s edge_id) PLUS
property events whose owner IS an edge touching the resource (edge-owned properties ride the
20260727000030 edge-facet shape). element_trail_edge reads that same owner arm for one edge since
20260930000010; element_trail_node has no edge arms, so over a resource this predicate is still the
only union of them. Every consumer — the survey''s ledger remainder, cut 2''s completion pass, any
operator audit — walks THIS predicate, never a second derivation.';

SELECT declare_migration(
    20260930000040,
    'additive',
    'COMMENT ON _resource_erasure_trail_scope only: it named the edge-owned property arm as missing from the trail, which 20260930000010 added to element_trail_edge. No body, signature or grant changes.'
);
