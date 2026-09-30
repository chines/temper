-- resource_lineage walks one indexed hop at a time.
--
-- The reader (`20260712000080`) timed out in production whenever the seed had a lineage
-- edge and the walk was allowed a second hop: `resource_lineage` over MCP answered at
-- depth 1 and returned a gateway 502 at depth 4 and at the default 16 (found exercising the
-- MCP surface live, 2026-09-30). The recursive term's plan was
--
--   Nested Loop  Join Filter: w.resource_id = e.source_id
--     -> WorkTable Scan on walk
--     -> Materialize -> Seq Scan on kb_edges
--          Filter: label = 'derived_from' AND <all three visibility gates>
--
-- i.e. every hop sequentially scanned kb_edges and ran `anchor_readable_by_profile` plus two
-- `endpoint_readable_by_profile` calls on EVERY derived_from edge in the deployment, before
-- joining to the frontier. Two causes compound:
--
--   * the only source/target indexes (`idx_kb_edges_source`, `idx_kb_edges_target`) are
--     partial on `NOT is_folded`, and this walk deliberately includes folded edges (a
--     superseded ancestor is shown, flagged), so no index can serve it;
--   * direction was an `OR` over `p_direction` inside one join condition, which no index
--     serves either.
--
-- Measured locally (15,000 derived_from among 45,000 edges): depth 1 in 570 ms, depth 2
-- cancelled after 411 s. At depth 1 the recursive side never executes (`depth < 1` empties
-- the worktable), which is why the shallow read looked healthy.
--
-- Fix:
--   1. Two indexes scoped to resource-to-resource `derived_from` edges, folded or not — the
--      exact population the walk reads, and a small fraction of kb_edges.
--   2. The reader branches on direction (plpgsql), so each hop is a plain equality on the
--      indexed column and the gates run only on the edges actually joined.
-- Semantics are re-emitted verbatim: label-keyed (never edge_kind), folded edges walked and
-- flagged, the path-array cycle guard, the depth bound, the per-edge home + both-endpoint
-- gates, and DISTINCT ON the shallowest depth. Signature and return type are unchanged.

CREATE INDEX idx_kb_edges_derived_from_source
    ON kb_edges (source_id)
    WHERE label = 'derived_from'
      AND source_table = 'kb_resources'
      AND target_table = 'kb_resources';

CREATE INDEX idx_kb_edges_derived_from_target
    ON kb_edges (target_id)
    WHERE label = 'derived_from'
      AND source_table = 'kb_resources'
      AND target_table = 'kb_resources';

CREATE OR REPLACE FUNCTION resource_lineage(
    p_profile uuid,
    p_resource uuid,
    p_direction text,
    p_max_depth int DEFAULT 16
) RETURNS TABLE(
    resource_id uuid,
    title text,
    is_active boolean,
    edge_id uuid,
    edge_is_folded boolean,
    depth int
) LANGUAGE plpgsql STABLE AS $$
BEGIN
    IF p_direction = 'ancestors' THEN
        -- "What does this derive from": follow source = node -> target.
        RETURN QUERY
        WITH RECURSIVE walk AS (
            SELECT e.target_id AS node, e.id AS via, e.is_folded AS via_folded, 1 AS hops,
                   ARRAY[p_resource, e.target_id] AS path
            FROM kb_edges e
            WHERE e.label = 'derived_from'
              AND e.source_table = 'kb_resources'
              AND e.target_table = 'kb_resources'
              AND e.source_id = p_resource
              AND anchor_readable_by_profile(p_profile, e.home_anchor_table, e.home_anchor_id)
              AND endpoint_readable_by_profile(p_profile, e.source_table, e.source_id)
              AND endpoint_readable_by_profile(p_profile, e.target_table, e.target_id)

            UNION ALL

            SELECT e.target_id, e.id, e.is_folded, w.hops + 1, w.path || e.target_id
            FROM walk w
            JOIN kb_edges e
              ON e.label = 'derived_from'
             AND e.source_table = 'kb_resources'
             AND e.target_table = 'kb_resources'
             AND e.source_id = w.node
            WHERE w.hops < p_max_depth
              AND e.target_id <> ALL(w.path)
              AND anchor_readable_by_profile(p_profile, e.home_anchor_table, e.home_anchor_id)
              AND endpoint_readable_by_profile(p_profile, e.source_table, e.source_id)
              AND endpoint_readable_by_profile(p_profile, e.target_table, e.target_id)
        )
        SELECT DISTINCT ON (w.node) w.node, r.title, r.is_active, w.via, w.via_folded, w.hops
        FROM walk w
        JOIN kb_resources r ON r.id = w.node
        ORDER BY w.node, w.hops;
    ELSE
        -- "What derives from this": follow target = node -> source.
        RETURN QUERY
        WITH RECURSIVE walk AS (
            SELECT e.source_id AS node, e.id AS via, e.is_folded AS via_folded, 1 AS hops,
                   ARRAY[p_resource, e.source_id] AS path
            FROM kb_edges e
            WHERE e.label = 'derived_from'
              AND e.source_table = 'kb_resources'
              AND e.target_table = 'kb_resources'
              AND e.target_id = p_resource
              AND anchor_readable_by_profile(p_profile, e.home_anchor_table, e.home_anchor_id)
              AND endpoint_readable_by_profile(p_profile, e.source_table, e.source_id)
              AND endpoint_readable_by_profile(p_profile, e.target_table, e.target_id)

            UNION ALL

            SELECT e.source_id, e.id, e.is_folded, w.hops + 1, w.path || e.source_id
            FROM walk w
            JOIN kb_edges e
              ON e.label = 'derived_from'
             AND e.source_table = 'kb_resources'
             AND e.target_table = 'kb_resources'
             AND e.target_id = w.node
            WHERE w.hops < p_max_depth
              AND e.source_id <> ALL(w.path)
              AND anchor_readable_by_profile(p_profile, e.home_anchor_table, e.home_anchor_id)
              AND endpoint_readable_by_profile(p_profile, e.source_table, e.source_id)
              AND endpoint_readable_by_profile(p_profile, e.target_table, e.target_id)
        )
        SELECT DISTINCT ON (w.node) w.node, r.title, r.is_active, w.via, w.via_folded, w.hops
        FROM walk w
        JOIN kb_resources r ON r.id = w.node
        ORDER BY w.node, w.hops;
    END IF;
END;
$$;

SELECT declare_migration(
    20260930000020,
    'additive',
    'resource_lineage re-emitted as a direction-branched plpgsql walk over two new partial indexes on resource-to-resource derived_from edges (source_id, target_id; folded included). Signature and return type are unchanged and the rows it returns are the same; only the plan changes. The two CREATE INDEX statements take a brief write lock on kb_edges while they build.'
);
