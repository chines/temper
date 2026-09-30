-- resource_lineage walks breadth-first, visiting each node once.
--
-- The reader (`20260712000080`) timed out whenever the seed had lineage and the walk was allowed
-- a second hop (a gateway 502 over MCP at depths 4 and 16). Two costs compounded:
--
--   * every hop seq-scanned kb_edges: the only source/target indexes are partial on
--     `NOT is_folded`, and this walk deliberately includes folded edges (a superseded ancestor is
--     shown, flagged). The two indexes below serve exactly the population it reads;
--   * a recursive CTE can only guard cycles per PATH, so it enumerated every simple path before
--     `DISTINCT ON` collapsed them, running the scalar gates on each path-edge. A lattice of 12
--     layers of 5 has 5^12 paths over 60 nodes; indexes alone leave that exponential.
--
-- So the walk is a plpgsql loop over a frontier with a visited set: each node is reached once, at
-- its shallowest depth, and each hop's gates run once over that hop's candidate edges. What a
-- later edit must not break:
--
--   * the gates are the same three conjuncts as every edge read: the home anchor via
--     `anchor_readable_by_profile`, both endpoints via `resources_visible_to` — the set form of
--     `endpoint_readable_by_profile`'s kb_resources arm, computed once per hop, not once per edge;
--   * label-keyed (never edge_kind); folded edges walked and flagged; the seed never re-emitted;
--   * depth 1 is always walked (a depth <= 0 or NULL answers depth 1, as before);
--   * a node reached over several edges at its shallowest depth reports a live edge before a
--     folded one, then the lowest edge id — previously the pick was arbitrary;
--   * any direction but 'ancestors' / 'descendants' walks nothing — previously NULL/unknown also did.

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
#variable_conflict use_column
DECLARE
    v_ancestors boolean := p_direction = 'ancestors';
    v_frontier  uuid[]  := ARRAY[p_resource];
    v_visited   uuid[]  := ARRAY[p_resource];
    v_hop       int     := 0;
    v_nodes     uuid[]    := '{}';
    v_vias      uuid[]    := '{}';
    v_folded    boolean[] := '{}';
    v_hops      int[]     := '{}';
    h_nodes     uuid[];
    h_vias      uuid[];
    h_folded    boolean[];
BEGIN
    IF p_direction IS DISTINCT FROM 'ancestors' AND p_direction IS DISTINCT FROM 'descendants' THEN
        RETURN;
    END IF;

    LOOP
        v_hop := v_hop + 1;

        WITH vis AS MATERIALIZED (
            SELECT v.resource_id FROM resources_visible_to(p_profile) v
        ),
        -- One hop out of the frontier. `near` is the frontier end, `far` the node reached:
        -- ancestors follow source -> target, descendants target -> source.
        step AS (
            SELECT e.id, e.is_folded, e.home_anchor_table, e.home_anchor_id,
                   e.source_id AS near, e.target_id AS far
            FROM kb_edges e
            WHERE v_ancestors
              AND e.label = 'derived_from'
              AND e.source_table = 'kb_resources'
              AND e.target_table = 'kb_resources'
              AND e.source_id = ANY(v_frontier)
            UNION ALL
            SELECT e.id, e.is_folded, e.home_anchor_table, e.home_anchor_id,
                   e.target_id, e.source_id
            FROM kb_edges e
            WHERE NOT v_ancestors
              AND e.label = 'derived_from'
              AND e.source_table = 'kb_resources'
              AND e.target_table = 'kb_resources'
              AND e.target_id = ANY(v_frontier)
        ),
        cand AS (
            SELECT s.*
            FROM step s
            WHERE NOT EXISTS (SELECT 1 FROM unnest(v_visited) AS seen(id) WHERE seen.id = s.far)
              AND s.near IN (SELECT vis.resource_id FROM vis)
              AND s.far  IN (SELECT vis.resource_id FROM vis)
        ),
        readable_homes AS (
            SELECT h.home_anchor_table, h.home_anchor_id
            FROM (SELECT DISTINCT c.home_anchor_table, c.home_anchor_id FROM cand c) h
            WHERE anchor_readable_by_profile(p_profile, h.home_anchor_table, h.home_anchor_id)
        ),
        picked AS (
            SELECT DISTINCT ON (c.far) c.far, c.id, c.is_folded
            FROM cand c
            JOIN readable_homes rh
              ON rh.home_anchor_table = c.home_anchor_table
             AND rh.home_anchor_id = c.home_anchor_id
            ORDER BY c.far, c.is_folded, c.id
        )
        SELECT array_agg(p.far), array_agg(p.id), array_agg(p.is_folded)
          INTO h_nodes, h_vias, h_folded
          FROM picked p;

        EXIT WHEN h_nodes IS NULL;

        v_nodes   := v_nodes || h_nodes;
        v_vias    := v_vias || h_vias;
        v_folded  := v_folded || h_folded;
        v_hops    := v_hops || array_fill(v_hop, ARRAY[cardinality(h_nodes)]);
        v_visited := v_visited || h_nodes;
        v_frontier := h_nodes;

        EXIT WHEN p_max_depth IS NULL OR v_hop >= p_max_depth;
    END LOOP;

    RETURN QUERY
    SELECT w.node, r.title, r.is_active, w.via, w.via_folded, w.hops
    FROM unnest(v_nodes, v_vias, v_folded, v_hops) AS w(node, via, via_folded, hops)
    JOIN kb_resources r ON r.id = w.node
    ORDER BY w.node;
END;
$$;

SELECT declare_migration(
    20260930000020,
    'additive',
    'resource_lineage re-emitted as a breadth-first plpgsql walk over two new partial indexes on resource-to-resource derived_from edges (source_id, target_id; folded included). Signature and return type are unchanged. For both real directions the node set and depths are unchanged; the edge reported for a node reached over several shallowest edges is now deterministic (live before folded), and an unknown or NULL direction now walks nothing — no caller passes one. The two CREATE INDEX statements take a brief write lock on kb_edges while they build.'
);
