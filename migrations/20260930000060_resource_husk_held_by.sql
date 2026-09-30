-- resource_husk_held_by: who may be told a resource was erased (resource erasure spec D6).
--
-- The 410 `resource_erased` is rendered only to a caller who still holds standing on the husk;
-- everyone else gets the uniform 404 an unknown id gets. This is that predicate.
--
-- True iff kb_resources.erased_at IS NOT NULL and the profile reaches the resource through the
-- first three arms of resources_visible_to (20260807000010), copied verbatim: the owner home, a
-- direct profile can_read grant, and a team can_read grant through profile_reachable_teams.
-- Those arms are read WITHOUT resources_visible_to's `r.is_active` floor, because an erased
-- resource is always inactive (kb_resources_erased_is_inactive, 20260929000010).
--
-- What a later edit must not break:
--   * erased_at, never is_active, is the husk test. A tombstone (soft-deleted, erased_at NULL) is
--     not an erasure and must stay false, or a 410 would announce an erasure that never happened.
--   * the context-homed arm and both cogmap arms are left out on purpose. Standing earned only by
--     reading a container is not standing on the resource; those callers get the 404.
--   * if an arm of resources_visible_to changes, revisit these three copies.

CREATE OR REPLACE FUNCTION resource_husk_held_by(p_profile uuid, p_resource uuid)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
               SELECT 1 FROM kb_resources r
                WHERE r.id = p_resource AND r.erased_at IS NOT NULL
           )
       AND EXISTS (
        WITH reachable_teams AS MATERIALIZED (
            SELECT team_id FROM profile_reachable_teams(p_profile)
        )
        SELECT 1
        FROM (
            -- owned (the home confers access to its OWNER; originator is provenance only, not access)
            SELECT h.resource_id FROM kb_resource_homes h
             WHERE h.owner_profile_id = p_profile
            UNION
            -- direct profile-anchored grant (consumer-axis ONLY -- never enters a vis(T))
            SELECT g.subject_id FROM kb_access_grants g
             WHERE g.subject_table = 'kb_resources' AND g.principal_table = 'kb_profiles'
               AND g.principal_id = p_profile AND g.can_read
            UNION
            -- team-anchored grant on a reachable (self-or-ancestor) team
            SELECT g.subject_id FROM kb_access_grants g
             JOIN reachable_teams rt ON g.principal_id = rt.team_id
             WHERE g.subject_table = 'kb_resources' AND g.principal_table = 'kb_teams' AND g.can_read
        ) v
        WHERE v.resource_id = p_resource
    );
$$;

COMMENT ON FUNCTION resource_husk_held_by(uuid, uuid) IS
    'True iff the resource is an erased husk (erased_at set) and the profile holds standing on it: '
    'the owner home, a direct profile can_read grant, or a team can_read grant through '
    'profile_reachable_teams. The three arms of resources_visible_to, minus its is_active floor. '
    'The context-homed and cogmap arms are excluded. A tombstone is false. Decides 410 vs 404 '
    'for a resource read.';

SELECT declare_migration(
    20260930000060,
    'additive',
    'Adds the new STABLE function resource_husk_held_by(uuid, uuid). No existing object, signature or grant changes, and nothing calls it until the service read path ships in the same release.'
);
