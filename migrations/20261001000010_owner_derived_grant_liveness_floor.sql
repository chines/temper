-- The owner's derived `grant` arm on kb_resources gains the subject-liveness floor.
--
-- derived_access_profile's kb_resources `grant` arm answered from home ownership alone
-- (kb_resource_homes.owner_profile_id). kb_resource_homes keeps its row when a resource is
-- soft-deleted or erased, so the owner of a tombstone or of an erased husk could administer grants
-- on it. The arm now carries the kb_resources.is_active semi-join, in the shape can()'s
-- explicit-branch floor uses (20260902000010). Grant administration on a dead resource is then
-- refused for its owner, as it already is for an explicit `can_grant` holder and for a system
-- admin (GrantAuthority::resolve's admin arm). The grant doors render the refusal: 410
-- RESOURCE_ERASED to a holder of an erased husk, else 403.
--
-- The `delete` arm is deliberately NOT floored. It is blob custody: the blob delete door's
-- relation arm asks can(..., 'delete', 'kb_resources', peer) over each live relation, a soft
-- delete folds no edge, and folding such an edge is refused on a tombstone. Flooring `delete`
-- would leave a blob related to a soft-deleted resource deletable by no one. The tombstone's owner
-- keeps custody of its blobs. An erased husk's relations are folded by the erasure act, so none
-- pins a blob.
--
-- Every other arm, and every answer on a live resource, is unchanged.
--
-- Additive: CREATE OR REPLACE of a pure STABLE sql function with the same signature and return
-- type. No table, column, constraint, grant or data changes.

CREATE OR REPLACE FUNCTION derived_access_profile(
    p_profile       uuid,
    p_action        text,
    p_subject_table text,
    p_subject_id    uuid
) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN p_subject_table = 'kb_resources' AND p_action = 'read'  THEN
            p_subject_id IN (SELECT resource_id FROM resources_visible_to(p_profile))
        WHEN p_subject_table = 'kb_resources' AND p_action = 'write' THEN
            can_modify_resource(p_profile, p_subject_id)
        WHEN p_subject_table = 'kb_resources' AND p_action = 'grant' THEN
            EXISTS (SELECT 1 FROM kb_resource_homes h
                    WHERE h.resource_id = p_subject_id
                      AND h.owner_profile_id = p_profile)
            AND EXISTS (SELECT 1 FROM kb_resources r
                         WHERE r.id = p_subject_id AND r.is_active)
        -- The owner of a resource's home derives `delete` on it (blob custody; no liveness floor).
        WHEN p_subject_table = 'kb_resources' AND p_action = 'delete' THEN
            EXISTS (SELECT 1 FROM kb_resource_homes h
                    WHERE h.resource_id = p_subject_id
                      AND h.owner_profile_id = p_profile)
        WHEN p_subject_table = 'kb_cogmaps'  AND p_action = 'read'  THEN
            cogmap_readable_by_profile(p_profile, p_subject_id)
        WHEN p_subject_table = 'kb_cogmaps'  AND p_action = 'write' THEN
            cogmap_authorable_by_profile(p_profile, p_subject_id)
        WHEN p_subject_table = 'kb_contexts' AND p_action = 'read'  THEN
            context_visible_to(p_profile, p_subject_id)
        WHEN p_subject_table = 'kb_contexts' AND p_action = 'write' THEN
            context_authorable_by_profile(p_profile, p_subject_id)
        ELSE false
    END;
$$;

COMMENT ON FUNCTION derived_access_profile(uuid, text, text, uuid) IS
  'Access derivable from structure rather than an explicit kb_access_grants row.

kb_resources: `read` is resources_visible_to; `write` is can_modify_resource; `grant` and `delete` belong to the owner of the resource''s home (kb_resource_homes.owner_profile_id). `read`, `write` and `grant` answer only a live subject (kb_resources.is_active): read and write through their predicates'' own floors, grant through an is_active semi-join. `delete` is blob custody and carries no liveness floor: a soft delete folds no edge, so a blob related to a soft-deleted resource stays deletable by that resource''s owner.

WHY the owner derives delete: grant-administration attenuates -- a delegated administrator may confer only capabilities it itself holds, and "holds" resolves through can(). With no derivable delete holder and no kb_access_grants row carrying can_delete, nobody could ever confer delete. The owner of the home is the principal who evidently should hold it.

kb_cogmaps: read and write through cogmap_readable_by_profile / cogmap_authorable_by_profile. kb_contexts: read and write through context_visible_to / context_authorable_by_profile.

WHY no delete arm for cogmaps or contexts: neither has an ownership floor comparable to kb_resource_homes.owner_profile_id -- a cogmap has no owner column, and context ownership is a different relation -- so a delete arm for either is a design question about that subject type. They answer false on the ELSE arm, as does every other subject kind and action.';

SELECT declare_migration(
    20261001000010,
    'additive',
    'CREATE OR REPLACE on the STABLE derived_access_profile(uuid,text,text,uuid): the kb_resources grant arm gains an is_active semi-join (EXISTS on kb_resources r WHERE r.id = p_subject_id AND r.is_active); the delete arm (blob custody) is unchanged. Signature, return type and every answer on a live resource are unchanged; the floor fires only on a soft-deleted or erased resource, where can() already refuses an explicit grant (20260902000010). A binary without this change already renders a false can() as its existing refusal. The COMMENT is restated in present truth. No table, column, constraint, grant or data changes.'
);
