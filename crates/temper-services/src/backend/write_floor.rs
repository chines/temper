//! The write floor (resource erasure spec D13, F4): the one check a write on a resource passes,
//! run INSIDE the write's own transaction so the check and the mutation cannot be separated.
//!
//! Each entry point, in order:
//!
//! 1. takes `FOR KEY SHARE` on the `kb_resources` row — the lock `_resource_write_guard` takes
//!    (migration `20260929040730`, re-commented in `20260930000070`). It conflicts with the erasure
//!    act's `FOR UPDATE`, so a write that races the act either lands before it or refuses after it.
//!    It does not conflict with the `FOR NO KEY UPDATE` a write's own projector takes on the same
//!    row, which `FOR SHARE` would (two writers each holding SHARE would deadlock on the upgrade);
//! 2. evaluates its admission — [`modify_floor_in_tx`]: `can_modify_resource` (migration
//!    `20260804000020`), called, never restated; [`liveness_floor_in_tx`]: `kb_resources.is_active`
//!    alone, for reassign, whose authority (owner or admin reach) stays its own;
//! 3. on deny only, classifies through `resource_husk_held_by` (migration `20260930000060`) — the
//!    probe the read side's `substrate_read::erased_or` asks: [`TemperError::ResourceErased`]
//!    (`410 RESOURCE_ERASED`) to a caller who holds the husk, else [`TemperError::Forbidden`]
//!    (`403`). An admitted write pays the locked SELECT and the admission, nothing more.
//!
//! **Why the lock and the admission are two statements.** Under READ COMMITTED (the transaction
//! default here) each statement takes a fresh snapshot. A lock that waited behind the act's
//! `FOR UPDATE` returns only once the act committed, so the admission that follows sees
//! `is_active = false` and the classification sees `erased_at`. A predicate folded into the
//! locking statement would evaluate its subqueries against the snapshot taken BEFORE the wait.
//! (Under REPEATABLE READ a lock that waits on a concurrent update raises a serialization failure
//! instead, which surfaces as an error, never as an admission.)
//!
//! **A missing row is not its own answer.** The lock on an unknown id locks nothing;
//! `can_modify_resource` is false, `resource_husk_held_by` is false, and the caller gets the same
//! `Forbidden` a live resource it may not modify gets.
//!
//! **A tombstone is never an erasure.** A soft-deleted resource (`is_active = false`, `erased_at`
//! NULL) is denied by both floors and classified `Forbidden`: `resource_husk_held_by` reads
//! `erased_at`, never `is_active`.
//!
//! The connection is the caller's transaction (`&mut tx`), the shape every `writes::*_in_tx` takes.
//! Called on a bare pool connection it still answers, but the lock is released at once and the
//! floor is a pre-check again — the gap this module exists to close.

use sqlx::PgConnection;
use temper_core::error::TemperError;
use temper_core::types::ids::{ProfileId, ResourceId};

use crate::backend::substrate_read::husk_held_by;

/// The modify floor: `profile` may modify `resource`, checked under the row lock in the caller's
/// transaction. `Ok(())` admits; a deny is [`TemperError::ResourceErased`] when `profile` holds
/// the erased husk, else [`TemperError::Forbidden`].
pub async fn modify_floor_in_tx(
    conn: &mut PgConnection,
    profile: ProfileId,
    resource: ResourceId,
) -> Result<(), TemperError> {
    // The lock is all this step is for; whether a row came back is the admission's question.
    lock_resource_row(conn, resource).await?;
    let can: Option<bool> = sqlx::query_scalar!(
        "SELECT can_modify_resource($1, $2)",
        *profile,
        resource.uuid(),
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(floor_err)?;
    if can.unwrap_or(false) {
        Ok(())
    } else {
        Err(erased_or_forbidden(conn, profile, resource).await)
    }
}

/// The liveness floor, for reassign: `resource` is live (`kb_resources.is_active`), checked under
/// the row lock in the caller's transaction. No authority check — the caller keeps its own. A deny
/// is classified exactly as [`modify_floor_in_tx`]'s is.
pub async fn liveness_floor_in_tx(
    conn: &mut PgConnection,
    profile: ProfileId,
    resource: ResourceId,
) -> Result<(), TemperError> {
    match lock_resource_row(conn, resource).await? {
        Some(true) => Ok(()),
        Some(false) | None => Err(erased_or_forbidden(conn, profile, resource).await),
    }
}

/// `FOR KEY SHARE` on the `kb_resources` row, returning its `is_active` — `None` when no row has
/// that id. One statement, so a wait on the act's `FOR UPDATE` returns the row version the act
/// committed (the READ COMMITTED re-check), the same reasoning `_resource_write_guard` states.
async fn lock_resource_row(
    conn: &mut PgConnection,
    resource: ResourceId,
) -> Result<Option<bool>, TemperError> {
    sqlx::query_scalar!(
        "SELECT is_active FROM kb_resources WHERE id = $1 FOR KEY SHARE",
        resource.uuid(),
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(floor_err)
}

/// The deny's classification: `ResourceErased` when `profile` holds the husk, else `Forbidden`.
/// `substrate_read::erased_or`'s shape, with `Forbidden` as the fallback; a fault stays a fault.
async fn erased_or_forbidden(
    conn: &mut PgConnection,
    profile: ProfileId,
    resource: ResourceId,
) -> TemperError {
    match husk_held_by(&mut *conn, profile, resource).await {
        Ok(true) => TemperError::ResourceErased(resource),
        Ok(false) => TemperError::Forbidden,
        Err(e) => floor_err(e),
    }
}

/// Bridge a database error into `TemperError`, as `db_backend`'s `api_err` does.
fn floor_err(e: sqlx::Error) -> TemperError {
    TemperError::Api(e.to_string())
}

#[cfg(all(test, feature = "test-db"))]
mod tests {
    //! Witnesses for both floors. Every state is made by a real path: the resource by
    //! `writes::create_resource_with`, the tombstone by `SeedAction::ResourceDelete`, the husk by
    //! `execute_resource_erasure` under a minted `SystemAdmin` proof (the pattern in
    //! `resource_erasure_service`'s tests). Only the read grant is a fixture row, as in
    //! `temper-substrate/tests/resource_husk_held_by.rs`.
    use sqlx::PgPool;
    use uuid::Uuid;

    use temper_core::types::ids::EntityId;
    use temper_substrate::events::{fire, EventContext, SeedAction};
    use temper_substrate::ids::ContextId;
    use temper_substrate::payloads::AnchorRef;
    use temper_substrate::writes::{self, CreateParams};
    use temper_workflow::operations::Surface;

    use super::*;
    use crate::auth::SystemAdmin;
    use crate::services::resource_erasure_service::{
        execute_resource_erasure, ResourceErasureOutcome, ResourceErasureRequest,
    };
    use crate::test_support;

    /// A principal: profile, its `<handle>@web` emitter entity, and a personal context.
    struct Principal {
        profile: ProfileId,
        emitter: EntityId,
        home: ContextId,
    }

    /// The handle is the FULL id: two UUIDv7s minted in one millisecond share leading bytes, so a
    /// truncated handle collides on `kb_profiles_handle_key`.
    async fn principal(pool: &PgPool) -> Principal {
        let id = Uuid::now_v7();
        let handle = format!("user-{id}");
        sqlx::query("INSERT INTO kb_profiles (id, handle, display_name) VALUES ($1, $2, $2)")
            .bind(id)
            .bind(&handle)
            .execute(pool)
            .await
            .expect("seed profile");
        let emitter: Uuid = sqlx::query_scalar(
            "INSERT INTO kb_entities (profile_id, name) VALUES ($1, $2) RETURNING id",
        )
        .bind(id)
        .bind(format!("{handle}@web"))
        .fetch_one(pool)
        .await
        .expect("seed emitter entity");
        let home: Uuid = sqlx::query_scalar(
            "INSERT INTO kb_contexts (owner_table, owner_id, slug, name) \
             VALUES ('kb_profiles', $1, 'home', 'Home') RETURNING id",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("seed personal context");
        Principal {
            profile: ProfileId::from(id),
            emitter: EntityId::from(emitter),
            home: ContextId::from(home),
        }
    }

    /// An operator's sealed proof, minted through the real gate after `grant_governance`.
    async fn operator(pool: &PgPool) -> SystemAdmin {
        let op = principal(pool).await;
        test_support::grant_governance(pool, op.profile.uuid()).await;
        test_support::system_admin_proof_for(pool, op.profile.uuid()).await
    }

    /// A live resource created through the REAL create path, homed in `owner`'s context.
    async fn resource(pool: &PgPool, owner: &Principal) -> ResourceId {
        let origin = format!("test://write-floor-{}", Uuid::now_v7());
        writes::create_resource_with(
            pool,
            CreateParams {
                idempotency_key: None,
                title: "write floor subject",
                origin_uri: &origin,
                body: "body under the write floor",
                doc_type: "research",
                home: AnchorRef::context(owner.home),
                owner: owner.profile,
                originator: owner.profile,
                emitter: owner.emitter,
                properties: &[],
                chunks: None,
                sources: vec![],
            },
            EventContext::default(),
        )
        .await
        .expect("create resource through the real path")
    }

    /// Soft-delete `resource` through the real path: a tombstone, never a husk.
    async fn tombstone(pool: &PgPool, owner: &Principal, resource: ResourceId) {
        let mut tx = pool.begin().await.expect("begin");
        fire(
            &mut tx,
            SeedAction::ResourceDelete {
                resource,
                emitter: owner.emitter,
            },
        )
        .await
        .expect("soft delete through the real path");
        tx.commit().await.expect("commit");
        let (is_active, erased): (bool, bool) = sqlx::query_as(
            "SELECT is_active, erased_at IS NOT NULL FROM kb_resources WHERE id = $1",
        )
        .bind(resource.uuid())
        .fetch_one(pool)
        .await
        .expect("row");
        assert!(
            !is_active && !erased,
            "precondition: a tombstone, not a husk"
        );
    }

    /// Erase `resource` through the real act; asserts it completed and left a husk.
    async fn erase(pool: &PgPool, resource: ResourceId) {
        let op = operator(pool).await;
        let outcome = execute_resource_erasure(
            pool,
            None,
            &op,
            ResourceErasureRequest {
                resource,
                also_strike_blobs: &[],
                surface: Surface::ApiHttp,
            },
        )
        .await
        .expect("the act answers");
        assert!(
            matches!(outcome, ResourceErasureOutcome::Completed(_)),
            "the act must complete, got {outcome:?}"
        );
        let erased: bool =
            sqlx::query_scalar("SELECT erased_at IS NOT NULL FROM kb_resources WHERE id = $1")
                .bind(resource.uuid())
                .fetch_one(pool)
                .await
                .expect("row");
        assert!(erased, "precondition: the act made a husk");
    }

    /// A direct profile `can_read` grant, and nothing more.
    async fn grant_read(pool: &PgPool, resource: ResourceId, grantee: ProfileId, by: ProfileId) {
        sqlx::query(
            "INSERT INTO kb_access_grants \
             (subject_table, subject_id, principal_table, principal_id, can_read, granted_by_profile_id) \
             VALUES ('kb_resources', $1, 'kb_profiles', $2, true, $3)",
        )
        .bind(resource.uuid())
        .bind(grantee.uuid())
        .bind(by.uuid())
        .execute(pool)
        .await
        .expect("insert read grant");
    }

    /// The modify floor in a fresh transaction, rolled back after.
    async fn modify(
        pool: &PgPool,
        profile: ProfileId,
        resource: ResourceId,
    ) -> Result<(), TemperError> {
        let mut tx = pool.begin().await.expect("begin");
        let answer = modify_floor_in_tx(&mut tx, profile, resource).await;
        tx.rollback().await.expect("rollback");
        answer
    }

    /// The liveness floor in a fresh transaction, rolled back after.
    async fn liveness(
        pool: &PgPool,
        profile: ProfileId,
        resource: ResourceId,
    ) -> Result<(), TemperError> {
        let mut tx = pool.begin().await.expect("begin");
        let answer = liveness_floor_in_tx(&mut tx, profile, resource).await;
        tx.rollback().await.expect("rollback");
        answer
    }

    // ── modify_floor_in_tx ──────────────────────────────────────────────────────────────────

    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn modify_floor_admits_the_owner_of_a_live_resource(pool: PgPool) {
        let owner = principal(&pool).await;
        let r = resource(&pool, &owner).await;
        let answer = modify(&pool, owner.profile, r).await;
        assert!(answer.is_ok(), "the owner may modify: {answer:?}");
    }

    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn modify_floor_forbids_a_non_modifier_of_a_live_resource(pool: PgPool) {
        let owner = principal(&pool).await;
        let stranger = principal(&pool).await;
        let r = resource(&pool, &owner).await;
        let answer = modify(&pool, stranger.profile, r).await;
        assert!(
            matches!(answer, Err(TemperError::Forbidden)),
            "a stranger is forbidden: {answer:?}"
        );
    }

    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn modify_floor_forbids_the_owner_of_a_tombstone_never_erased(pool: PgPool) {
        let owner = principal(&pool).await;
        let r = resource(&pool, &owner).await;
        tombstone(&pool, &owner, r).await;
        let answer = modify(&pool, owner.profile, r).await;
        assert!(
            matches!(answer, Err(TemperError::Forbidden)),
            "a tombstone is Forbidden, never ResourceErased: {answer:?}"
        );
    }

    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn modify_floor_answers_erased_to_the_owner_of_a_husk(pool: PgPool) {
        let owner = principal(&pool).await;
        let r = resource(&pool, &owner).await;
        erase(&pool, r).await;
        let answer = modify(&pool, owner.profile, r).await;
        assert!(
            matches!(answer, Err(TemperError::ResourceErased(id)) if id == r),
            "the owner of a husk is told it was erased: {answer:?}"
        );
    }

    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn modify_floor_answers_erased_to_a_read_grant_holder_of_a_husk(pool: PgPool) {
        let owner = principal(&pool).await;
        let reader = principal(&pool).await;
        let r = resource(&pool, &owner).await;
        grant_read(&pool, r, reader.profile, owner.profile).await;
        assert!(
            matches!(
                modify(&pool, reader.profile, r).await,
                Err(TemperError::Forbidden)
            ),
            "precondition: a read-only grant does not admit a modify while live"
        );
        erase(&pool, r).await;
        let answer = modify(&pool, reader.profile, r).await;
        assert!(
            matches!(answer, Err(TemperError::ResourceErased(id)) if id == r),
            "a read-grant holder of a husk is told it was erased (the read population): {answer:?}"
        );
    }

    /// Not one of the plan's six: the oracle guard. A husk the caller holds no standing on answers
    /// exactly as an unknown id does.
    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn modify_floor_forbids_a_stranger_to_a_husk(pool: PgPool) {
        let owner = principal(&pool).await;
        let stranger = principal(&pool).await;
        let r = resource(&pool, &owner).await;
        erase(&pool, r).await;
        let answer = modify(&pool, stranger.profile, r).await;
        assert!(
            matches!(answer, Err(TemperError::Forbidden)),
            "a stranger to a husk gets Forbidden, never ResourceErased: {answer:?}"
        );
    }

    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn modify_floor_forbids_an_unknown_id(pool: PgPool) {
        let caller = principal(&pool).await;
        let answer = modify(&pool, caller.profile, ResourceId::from(Uuid::now_v7())).await;
        assert!(
            matches!(answer, Err(TemperError::Forbidden)),
            "an unknown id is Forbidden, not a distinct answer: {answer:?}"
        );
    }

    // ── liveness_floor_in_tx ────────────────────────────────────────────────────────────────

    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn liveness_floor_admits_a_non_owner_of_a_live_resource(pool: PgPool) {
        let owner = principal(&pool).await;
        let stranger = principal(&pool).await;
        let r = resource(&pool, &owner).await;
        let answer = liveness(&pool, stranger.profile, r).await;
        assert!(
            answer.is_ok(),
            "liveness checks no authority, so a non-owner passes on a live resource: {answer:?}"
        );
    }

    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn liveness_floor_forbids_a_tombstone(pool: PgPool) {
        let owner = principal(&pool).await;
        let r = resource(&pool, &owner).await;
        tombstone(&pool, &owner, r).await;
        let answer = liveness(&pool, owner.profile, r).await;
        assert!(
            matches!(answer, Err(TemperError::Forbidden)),
            "a tombstone fails liveness as Forbidden, never ResourceErased: {answer:?}"
        );
    }

    #[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
    async fn liveness_floor_answers_erased_to_the_holder_of_a_husk(pool: PgPool) {
        let owner = principal(&pool).await;
        let r = resource(&pool, &owner).await;
        erase(&pool, r).await;
        let answer = liveness(&pool, owner.profile, r).await;
        assert!(
            matches!(answer, Err(TemperError::ResourceErased(id)) if id == r),
            "the holder of a husk is told it was erased: {answer:?}"
        );
    }
}
