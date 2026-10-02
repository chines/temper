#![cfg(feature = "test-db")]
//! Reconcile's authority, decided by regime (`DbBackend::authorize_reconcile`): a map in the
//! admin-only regime — the reserved L0 kernel, or a map joined to the gating (root) team — requires
//! `is_system_admin`; every other map requires authorship of the map, a system admin included
//! (ruled 2026-10-01). The L0 system-default map (`20260625000001`) is joined to `temper-system`, so
//! it is the canonical admin-regime case.
//!
//! The canonical seed leaves `kb_system_settings.gating_team_slug` NULL (open mode). Both the
//! regime's root-join detection AND `is_system_admin` resolve through that slug, so these tests first
//! configure it to `temper-system` — the production-shaped config the gate is designed for.

use sqlx::PgPool;
use uuid::Uuid;

use temper_core::error::TemperError;
use temper_core::types::ids::{CogmapId, ProfileId};
use temper_services::backend::DbBackend;

mod common;

const L0_COGMAP: CogmapId = CogmapId(Uuid::from_u128(0x00000000_0000_0000_0005_000000000001));

/// Configure the gating team slug to the root team born by the L0 migration. Without this the
/// canonical seed runs in `open` mode with a NULL gating slug (no root team configured).
async fn set_gating_team(pool: &PgPool) {
    sqlx::query("UPDATE kb_system_settings SET gating_team_slug = 'temper-system' WHERE id = 1")
        .execute(pool)
        .await
        .expect("set gating team slug");
}

/// Mint an admin profile under D11: admin-ness is `approved` standing + a `kb_principal_governance`
/// grant — neither the Phase-2-retired `system_access` column nor gating ownership confers it.
async fn admin_profile(pool: &PgPool, email: &str) -> Uuid {
    let id = common::fixtures::create_test_profile(pool, email).await;
    common::fixtures::make_test_admin(pool, id).await;
    id
}

fn as_profile(pool: &PgPool, id: Uuid) -> DbBackend {
    DbBackend::new(pool.clone(), ProfileId::from(id))
}

/// FAILS IF a non-admin may reconcile the root-joined L0 map, or an admin may not.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn l0_reconcile_requires_system_admin(pool: PgPool) {
    set_gating_team(&pool).await;

    let non_admin = common::fixtures::create_test_profile(&pool, "nonadmin@example.com").await;
    let denied = as_profile(&pool, non_admin)
        .authorize_reconcile(L0_COGMAP)
        .await;
    assert!(
        matches!(denied, Err(TemperError::Forbidden)),
        "non-admin must be Forbidden on the root-team-joined L0 map, got {denied:?}"
    );

    let admin = admin_profile(&pool, "admin@example.com").await;
    as_profile(&pool, admin)
        .authorize_reconcile(L0_COGMAP)
        .await
        .expect("an admin passes L0's regime gate");
}

/// FAILS IF L0 is reconcilable by anyone while gating is unconfigured. The regime is fail-CLOSED:
/// the reserved map requires `is_system_admin` unconditionally, and with gating unconfigured
/// `is_system_admin` is false for everyone — so L0 is immutable until an operator configures gating.
/// Without the unconditional L0 branch a NULL gating slug would drop L0 into the authorship arm.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn l0_is_immutable_when_gating_unconfigured(pool: PgPool) {
    let any_profile = common::fixtures::create_test_profile(&pool, "anyone@example.com").await;
    let denied = as_profile(&pool, any_profile)
        .authorize_reconcile(L0_COGMAP)
        .await;
    assert!(
        matches!(denied, Err(TemperError::Forbidden)),
        "L0 must be immutable (Forbidden to all) when gating is unconfigured, got {denied:?}"
    );
}

/// FAILS IF a map outside the admin-only regime is reconcilable without authorship. A map NOT joined
/// to the gating team falls to `check_cogmap_authorable`: a principal who holds no grant on it (here
/// an unknown map, which nobody authors) is refused in the argument-free dialect.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn a_non_root_cogmap_requires_authorship(pool: PgPool) {
    set_gating_team(&pool).await;

    let non_admin = common::fixtures::create_test_profile(&pool, "user@example.com").await;
    let denied = as_profile(&pool, non_admin)
        .authorize_reconcile(CogmapId::new())
        .await;
    assert!(
        matches!(denied, Err(TemperError::Forbidden)),
        "a non-author must be refused on a map outside the admin-only regime, got {denied:?}"
    );
}

/// Genesis a map as `creator` (not L0, joined to no team). Returns its id.
async fn genesis_map(pool: &PgPool, creator: Uuid, name: &str) -> Uuid {
    use temper_workflow::operations::{Backend, CreateCognitiveMap, Surface};
    as_profile(pool, creator)
        .create_cognitive_map(CreateCognitiveMap {
            request: temper_core::types::reconcile::CreateCogmapRequest {
                cogmap_id: None,
                telos_resource_id: None,
                name: name.to_string(),
                telos_title: format!("{name} telos"),
                telos: None,
            },
            origin: Surface::ApiHttp,
        })
        .await
        .expect("genesis a map")
        .value
        .cogmap_id
}

/// FAILS IF joining a map to the gating team does not put it in the admin-only regime. A non-admin
/// who holds a WRITE grant — authorship, which admits it on an unjoined map (the control below) — is
/// refused on a non-L0 map joined to the gating team, so the refusal is the regime's, not a missing
/// grant's. The bite: make `access_service::cogmap_write_requires_admin` answer false for every map
/// but L0 — the joined map then falls to authorship and the grant admits it.
#[sqlx::test(migrator = "temper_api::MIGRATOR")]
async fn a_gating_team_map_refuses_a_non_admin_author(pool: PgPool) {
    set_gating_team(&pool).await;
    let creator = admin_profile(&pool, "creator@example.com").await;
    let author = common::fixtures::create_test_profile(&pool, "author@example.com").await;

    let unjoined = genesis_map(&pool, creator, "Unjoined map").await;
    common::fixtures::grant_cogmap_write(&pool, unjoined, author).await;
    as_profile(&pool, author)
        .authorize_reconcile(CogmapId::from(unjoined))
        .await
        .expect("control: a write grant admits its holder on a map outside the admin-only regime");

    let joined = genesis_map(&pool, creator, "Gating-team map").await;
    sqlx::query(
        "INSERT INTO kb_team_cogmaps (cogmap_id, team_id) \
         SELECT $1, id FROM kb_teams WHERE slug = 'temper-system'",
    )
    .bind(joined)
    .execute(&pool)
    .await
    .expect("join the map to the gating team");
    common::fixtures::grant_cogmap_write(&pool, joined, author).await;
    let denied = as_profile(&pool, author)
        .authorize_reconcile(CogmapId::from(joined))
        .await;
    assert!(
        matches!(denied, Err(TemperError::Forbidden)),
        "a non-admin author is refused on a gating-team map, got {denied:?}"
    );
}
