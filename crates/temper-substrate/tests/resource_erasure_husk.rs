#![cfg(feature = "artifact-tests")]
//! The resource-erasure husk (spec 2026-09-28, D6): `kb_resources.erased_at`, the invariant that
//! an erased resource is inactive, and what that invariant buys the region-label fallback.
//!
//! The act that sets `erased_at` lands in a later build, so these tests write the husk state
//! directly: the projection shape the act will produce, an inactive row with `erased_at` set and a
//! sentinel title.
//!
//! **Why Witness 19 is proven through the invariant, not a new predicate.** The spec asks that
//! the region-label fallback skip erased members. Every read that surfaces a member title from a
//! region (`anchor_shape`, `graph_cogmap_territories`, `graph_region_territories`) already joins
//! `kb_resources ... AND r.is_active`, so an extra `erased_at IS NULL` would be dead code the day
//! `erased_at IS NOT NULL ⇒ NOT is_active` holds. The invariant is therefore a CHECK
//! (`kb_resources_erased_is_inactive`), and this file proves both halves: the database refuses the
//! state that would leak, and none of the three reads labels a region with an erased member.

use sqlx::PgPool;
use uuid::Uuid;

mod common;

async fn insert_cogmap_resource(pool: &PgPool, cogmap: Uuid, owner: Uuid, title: &str) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO kb_resources (title, origin_uri) VALUES ($1,'') RETURNING id",
    )
    .bind(title)
    .fetch_one(pool)
    .await
    .expect("insert resource");
    sqlx::query(
        "INSERT INTO kb_resource_homes \
           (resource_id, anchor_table, anchor_id, originator_profile_id, owner_profile_id) \
         VALUES ($1, 'kb_cogmaps', $2, $3, $3)",
    )
    .bind(id)
    .bind(cogmap)
    .bind(owner)
    .execute(pool)
    .await
    .expect("home resource in cogmap");
    id
}

/// The husk the act will leave: inactive, `erased_at` set, title replaced by its sentinel.
async fn erase_to_husk(pool: &PgPool, resource: Uuid) {
    sqlx::query(
        "UPDATE kb_resources \
            SET is_active = false, erased_at = now(), title = 'erased-' || id::text \
          WHERE id = $1",
    )
    .bind(resource)
    .execute(pool)
    .await
    .expect("write the husk state");
}

struct Fx {
    cogmap: Uuid,
    team: Uuid,
    reader: Uuid,
    lens: Uuid,
    region: Uuid,
    /// The most-affine member: the one the fallback labels the region with.
    leaky: Uuid,
    kept: Uuid,
}

/// One readable cogmap holding one unlabelled region with two members. `leaky` has the higher
/// affinity, so it is the fallback's pick until it is erased.
async fn fixture(pool: &PgPool) -> Fx {
    common::seed_system(pool).await;
    let (cogmap, _) = common::genesis_cogmap(pool, "husk", "Husk").await;
    let team = common::create_team(pool, "husk-team").await;
    let reader = common::create_profile(pool, "reader@example.com").await;
    common::add_team_member(pool, team, reader).await;
    sqlx::query("INSERT INTO kb_team_cogmaps (team_id, cogmap_id) VALUES ($1, $2)")
        .bind(team)
        .bind(cogmap)
        .execute(pool)
        .await
        .expect("join the cogmap to the team");
    let lens: Uuid = sqlx::query_scalar(
        "SELECT id FROM kb_cogmap_lenses WHERE name='telos-default' AND cogmap_id IS NULL",
    )
    .fetch_one(pool)
    .await
    .expect("global telos-default lens");
    let event: Uuid = sqlx::query_scalar("SELECT id FROM kb_events LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("any event for FK");
    let system: Uuid = sqlx::query_scalar("SELECT id FROM kb_profiles WHERE handle='system'")
        .fetch_one(pool)
        .await
        .expect("system profile");

    // label NULL: the fallback is what names this region.
    let region: Uuid = sqlx::query_scalar(
        "INSERT INTO kb_cogmap_regions
           (cogmap_id, home_anchor_table, home_anchor_id, lens_id, centroid, salience,
            content_cohesion, label, member_count, asserted_by_event_id, last_event_id, is_folded)
         VALUES ($1, 'kb_cogmaps', $1, $2, array_fill(0::double precision, ARRAY[768])::vector,
            1.0, NULL, NULL, 2, $3, $3, false)
         RETURNING id",
    )
    .bind(cogmap)
    .bind(lens)
    .bind(event)
    .fetch_one(pool)
    .await
    .expect("insert region");

    let leaky = insert_cogmap_resource(pool, cogmap, system, "Jane Roe 078-05-1120 notes").await;
    let kept = insert_cogmap_resource(pool, cogmap, system, "Deployment runbook").await;
    for (member, affinity) in [(leaky, 0.9_f64), (kept, 0.5)] {
        sqlx::query(
            "INSERT INTO kb_cogmap_region_members (region_id, member_table, member_id, affinity) \
             VALUES ($1, 'kb_resources', $2, $3)",
        )
        .bind(region)
        .bind(member)
        .bind(affinity)
        .execute(pool)
        .await
        .expect("add region member");
    }

    Fx {
        cogmap,
        team,
        reader,
        lens,
        region,
        leaky,
        kept,
    }
}

/// The region's label as each of the three fallback reads renders it, in a fixed order.
async fn labels(pool: &PgPool, fx: &Fx) -> Vec<(&'static str, Option<String>)> {
    let shape: Option<String> = sqlx::query_scalar(
        "SELECT label FROM anchor_shape('kb_cogmaps', $1, 'profile', $2, NULL) \
          WHERE region_id = $3",
    )
    .bind(fx.cogmap)
    .bind(fx.reader)
    .bind(fx.region)
    .fetch_one(pool)
    .await
    .expect("anchor_shape row for the region");
    let territories: Option<String> = sqlx::query_scalar(
        "SELECT label FROM graph_cogmap_territories($1, $2, $3) WHERE region_id = $4",
    )
    .bind(fx.reader)
    .bind(fx.cogmap)
    .bind(fx.lens)
    .bind(fx.region)
    .fetch_one(pool)
    .await
    .expect("graph_cogmap_territories row for the region");
    let team_territories: Option<String> = sqlx::query_scalar(
        "SELECT label FROM graph_region_territories($1, $2, $3) WHERE region_id = $4",
    )
    .bind(fx.reader)
    .bind(fx.team)
    .bind(fx.lens)
    .bind(fx.region)
    .fetch_one(pool)
    .await
    .expect("graph_region_territories row for the region");
    vec![
        ("anchor_shape", shape),
        ("graph_cogmap_territories", territories),
        ("graph_region_territories", team_territories),
    ]
}

/// FAILS IF: an erased resource can be active. That state would put its sentinel title into every
/// `is_active`-gated read, and it would read as reactivated rather than erased.
#[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
async fn an_erased_resource_cannot_be_active(pool: PgPool) {
    let fx = fixture(&pool).await;

    let active_husk = sqlx::query("UPDATE kb_resources SET erased_at = now() WHERE id = $1")
        .bind(fx.leaky)
        .execute(&pool)
        .await;
    assert!(
        active_husk.is_err(),
        "erased_at on an active resource must violate kb_resources_erased_is_inactive"
    );

    erase_to_husk(&pool, fx.leaky).await;
    let reactivated = sqlx::query("UPDATE kb_resources SET is_active = true WHERE id = $1")
        .bind(fx.leaky)
        .execute(&pool)
        .await;
    assert!(
        reactivated.is_err(),
        "an erased resource must not be reactivated"
    );

    // A soft delete is not an erasure (Witness 8's first half): inactive with erased_at NULL.
    sqlx::query("UPDATE kb_resources SET is_active = false WHERE id = $1")
        .bind(fx.kept)
        .execute(&pool)
        .await
        .expect("an ordinary soft delete is untouched by the invariant");
    let erased_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT erased_at FROM kb_resources WHERE id = $1")
            .bind(fx.kept)
            .fetch_one(&pool)
            .await
            .expect("read erased_at");
    assert!(erased_at.is_none());
}

/// Witness 19 (spec D6): a region whose most-affine member is erased does not render that member's
/// sentinel title (`erased-<id>`) as its fallback label, in any of the three reads that compute
/// one. It falls back to the next visible member instead.
#[sqlx::test(migrator = "temper_substrate::MIGRATOR")]
async fn a_region_label_never_renders_an_erased_member(pool: PgPool) {
    let fx = fixture(&pool).await;

    // Precondition: the fallback really does pick the most-affine member, or the witness below
    // would pass without testing anything.
    for (read, label) in labels(&pool, &fx).await {
        assert_eq!(
            label.as_deref(),
            Some("Jane Roe 078-05-1120 notes"),
            "{read}: before erasure the fallback labels the region with its most-affine member"
        );
    }

    erase_to_husk(&pool, fx.leaky).await;

    for (read, label) in labels(&pool, &fx).await {
        let label = label.unwrap_or_default();
        assert!(
            !label.starts_with("erased-") && !label.contains("078-05-1120"),
            "{read}: the region's fallback label reads {label:?}, naming an erased member"
        );
        assert_eq!(
            label, "Deployment runbook",
            "{read}: the fallback moves to the next visible member"
        );
    }
}
