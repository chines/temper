//! `/api/query` alone, carrying the one bound on a composition that the schema cannot express.
//!
//! **Merged into `gated_routes` rather than mounted there, purely so the layer is scoped.** A
//! `DefaultBodyLimit` applies to every route in the router it is attached to, and no other gated
//! route has any reason to accept a body this size — the same argument that keeps
//! `webhook_intake_routes` separate, and the reason this is a merge rather than one more
//! `.routes(...)` line. It stays inside `gated_routes`' auth and system-access layers, which are
//! applied to the merged whole in `create_app`; nothing about the mounting changes who may knock.

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::handlers;
use temper_services::state::AppState;

pub(super) fn query_routes() -> OpenApiRouter<AppState> {
    use axum::extract::DefaultBodyLimit;

    OpenApiRouter::new()
        .routes(routes!(handlers::query::query))
        .layer(DefaultBodyLimit::max(QUERY_MAX_BODY_BYTES))
}

/// The largest composition `/api/query` will read.
///
/// # Declared because the inherited number is wrong, not merely because inheriting is untidy
///
/// Nothing in temper-api set `DefaultBodyLimit`, so axum's 2 MB default was this door's operative
/// bound by accident. `MAX_PER_CANDIDATE_PROBES`' own doc already reasons *against* that number as
/// a bound — *"the list fits in a fraction of axum's default 2 MB body limit"* — which is the tell
/// that it was doing work nobody had chosen.
///
/// **And it is wrong in the direction that refuses legal plans.** A caller may send a precomputed
/// 768-float embedding beside each question (`Intention::embedding`, which the CLI always does),
/// and that is ~10 KB per stage on the wire. At `MAX_STAGES` stages, with a question at
/// `MAX_INTENTION_QUERY_BYTES` and bounds at `MAX_ID_SET_IDS`, a composition the contract calls
/// legal serializes to **2,194,320 bytes** `[measured — 2026-08-28, by the test named below]` —
/// 97 KB past the inherited 2,097,152. So the door would have answered a plan its own contract
/// admits with a bare 413: no refusal list, no vocabulary, in the door whose whole promise is that
/// every refusal arrives at once and in the caller's own terms.
/// `the_largest_legal_composition_fits_inside_the_declared_body_limit` holds that, and fails
/// against the inherited number rather than merely describing it.
///
/// # Why a raised number and not the sum
///
/// The 4 MB this constant carried from 2026-08-28 to the network door was the same argument in
/// miniature: the measured largest legal composition (2,455,972 bytes — the test named below
/// holds it against the number) fits 1.71x under it. The network-door ruling (design §D4) then
/// re-sized the backstop to the transport contract: `/api/query` is a tool-carrying endpoint,
/// and a second, smaller opinion about body size is exactly the invisible gate ruling 3
/// removes. The declaration caps above remain the real bound; this number catches only the
/// cost they cannot see.
///
/// **Every COUNT the contract admits is now bounded, and what remains unbounded is LENGTH.**
/// `[narrowed — 2026-08-28, after review]` This paragraph first named only the length half, which
/// understated why the backstop was needed: `ReturnSpec::with`, `EdgeFilter::edge_kinds`,
/// `EdgeFilter::labels`, `ResourceFilter::doc_type` and `ResourceFilter::tags` were `Vec`s no pass
/// capped, and `validate_returns` checked section MEMBERSHIP only — so `with: [open_meta; 10_000]`
/// per return validated `Ok` and serialized to **9.6 MB**, and ten thousand one-character labels
/// per stage to **4.7 MB**. Both are refused now: `MAX_FILTER_VALUES` bounds the three open lists,
/// and `DuplicateSetMember` bounds the two closed vocabularies at their own size.
///
/// So the coherence property below holds over every field whose COUNT the contract fixes, and
/// `the_largest_legal_composition_fits_inside_the_declared_body_limit` measures that maximum at
/// **2,455,972 bytes** — under this number at either size it has carried (4 MB: 1.71x under;
/// 25 MB: 10.6x under).
///
/// What it does not bound is SIZE, and there are two kinds `[both named — 2026-08-28, after review]`:
/// the LENGTH of a string inside a counted list (a facet key, a label, a `title_contains`), and the
/// serialized size of a single `Contains` VALUE — `probe_count` charges one probe per value however
/// large, so one value holding a million-element JSON array is 6.9 MB and validates `Ok`.
///
/// Through the counted lists, reaching 4 MB now takes ~400 bytes per label across every stage
/// rather than one byte, which is the difference between a caller and an adversary. Through a
/// `Contains` value it takes a single field. That second one is the thing to bound next, and it is
/// why this limit is a backstop and not a sum.
pub const QUERY_MAX_BODY_BYTES: usize = 25 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::QUERY_MAX_BODY_BYTES;
    use std::collections::BTreeMap;
    use temper_core::types::graph::EdgeKind;
    use temper_core::types::query::act::ActName;
    use temper_core::types::query::composition::{
        Composition, Intention, OutcomeDeclaration, ReturnSpec, StageNode,
        MAX_INTENTION_QUERY_BYTES, MAX_STAGES,
    };
    use temper_core::types::query::envelope::ActInvocation;
    use temper_core::types::query::filter::{
        EdgeFilter, FacetPredicate, PropertyOp, PropertyPredicate, ResourceFilter,
        MAX_FILTER_VALUES,
    };
    use temper_core::types::query::id_set::{IdKind, IdSet, MAX_ID_SET_IDS};
    use temper_core::types::query::scalars::BoundTerm;
    use temper_core::types::query::stage::{StageInput, StageName, StageRelation};
    use temper_core::types::query::validate::validate;
    use temper_core::types::resource_view::ResourceSection;

    /// **The coherence condition that makes the caps one decision rather than several ifs.**
    ///
    /// Every bound on what a request may declare is published on the field it bounds and refused in
    /// the shape pass, with a typed reason and every sibling refusal beside it. The body limit is
    /// the one such bound the schema cannot carry, so it is declared here — and it is only
    /// coherent with the others if a caller never meets it while inside them. A composition at
    /// every published cap that does not FIT is a plan the contract calls legal and the transport
    /// answers with a bare 413: no refusal list, no vocabulary, in the door whose whole promise is
    /// that a plan is repaired in one round trip.
    ///
    /// **The plan is VALIDATED before it is measured, and that assertion is not ceremony**
    /// `[added — 2026-08-28, found in review]`. The first version of this fixture used
    /// `find-about-anywhere` and carried a seed and a bound — an act that declares
    /// `accepts_bounds: vec![]` and `accepts_seeds: vec![]` (`registry.rs:202-203`, *"a bound would
    /// make this find-about-within"*). So it measured a plan carrying **128 refusals** while its
    /// own doc called it *"a plan the contract calls legal"*, and nothing asked. The size claim
    /// happened to survive — `follow-from` is the one act declaring both, and swapping it moved the
    /// total by 512 bytes — but a size measured over an illegal plan proves nothing about what the
    /// door must accept, and the next edit to this fixture would have had no guard at all.
    ///
    /// The dominant term is the **caller id sets**, at roughly twice the embeddings
    /// `[measured — 2026-08-28]`: 1,286,912 bytes against 639,872, with the questions third at
    /// 262,144. Named because both were misattributed here first — strip the id sets and the
    /// fixture is 907,408 bytes, comfortably inside the inherited limit, so they are what carries
    /// it past.
    ///
    /// **What it does NOT prove**, stated because a green here reads like completeness. Two things:
    ///
    /// - **It is a floor, not the maximum.** Every COUNT the contract admits is bounded as of
    ///   2026-08-28, so what escapes is SIZE: the length of a string inside a counted list (a facet
    ///   key, a label, a `title_contains`), and the serialized size of a `Contains` VALUE, which
    ///   `probe_count` counts as one probe however large — a single value holding a million-element
    ///   JSON array is 6.9 MB and validates `Ok` `[measured — 2026-08-28]`. Reaching the limit
    ///   through the counted lists now takes ~400 bytes per label across every stage instead of
    ///   one; through a `Contains` value it takes one.
    /// - **The headline number is the WALK shape, which admits no `ResourceFilter`** — so
    ///   `doc_type` and `tags` at their cap appear only in the selection shape, which is half the
    ///   size. No single act admits every bounded field, which is why both are measured; but the
    ///   maximum reported is not maximal in those two fields.
    ///
    #[test]
    fn the_largest_legal_composition_fits_inside_the_declared_body_limit() {
        // **Two shapes, both measured, because no single act admits every bounded field and the
        // larger one is not obvious.** `follow-from` takes a seed, a bound and an `EdgeFilter`;
        // `find-resources-with` is the only act whose `ResourceFilter` is not refused
        // (`capability.rs`'s narrowings block), and it accepts no bounds and no page terms at all.
        // A first version mixed them and measured 1,756,196 — LESS than either pure shape, because
        // half its stages carried no id sets. Measuring both and taking the larger is what stops
        // this test from quietly reporting a maximum that is not one.
        let walk = plan_of(MAX_STAGES, ActName::FollowFrom);
        let select = plan_of(MAX_STAGES, ActName::FindResourcesWith);

        for (what, c) in [("walk", &walk), ("selection", &select)] {
            // Legal FIRST. A byte count over a plan the validator refuses is a measurement of
            // nothing — and the first version of this test measured one carrying 128 refusals
            // while its own doc called it legal `[found in review — 2026-08-28]`.
            assert!(
                validate(c).is_ok(),
                "the {what} fixture must be a composition this server would RUN, or its size says \
                 nothing about what the door has to accept: {:?}",
                validate(c).err()
            );
        }

        let sizes: Vec<usize> = [&walk, &select]
            .iter()
            .map(|c| {
                serde_json::to_vec(c)
                    .expect("a composition serializes")
                    .len()
            })
            .collect();
        let bytes = *sizes.iter().max().expect("two shapes");
        assert!(
            bytes < QUERY_MAX_BODY_BYTES,
            "the largest composition at every published cap serializes to {bytes} bytes (walk \
             {}, selection {}), which the declared body limit of {QUERY_MAX_BODY_BYTES} would \
             refuse with a bare 413 — raise the limit, or lower the field caps, but do not let the \
             contract admit a plan the door cannot read",
            sizes[0],
            sizes[1]
        );
    }

    /// `n` stages of one act, each maximal over every field that act admits and every cap the
    /// contract publishes.
    ///
    /// **A selection-shaped plan still ends in one walk stage**, because a selection orders nothing
    /// and is refused in `returns` (`StageNotReturnable`) while a composition that returns nothing
    /// is refused outright (`NoReturns`). So the pure shape is not legal at any size, and the
    /// largest selection-shaped plan is `n - 1` selections plus the walk that answers.
    fn plan_of(n: usize, act: ActName) -> Composition {
        let all_walk = act == ActName::FollowFrom;
        let stages: Vec<StageNode> = (0..n)
            .map(|i| {
                let walk = all_walk || i == n - 1;
                StageNode::Act(ActInvocation {
                    // Stage names at their own ceiling — 63 (`stage.rs:43`).
                    name: StageName::parse(&format!(
                        "s{i}{}",
                        "n".repeat(60 - i.to_string().len())
                    ))
                    .expect("legal stage name"),
                    act: if walk {
                        ActName::FollowFrom
                    } else {
                        act.clone()
                    },
                    intention: Some(Intention {
                        query: "x".repeat(MAX_INTENTION_QUERY_BYTES),
                        // A real normalized BGE component, so the serialized width is the one a
                        // caller actually sends rather than the two bytes `0.0` would cost.
                        //
                        // Every stage carries one, which is also what keeps this inside
                        // `MAX_COMPOSITION_INTENTION_BYTES`: that bound counts only what the SERVER
                        // must embed, and a caller who precomputed has already paid it. A fixture
                        // without embeddings is a DIFFERENT and SMALLER maximum, because the
                        // aggregate budget then caps its question text at 64 KB.
                        embedding: Some(vec![-0.041_899_003; 768]),
                    }),
                    inputs: if walk {
                        vec![
                            StageInput::Caller {
                                relation: StageRelation::Seed,
                                ids: full_id_set(),
                            },
                            StageInput::Caller {
                                relation: StageRelation::Bound,
                                ids: full_id_set(),
                            },
                        ]
                    } else {
                        // A selection accepts no bounds of any kind and no page terms — it declares
                        // a set. Both are `capability`'s refusals, and hitting them is how this
                        // fixture learned the shape rather than assuming it.
                        vec![]
                    },
                    terms: if walk {
                        BTreeMap::from([(BoundTerm::Limit, 50), (BoundTerm::Offset, 50)])
                    } else {
                        BTreeMap::new()
                    },
                    resource_filter: (!walk).then(full_resource_filter),
                    edge_filter: walk.then(full_edge_filter),
                    properties: vec![],
                })
            })
            .collect();

        Composition {
            outcome: OutcomeDeclaration {
                // A selection orders nothing and is refused in `returns` (`StageNotReturnable`), so
                // that shape returns its first stage only — which is what a caller would do.
                // Every walk stage, which for the walk shape is all of them and for the selection
                // shape is the one that answers.
                returns: stages
                    .iter()
                    .filter(|n| matches!(n, StageNode::Act(i) if i.act == ActName::FollowFrom))
                    .map(|node| ReturnSpec {
                        stage: node.name().clone(),
                        with: vec![ResourceSection::OpenMeta],
                    })
                    .collect(),
            },
            stages,
        }
    }

    /// Every narrowing list at [`MAX_FILTER_VALUES`], and both per-candidate containers at the caps
    /// `capability.rs` enforces — 32 predicates summing to 256 probes.
    fn full_resource_filter() -> ResourceFilter {
        ResourceFilter {
            doc_type: vec!["d".to_string(); MAX_FILTER_VALUES],
            tags: vec!["t".to_string(); MAX_FILTER_VALUES],
            facets: (0..16)
                .map(|i| FacetPredicate {
                    key: format!("k{i}"),
                    value: "v".to_string(),
                })
                .collect(),
            // 16 facets + 16 predicates = 32, the predicate cap; 16 facets + 240 probes = 256,
            // the probe cap. Facets count against BOTH, which is what the container's own doc
            // means by summing what walks the same candidate set.
            properties: capped_properties(16, 15),
            stage: Some("s".to_string()),
            status: Some("a".to_string()),
            owner: Some("o".to_string()),
            title_contains: Some("t".to_string()),
        }
    }

    fn full_edge_filter() -> EdgeFilter {
        EdgeFilter {
            // A closed vocabulary carried as a list, and repeats are refused — so its ceiling IS
            // the vocabulary, and naming every member is what makes this maximal. `[widened from
            // one — 2026-08-28, found in review]`
            edge_kinds: vec![
                EdgeKind::Express,
                EdgeKind::Contains,
                EdgeKind::LeadsTo,
                EdgeKind::Near,
            ],
            labels: vec!["l".to_string(); MAX_FILTER_VALUES],
            // No facets on an edge container, so all 32 predicates and all 256 probes are the
            // property list's.
            properties: capped_properties(32, 8),
        }
    }

    /// `preds` predicates each carrying `vals` values. The two caps a container must satisfy are
    /// `MAX_PER_CANDIDATE_PREDICATES` (32, summed with `facets` where the container has them) and
    /// `MAX_PER_CANDIDATE_PROBES` (256, likewise) — so the split differs between the two containers
    /// and is passed rather than assumed.
    fn capped_properties(preds: usize, vals: usize) -> Vec<PropertyPredicate> {
        (0..preds)
            .map(|i| PropertyPredicate {
                key: format!("p{i}"),
                op: PropertyOp::Contains {
                    values: (0..vals)
                        .map(|v| serde_json::json!(format!("v{v}")))
                        .collect(),
                },
            })
            .collect()
    }

    fn full_id_set() -> IdSet {
        IdSet {
            kind: IdKind::Resource,
            provenance: None,
            ids: (0..MAX_ID_SET_IDS).map(|_| uuid::Uuid::now_v7()).collect(),
        }
    }
}
