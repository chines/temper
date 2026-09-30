//! Freshness and cache scope for list/read results (SEP-2549).
//!
//! MCP 2026-07-28 makes `ttlMs` and `cacheScope` REQUIRED on `tools/list`,
//! `resources/list`, `resources/templates/list` and `resources/read`, and strict
//! clients enforce it: Claude Code rejects a `tools/list` answer without them
//! (`Invalid result for tools/list: ttlMs expected number; cacheScope invalid_value`)
//! and drops every tool the server offers. rmcp 3.4.1's constructors leave both
//! unset, so every result this server answers is stamped from here. Older-protocol
//! peers ignore the extra fields.
//!
//! Two postures, because this is a shared, multi-tenant server:
//!
//! - **Deployment surface** (`tools/list`, `resources/templates/list`): decided by
//!   the build and the instance's configuration (`advertise_blob_tools` reads
//!   config, never the caller), so the answer is the same for every caller —
//!   `Public`. The TTL bounds how long a client may keep a pre-deploy tool list;
//!   the server sends no `list_changed`, and a stale list degrades to the typed
//!   refusal a hidden door already answers. If advertisement ever becomes
//!   per-caller, this scope must become `Private`.
//! - **Caller data** (`resources/list`, `resources/read`): gated by the caller's
//!   own bearer at the API and changed by every write, so it is `Private` and
//!   immediately stale.

use rmcp::model::CacheScope;

/// Freshness of the deployment surface: five minutes.
pub(crate) const DEPLOYMENT_SURFACE_TTL_MS: u64 = 5 * 60 * 1000;
/// The deployment surface is identical for every caller.
pub(crate) const DEPLOYMENT_SURFACE_SCOPE: CacheScope = CacheScope::Public;

/// Caller data is stale the moment it is answered.
pub(crate) const CALLER_DATA_TTL_MS: u64 = 0;
/// Caller data is visible only to the caller who asked.
pub(crate) const CALLER_DATA_SCOPE: CacheScope = CacheScope::Private;
