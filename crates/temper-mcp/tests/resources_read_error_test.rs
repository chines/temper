//! The MCP resources protocol (`resources/read`) maps a door's refusal the way the tools do: an
//! erased resource is `invalid_params` naming the erasure, a not-found is `invalid_params`, and
//! only a fault is `internal_error`. Driven through the public `read_resource` over an in-process
//! client whose every request is answered with a fixed status and body, so the mapping is what is
//! under test. (The stub router lives here, outside `src/`, where `audit-mcp-route-auth.sh`
//! freezes router assembly to `router.rs`.)

use rmcp::model::{ErrorCode, ReadResourceRequestParams};
use temper_core::types::ids::ResourceId;
use temper_mcp::resources::read_resource;
use uuid::Uuid;

/// An in-process client whose every request is answered `status` with `body` — the read's
/// door stood in by a fixed answer, so the mapping is what is under test.
fn client_answering(status: axum::http::StatusCode, body: String) -> temper_client::TemperClient {
    let app = axum::Router::new().fallback(axum::routing::any(move || {
        let body = body.clone();
        std::future::ready((status, body))
    }));
    temper_client::TemperClient::in_process_with_token(
        app,
        temper_workflow::operations::Surface::Mcp,
        "tok".to_owned(),
        std::sync::Arc::new(temper_client::auth::MemoryTokenStore::empty()),
    )
    .expect("in-process client builds")
}

/// Both resource URIs, for one id.
fn uris(id: Uuid) -> [String; 2] {
    [
        format!("temper://resources/{id}"),
        format!("temper://resources/{id}/content"),
    ]
}

/// An erased resource read through the resources protocol is named, as on the tools. FAILS IF
/// either URI's read maps its error with anything but `map_read_err` (the old per-read closure
/// answered `INTERNAL_ERROR` for every refusal).
#[tokio::test]
async fn an_erased_resource_read_is_a_named_invalid_params() {
    let id = ResourceId::from(Uuid::now_v7());
    let body = serde_json::json!({
        "error": {
            "code": temper_core::error::RESOURCE_ERASED_CODE,
            "message": temper_core::error::TemperError::ResourceErased(id).to_string(),
        }
    })
    .to_string();
    let client = client_answering(axum::http::StatusCode::GONE, body);
    for uri in uris(Uuid::from(id)) {
        match read_resource(&client, ReadResourceRequestParams::new(uri.clone())).await {
            Err(err) => {
                assert_eq!(err.code, ErrorCode::INVALID_PARAMS, "{uri}");
                assert_eq!(err.message, format!("resource {id} was erased"), "{uri}");
            }
            Ok(_) => panic!("{uri}: an erased read must refuse"),
        }
    }
}

/// A not-found is the caller's, not a fault, and does not say "erased". FAILS IF either URI's
/// read answers a `404` with `INTERNAL_ERROR`.
#[tokio::test]
async fn a_not_found_resource_read_is_invalid_params() {
    let id = Uuid::now_v7();
    let body = serde_json::json!({
        "error": { "code": "NOT_FOUND", "message": format!("resource {id} not found") }
    })
    .to_string();
    let client = client_answering(axum::http::StatusCode::NOT_FOUND, body);
    for uri in uris(id) {
        match read_resource(&client, ReadResourceRequestParams::new(uri.clone())).await {
            Err(err) => {
                assert_eq!(err.code, ErrorCode::INVALID_PARAMS, "{uri}");
                assert!(!err.message.contains("erased"), "{uri}: {}", err.message);
            }
            Ok(_) => panic!("{uri}: a not-found read must refuse"),
        }
    }
}
