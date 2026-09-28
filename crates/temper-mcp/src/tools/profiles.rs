//! Profile tools — retrieve the authenticated user's profile.

use rmcp::model::CallToolResult;

use crate::service::TemperMcpService;

pub async fn get_profile(
    _svc: &TemperMcpService,
    authed: temper_services::auth::AuthenticatedProfile,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let text = serde_json::to_string_pretty(authed.profile()).unwrap_or_else(|_| "{}".to_string());
    Ok(CallToolResult::success(vec![
        rmcp::model::ContentBlock::text(text),
    ]))
}
