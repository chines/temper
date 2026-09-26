//! Profile tools — retrieve the authenticated user's profile.

use rmcp::model::CallToolResult;

use temper_core::types::Profile;

use crate::service::TemperMcpService;

pub async fn get_profile(
    _svc: &TemperMcpService,
    profile: Profile,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let text = serde_json::to_string_pretty(&profile).unwrap_or_else(|_| "{}".to_string());
    Ok(CallToolResult::success(vec![
        rmcp::model::ContentBlock::text(text),
    ]))
}
