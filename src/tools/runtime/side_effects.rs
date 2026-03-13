use crate::config::Config;
use crate::daemon_db::DbAccess;

pub(crate) struct ToolConversationRecord<'a> {
    pub session_id: &'a str,
    pub original_query: &'a str,
    pub response_type: &'a str,
    pub response: &'a str,
    pub explanation: Option<&'a str>,
    pub executed: bool,
    pub pending: bool,
    pub audit_risk: Option<&'a str>,
}

pub(crate) fn record_tool_conversation(
    db: &dyn DbAccess,
    config: &Config,
    private: bool,
    record: ToolConversationRecord<'_>,
) -> anyhow::Result<()> {
    if private {
        return Ok(());
    }

    if let Some(risk) = record.audit_risk {
        crate::audit::audit_log(
            record.session_id,
            record.original_query,
            record.response_type,
            record.response,
            risk,
        );
    }

    let redacted_query = crate::redact::redact_secrets(record.original_query, &config.redaction);
    let redacted_response = crate::redact::redact_secrets(record.response, &config.redaction);
    let redacted_explanation = record
        .explanation
        .map(|value| crate::redact::redact_secrets(value, &config.redaction));

    db.insert_conversation(
        record.session_id,
        &redacted_query,
        record.response_type,
        &redacted_response,
        redacted_explanation.as_deref(),
        record.executed,
        record.pending,
    )?;

    Ok(())
}
