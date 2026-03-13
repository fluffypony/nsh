use anyhow::Context;
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
    record_tool_conversation_with_audit(db, config, private, record, |session, query, tool, response, risk| {
        crate::audit::audit_log(session, query, tool, response, risk)
    })
}

fn record_tool_conversation_with_audit<F>(
    db: &dyn DbAccess,
    config: &Config,
    private: bool,
    record: ToolConversationRecord<'_>,
    audit_log: F,
) -> anyhow::Result<()>
where
    F: FnOnce(&str, &str, &str, &str, &str) -> anyhow::Result<()>,
{
    if private {
        return Ok(());
    }

    if let Some(risk) = record.audit_risk {
        audit_log(
            record.session_id,
            record.original_query,
            record.response_type,
            record.response,
            risk,
        )
        .context("failed to write audit log for tool conversation")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> crate::db::Db {
        crate::db::Db::open_in_memory().expect("in-memory db")
    }

    #[test]
    fn record_tool_conversation_surfaces_audit_failures() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234)
            .expect("create session");

        let result = record_tool_conversation_with_audit(
            &db,
            &Config::default(),
            false,
            ToolConversationRecord {
                session_id: "s1",
                original_query: "show logs",
                response_type: "chat",
                response: "ok",
                explanation: None,
                executed: false,
                pending: false,
                audit_risk: Some("safe"),
            },
            |_, _, _, _, _| Err(anyhow::anyhow!("disk full")),
        );

        let error = result.expect_err("audit failure should surface");
        assert!(error.to_string().contains("failed to write audit log"));
        assert!(
            db.get_conversations("s1", 10)
                .expect("load conversations")
                .is_empty()
        );
    }
}
