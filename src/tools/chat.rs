use crate::db::Db;

/// Handle the `chat` tool: display the response text.
pub fn execute(
    input: &serde_json::Value,
    original_query: &str,
    db: &Db,
    session_id: &str,
    private: bool,
) -> anyhow::Result<()> {
    let response = input["response"].as_str().unwrap_or("");

    let color = "\x1b[3;36m"; // cyan italic
    let reset = "\x1b[0m";
    eprintln!("{color}{response}{reset}");

    if !private {
        crate::audit::audit_log(session_id, original_query, "chat", response, "safe");
        let redacted_query = crate::redact::redact_secrets(original_query, &crate::config::RedactionConfig::default());
        let redacted_response = crate::redact::redact_secrets(response, &crate::config::RedactionConfig::default());
        db.insert_conversation(
            session_id,
            &redacted_query,
            "chat",
            &redacted_response,
            None,
            false,
            false,
        )?;
    }

    Ok(())
}
