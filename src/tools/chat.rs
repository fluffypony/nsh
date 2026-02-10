use crate::db::Db;

/// Handle the `chat` tool: display the response text.
pub fn execute(
    input: &serde_json::Value,
    original_query: &str,
    db: &Db,
    session_id: &str,
    private: bool,
    config: &crate::config::Config,
) -> anyhow::Result<()> {
    let response = input["response"].as_str().unwrap_or("");

    let skin = termimad::MadSkin::default();
    skin.write_text_on(&mut std::io::stderr(), response)?;

    if !private {
        crate::audit::audit_log(session_id, original_query, "chat", response, "safe");
        let redacted_query = crate::redact::redact_secrets(original_query, &config.redaction);
        let redacted_response = crate::redact::redact_secrets(response, &config.redaction);
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
