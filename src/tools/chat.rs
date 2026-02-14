use crate::daemon_db::DbAccess;

/// Handle the `chat` tool: display the response text.
pub fn execute(
    input: &serde_json::Value,
    original_query: &str,
    db: &dyn DbAccess,
    session_id: &str,
    private: bool,
    config: &crate::config::Config,
    render_output: bool,
) -> anyhow::Result<()> {
    let response = input["response"].as_str().unwrap_or("");

    if render_output {
        if crate::streaming::json_output_enabled() {
            let event = serde_json::json!({
                "type": "chat",
                "response": response,
            });
            eprintln!("{}", serde_json::to_string(&event)?);
        } else {
            let skin = termimad::MadSkin::default();
            skin.write_text_on(&mut std::io::stderr(), response)?;
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_db() -> crate::db::Db {
        crate::db::Db::open_in_memory().expect("in-memory db")
    }

    #[test]
    fn test_execute_private_does_not_insert_conversation() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let input = serde_json::json!({"response": "hello world"});
        let config = Config::default();
        execute(&input, "test query", &db, "s1", true, &config, true).unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert!(
            convos.is_empty(),
            "private=true should not insert conversations"
        );
    }

    #[test]
    fn test_execute_non_private_inserts_conversation() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let input = serde_json::json!({"response": "some response"});
        let config = Config::default();
        execute(&input, "my query", &db, "s1", false, &config, true).unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].query, "my query");
        assert_eq!(convos[0].response, "some response");
        assert_eq!(convos[0].response_type, "chat");
    }

    #[test]
    fn test_execute_empty_response() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let input = serde_json::json!({"response": ""});
        let config = Config::default();
        execute(&input, "query", &db, "s1", false, &config, true).unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].response, "");
    }

    #[test]
    fn test_execute_missing_response_field() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let input = serde_json::json!({});
        let config = Config::default();
        execute(&input, "query", &db, "s1", false, &config, true).unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].response, "");
    }

    #[test]
    fn test_execute_response_with_markdown() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let md = "# Title\n\n**bold** and *italic*\n\n```rust\nfn main() {}\n```\n";
        let input = serde_json::json!({"response": md});
        let config = Config::default();
        execute(&input, "explain code", &db, "s1", false, &config, true).unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].response, md);
    }

    #[test]
    fn test_execute_render_output_false_still_persists() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let input = serde_json::json!({"response": "silent response"});
        let config = Config::default();
        execute(&input, "query", &db, "s1", false, &config, false).unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].response, "silent response");
    }
}
