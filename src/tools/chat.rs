use crate::daemon_db::DbAccess;
use crate::tools::{ToolInvocationContext, ToolInvocationResult};
use std::io::Write;

pub fn render_response(response: &str, json_output: bool) -> anyhow::Result<()> {
    let mut stderr = std::io::stderr();
    render_response_to(response, json_output, &mut stderr)
}

fn render_response_to(
    response: &str,
    json_output: bool,
    output: &mut impl Write,
) -> anyhow::Result<()> {
    if json_output {
        let event = serde_json::json!({
            "type": "chat",
            "response": response,
        });
        writeln!(output, "{}", serde_json::to_string(&event)?)?;
    } else {
        writeln!(output)?;
        write!(output, "{response}")?;
        if !response.ends_with('\n') {
            writeln!(output)?;
        }
        writeln!(output)?;
    }

    Ok(())
}

/// Handle the `chat` tool: display the response text.
pub fn invoke(
    input: &serde_json::Value,
    ctx: &ToolInvocationContext<'_>,
) -> anyhow::Result<ToolInvocationResult> {
    let (db, session_id) = ctx.conversation_state()?;
    execute(
        input,
        ctx.original_query,
        db,
        session_id,
        ctx.private,
        ctx.config,
        ctx.render_output,
        ctx.json_output,
    )?;
    Ok(ToolInvocationResult::success("Message displayed."))
}

fn execute(
    input: &serde_json::Value,
    original_query: &str,
    db: &dyn DbAccess,
    session_id: &str,
    private: bool,
    config: &crate::config::Config,
    render_output: bool,
    json_output: bool,
) -> anyhow::Result<()> {
    let response = input["response"].as_str().unwrap_or("");

    if render_output {
        render_response(response, json_output)?;
    }

    crate::tools::record_tool_conversation(
        db,
        config,
        private,
        crate::tools::ToolConversationRecord {
            session_id,
            original_query,
            response_type: "chat",
            response,
            explanation: None,
            executed: false,
            pending: false,
            audit_risk: Some("safe"),
        },
    )?;

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
        execute(&input, "test query", &db, "s1", true, &config, true, false).unwrap();

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
        execute(&input, "my query", &db, "s1", false, &config, true, false).unwrap();

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
        execute(&input, "query", &db, "s1", false, &config, true, false).unwrap();

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
        execute(&input, "query", &db, "s1", false, &config, true, false).unwrap();

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
        execute(
            &input,
            "explain code",
            &db,
            "s1",
            false,
            &config,
            true,
            false,
        )
        .unwrap();

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
        execute(&input, "query", &db, "s1", false, &config, false, false).unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].response, "silent response");
    }

    #[test]
    fn render_response_to_preserves_plain_text_without_termimad() {
        let mut output = Vec::new();
        render_response_to("line 1\nline 2", false, &mut output).expect("render plain text");

        let rendered = String::from_utf8(output).expect("utf8");
        assert!(rendered.contains("line 1\nline 2"));
    }

    #[test]
    fn render_response_to_emits_json_event() {
        let mut output = Vec::new();
        render_response_to("hello", true, &mut output).expect("render json");

        let rendered = String::from_utf8(output).expect("utf8");
        let parsed: serde_json::Value = serde_json::from_str(rendered.trim()).expect("json");
        assert_eq!(parsed["type"], "chat");
        assert_eq!(parsed["response"], "hello");
    }
}
