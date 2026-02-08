use crate::db::Db;

/// Handle the `chat` tool: display the response text.
pub fn execute(
    input: &serde_json::Value,
    original_query: &str,
    db: &Db,
    session_id: &str,
) -> anyhow::Result<()> {
    let response = input["response"].as_str().unwrap_or("");

    let color = "\x1b[3;36m"; // cyan italic
    let reset = "\x1b[0m";
    eprintln!("{color}{response}{reset}");

    db.insert_conversation(
        session_id,
        original_query,
        "chat",
        response,
        None,
        false,
        false,
    )?;

    Ok(())
}
