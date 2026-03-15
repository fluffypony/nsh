/// Describe a tool invocation in a human-readable status string.
///
/// Shared by the query loop and coding agent to avoid duplicating
/// tool-name → description logic.  Returns `None` for tools that
/// have no common description (callers provide their own fallback).
pub(crate) fn describe_common_tool(name: &str, input: &serde_json::Value) -> Option<String> {
    match name {
        "read_file" => Some(format!(
            "reading {}",
            input["path"].as_str().unwrap_or("(missing path)"),
        )),
        "write_file" => Some(format!(
            "writing {}",
            input["path"].as_str().unwrap_or("(missing path)"),
        )),
        "patch_file" => Some(format!(
            "patching {}",
            input["path"].as_str().unwrap_or("(missing path)"),
        )),
        "grep_file" => {
            let path = input["path"].as_str().unwrap_or("(missing path)");
            let pat = input["pattern"].as_str();
            match pat {
                Some(p) if !p.is_empty() => Some(format!("searching {path} for /{p}/")),
                _ => Some(format!("searching {path} for /(missing pattern)/")),
            }
        }
        "glob" => Some(format!(
            "finding {}",
            input["pattern"].as_str().unwrap_or("(missing pattern)"),
        )),
        "list_directory" => Some(format!(
            "listing {}",
            input["path"].as_str().unwrap_or("."),
        )),
        "ask_user" => Some("asking for input...".to_string()),
        _ => None,
    }
}
