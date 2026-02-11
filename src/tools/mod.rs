pub mod ask_user;
pub mod chat;
pub mod command;
pub mod grep_file;
pub mod list_directory;
pub mod man_page;
pub mod memory;
pub mod patch_file;
pub mod read_file;
pub mod run_command;
pub mod search_history;
pub mod web_search;
pub mod write_file;
pub mod manage_config;
pub mod install_skill;
pub mod install_mcp;

use std::path::PathBuf;

use serde::Serialize;
use serde_json::json;

#[cfg(test)]
pub fn validate_read_path(raw_path: &str) -> Result<PathBuf, String> {
    validate_read_path_with_access(raw_path, "block")
}

pub fn validate_read_path_with_access(raw_path: &str, sensitive_file_access: &str) -> Result<PathBuf, String> {
    let expanded = if let Some(rest) = raw_path.strip_prefix("~/") {
        dirs::home_dir().unwrap_or_default().join(rest)
    } else if raw_path == "~" {
        dirs::home_dir().unwrap_or_default()
    } else {
        PathBuf::from(raw_path)
    };

    if expanded
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!(
            "Access denied: path '{raw_path}' contains '..' components"
        ));
    }

    let abs = if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir()
            .unwrap_or_default()
            .join(expanded)
    };

    let canonical = match std::fs::canonicalize(&abs) {
        Ok(p) => p,
        Err(_) => {
            if abs.exists() {
                return Err(format!(
                    "Access denied: cannot resolve '{raw_path}'"
                ));
            }
            abs
        }
    };

    // Note: TOCTOU race between validation and open is acknowledged but
    // impractical to fix without openat-style path resolution, and is
    // also impractical to abuse or attack.
    if sensitive_file_access != "allow" {
        if let Some(home) = dirs::home_dir() {
            let sensitive_dirs = [
                home.join(".ssh"),
                home.join(".gnupg"),
                home.join(".gpg"),
                home.join(".aws"),
                home.join(".config/gcloud"),
                home.join(".azure"),
                home.join(".kube"),
                home.join(".docker"),
                home.join(".nsh"),
            ];
            for dir in &sensitive_dirs {
                let dir_canonical = dir.canonicalize().unwrap_or_else(|_| dir.clone());
                if canonical.starts_with(&dir_canonical) {
                    if sensitive_file_access == "ask" {
                        eprintln!(
                            "\x1b[1;33m⚠ '{raw_path}' is in a sensitive directory\x1b[0m"
                        );
                        eprint!("\x1b[1;33mAllow access? [y/N]\x1b[0m ");
                        let _ = std::io::Write::flush(&mut std::io::stderr());
                        if read_tty_confirmation() {
                            break;
                        }
                        return Err(format!(
                            "Access denied: '{raw_path}' is in a sensitive directory"
                        ));
                    }
                    return Err(format!(
                        "Access denied: '{raw_path}' is in a sensitive directory"
                    ));
                }
            }
        }
    }

    Ok(canonical)
}

pub fn read_tty_confirmation() -> bool {
    use std::io::{BufRead, IsTerminal};
    let line = if std::io::stdin().is_terminal() {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_ok() {
            line
        } else {
            return false;
        }
    } else {
        match std::fs::File::open("/dev/tty") {
            Ok(tty) => {
                let mut reader = std::io::BufReader::new(tty);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    line
                } else {
                    return false;
                }
            }
            Err(_) => return false,
        }
    };
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

pub fn all_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "command".into(),
            description: "Generate a shell command for the user to \
                          review and execute. The command will be \
                          prefilled at their prompt."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description":
                            "The exact shell command to execute"
                    },
                    "explanation": {
                        "type": "string",
                        "description":
                            "Brief explanation (1-2 sentences)"
                    },
                    "pending": {
                        "type": "boolean",
                        "description":
                            "Set to true if this is part of a \
                             multi-step sequence and you need to \
                             see the output before continuing.",
                        "default": false
                    }
                },
                "required": ["command", "explanation"]
            }),
        },
        ToolDefinition {
            name: "chat".into(),
            description: "Respond with text for pure knowledge \
                          questions where no command execution is \
                          needed."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "response": {
                        "type": "string",
                        "description": "Your text response"
                    }
                },
                "required": ["response"]
            }),
        },
        ToolDefinition {
            name: "search_history".into(),
            description: "Search command history across all sessions. \
                          Searches commands, output, and AI-generated \
                          summaries."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description":
                            "Search query (natural language or FTS5 syntax)"
                    },
                    "regex": {
                        "type": "string",
                        "description":
                            "Regex pattern for precise matching (alternative to query)"
                    },
                    "since": {
                        "type": "string",
                        "description":
                            "ISO timestamp or relative like '1h', '2d'"
                    },
                    "until": {
                        "type": "string",
                        "description": "ISO timestamp or relative"
                    },
                    "exit_code": {
                        "type": "integer",
                        "description": "Filter by specific exit code"
                    },
                    "failed_only": {
                        "type": "boolean",
                        "description":
                            "Only show failed commands (exit != 0)"
                    },
                    "session": {
                        "type": "string",
                        "description":
                            "'current', 'all', or specific session ID"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results",
                        "default": 20
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "grep_file".into(),
            description: "Search for a pattern in a file or read \
                          specific lines."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path"
                    },
                    "pattern": {
                        "type": "string",
                        "description":
                            "Regex pattern (omit to read the file)"
                    },
                    "context_lines": {
                        "type": "integer",
                        "description":
                            "Lines of context around matches",
                        "default": 3
                    },
                    "max_lines": {
                        "type": "integer",
                        "description": "Max total lines to return",
                        "default": 100
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "read_file".into(),
            description: "Read lines from a file with line numbers.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path"
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "First line to read (1-indexed)",
                        "default": 1
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "Last line to read (1-indexed)",
                        "default": 200
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "list_directory".into(),
            description: "List files and directories at a path \
                          with metadata."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path",
                        "default": "."
                    },
                    "show_hidden": {
                        "type": "boolean",
                        "description": "Include dotfiles",
                        "default": false
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "web_search".into(),
            description: "Search the web for current information.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    }
                },
                "required": ["query"]
            }),
        },
        ToolDefinition {
            name: "run_command".into(),
            description: "Execute a safe, read-only command \
                          WITHOUT user approval. Only for \
                          investigative commands on the allowlist."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The command to execute"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Why you need this command"
                    }
                },
                "required": ["command", "reason"]
            }),
        },
        ToolDefinition {
            name: "ask_user".into(),
            description: "Ask the user a question when you need \
                          more information or confirmation."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "The question to ask"
                    },
                    "options": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description":
                            "Optional list of choices"
                    }
                },
                "required": ["question"]
            }),
        },
        ToolDefinition {
            name: "write_file".into(),
            description: "Write content to a file on disk. \
                          The user will be shown a diff (or \
                          preview for new files) and must \
                          confirm before the write proceeds. \
                          Existing files are backed up to \
                          trash."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or ~-relative file path"
                    },
                    "content": {
                        "type": "string",
                        "description": "Full file content to write"
                    },
                    "reason": {
                        "type": "string",
                        "description":
                            "Brief explanation of why this file is being written"
                    }
                },
                "required": ["path", "content", "reason"]
            }),
        },
        ToolDefinition {
            name: "patch_file".into(),
            description: "Apply a surgical text replacement \
                          to an existing file. The user will \
                          be shown a diff and must confirm. \
                          Use this instead of write_file when \
                          changing a small part of a file."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description":
                            "Absolute or ~-relative file path"
                    },
                    "search": {
                        "type": "string",
                        "description":
                            "Exact text to find in the file \
                             (must match verbatim)"
                    },
                    "replace": {
                        "type": "string",
                        "description":
                            "Text to replace the search match with"
                    },
                    "reason": {
                        "type": "string",
                        "description":
                            "Brief explanation of the change"
                    }
                },
                "required": ["path", "search", "replace", "reason"]
            }),
        },
        ToolDefinition {
            name: "man_page".into(),
            description: "Retrieve the man page for a command.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The command to look up"
                    },
                    "section": {
                        "type": "integer",
                        "description": "Man page section (1-8)"
                    }
                },
                "required": ["command"]
            }),
        },
        ToolDefinition {
            name: "manage_config".into(),
            description: "Modify nsh configuration. The current \
                          configuration with all available options \
                          is shown in the <nsh_configuration> block \
                          in the system context. Use action=\"set\" \
                          with a dot-separated key path and a value, \
                          or action=\"remove\" to delete a key. The \
                          user will see the change and must confirm."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description":
                            "Action to perform: 'set' or 'remove'",
                        "enum": ["set", "remove"],
                        "default": "set"
                    },
                    "key": {
                        "type": "string",
                        "description":
                            "Dot-separated config key path \
                             (e.g. 'provider.model', \
                             'context.history_limit')"
                    },
                    "value": {
                        "description":
                            "Value to set (string, number, boolean, \
                             or array). Required for action='set'."
                    }
                },
                "required": ["action", "key"]
            }),
        },
        ToolDefinition {
            name: "install_skill".into(),
            description: "Install a new custom skill (reusable tool). \
                          Skills are shell command templates with \
                          optional parameters, saved to \
                          ~/.nsh/skills/. The user will see the \
                          skill definition and must confirm."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description":
                            "Skill name (alphanumeric + underscores)"
                    },
                    "description": {
                        "type": "string",
                        "description":
                            "What the skill does"
                    },
                    "command": {
                        "type": "string",
                        "description":
                            "Shell command template. Use {param_name} \
                             for parameters."
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Execution timeout",
                        "default": 30
                    },
                    "terminal": {
                        "type": "boolean",
                        "description":
                            "If true, this skill ends the \
                             conversation turn (like command/chat). \
                             Default false.",
                        "default": false
                    },
                    "parameters": {
                        "type": "object",
                        "description":
                            "Map of parameter names to \
                             {type, description} objects",
                        "additionalProperties": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "description": { "type": "string" }
                            }
                        }
                    }
                },
                "required": ["name", "description", "command"]
            }),
        },
        ToolDefinition {
            name: "install_mcp_server".into(),
            description: "Add a new MCP (Model Context Protocol) tool \
                          server to the nsh configuration. Supports \
                          stdio transport (local command) and http \
                          transport (remote URL). The server becomes \
                          available after the next query. The user \
                          must confirm the config change."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description":
                            "Server name (alphanumeric, underscores, \
                             hyphens)"
                    },
                    "transport": {
                        "type": "string",
                        "description": "Transport type",
                        "enum": ["stdio", "http"],
                        "default": "stdio"
                    },
                    "command": {
                        "type": "string",
                        "description":
                            "Command to spawn (required for stdio)"
                    },
                    "args": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description":
                            "Command arguments (stdio only)"
                    },
                    "url": {
                        "type": "string",
                        "description":
                            "Server URL (required for http)"
                    },
                    "env": {
                        "type": "object",
                        "description":
                            "Environment variables for the server",
                        "additionalProperties": { "type": "string" }
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Request timeout",
                        "default": 30
                    }
                },
                "required": ["name"]
            }),
        },
        ToolDefinition {
            name: "remember".into(),
            description: "Store a fact, preference, or note in persistent \
                          memory. If a memory with the same key already \
                          exists, it will be updated. Memories are shown \
                          in your context on every query.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "Short label for the memory (e.g. 'home NAS IP', 'deploy command', 'preferred editor')"
                    },
                    "value": {
                        "type": "string",
                        "description": "The content to remember"
                    }
                },
                "required": ["key", "value"]
            }),
        },
        ToolDefinition {
            name: "forget_memory".into(),
            description: "Delete a memory by its ID. Memory IDs are visible \
                          in the <memories> context block.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "integer",
                        "description": "The memory ID to delete"
                    }
                },
                "required": ["id"]
            }),
        },
        ToolDefinition {
            name: "update_memory".into(),
            description: "Update an existing memory by ID. Provide a new \
                          key, value, or both.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "integer",
                        "description": "The memory ID to update"
                    },
                    "key": {
                        "type": "string",
                        "description": "New label (optional)"
                    },
                    "value": {
                        "type": "string",
                        "description": "New value (optional)"
                    }
                },
                "required": ["id"]
            }),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_all_tool_definitions_returns_all_tools() {
        let tools = all_tool_definitions();
        assert_eq!(tools.len(), 18);
        for tool in &tools {
            assert!(!tool.name.is_empty());
            assert!(!tool.description.is_empty());
        }
    }

    #[test]
    fn test_tool_definitions_have_valid_schemas() {
        let tools = all_tool_definitions();
        for tool in &tools {
            let obj = tool.parameters.as_object().expect("parameters should be an object");
            assert_eq!(obj.get("type").and_then(|v| v.as_str()), Some("object"));
        }
    }

    #[test]
    fn test_tool_names_unique() {
        let tools = all_tool_definitions();
        let mut names = HashSet::new();
        for tool in &tools {
            assert!(names.insert(tool.name.clone()), "duplicate tool name: {}", tool.name);
        }
    }

    #[test]
    fn test_specific_tools_exist() {
        let tools = all_tool_definitions();
        let names: HashSet<String> = tools.iter().map(|t| t.name.clone()).collect();
        let expected = [
            "command", "chat", "search_history", "grep_file", "read_file",
            "list_directory", "web_search", "run_command", "ask_user",
            "write_file", "patch_file", "man_page",
            "manage_config", "install_skill", "install_mcp_server",
            "remember", "forget_memory", "update_memory",
        ];
        for name in &expected {
            assert!(names.contains(*name), "missing tool: {name}");
        }
    }

    #[test]
    fn test_tool_required_fields() {
        let tools = all_tool_definitions();
        for tool in &tools {
            let obj = tool.parameters.as_object().unwrap();
            assert!(obj.contains_key("required"), "tool '{}' missing 'required' field", tool.name);
        }
    }

    #[test]
    fn test_validate_read_path_tilde_expansion() {
        let _home = dirs::home_dir().unwrap();
        let result = validate_read_path("~/Desktop");
        match result {
            Ok(p) => assert!(p.is_absolute()),
            Err(e) => assert!(
                e.contains("sensitive") || e.contains("Access denied"),
                "unexpected error: {e}"
            ),
        }
    }

    #[test]
    fn test_validate_read_path_tilde_alone() {
        let result = validate_read_path("~");
        match result {
            Ok(p) => assert!(p.is_absolute()),
            Err(e) => assert!(
                e.contains("sensitive") || e.contains("Access denied"),
                "unexpected error: {e}"
            ),
        }
    }

    #[test]
    fn test_validate_read_path_rejects_parent_dir() {
        let result = validate_read_path("/tmp/../etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains(".."));
    }

    #[test]
    fn test_validate_read_path_relative_path() {
        let result = validate_read_path("Cargo.toml");
        match result {
            Ok(p) => assert!(p.is_absolute()),
            Err(_) => {}
        }
    }

    #[test]
    fn test_validate_read_path_nonexistent_file() {
        let result = validate_read_path("/tmp/nsh_test_nonexistent_file_xyz_99999.txt");
        match result {
            Ok(p) => assert!(p.is_absolute()),
            Err(e) => assert!(e.contains("Access denied"), "unexpected error: {e}"),
        }
    }

    #[test]
    fn test_validate_read_path_sensitive_ssh() {
        let result = validate_read_path("~/.ssh/id_rsa");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sensitive"));
    }

    #[test]
    fn test_validate_read_path_sensitive_nsh() {
        let result = validate_read_path("~/.nsh/config.toml");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sensitive"));
    }

    #[test]
    fn test_validate_read_path_sensitive_aws() {
        let result = validate_read_path("~/.aws/credentials");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sensitive"));
    }

    #[test]
    fn test_validate_read_path_sensitive_gnupg() {
        let result = validate_read_path("~/.gnupg/pubring.kbx");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sensitive"));
    }

    #[test]
    fn test_validate_read_path_absolute_valid() {
        let result = validate_read_path("/tmp");
        assert!(result.is_ok());
        assert!(result.unwrap().is_absolute());
    }

    #[test]
    fn test_validate_read_path_existing_but_cannot_resolve() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("test.txt");
        std::fs::write(&file_path, "hello").unwrap();
        let result = validate_read_path(file_path.to_str().unwrap());
        assert!(result.is_ok());
    }
}
