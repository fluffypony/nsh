pub mod ask_user;
pub mod chat;
pub mod command;
pub mod glob;
pub mod grep_file;
pub mod install_mcp;
pub mod install_skill;
pub mod list_directory;
pub mod man_page;
pub mod manage_config;
pub mod memory;
pub mod patch_file;
pub mod read_file;
pub mod run_command;
pub mod search_history;
pub mod web_search;
pub mod write_file;
pub mod github;
pub mod uninstall_skill;
pub mod skill_exists;

use std::path::PathBuf;

use serde::Serialize;
use std::io::IsTerminal;
use serde_json::json;

#[cfg(test)]
pub fn validate_read_path(raw_path: &str) -> Result<PathBuf, String> {
    validate_read_path_with_access(raw_path, "block")
}

/// Heuristic per-tool default timeout in seconds.
pub fn default_timeout_for_tool(name: &str) -> u64 {
    match name {
        "read_file" | "grep_file" | "list_directory" | "glob" => 15,
        "man_page" => 10,
        "list_tools" | "find_tools" => 10,
        "search_history" | "search_memory" | "core_memory_append"
        | "core_memory_rewrite" | "store_memory" | "retrieve_secret" => 15,
        "run_command" => 60,
        "web_search" | "github" => 45,
        "manage_config" | "install_skill" | "install_mcp_server" | "skill_exists"
        | "uninstall_skill" => 30,
        "code" => 900,
        _ if name.starts_with("mcp_") => 60,
        _ if name.starts_with("skill_") => 60,
        _ => 60,
    }
}

pub fn validate_read_path_with_access(
    raw_path: &str,
    sensitive_file_access: &str,
) -> Result<PathBuf, String> {
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
        std::env::current_dir().unwrap_or_default().join(expanded)
    };

    let canonical = match std::fs::canonicalize(&abs) {
        Ok(p) => p,
        Err(_) => {
            if abs.exists() {
                return Err(format!("Access denied: cannot resolve '{raw_path}'"));
            }
            abs
        }
    };

    // Note: TOCTOU race between validation and open is acknowledged but
    // impractical to fix without openat-style path resolution, and is
    // also impractical to abuse or attack.
    if sensitive_file_access != "allow" {
        if let Some(home) = dirs::home_dir() {
            // Allowlist: reads under ~/.nsh/skills are considered safe so the agent
            // can introspect installed skills (READ-ONLY). This prevents a deadlock
            // where it cannot answer questions about skills it just installed.
            let allowed_read_only = home.join(".nsh").join("skills");
            let allowed_read_only = allowed_read_only
                .canonicalize()
                .unwrap_or(allowed_read_only);
            if canonical.starts_with(&allowed_read_only) {
                return Ok(canonical);
            }
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
                        let th = crate::tui::theme::current_theme();
                        eprintln!("{}⚠ '{raw_path}' is in a sensitive directory{}", th.warning, th.reset);
                        eprint!("{}Allow access? [y/N]{} ", th.warning, th.reset);
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

/// Like read_tty_confirmation but defaults to "No" when a read error occurs.
/// Useful for potentially dangerous defaults where we should not auto-approve.
pub fn read_tty_confirmation_default_yes() -> bool {
    use std::io::{BufRead, IsTerminal};
    let line = if std::io::stdin().is_terminal() {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_ok() {
            line
        } else {
            return false; // default to No on read error
        }
    } else {
        match std::fs::File::open("/dev/tty") {
            Ok(tty) => {
                let mut reader = std::io::BufReader::new(tty);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    line
                } else {
                    return false; // default to No on read error
                }
            }
            Err(_) => return false,
        }
    };
    !matches!(line.trim().to_lowercase().as_str(), "n" | "no")
}

/// Read a single line of user input with a timeout (in seconds).
/// Returns Some(trimmed_line) if input received and non-empty; otherwise None.
pub fn read_user_input_with_timeout(timeout_secs: u64) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        let mut line = String::new();
        let result = if std::io::stdin().is_terminal() {
            std::io::stdin().read_line(&mut line).map(|_| line)
        } else {
            match std::fs::File::open("/dev/tty") {
                Ok(tty) => {
                    let mut reader = std::io::BufReader::new(tty);
                    reader.read_line(&mut line).map(|_| line)
                }
                Err(_) => return,
            }
        };
        if let Ok(text) = result {
            let _ = tx.send(text.trim().to_string());
        }
    });

    match rx.recv_timeout(std::time::Duration::from_secs(timeout_secs)) {
        Ok(line) if !line.is_empty() => Some(line),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

pub fn all_tool_definitions() -> Vec<ToolDefinition> {
    let mut defs = vec![
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
                            "Set to true to maintain control after execution. Use this to: \
                             1) Verify the command succeeded (e.g. check version after install). \
                             2) Chain multiple steps (download → extract → install → configure). \
                             3) See error output and auto-fix it. \
                             Only set to false for the very final command that completes the user's goal. \
                             In autorun mode, pending commands execute immediately. In other modes, \
                             the user confirms and you continue.",
                        "default": false
                    },
                    "expected_timeout_seconds": {
                        "type": "integer",
                        "description": "Your estimated time for this command to complete. Use this for long-running operations like installs, builds, or downloads. Default: 120.",
                        "default": 120
                    }
                },
                "required": ["command", "explanation"]
            }),
        },
        ToolDefinition {
            name: "chat".into(),
            description: "Display a text message to the user. Does NOT end the loop — \
                          use this to explain findings, provide status updates, or \
                          share information while continuing to work. \
                          Never use chat to ask questions (use ask_user instead). \
                          When all work is complete, call 'done' to end the loop."
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
                          summaries. If search_history returns an error, retry with a smaller limit \
                          (e.g., 20) or narrower filters. For large history queries, prefer limit <= 30."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description":
                            "Search query (natural language or FTS5 syntax)"
                    },
                    "command": {
                        "type": "string",
                        "description":
                            "Executable filter for entity-aware lookups (for example: ssh, ping, rsync)"
                    },
                    "entity": {
                        "type": "string",
                        "description":
                            "Entity filter (hostname, IP, or remote target token)"
                    },
                    "entity_type": {
                        "type": "string",
                        "description":
                            "Entity type filter: machine, host, or ip"
                    },
                    "latest_only": {
                        "type": "boolean",
                        "description":
                            "If true, return only the most recent entity match"
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
                            "'current' (all sessions on this TTY/terminal window), 'all' (every session globally), or a specific session ID"
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
            description: "Read a file. For small files (≤200 lines), returns full content with token count. \
                           For larger files, returns line count and estimated token count (cl100k_base) so you \
                           can decide: call again with full=true for the complete file, or use start_line/end_line \
                           for a range. Unless the file exceeds ~900k tokens, requesting the full file is fine — \
                           the provider will error if it doesn't fit the context window.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path"
                    },
                    "full": {
                        "type": "boolean",
                        "description": "Return the entire file regardless of size",
                        "default": false
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "First line to read (1-indexed)"
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "Last line to read (1-indexed)"
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
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Recurse into subdirectories",
                        "default": false
                    },
                    "max_entries": {
                        "type": "integer",
                        "description": "Maximum number of entries to return",
                        "default": 100
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "glob".into(),
            description: "Find files matching a glob pattern in the project tree \
                          (respects .gitignore). Use for quick file discovery."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob pattern (e.g. '**/*.rs', 'src/**/*.ts', '*.toml')"
                    },
                    "path": {
                        "type": "string",
                        "description": "Root directory to search from (default: current directory)"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default: 200)"
                    }
                },
                "required": ["pattern"]
            }),
        },
        ToolDefinition {
            name: "web_search".into(),
            description: "Search the web. Use this PROACTIVELY to resolve ambiguous \
                          package names, find installation methods, debug errors, or \
                          verify the canonical approach before acting."
                .into(),
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
        // ── GitHub Tool ──────────────────────────────────────────────
        ToolDefinition {
            name: "github".into(),
            description: "Access public GitHub repositories without authentication. \
                          Can fetch the README (with a goal to auto-summarize), \
                          list the repo file tree, or fetch a specific file. \
                          Prefer this over web_search when a GitHub repo URL or name is known."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["fetch_readme", "fetch_tree", "fetch_file"],
                        "description": "What to fetch"
                    },
                    "repo": {
                        "type": "string",
                        "description": "Repository in 'owner/repo' format or a full GitHub URL"
                    },
                    "path": {
                        "type": "string",
                        "description": "File path within the repo (required for fetch_file)"
                    },
                    "goal": {
                        "type": "string",
                        "description": "For fetch_readme: a specific question to answer \
                                        (e.g. 'how do we install this?'). The README will be \
                                        summarized to only include relevant info, saving context."
                    },
                    "depth": {
                        "type": "integer",
                        "description": "For fetch_tree: max directory depth (default 2, max 5)"
                    }
                },
                "required": ["action", "repo"]
            }),
        },
        ToolDefinition {
            name: "run_command".into(),
            description: "Execute a shell command in the background and return its output. \
                          THIS IS YOUR PRIMARY INVESTIGATIVE AND EXECUTION TOOL. Use it to \
                          check versions, compile code, run tests, install packages, and \
                          perform any intermediate steps. You can call this multiple times \
                          to pursue a goal autonomously. The user will be prompted to approve \
                          commands not in the strict allowlist."
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
                    },
                    "expected_timeout_seconds": {
                        "type": "integer",
                        "description": "Expected maximum duration in seconds. If exceeded, the user will be asked whether to continue waiting. Default varies by tool."
                    }
                },
                "required": ["command", "reason"]
            }),
        },
        ToolDefinition {
            name: "ask_user".into(),
            description: "Ask the user a question to resolve ambiguity, get a preference, \
                          or confirm a decision. Unlike 'chat', this tool keeps the agent \
                          loop active — you receive the user's answer and can continue \
                          working immediately. Use this PROACTIVELY for disambiguation \
                          rather than guessing."
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
                    },
                    "default_response": {
                        "type": "string",
                        "description": "The best response to auto-select if the user does not respond within the timeout. REQUIRED when running in autorun mode. Should be a concrete, actionable answer — not empty or 'I don't know'. Choose the safest reasonable default."
                    }
                },
                "required": ["question"]
            }),
        },
        ToolDefinition {
            name: "code".into(),
            description: "Delegate a task to a specialized coding sub-agent that uses a more \
                          capable model optimized for code. The sub-agent can autonomously \
                          read files, write/edit code, search the codebase, and run shell \
                          commands (build, test, lint) to verify its work. Use this when the \
                          user asks to: write/create code, modify/refactor existing code, add \
                          features, fix bugs or failing tests, debug code issues, explain code, \
                          advise on architecture, run tests and fix failures, do code reviews, \
                          or other programming tasks."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "task": {
                        "type": "string",
                        "description": "Detailed coding task with requirements and expected behavior"
                    },
                    "context": {
                        "type": "string",
                        "description": "Additional context like paths, errors, constraints, and preferences"
                    }
                },
                "required": ["task"]
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
            description: "Install a skill from a Git repo or as a manual definition. \
                          PREFERRED: pass 'repo' with a GitHub URL to clone the repo into \
                          ~/.nsh/skills/<name>. The skill's SKILL.md, README.md, or skill.toml \
                          is auto-detected and loaded. nsh natively supports skills from ANY \
                          AI ecosystem (Claude Code, LangChain, OpenAI Agents, Cursor, etc.) — \
                          just clone the repo and nsh reads the skill documents directly. \
                          FALLBACK: for simple command-template or code-based skills without a \
                          repo, pass name+description+command (or runtime+script). The user will \
                          see the definition and must confirm."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Git repo URL to clone (e.g. https://github.com/user/skill-repo). \
                                        This is the PREFERRED installation method. The repo is cloned \
                                        into ~/.nsh/skills/<repo-name> and its SKILL.md/README.md is \
                                        auto-detected. If already cloned, pulls updates."
                    },
                    "name": {
                        "type": "string",
                        "description": "Skill name (alphanumeric + underscores). Only needed for manual (non-repo) skills."
                    },
                    "description": {
                        "type": "string",
                        "description": "What the skill does. Only needed for manual (non-repo) skills."
                    },
                    "command": {
                        "type": "string",
                        "description": "Shell command template. Use {param_name} for parameters."
                    },
                    "runtime": {
                        "type": "string",
                        "description": "Runtime for code skills (e.g. python3, node)"
                    },
                    "script": {
                        "type": "string",
                        "description": "Inline script source for code skills"
                    },
                    "docs": {
                        "type": "string",
                        "description": "Optional SKILL.md contents to store alongside the skill (doc-only mode if no command/runtime/script)"
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Execution timeout",
                        "default": 30
                    },
                    "terminal": {
                        "type": "boolean",
                        "description": "If true, ends the conversation turn (like command/chat).",
                        "default": false
                    },
                    "parameters": {
                        "type": "object",
                        "description": "Map of parameter names to {type, description} objects",
                        "additionalProperties": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "description": { "type": "string" }
                            }
                        }
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "uninstall_skill".into(),
            description: "Uninstall a custom skill by removing its TOML from ~/.nsh/skills. \
                          Optionally remove a same-named directory under ~/.nsh/skills if it exists \
                          (e.g., from a previous repo clone). Always prompts for confirmation."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Skill name (alphanumeric + underscores)"
                    },
                    "remove_dir": {
                        "type": "boolean",
                        "description": "Also remove ~/.nsh/skills/{name} directory if present",
                        "default": true
                    }
                },
                "required": ["name"]
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
            name: "skill_exists".into(),
            description: "Check whether a skill is installed by name. Returns a human-readable status including TOML and docs paths if present.".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Skill name (alphanumeric + underscores)"
                    }
                },
                "required": ["name"]
            }),
        },
        // ── Done Tool ────────────────────────────────────────────────
        ToolDefinition {
            name: "done".into(),
            description: "End the autonomous loop. This is the ONLY tool that stops \
                          execution. You MUST call this when the task is complete or \
                          when you've decided further progress is not possible. \
                          Provide a reason: explain what was accomplished (success) \
                          or why you cannot continue (failure). Never call other \
                          tools after calling done in the same turn."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "result": {
                        "type": "string",
                        "description": "Why the loop is ending: what was accomplished, \
                                        or why you cannot proceed further"
                    }
                },
                "required": ["result"]
            }),
        },
        // ── Memory tools ─────────────────────────────────
        ToolDefinition {
            name: "search_memory".into(),
            description: "Search the persistent memory system for relevant information \
                          using BM25 full-text search. Searches across summaries, details, \
                          names, content, and LLM-generated semantic keywords."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "memory_type": {
                        "type": "string",
                        "enum": ["episodic", "semantic", "procedural", "resource", "knowledge", "all"],
                        "description": "Which memory type to search, or 'all' for all types"
                    },
                    "query": {
                        "type": "string",
                        "description": "Search query (natural language or keywords)"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 10,
                        "description": "Maximum results per type"
                    }
                },
                "required": ["memory_type", "query"]
            }),
        },
        ToolDefinition {
            name: "core_memory_append".into(),
            description: "Append new information to a core memory block. Core memory is \
                          always loaded into context. Use this to persistently remember \
                          user preferences, facts about the user, or environment details."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "label": {
                        "type": "string",
                        "enum": ["human", "persona", "environment"],
                        "description": "Which core block to append to"
                    },
                    "content": {
                        "type": "string",
                        "description": "Text to append (will be added on a new line)"
                    }
                },
                "required": ["label", "content"]
            }),
        },
        ToolDefinition {
            name: "core_memory_rewrite".into(),
            description: "Rewrite a core memory block entirely with condensed/updated \
                          content. Use when a block is >80% full and needs condensing, \
                          or when information needs significant restructuring."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "label": {
                        "type": "string",
                        "enum": ["human", "persona", "environment"],
                        "description": "Which core block to rewrite"
                    },
                    "content": {
                        "type": "string",
                        "description": "Complete new content for the block"
                    }
                },
                "required": ["label", "content"]
            }),
        },
        ToolDefinition {
            name: "store_memory".into(),
            description: "Explicitly store a new entry in persistent memory. Use when you \
                          learn something worth remembering across sessions. For semantic: \
                          facts about projects, tools, people. For procedural: step-by-step \
                          workflows. For resource: important file contents. For knowledge: \
                          credentials (encrypted)."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "memory_type": {
                        "type": "string",
                        "enum": ["semantic", "procedural", "resource", "knowledge"],
                        "description": "Type of memory to store"
                    },
                    "data": {
                        "type": "object",
                        "description": "Memory data with search_keywords field required. \
                                        Semantic: {name, summary, details, category, search_keywords}. \
                                        Procedural: {entry_type, summary, steps[], trigger_pattern, search_keywords}. \
                                        Resource: {title, summary, resource_type, content, file_path, search_keywords}. \
                                        Knowledge: {entry_type, caption, secret_value, source, sensitivity, search_keywords}."
                    }
                },
                "required": ["memory_type", "data"]
            }),
        },
        ToolDefinition {
            name: "retrieve_secret".into(),
            description: "Retrieve the actual decrypted value of a high-sensitivity secret \
                          from the Knowledge Vault. Only use when the user explicitly asks \
                          for a stored credential, API key, or connection string. Normal \
                          retrieval only shows captions."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "caption_query": {
                        "type": "string",
                        "description": "Search query matching the secret's caption/description"
                    }
                },
                "required": ["caption_query"]
            }),
        },
    ];

    // Inject expected_timeout_seconds into tool schemas that don't already have it
    for def in &mut defs {
        if let Some(props) = def
            .parameters
            .get_mut("properties")
            .and_then(|p| p.as_object_mut())
        {
            if !props.contains_key("expected_timeout_seconds") {
                props.insert(
                    "expected_timeout_seconds".to_string(),
                    serde_json::json!({
                        "type": "integer",
                        "description": "Expected maximum duration in seconds. If exceeded, the user will be asked whether to continue waiting. Default varies by tool."
                    }),
                );
            }
        }
    }

    defs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_all_tool_definitions_returns_all_tools() {
        let tools = all_tool_definitions();
        // Keep this resilient as tool set grows
        assert!(tools.len() >= 22);
        for tool in &tools {
            assert!(!tool.name.is_empty());
            assert!(!tool.description.is_empty());
        }
    }

    #[test]
    fn test_tool_definitions_have_valid_schemas() {
        let tools = all_tool_definitions();
        for tool in &tools {
            let obj = tool
                .parameters
                .as_object()
                .expect("parameters should be an object");
            assert_eq!(obj.get("type").and_then(|v| v.as_str()), Some("object"));
        }
    }

    #[test]
    fn test_tool_names_unique() {
        let tools = all_tool_definitions();
        let mut names = HashSet::new();
        for tool in &tools {
            assert!(
                names.insert(tool.name.clone()),
                "duplicate tool name: {}",
                tool.name
            );
        }
    }

    #[test]
    fn test_specific_tools_exist() {
        let tools = all_tool_definitions();
        let names: HashSet<String> = tools.iter().map(|t| t.name.clone()).collect();
        let expected = [
            "command",
            "chat",
            "search_history",
            "grep_file",
            "read_file",
            "list_directory",
            "glob",
            "web_search",
            "github",
            "run_command",
            "ask_user",
            "code",
            "write_file",
            "patch_file",
            "man_page",
            "manage_config",
            "install_skill",
            "install_mcp_server",
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
            assert!(
                obj.contains_key("required"),
                "tool '{}' missing 'required' field",
                tool.name
            );
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
        if let Ok(p) = result {
            assert!(p.is_absolute());
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
        match result {
            Ok(p) => assert!(p.is_absolute()),
            Err(e) => assert!(e.contains("sensitive")),
        }
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

    #[test]
    fn test_validate_read_path_with_access_allow_bypasses_sensitive() {
        let result = validate_read_path_with_access("~/.ssh/id_rsa", "allow");
        match result {
            Ok(p) => assert!(p.is_absolute()),
            Err(e) => {
                assert!(
                    !e.contains("sensitive"),
                    "allow mode should not block sensitive dirs, got: {e}"
                );
            }
        }
    }

    #[test]
    fn test_validate_read_path_with_access_block_rejects_sensitive() {
        let result = validate_read_path_with_access("~/.ssh/id_rsa", "block");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sensitive"));
    }

    #[test]
    fn test_validate_read_path_sensitive_gpg() {
        let result = validate_read_path("~/.gpg/keys");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sensitive"));
    }

    #[test]
    fn test_validate_read_path_sensitive_kube() {
        let result = validate_read_path("~/.kube/config");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sensitive"));
    }

    #[test]
    fn test_validate_read_path_sensitive_docker() {
        let result = validate_read_path("~/.docker/config.json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sensitive"));
    }

    #[test]
    fn test_validate_read_path_sensitive_azure() {
        let result = validate_read_path("~/.azure/credentials");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sensitive"));
    }

    #[test]
    fn test_validate_read_path_sensitive_gcloud() {
        let result = validate_read_path("~/.config/gcloud/credentials.json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sensitive"));
    }

    #[test]
    fn test_validate_read_path_parent_dir_in_middle() {
        let result = validate_read_path("/usr/local/../bin/ls");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains(".."));
    }

    #[test]
    fn test_validate_read_path_parent_dir_at_end() {
        let result = validate_read_path("/tmp/foo/..");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains(".."));
    }

    #[test]
    fn test_tool_definition_serializes_to_json() {
        let tool = ToolDefinition {
            name: "test_tool".into(),
            description: "A test tool".into(),
            parameters: json!({"type": "object", "properties": {}, "required": []}),
        };
        let serialized = serde_json::to_value(&tool).unwrap();
        assert_eq!(serialized["name"], "test_tool");
        assert_eq!(serialized["description"], "A test tool");
        assert!(serialized["parameters"].is_object());
    }

    #[test]
    fn test_tool_definition_clone() {
        let tool = ToolDefinition {
            name: "clone_test".into(),
            description: "desc".into(),
            parameters: json!({"type": "object"}),
        };
        let cloned = tool.clone();
        assert_eq!(cloned.name, tool.name);
        assert_eq!(cloned.description, tool.description);
        assert_eq!(cloned.parameters, tool.parameters);
    }

    #[test]
    fn test_tool_definition_debug() {
        let tool = ToolDefinition {
            name: "debug_test".into(),
            description: "desc".into(),
            parameters: json!({}),
        };
        let debug_str = format!("{tool:?}");
        assert!(debug_str.contains("debug_test"));
    }

    #[test]
    fn test_command_tool_schema_properties() {
        let tools = all_tool_definitions();
        let command = tools.iter().find(|t| t.name == "command").unwrap();
        let props = command.parameters["properties"].as_object().unwrap();
        assert!(props.contains_key("command"));
        assert!(props.contains_key("explanation"));
        assert!(props.contains_key("pending"));
        assert_eq!(props["pending"]["type"], "boolean");
        assert_eq!(props["pending"]["default"], false);
        let required = command.parameters["required"].as_array().unwrap();
        let req_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(req_strs.contains(&"command"));
        assert!(req_strs.contains(&"explanation"));
        assert!(!req_strs.contains(&"pending"));
    }

    #[test]
    fn test_chat_tool_schema() {
        let tools = all_tool_definitions();
        let chat = tools.iter().find(|t| t.name == "chat").unwrap();
        let props = chat.parameters["properties"].as_object().unwrap();
        assert!(props.contains_key("response"));
        assert_eq!(props["response"]["type"], "string");
        let required = chat.parameters["required"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0], "response");
    }

    #[test]
    fn test_search_history_tool_schema() {
        let tools = all_tool_definitions();
        let sh = tools.iter().find(|t| t.name == "search_history").unwrap();
        let props = sh.parameters["properties"].as_object().unwrap();
        let expected_props = [
            "query",
            "command",
            "entity",
            "entity_type",
            "latest_only",
            "regex",
            "since",
            "until",
            "exit_code",
            "failed_only",
            "session",
            "limit",
        ];
        for p in &expected_props {
            assert!(
                props.contains_key(*p),
                "search_history missing property: {p}"
            );
        }
        assert_eq!(props["exit_code"]["type"], "integer");
        assert_eq!(props["failed_only"]["type"], "boolean");
        assert_eq!(props["latest_only"]["type"], "boolean");
        assert_eq!(props["limit"]["default"], 20);
    }

    #[test]
    fn test_write_file_tool_requires_path_content_reason() {
        let tools = all_tool_definitions();
        let wf = tools.iter().find(|t| t.name == "write_file").unwrap();
        let required = wf.parameters["required"].as_array().unwrap();
        let req_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(req_strs.contains(&"path"));
        assert!(req_strs.contains(&"content"));
        assert!(req_strs.contains(&"reason"));
    }

    #[test]
    fn test_patch_file_tool_requires_all_fields() {
        let tools = all_tool_definitions();
        let pf = tools.iter().find(|t| t.name == "patch_file").unwrap();
        let required = pf.parameters["required"].as_array().unwrap();
        let req_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(req_strs.len(), 4);
        assert!(req_strs.contains(&"path"));
        assert!(req_strs.contains(&"search"));
        assert!(req_strs.contains(&"replace"));
        assert!(req_strs.contains(&"reason"));
    }

    #[test]
    fn test_manage_config_tool_action_enum() {
        let tools = all_tool_definitions();
        let mc = tools.iter().find(|t| t.name == "manage_config").unwrap();
        let action = &mc.parameters["properties"]["action"];
        let enum_vals = action["enum"].as_array().unwrap();
        let vals: Vec<&str> = enum_vals.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(vals.contains(&"set"));
        assert!(vals.contains(&"remove"));
        assert_eq!(vals.len(), 2);
    }

    #[test]
    fn test_install_mcp_server_transport_enum() {
        let tools = all_tool_definitions();
        let mcp = tools
            .iter()
            .find(|t| t.name == "install_mcp_server")
            .unwrap();
        let transport = &mcp.parameters["properties"]["transport"];
        let enum_vals = transport["enum"].as_array().unwrap();
        let vals: Vec<&str> = enum_vals.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(vals.contains(&"stdio"));
        assert!(vals.contains(&"http"));
    }
    #[test]
    fn test_all_tools_have_properties_object() {
        let tools = all_tool_definitions();
        for tool in &tools {
            let props = tool.parameters.get("properties");
            assert!(
                props.is_some() && props.unwrap().is_object(),
                "tool '{}' missing properties object",
                tool.name
            );
        }
    }

    #[test]
    fn test_all_required_fields_exist_in_properties() {
        let tools = all_tool_definitions();
        for tool in &tools {
            let props = tool.parameters["properties"].as_object().unwrap();
            let required = tool.parameters["required"].as_array().unwrap();
            for req in required {
                let key = req.as_str().unwrap();
                assert!(
                    props.contains_key(key),
                    "tool '{}' requires '{}' but it's not in properties",
                    tool.name,
                    key
                );
            }
        }
    }

    #[test]
    fn test_all_property_types_are_valid_json_schema_types() {
        let valid_types = ["string", "integer", "boolean", "array", "object", "number"];
        let tools = all_tool_definitions();
        for tool in &tools {
            let props = tool.parameters["properties"].as_object().unwrap();
            for (key, prop) in props {
                if let Some(ty) = prop.get("type").and_then(|v| v.as_str()) {
                    assert!(
                        valid_types.contains(&ty),
                        "tool '{}' property '{}' has invalid type '{}'",
                        tool.name,
                        key,
                        ty
                    );
                }
            }
        }
    }

    #[test]
    fn test_grep_file_tool_properties() {
        let tools = all_tool_definitions();
        let gf = tools.iter().find(|t| t.name == "grep_file").unwrap();
        let props = gf.parameters["properties"].as_object().unwrap();
        assert!(props.contains_key("path"));
        assert!(props.contains_key("pattern"));
        assert!(props.contains_key("context_lines"));
        assert!(props.contains_key("max_lines"));
        assert_eq!(props["context_lines"]["default"], 3);
        assert_eq!(props["max_lines"]["default"], 100);
    }

    #[test]
    fn test_read_file_tool_properties() {
        let tools = all_tool_definitions();
        let rf = tools.iter().find(|t| t.name == "read_file").unwrap();
        let props = rf.parameters["properties"].as_object().unwrap();
        assert!(props.contains_key("path"));
        assert!(props.contains_key("full"));
        assert!(props.contains_key("start_line"));
        assert!(props.contains_key("end_line"));
        assert_eq!(props["full"]["default"], false);
    }

    #[test]
    fn test_list_directory_tool_defaults() {
        let tools = all_tool_definitions();
        let ld = tools.iter().find(|t| t.name == "list_directory").unwrap();
        let props = ld.parameters["properties"].as_object().unwrap();
        assert_eq!(props["path"]["default"], ".");
        assert_eq!(props["show_hidden"]["default"], false);
        assert_eq!(props["recursive"]["default"], false);
        assert_eq!(props["max_entries"]["default"], 100);
        let required = ld.parameters["required"].as_array().unwrap();
        assert!(required.is_empty());
    }

    #[test]
    fn test_run_command_tool_requires_command_and_reason() {
        let tools = all_tool_definitions();
        let rc = tools.iter().find(|t| t.name == "run_command").unwrap();
        let required = rc.parameters["required"].as_array().unwrap();
        let req_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(req_strs.contains(&"command"));
        assert!(req_strs.contains(&"reason"));
    }

    #[test]
    fn test_ask_user_tool_options_is_array() {
        let tools = all_tool_definitions();
        let au = tools.iter().find(|t| t.name == "ask_user").unwrap();
        let props = au.parameters["properties"].as_object().unwrap();
        assert_eq!(props["options"]["type"], "array");
        assert_eq!(props["options"]["items"]["type"], "string");
    }

    #[test]
    fn test_install_skill_tool_parameters_additionalproperties() {
        let tools = all_tool_definitions();
        let is = tools.iter().find(|t| t.name == "install_skill").unwrap();
        let params_prop = &is.parameters["properties"]["parameters"];
        assert_eq!(params_prop["type"], "object");
        assert!(params_prop.get("additionalProperties").is_some());
    }

    #[test]
    fn test_install_mcp_server_args_is_string_array() {
        let tools = all_tool_definitions();
        let mcp = tools
            .iter()
            .find(|t| t.name == "install_mcp_server")
            .unwrap();
        let args = &mcp.parameters["properties"]["args"];
        assert_eq!(args["type"], "array");
        assert_eq!(args["items"]["type"], "string");
    }

    #[test]
    fn test_tool_count_matches_expected_names() {
        let tools = all_tool_definitions();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        // Avoid brittle exact ordering/length checks; assert a subset of critical tools exists.
        for must in [
            "command",
            "chat",
            "run_command",
            "web_search",
            "github",
            "ask_user",
            "write_file",
            "patch_file",
            "manage_config",
        ] {
            assert!(names.contains(&must), "tool list missing {must}");
        }
    }

    #[test]
    fn test_no_tool_has_empty_parameters() {
        let tools = all_tool_definitions();
        for tool in &tools {
            assert!(
                !tool.parameters.is_null(),
                "tool '{}' has null parameters",
                tool.name
            );
        }
    }

    #[test]
    fn test_man_page_section_is_integer() {
        let tools = all_tool_definitions();
        let mp = tools.iter().find(|t| t.name == "man_page").unwrap();
        let section = &mp.parameters["properties"]["section"];
        assert_eq!(section["type"], "integer");
    }

    #[test]
    fn test_install_mcp_server_timeout_default() {
        let tools = all_tool_definitions();
        let mcp = tools
            .iter()
            .find(|t| t.name == "install_mcp_server")
            .unwrap();
        let timeout = &mcp.parameters["properties"]["timeout_seconds"];
        assert_eq!(timeout["type"], "integer");
        assert_eq!(timeout["default"], 30);
    }

    #[test]
    fn test_install_skill_timeout_default() {
        let tools = all_tool_definitions();
        let is = tools.iter().find(|t| t.name == "install_skill").unwrap();
        let timeout = &is.parameters["properties"]["timeout_seconds"];
        assert_eq!(timeout["default"], 30);
    }

    #[test]
    fn test_install_skill_terminal_default() {
        let tools = all_tool_definitions();
        let is = tools.iter().find(|t| t.name == "install_skill").unwrap();
        let terminal = &is.parameters["properties"]["terminal"];
        assert_eq!(terminal["type"], "boolean");
        assert_eq!(terminal["default"], false);
    }

    #[test]
    fn test_validate_read_path_nonexistent_under_tmp() {
        let result = validate_read_path("/tmp/nsh_nonexistent_subdir/foo/bar.txt");
        if let Ok(p) = result {
            assert!(p.is_absolute());
        }
    }

    #[test]
    fn test_validate_read_path_empty_string() {
        let result = validate_read_path("");
        if let Ok(p) = result {
            assert!(p.is_absolute());
        }
    }

    #[test]
    fn test_validate_read_path_dot() {
        let result = validate_read_path(".");
        assert!(result.is_ok());
        assert!(result.unwrap().is_absolute());
    }

    #[test]
    fn test_web_search_tool_requires_query() {
        let tools = all_tool_definitions();
        let ws = tools.iter().find(|t| t.name == "web_search").unwrap();
        let required = ws.parameters["required"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0], "query");
    }

    #[test]
    fn test_validate_read_path_allow_mode_normal_path() {
        let result = validate_read_path_with_access("/tmp", "allow");
        assert!(result.is_ok());
        assert!(result.unwrap().is_absolute());
    }

    #[test]
    fn test_validate_read_path_allow_mode_rejects_dotdot() {
        let result = validate_read_path_with_access("/tmp/../etc/passwd", "allow");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains(".."));
    }

    #[test]
    fn test_validate_read_path_tilde_subpath_nonexistent() {
        let result = validate_read_path("~/nonexistent_nsh_test_dir_999/file.txt");
        match result {
            Ok(p) => assert!(p.is_absolute()),
            Err(e) => assert!(
                e.contains("Access denied") || e.contains("sensitive"),
                "unexpected error: {e}"
            ),
        }
    }

    #[test]
    fn test_validate_read_path_relative_nonexistent() {
        let result = validate_read_path("nsh_nonexistent_relative_test_file_xyz.txt");
        match result {
            Ok(p) => assert!(p.is_absolute()),
            Err(e) => assert!(e.contains("Access denied"), "unexpected error: {e}"),
        }
    }

    #[test]
    fn test_validate_read_path_block_mode_non_sensitive_path() {
        let result = validate_read_path_with_access("/tmp", "block");
        assert!(result.is_ok());
        assert!(result.unwrap().is_absolute());
    }
}
