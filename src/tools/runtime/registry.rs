use serde::Serialize;
use serde_json::json;

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
                             In autorun mode, pending commands execute immediately and output is returned. \
                             pending=false also auto-runs if allowed by the security policy. \
                             In other modes, the user confirms and you continue.",
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
            description: "Search for a regex pattern in a file. \
                          Use read_file to read file contents."
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
                        "description": "Regex pattern to search for"
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
                "required": ["path", "pattern"]
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
                          verify the canonical approach before acting. Requires a \
                          search-capable [web_search] provider/model configuration; \
                          otherwise the tool will fail instead of guessing from model memory."
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
            description: "Execute a shell command for quick, non-interactive local inspection. \
                          Use for: which, --version, ls, cat, grep, git status, brew info, and similar \
                          short-lived read-only probes. Do NOT use for: package installs/upgrades, \
                          interactive commands, password prompts, or long-running operations. \
                          Use the `command` tool with pending=true for those."
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
        ToolDefinition {
            name: "done".into(),
            description: "End the autonomous loop. This is the ONLY tool that stops \
                          execution. You MUST call this when the task is complete or \
                          when you've decided further progress is not possible. \
                          Provide a structured summary of what was done. Never call \
                          other tools after calling done in the same turn."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "result": {
                        "type": "string",
                        "description": "Why the loop is ending: what was accomplished, \
                                        or why you cannot proceed further"
                    },
                    "completed_items": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of items from the user's request that were completed"
                    },
                    "deferred_items": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Items that were identified but deferred as out of scope"
                    },
                    "decisions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Key decisions made during execution (e.g., which alternative was chosen)"
                    },
                    "files_changed": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of files that were created or modified"
                    }
                },
                "required": ["result"]
            }),
        },
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

    for def in &mut defs {
        if let Some(props) = def
            .parameters
            .get_mut("properties")
            .and_then(|properties| properties.as_object_mut())
            && !props.contains_key("expected_timeout_seconds")
        {
            props.insert(
                    "expected_timeout_seconds".to_string(),
                    serde_json::json!({
                        "type": "integer",
                        "description": "Expected maximum duration in seconds. If exceeded, the user will be asked whether to continue waiting. Default varies by tool."
                    }),
                );
        }
    }

    defs
}

#[cfg(test)]
mod tests {
    use super::all_tool_definitions;

    #[test]
    fn all_tool_definitions_contains_core_tools() {
        let definitions = all_tool_definitions();
        let names: Vec<&str> = definitions
            .iter()
            .map(|definition| definition.name.as_str())
            .collect();

        assert!(names.contains(&"command"));
        assert!(names.contains(&"read_file"));
        assert!(names.contains(&"write_file"));
    }

    #[test]
    fn all_tool_definitions_expose_object_parameter_schemas() {
        for definition in all_tool_definitions() {
            let parameters = definition.parameters.as_object().unwrap();
            assert_eq!(
                parameters.get("type").and_then(|value| value.as_str()),
                Some("object")
            );
            assert!(parameters.contains_key("required"));
        }
    }
}
