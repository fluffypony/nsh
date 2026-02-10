pub mod ask_user;
pub mod chat;
pub mod command;
pub mod grep_file;
pub mod list_directory;
pub mod man_page;
pub mod patch_file;
pub mod read_file;
pub mod run_command;
pub mod search_history;
pub mod web_search;
pub mod write_file;

use serde::Serialize;
use serde_json::json;

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
    ]
}
