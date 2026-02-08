pub mod ask_user;
pub mod chat;
pub mod command;
pub mod grep_file;
pub mod list_directory;
pub mod man_page;
pub mod run_command;
pub mod scrollback;
pub mod search_history;
pub mod web_search;

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
            name: "scrollback".into(),
            description: "Request recent terminal output from the \
                          current session."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "lines": {
                        "type": "integer",
                        "description":
                            "Number of recent lines (max 1000)",
                        "default": 100
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "search_history".into(),
            description: "Full-text search across all shell command \
                          history and output across all sessions."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description":
                            "Search query (FTS5 syntax)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results",
                        "default": 10
                    }
                },
                "required": ["query"]
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
            description: "Search the web for current information."
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
            name: "man_page".into(),
            description: "Retrieve the man page for a command."
                .into(),
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
