use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UsagePeriod {
    Today,
    Week,
    Month,
    All,
}

pub struct ResourceMemoryWrite<'a> {
    pub resource_type: &'a str,
    pub file_path: Option<&'a str>,
    pub file_hash: Option<&'a str>,
    pub title: &'a str,
    pub summary: &'a str,
    pub content: Option<&'a str>,
    pub search_keywords: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryMatch {
    pub id: i64,
    pub session_id: String,
    pub command: String,
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
    pub started_at: String,
    pub output: Option<String>,
    pub summary: Option<String>,
    pub cmd_highlight: String,
    pub output_highlight: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEntityMatch {
    pub command_id: i64,
    pub session_id: String,
    pub command: String,
    pub cwd: Option<String>,
    pub started_at: String,
    pub executable: String,
    pub entity: String,
    pub entity_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandForSummary {
    pub id: i64,
    pub command: String,
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
    pub output: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandWithSummary {
    pub command: String,
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
    pub started_at: String,
    pub duration_ms: Option<i64>,
    pub summary: Option<String>,
    pub output: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtherSessionSummary {
    pub command: String,
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
    pub started_at: String,
    pub summary: Option<String>,
    pub tty: String,
    pub shell: String,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(into = "String", from = "String")]
pub enum ConversationResponseKind {
    Chat,
    Command,
    Other(String),
}

impl ConversationResponseKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Chat => "chat",
            Self::Command => "command",
            Self::Other(value) => value.as_str(),
        }
    }

    pub fn is_command(&self) -> bool {
        matches!(self, Self::Command)
    }
}

impl From<&str> for ConversationResponseKind {
    fn from(value: &str) -> Self {
        match value {
            "chat" | "answer" => Self::Chat,
            "command" => Self::Command,
            other => Self::Other(other.to_string()),
        }
    }
}

impl From<String> for ConversationResponseKind {
    fn from(value: String) -> Self {
        match value.as_str() {
            "chat" | "answer" => Self::Chat,
            "command" => Self::Command,
            _ => Self::Other(value),
        }
    }
}

impl From<ConversationResponseKind> for String {
    fn from(value: ConversationResponseKind) -> Self {
        match value {
            ConversationResponseKind::Chat => "chat".to_string(),
            ConversationResponseKind::Command => "command".to_string(),
            ConversationResponseKind::Other(other) => other,
        }
    }
}

impl PartialEq<&str> for ConversationResponseKind {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl std::fmt::Display for ConversationResponseKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationExchange {
    pub query: String,
    pub response_type: ConversationResponseKind,
    pub response: String,
    pub explanation: Option<String>,
    pub result_exit_code: Option<i32>,
    pub result_output_snippet: Option<String>,
    pub created_at: Option<String>,
}

impl ConversationExchange {
    pub fn to_user_message(&self) -> crate::provider::Message {
        crate::provider::Message {
            role: crate::provider::Role::User,
            content: vec![crate::provider::ContentBlock::Text {
                text: self.query.clone(),
            }],
        }
    }

    pub fn to_assistant_message(&self, tool_id: &str) -> crate::provider::Message {
        use crate::provider::{ContentBlock, Message, Role};

        match self.response_type {
            ConversationResponseKind::Command => {
                let input = serde_json::json!({
                    "command": self.response,
                    "explanation": self.explanation
                        .as_deref().unwrap_or(""),
                });
                Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: tool_id.to_string(),
                        name: "command".into(),
                        input,
                    }],
                }
            }
            _ => {
                let input = serde_json::json!({
                    "response": self.response,
                });
                Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: tool_id.to_string(),
                        name: "chat".into(),
                        input,
                    }],
                }
            }
        }
    }

    pub fn to_tool_result_message(&self, tool_id: &str) -> crate::provider::Message {
        use crate::provider::{ContentBlock, Message, Role};

        let tool_name = if self.response_type.is_command() {
            "command"
        } else {
            "chat"
        };
        let mut raw_content = match self.response_type {
            ConversationResponseKind::Command => format!("Command prefilled: {}", self.response),
            _ => self.response.clone(),
        };
        if let Some(code) = &self.result_exit_code {
            let result_text = match &self.result_output_snippet {
                Some(output) => format!("\nUser executed. Exit {code}. Output:\n{output}"),
                None => format!("\nUser executed. Exit {code}."),
            };
            raw_content.push_str(&result_text);
        }
        let content = format!("<tool_result name=\"{tool_name}\">\n{raw_content}\n</tool_result>");
        Message {
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: tool_id.to_string(),
                content,
                is_error: false,
            }],
        }
    }
}
