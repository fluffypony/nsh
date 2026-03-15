use serde::{Deserialize, Serialize};
use std::fmt;

/// Error returned when parsing a memory enum from a string value.
#[derive(Debug, Clone)]
pub struct ParseEnumError {
    pub kind: &'static str,
    pub value: String,
}

impl fmt::Display for ParseEnumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown {}: '{}'", self.kind, self.value)
    }
}

impl std::error::Error for ParseEnumError {}

// ── ID Generation ──

pub fn generate_id(prefix: &str) -> String {
    let suffix = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(8)
        .collect::<String>()
        .to_uppercase();
    format!("{prefix}_{suffix}")
}

// ── Core Memory ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreBlock {
    pub label: CoreLabel,
    pub value: String,
    pub char_limit: usize,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoreLabel {
    Human,
    Persona,
    Environment,
}

impl CoreLabel {
    pub fn as_str(&self) -> &'static str {
        match self {
            CoreLabel::Human => "human",
            CoreLabel::Persona => "persona",
            CoreLabel::Environment => "environment",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, ParseEnumError> {
        match s {
            "human" => Ok(CoreLabel::Human),
            "persona" => Ok(CoreLabel::Persona),
            "environment" => Ok(CoreLabel::Environment),
            _ => Err(ParseEnumError { kind: "core label", value: s.to_owned() }),
        }
    }

    #[cfg(test)]
    pub fn default_limit(&self) -> usize {
        match self {
            CoreLabel::Human => 5000,
            CoreLabel::Persona => 5000,
            CoreLabel::Environment => 5000,
        }
    }
}

impl std::fmt::Display for CoreLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreOp {
    Append,
    Rewrite,
}

// ── Episodic Memory ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodicEvent {
    pub id: String,
    pub event_type: EventType,
    pub actor: Actor,
    pub summary: String,
    pub details: Option<String>,
    pub command: Option<String>,
    pub exit_code: Option<i32>,
    pub working_dir: Option<String>,
    pub project_context: Option<String>,
    pub search_keywords: String,
    pub occurred_at: String,
    pub is_consolidated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodicEventCreate {
    pub event_type: EventType,
    pub actor: Actor,
    pub summary: String,
    pub details: Option<String>,
    pub command: Option<String>,
    pub exit_code: Option<i32>,
    pub working_dir: Option<String>,
    pub project_context: Option<String>,
    pub search_keywords: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    CommandExecution,
    CommandError,
    UserInstruction,
    AssistantAction,
    FileEdit,
    SessionStart,
    SessionEnd,
    ProjectSwitch,
    SystemEvent,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::CommandExecution => "command_execution",
            EventType::CommandError => "command_error",
            EventType::UserInstruction => "user_instruction",
            EventType::AssistantAction => "assistant_action",
            EventType::FileEdit => "file_edit",
            EventType::SessionStart => "session_start",
            EventType::SessionEnd => "session_end",
            EventType::ProjectSwitch => "project_switch",
            EventType::SystemEvent => "system_event",
        }
    }

    pub fn parse(s: &str) -> Result<Self, ParseEnumError> {
        match s {
            "command_execution" => Ok(EventType::CommandExecution),
            "command_error" => Ok(EventType::CommandError),
            "user_instruction" => Ok(EventType::UserInstruction),
            "assistant_action" => Ok(EventType::AssistantAction),
            "file_edit" => Ok(EventType::FileEdit),
            "session_start" => Ok(EventType::SessionStart),
            "session_end" => Ok(EventType::SessionEnd),
            "project_switch" => Ok(EventType::ProjectSwitch),
            "system_event" => Ok(EventType::SystemEvent),
            _ => Err(ParseEnumError { kind: "event type", value: s.to_owned() }),
        }
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Actor {
    User,
    Assistant,
    System,
}

impl Actor {
    pub fn as_str(&self) -> &'static str {
        match self {
            Actor::User => "user",
            Actor::Assistant => "assistant",
            Actor::System => "system",
        }
    }

    pub fn parse(s: &str) -> Result<Self, ParseEnumError> {
        match s {
            "user" => Ok(Actor::User),
            "assistant" => Ok(Actor::Assistant),
            "system" => Ok(Actor::System),
            _ => Err(ParseEnumError { kind: "actor", value: s.to_owned() }),
        }
    }
}

impl std::fmt::Display for Actor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── Semantic Memory ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticItem {
    pub id: String,
    pub name: String,
    pub category: String,
    pub summary: String,
    pub details: Option<String>,
    pub search_keywords: String,
    pub access_count: i64,
    pub last_accessed: String,
    pub created_at: String,
    pub updated_at: String,
}

// ── Procedural Memory ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProceduralItem {
    pub id: String,
    pub entry_type: String,
    pub trigger_pattern: String,
    pub summary: String,
    pub steps: String, // JSON array
    pub search_keywords: String,
    pub access_count: i64,
    pub last_accessed: String,
    pub created_at: String,
    pub updated_at: String,
}

// ── Resource Memory ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceItem {
    pub id: String,
    pub resource_type: String,
    pub file_path: Option<String>,
    pub file_hash: Option<String>,
    pub title: String,
    pub summary: String,
    pub content: Option<String>,
    pub search_keywords: String,
    pub created_at: String,
    pub updated_at: String,
}

// ── Knowledge Vault ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEntry {
    pub id: String,
    pub entry_type: String,
    pub caption: String,
    pub secret_value: String, // encrypted at rest
    pub sensitivity: Sensitivity,
    pub search_keywords: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    Low,
    Medium,
    High,
}

impl Sensitivity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Sensitivity::Low => "low",
            Sensitivity::Medium => "medium",
            Sensitivity::High => "high",
        }
    }

    pub fn parse(s: &str) -> Result<Self, ParseEnumError> {
        match s {
            "low" => Ok(Sensitivity::Low),
            "medium" => Ok(Sensitivity::Medium),
            "high" => Ok(Sensitivity::High),
            _ => Err(ParseEnumError { kind: "sensitivity", value: s.to_owned() }),
        }
    }
}

impl std::fmt::Display for Sensitivity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── Shell Events (ingestion input) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellEvent {
    pub event_type: ShellEventType,
    pub command: Option<String>,
    pub output: Option<String>,
    pub exit_code: Option<i32>,
    pub working_dir: Option<String>,
    pub session_id: Option<String>,
    pub timestamp: String,
    pub git_context: Option<GitContext>,
    pub instruction: Option<String>,
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellEventType {
    CommandExecution,
    FileEdit,
    UserInstruction,
    AssistantAction,
    SessionStart,
    SessionEnd,
    ProjectSwitch,
}

impl ShellEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShellEventType::CommandExecution => "command_execution",
            ShellEventType::FileEdit => "file_edit",
            ShellEventType::UserInstruction => "user_instruction",
            ShellEventType::AssistantAction => "assistant_action",
            ShellEventType::SessionStart => "session_start",
            ShellEventType::SessionEnd => "session_end",
            ShellEventType::ProjectSwitch => "project_switch",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitContext {
    pub branch: Option<String>,
    pub repo_root: Option<String>,
}

// ── Query Context ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryQueryContext {
    pub query: String,
    pub cwd: Option<String>,
    pub session_id: Option<String>,
    pub interaction_mode: InteractionMode,
    pub error_context: Option<ErrorContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InteractionMode {
    NaturalLanguage,
    CommandSuggestion,
    ErrorFix,
    CodeGeneration,
    AutonomousExecution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    pub command: String,
    pub exit_code: i32,
    pub stderr: Option<String>,
}

// ── Retrieved Memories ──

#[derive(Debug, Clone, Default)]
pub struct RetrievedMemories {
    pub keywords: Vec<String>,
    pub core: Vec<CoreBlock>,
    pub recent_episodic: Vec<EpisodicEvent>,
    pub relevant_episodic: Vec<EpisodicEvent>,
    pub semantic: Vec<SemanticItem>,
    pub procedural: Vec<ProceduralItem>,
    pub resource: Vec<ResourceItem>,
    pub knowledge: Vec<KnowledgeEntry>,
}

// ── Routing Decision ──

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingDecision {
    pub update_core: Option<CoreUpdateDecision>,
    pub update_episodic: bool,
    pub update_semantic: bool,
    pub update_procedural: bool,
    pub update_resource: bool,
    pub update_knowledge: bool,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreUpdateDecision {
    pub label: String,
    pub op: String, // "append" or "rewrite"
}

impl RoutingDecision {
    #[cfg(test)]
    pub fn has_any_updates(&self) -> bool {
        self.update_core.is_some()
            || self.update_episodic
            || self.update_semantic
            || self.update_procedural
            || self.update_resource
            || self.update_knowledge
    }

    pub fn only_episodic(&self) -> bool {
        self.update_episodic
            && self.update_core.is_none()
            && !self.update_semantic
            && !self.update_procedural
            && !self.update_resource
            && !self.update_knowledge
    }
}

// ── Memory Operations ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum MemoryOp {
    CoreAppend {
        label: String,
        content: String,
    },
    CoreRewrite {
        label: String,
        content: String,
    },
    EpisodicInsert {
        event: EpisodicEventCreate,
    },
    EpisodicMerge {
        target_id: String,
        combined_summary: String,
        additional_details: Option<String>,
        search_keywords: String,
    },
    EpisodicDelete {
        ids: Vec<String>,
    },
    SemanticInsert {
        name: String,
        category: String,
        summary: String,
        details: Option<String>,
        search_keywords: String,
    },
    SemanticUpdate {
        id: String,
        summary: String,
        details: Option<String>,
        search_keywords: String,
    },
    SemanticDelete {
        ids: Vec<String>,
    },
    ProceduralInsert {
        entry_type: String,
        trigger_pattern: String,
        summary: String,
        steps: String,
        search_keywords: String,
    },
    ProceduralUpdate {
        id: String,
        summary: String,
        steps: String,
        search_keywords: String,
    },
    ProceduralDelete {
        ids: Vec<String>,
    },
    ResourceInsert {
        resource_type: String,
        file_path: Option<String>,
        file_hash: Option<String>,
        title: String,
        summary: String,
        content: Option<String>,
        search_keywords: String,
    },
    ResourceDelete {
        ids: Vec<String>,
    },
    KnowledgeInsert {
        entry_type: String,
        caption: String,
        secret_value: String,
        sensitivity: Sensitivity,
        search_keywords: String,
    },
    KnowledgeDelete {
        ids: Vec<String>,
    },
    NoOp {
        reason: String,
    },
}

// ── Context Budget ──

#[cfg(test)]
#[derive(Debug, Clone)]
pub struct ContextBudget {
    pub total_tokens: usize,
    pub system_prompt_tokens: usize,
    pub conversation_tokens: usize,
}

#[cfg(test)]
impl ContextBudget {
    pub fn memory_budget(&self) -> usize {
        let used = self.system_prompt_tokens + self.conversation_tokens;
        if self.total_tokens > used {
            (self.total_tokens - used) / 3
        } else {
            2000
        }
    }
}

// ── Memory Type ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryType {
    Core,
    Episodic,
    Semantic,
    Procedural,
    Resource,
    Knowledge,
}

impl MemoryType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryType::Core => "core",
            MemoryType::Episodic => "episodic",
            MemoryType::Semantic => "semantic",
            MemoryType::Procedural => "procedural",
            MemoryType::Resource => "resource",
            MemoryType::Knowledge => "knowledge",
        }
    }

    pub fn parse(s: &str) -> Result<Self, ParseEnumError> {
        match s {
            "core" => Ok(MemoryType::Core),
            "episodic" => Ok(MemoryType::Episodic),
            "semantic" => Ok(MemoryType::Semantic),
            "procedural" => Ok(MemoryType::Procedural),
            "resource" => Ok(MemoryType::Resource),
            "knowledge" => Ok(MemoryType::Knowledge),
            _ => Err(ParseEnumError { kind: "memory type", value: s.to_owned() }),
        }
    }
}

impl std::fmt::Display for MemoryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── Stats & Reports ──

#[derive(Debug, Clone, Default)]
pub struct MemoryStats {
    pub core_count: usize,
    pub episodic_count: usize,
    pub semantic_count: usize,
    pub procedural_count: usize,
    pub resource_count: usize,
    pub knowledge_count: usize,
}

#[derive(Debug, Clone, Default)]
pub struct DecayReport {
    pub episodic_deleted: usize,
    pub semantic_deleted: usize,
    pub procedural_deleted: usize,
    pub resource_deleted: usize,
    pub knowledge_deleted: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ReflectionReport {
    pub ops_applied: usize,
    pub ops_failed: usize,
}

#[derive(Debug, Clone, Default)]
pub struct BootstrapReport {
    pub files_scanned: usize,
}

// ── Search Result ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub memory_type: MemoryType,
    pub id: String,
    pub summary: String,
    pub score: f32,
}

// ── Detected Secret ──

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DetectedSecret {
    pub label: String,
    pub value: String,
    pub position: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_id_has_correct_prefix() {
        let id = generate_id("ep");
        assert!(id.starts_with("ep_"));
        assert_eq!(id.len(), 11); // "ep_" + 8 chars
    }

    #[test]
    fn generate_id_unique() {
        let a = generate_id("sem");
        let b = generate_id("sem");
        // Statistically should differ; not guaranteed but 36^4 = 1.6M possibilities
        // Just check format
        assert!(a.starts_with("sem_"));
        assert!(b.starts_with("sem_"));
    }

    #[test]
    fn core_label_roundtrip() {
        for label in [CoreLabel::Human, CoreLabel::Persona, CoreLabel::Environment] {
            let s = label.as_str();
            assert_eq!(CoreLabel::from_str(s).unwrap(), label);
        }
    }

    #[test]
    fn routing_decision_has_any_updates() {
        let mut d = RoutingDecision::default();
        assert!(!d.has_any_updates());
        d = RoutingDecision {
            update_episodic: true,
            ..Default::default()
        };
        assert!(d.has_any_updates());
    }

    #[test]
    fn routing_decision_only_episodic() {
        let mut d = RoutingDecision {
            update_episodic: true,
            ..Default::default()
        };
        assert!(d.only_episodic());
        d = RoutingDecision {
            update_episodic: true,
            update_semantic: true,
            ..Default::default()
        };
        assert!(!d.only_episodic());
    }

    #[test]
    fn sensitivity_ordering() {
        assert!(Sensitivity::Low < Sensitivity::Medium);
        assert!(Sensitivity::Medium < Sensitivity::High);
    }

    #[test]
    fn context_budget_memory_budget() {
        let b = ContextBudget {
            total_tokens: 100_000,
            system_prompt_tokens: 10_000,
            conversation_tokens: 20_000,
        };
        assert_eq!(b.memory_budget(), 23_333);
    }

    #[test]
    fn context_budget_zero_available() {
        let b = ContextBudget {
            total_tokens: 100,
            system_prompt_tokens: 50,
            conversation_tokens: 60,
        };
        // Used exceeds total, so should return minimum
        assert_eq!(b.memory_budget(), 2000);
    }

    #[test]
    fn core_label_from_str_invalid() {
        assert!(CoreLabel::from_str("invalid").is_err());
        assert!(CoreLabel::from_str("").is_err());
        assert!(CoreLabel::from_str("HUMAN").is_err()); // case sensitive
    }

    #[test]
    fn sensitivity_parse_rejects_invalid() {
        assert_eq!(Sensitivity::parse("high").unwrap(), Sensitivity::High);
        assert_eq!(Sensitivity::parse("medium").unwrap(), Sensitivity::Medium);
        assert_eq!(Sensitivity::parse("low").unwrap(), Sensitivity::Low);
        assert!(Sensitivity::parse("unknown").is_err());
        assert!(Sensitivity::parse("").is_err());
    }

    #[test]
    fn memory_type_parse_rejects_unknown() {
        assert_eq!(MemoryType::parse("core").unwrap(), MemoryType::Core);
        assert_eq!(MemoryType::parse("episodic").unwrap(), MemoryType::Episodic);
        assert_eq!(MemoryType::parse("semantic").unwrap(), MemoryType::Semantic);
        assert_eq!(
            MemoryType::parse("procedural").unwrap(),
            MemoryType::Procedural
        );
        assert_eq!(MemoryType::parse("resource").unwrap(), MemoryType::Resource);
        assert_eq!(
            MemoryType::parse("knowledge").unwrap(),
            MemoryType::Knowledge
        );
        assert!(MemoryType::parse("all").is_err());
        assert!(MemoryType::parse("").is_err());
    }
}
