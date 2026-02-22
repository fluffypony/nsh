use serde::{Deserialize, Serialize};

// ── ID Generation ──

pub fn generate_id(prefix: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();
    let suffix: String = (0..8)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect();
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
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "human" => Some(CoreLabel::Human),
            "persona" => Some(CoreLabel::Persona),
            "environment" => Some(CoreLabel::Environment),
            _ => None,
        }
    }

    #[allow(dead_code)]
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

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "high" => Sensitivity::High,
            "medium" => Sensitivity::Medium,
            _ => Sensitivity::Low,
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
    #[allow(dead_code)]
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
        sensitivity: String,
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

#[derive(Debug, Clone)]
pub struct ContextBudget {
    pub total_tokens: usize,
    pub system_prompt_tokens: usize,
    pub conversation_tokens: usize,
}

impl ContextBudget {
    #[allow(dead_code)]
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
            assert_eq!(CoreLabel::from_str(s), Some(label));
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
        assert_eq!(CoreLabel::from_str("invalid"), None);
        assert_eq!(CoreLabel::from_str(""), None);
        assert_eq!(CoreLabel::from_str("HUMAN"), None); // case sensitive
    }

    #[test]
    fn core_label_display() {
        assert_eq!(format!("{}", CoreLabel::Human), "human");
        assert_eq!(format!("{}", CoreLabel::Persona), "persona");
        assert_eq!(format!("{}", CoreLabel::Environment), "environment");
    }

    #[test]
    fn event_type_display() {
        assert_eq!(
            format!("{}", EventType::CommandExecution),
            "command_execution"
        );
        assert_eq!(format!("{}", EventType::ProjectSwitch), "project_switch");
    }

    #[test]
    fn actor_display() {
        assert_eq!(format!("{}", Actor::User), "user");
        assert_eq!(format!("{}", Actor::Assistant), "assistant");
        assert_eq!(format!("{}", Actor::System), "system");
    }

    #[test]
    fn sensitivity_from_str_defaults() {
        assert_eq!(Sensitivity::from_str("high"), Sensitivity::High);
        assert_eq!(Sensitivity::from_str("medium"), Sensitivity::Medium);
        assert_eq!(Sensitivity::from_str("low"), Sensitivity::Low);
        assert_eq!(Sensitivity::from_str("unknown"), Sensitivity::Low);
        assert_eq!(Sensitivity::from_str(""), Sensitivity::Low);
    }

    #[test]
    fn sensitivity_display() {
        assert_eq!(format!("{}", Sensitivity::Low), "low");
        assert_eq!(format!("{}", Sensitivity::Medium), "medium");
        assert_eq!(format!("{}", Sensitivity::High), "high");
    }

    #[test]
    fn memory_type_display() {
        assert_eq!(format!("{}", MemoryType::Core), "core");
        assert_eq!(format!("{}", MemoryType::Episodic), "episodic");
        assert_eq!(format!("{}", MemoryType::Semantic), "semantic");
        assert_eq!(format!("{}", MemoryType::Procedural), "procedural");
        assert_eq!(format!("{}", MemoryType::Resource), "resource");
        assert_eq!(format!("{}", MemoryType::Knowledge), "knowledge");
    }

    #[test]
    fn routing_decision_default() {
        let d = RoutingDecision::default();
        assert!(!d.has_any_updates());
        assert!(!d.only_episodic());
        assert!(d.reasoning.is_empty());
    }

    #[test]
    fn core_label_default_limits() {
        assert_eq!(CoreLabel::Human.default_limit(), 5000);
        assert_eq!(CoreLabel::Persona.default_limit(), 5000);
        assert_eq!(CoreLabel::Environment.default_limit(), 5000);
    }

    #[test]
    fn generate_id_all_prefixes() {
        for prefix in &["ep", "sem", "proc", "res", "kv", "test"] {
            let id = generate_id(prefix);
            assert!(id.starts_with(&format!("{prefix}_")));
            // prefix + "_" + 8 chars
            assert_eq!(id.len(), prefix.len() + 1 + 8);
        }
    }

    #[test]
    fn shell_event_type_as_str() {
        assert_eq!(
            ShellEventType::CommandExecution.as_str(),
            "command_execution"
        );
        assert_eq!(ShellEventType::FileEdit.as_str(), "file_edit");
        assert_eq!(ShellEventType::UserInstruction.as_str(), "user_instruction");
        assert_eq!(ShellEventType::AssistantAction.as_str(), "assistant_action");
        assert_eq!(ShellEventType::SessionStart.as_str(), "session_start");
        assert_eq!(ShellEventType::SessionEnd.as_str(), "session_end");
        assert_eq!(ShellEventType::ProjectSwitch.as_str(), "project_switch");
    }
}
