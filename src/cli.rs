use clap::{Parser, Subcommand};
use clap_complete::Shell as ClapShell;

#[derive(Parser)]
#[command(
    name = "nsh",
    version = env!("NSH_BUILD_VERSION"),
    long_version = env!("NSH_BUILD_LONG_VERSION"),
    about = "Natural Shell — AI-powered shell assistant"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Print shell integration code
    Init {
        /// Shell type: zsh, bash, or fish
        shell: String,
    },

    /// Start PTY wrapper (called by init script)
    Wrap {
        /// Shell to wrap
        #[arg(long, default_value = "")]
        shell: String,
    },

    /// Handle a natural language query (called by ? / ?? alias)
    Query {
        /// Enable thinking/reasoning mode
        #[arg(long, default_value_t = false)]
        think: bool,
        /// Private mode: don't store query/response in history
        #[arg(long, default_value_t = false)]
        private: bool,
        /// Output structured JSON instead of terminal display
        #[arg(long, default_value_t = false)]
        json: bool,
        /// The natural language query
        #[arg(trailing_var_arg = true)]
        words: Vec<String>,
    },

    /// Record a command execution (called by preexec/precmd hooks)
    Record {
        #[arg(long)]
        session: String,
        #[arg(long)]
        command: String,
        #[arg(long)]
        cwd: String,
        #[arg(long)]
        exit_code: i32,
        #[arg(long)]
        started_at: String,
        #[arg(long)]
        duration_ms: Option<i64>,
        #[arg(long, default_value = "")]
        tty: String,
        #[arg(long, default_value_t = 0)]
        pid: i32,
        #[arg(long, default_value = "")]
        shell: String,
    },

    /// Session management
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },

    /// Search command history
    History {
        #[command(subcommand)]
        action: HistoryAction,
    },

    /// Clear session conversation context
    Reset,

    /// Show/edit configuration
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },

    /// Show cost/usage statistics
    Cost {
        /// Time period: today, week, month, or all
        #[arg(default_value = "month")]
        period: String,
    },

    /// Provider management
    Provider {
        #[command(subcommand)]
        action: ProviderAction,
    },

    /// Interactive chat / REPL mode
    Chat,

    /// Export conversation history
    Export {
        /// Output format: markdown or json
        #[arg(long)]
        format: Option<String>,
        /// Session ID (defaults to current)
        #[arg(long)]
        session: Option<String>,
    },

    /// Show nsh status
    Status,

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: ClapShell,
    },

    /// Check and repair nsh database integrity
    Doctor {
        /// Skip pruning old data
        #[arg(long, default_value_t = false)]
        no_prune: bool,
        /// Skip vacuum
        #[arg(long, default_value_t = false)]
        no_vacuum: bool,
        /// Override retention period (days)
        #[arg(long)]
        prune_days: Option<u32>,
    },

    /// Update session heartbeat
    Heartbeat {
        #[arg(long)]
        session: String,
    },

    /// Skip capturing the next command's output
    RedactNext,

    /// Self-update nsh to the latest version
    Update,

    /// Send a message to the daemon (thin client)
    DaemonSend {
        #[command(subcommand)]
        action: DaemonSendAction,
    },

    /// Read data from the daemon (synchronous)
    DaemonRead {
        #[command(subcommand)]
        action: DaemonReadAction,
    },

    /// Internal: run shell history import in a detached worker process
    #[command(hide = true)]
    HistoryImportRun,
}

#[derive(Subcommand)]
pub enum SessionAction {
    /// Start a new session
    Start {
        #[arg(long)]
        session: String,
        #[arg(long)]
        tty: String,
        #[arg(long)]
        shell: String,
        #[arg(long)]
        pid: i32,
    },
    /// End a session
    End {
        #[arg(long)]
        session: String,
    },
    /// Label the current session
    Label {
        /// Session label text
        label: String,
        /// Session ID (defaults to current)
        #[arg(long)]
        session: Option<String>,
    },
    /// Internal: print latest working directory for a TTY
    #[command(hide = true)]
    LastCwd {
        #[arg(long)]
        tty: String,
    },
}

#[derive(Subcommand)]
pub enum HistoryAction {
    /// Full-text search across command history
    Search {
        query: String,
        #[arg(long, default_value = "20")]
        limit: usize,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Print the config file path
    Path,
    /// Show current configuration
    Show {
        /// Show unredacted config (include full API keys)
        #[arg(long, default_value_t = false)]
        raw: bool,
    },
    /// Open config in $EDITOR
    Edit,
}

#[derive(Subcommand)]
pub enum ProviderAction {
    /// List locally available models (Ollama)
    ListLocal,
}

#[derive(Subcommand)]
pub enum DaemonSendAction {
    /// Record a command via daemon
    Record {
        #[arg(long)]
        session: String,
        #[arg(long)]
        command: String,
        #[arg(long)]
        cwd: String,
        #[arg(long)]
        exit_code: i32,
        #[arg(long)]
        started_at: String,
        #[arg(long)]
        duration_ms: Option<i64>,
        #[arg(long, default_value = "")]
        tty: String,
        #[arg(long, default_value_t = 0)]
        pid: i32,
        #[arg(long, default_value = "")]
        shell: String,
    },
    /// Send heartbeat via daemon
    Heartbeat {
        #[arg(long)]
        session: String,
    },
    /// Mark current scrollback position for per-command capture
    CaptureMark {
        #[arg(long)]
        session: String,
    },
    /// Get daemon status
    Status,
}

#[derive(Subcommand)]
pub enum DaemonReadAction {
    /// Read captured output since last mark
    CaptureRead {
        #[arg(long)]
        session: String,
        #[arg(long, default_value = "1000")]
        max_lines: usize,
    },
    /// Read current scrollback
    Scrollback {
        #[arg(long, default_value = "1000")]
        max_lines: usize,
    },
}
