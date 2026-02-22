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
        /// Shell type: zsh, bash, fish, powershell, pwsh, or cmd
        shell: String,
        /// Print only the hook content hash (for shell-side comparison)
        #[arg(long, default_value_t = false)]
        hash: bool,
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
        /// Optional doctor diagnostic target
        #[command(subcommand)]
        action: Option<DoctorAction>,
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

    /// Restart the nsh daemon
    Restart,

    /// Auto-detect API keys and configure nsh
    #[command(alias = "autoconfig")]
    Autoconfigure,

    /// Self-update nsh to the latest version
    Update,

    /// Manage persistent memory
    Memory {
        #[command(subcommand)]
        action: MemoryAction,
    },

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

    /// Internal: run the global nsh database daemon
    #[command(name = "nshd", hide = true)]
    Nshd,
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
    /// Internal: print configured suppressed exit codes for shell hints
    #[command(hide = true)]
    SuppressedExitCodes,
    /// Internal: add an exit code to suppressed shell failure hints
    #[command(hide = true)]
    IgnoreExitCode {
        #[arg(long)]
        code: i32,
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
pub enum MemoryAction {
    /// Search across memory types
    Search {
        query: String,
        #[arg(long)]
        r#type: Option<String>,
        #[arg(long, default_value = "10")]
        limit: usize,
    },
    /// Show memory statistics
    Stats,
    /// Show core memory contents
    Core,
    /// Run memory maintenance (decay + reflection)
    Maintain,
    /// Run bootstrap scan
    Bootstrap,
    /// Clear memories (optionally by type)
    Clear {
        #[arg(long)]
        r#type: Option<String>,
    },
    /// Run memory decay (cleanup old entries)
    Decay,
    /// Run memory reflection (consolidation)
    Reflect,
    /// Export all memories as JSON
    Export {
        #[arg(long)]
        format: Option<String>,
    },
    /// Show memory maintenance telemetry only
    Telemetry,
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

#[derive(Subcommand)]
pub enum DoctorAction {
    /// Check whether command output capture is active for this shell session
    Capture,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_export_with_format_and_session() {
        let cli =
            Cli::try_parse_from(["nsh", "export", "--format", "json", "--session", "sess-123"])
                .expect("export should parse");

        match cli.command {
            Commands::Export { format, session } => {
                assert_eq!(format.as_deref(), Some("json"));
                assert_eq!(session.as_deref(), Some("sess-123"));
            }
            _ => panic!("expected export command"),
        }
    }

    #[test]
    fn parses_query_flags_and_trailing_words() {
        let cli = Cli::try_parse_from([
            "nsh",
            "query",
            "--think",
            "--private",
            "--json",
            "find",
            "latest",
            "release",
        ])
        .expect("query should parse");

        match cli.command {
            Commands::Query {
                think,
                private,
                json,
                words,
            } => {
                assert!(think);
                assert!(private);
                assert!(json);
                assert_eq!(words, vec!["find", "latest", "release"]);
            }
            _ => panic!("expected query command"),
        }
    }

    #[test]
    fn parses_provider_list_local() {
        let cli = Cli::try_parse_from(["nsh", "provider", "list-local"])
            .expect("provider list-local should parse");

        match cli.command {
            Commands::Provider {
                action: ProviderAction::ListLocal,
            } => {}
            _ => panic!("expected provider list-local command"),
        }
    }

    #[test]
    fn parses_daemon_read_scrollback_with_default() {
        let cli = Cli::try_parse_from(["nsh", "daemon-read", "scrollback"])
            .expect("daemon-read scrollback should parse");

        match cli.command {
            Commands::DaemonRead {
                action: DaemonReadAction::Scrollback { max_lines },
            } => assert_eq!(max_lines, 1000),
            _ => panic!("expected daemon-read scrollback command"),
        }
    }

    #[test]
    fn rejects_invalid_provider_subcommand() {
        let text = match Cli::try_parse_from(["nsh", "provider", "bogus"]) {
            Ok(_) => panic!("expected parser error"),
            Err(err) => err.to_string(),
        };
        assert!(
            text.contains("unrecognized subcommand") || text.contains("invalid subcommand"),
            "unexpected error text: {text}"
        );
    }

    #[test]
    fn parses_hidden_nshd_command() {
        let cli = Cli::try_parse_from(["nsh", "nshd"]).expect("nshd should parse");
        match cli.command {
            Commands::Nshd => {}
            _ => panic!("expected hidden nshd command"),
        }
    }
}
