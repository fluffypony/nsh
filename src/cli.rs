use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "nsh",
    version,
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
        /// Shell type: zsh or bash
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
}

#[derive(Subcommand)]
pub enum SessionAction {
    /// End a session
    End {
        #[arg(long)]
        session: String,
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
    Show,
    /// Open config in $EDITOR
    Edit,
}
