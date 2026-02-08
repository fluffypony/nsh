# nsh — Natural Shell

An AI-powered shell assistant that lives in your terminal. Ask questions in
natural language, get commands prefilled at your prompt, and let the AI
investigate your environment before answering — reading files, searching
history, browsing the web, and more.

## Features

- **Natural language queries** — type `?` or `??` followed by what you want
- **Command prefill** — suggested commands appear at your prompt for review before execution
- **Context-aware** — captures scrollback, command history, and cross-session activity
- **Tool-augmented AI** — the LLM can read files, search history, browse the web, list directories, run safe commands, read man pages, and ask you questions
- **Multi-step workflows** — the AI chains investigative steps before suggesting a command (up to 10 iterations)
- **Full-text search** — SQLite FTS5-backed search across all command history and output
- **Multi-session awareness** — sees what you're doing in other active terminal sessions
- **Conversation memory** — maintains context within a session for follow-up queries

## Requirements

- **Rust 1.85+** (2024 edition)
- **macOS or Linux** (uses POSIX PTY APIs)
- **Zsh or Bash**
- An [OpenRouter](https://openrouter.ai/) API key

## Quick Start

```bash
cargo install --path .

mkdir -p ~/.nsh
cat > ~/.nsh/config.toml << 'EOF'
[provider]
default = "openrouter"

[provider.openrouter]
api_key = "sk-or-v1-..."
EOF
```

Add shell integration to your shell config:

```bash
# Zsh (~/.zshrc)
eval "$(nsh init zsh)"

# Bash (~/.bashrc)
eval "$(nsh init bash)"
```

Start a new shell session, then:

```bash
? why is my docker build failing
? install ripgrep
?? set up a python venv for this project
```

## Installation

```bash
# Install from source (puts binary in ~/.cargo/bin)
cargo install --path .

# Or build a release binary manually
cargo build --release
# Binary at target/release/nsh
```

The release profile is optimized for size with LTO, single codegen unit,
symbol stripping, and `opt-level = "z"`.

## Setup

### 1. Shell Integration

Add one of these to your shell config file:

```bash
# Zsh (~/.zshrc)
eval "$(nsh init zsh)"

# Bash (~/.bashrc)
eval "$(nsh init bash)"
```

This installs:
- `?` and `??` aliases that route queries to `nsh query`
- `preexec`/`precmd` hooks (zsh) or `DEBUG` trap + `PROMPT_COMMAND` (bash) to record commands and exit codes
- A pending-command check that prefills suggested commands at your prompt
- Session cleanup on shell exit via `EXIT` trap

Each `eval` generates a unique `NSH_SESSION_ID` (UUID v4) for the shell
session and exports it along with `NSH_TTY`.

### 2. API Key

```bash
mkdir -p ~/.nsh
cat > ~/.nsh/config.toml << 'EOF'
[provider]
default = "openrouter"
model = "google/gemini-2.5-flash"

[provider.openrouter]
api_key = "sk-or-v1-..."
EOF
```

To retrieve the key from a command (e.g. a password manager) instead of
storing it in plaintext:

```toml
[provider.openrouter]
api_key_cmd = "op read 'op://Vault/OpenRouter/credential'"
```

When both `api_key` and `api_key_cmd` are set, `api_key` takes precedence
if non-empty. The command is run via `sh -c`.

### 3. Scrollback Capture (Optional)

To let the AI read your recent terminal output via the `scrollback` tool,
start your shell through the PTY wrapper:

```bash
# Add to your shell config, BEFORE the eval line
nsh wrap
```

`nsh wrap` replaces the current process with a PTY-wrapped shell. Without
it, the `scrollback` tool reports that PTY wrap mode is not active.

By default `nsh wrap` launches `$SHELL`; override with `--shell /path/to/shell`.

## Usage

```bash
# Ask a question — the AI picks the best tool
? why is my docker build failing
? install ripgrep
? what does the -r flag do in cp

# Same behavior with ??
?? set up a python venv for this project

# Search your command history (FTS5 full-text search)
nsh history search "cargo build"
nsh history search "docker" --limit 50

# Clear conversation context for current session
nsh reset

# View or edit configuration
nsh config            # Print config file path (default action)
nsh config path       # Same as above
nsh config show       # Print current config file contents
nsh config edit       # Open in $EDITOR (defaults to vi)
```

## How It Works

1. Shell hooks capture every command and its exit code into a local SQLite database
2. `?` / `??` sends your natural language query to the configured LLM with context:
   - OS, shell, current directory, and username
   - Recent conversation history from this session
   - Recent commands from other active terminal sessions (cross-TTY context)
3. The LLM responds exclusively via tool calls in an agentic loop (up to 10 iterations)
4. **Terminal tools** end the loop:
   - `command` — writes the suggested command to a pending file; the shell hook prefills it at your prompt
   - `chat` — displays a text response for knowledge questions
5. **Intermediate tools** gather more context and the loop continues:
   - `scrollback` — reads recent terminal output (requires PTY wrap mode)
   - `search_history` — FTS5 search across all command history
   - `grep_file` — regex search or read a local file
   - `list_directory` — list files with metadata
   - `web_search` — search the web via Perplexity/Sonar on OpenRouter
   - `run_command` — execute safe, allowlisted commands silently
   - `ask_user` — prompt for clarification or confirmation
   - `man_page` — retrieve man page for a command

## Configuration

Configuration lives at `~/.nsh/config.toml`. All fields are optional; the
defaults below are from the source code.

```toml
[provider]
default = "openrouter"                           # LLM provider (openrouter, anthropic, or openai)
model = "google/gemini-2.5-flash"                # Primary model
fallback_model = "anthropic/claude-sonnet-4.5"  # Used if primary fails
web_search_model = "perplexity/sonar"            # Model for the web_search tool

[provider.openrouter]
api_key = "sk-or-..."                            # API key (plaintext)
api_key_cmd = "pass show openrouter"             # Or retrieve from command
base_url = "https://openrouter.ai/api/v1"        # Custom base URL

[context]
scrollback_bytes = 1048576    # Scrollback buffer size in bytes (default: 1 MB)
scrollback_lines = 1000       # Max scrollback lines to send to LLM
history_limit = 20            # Conversation history entries per session
token_budget = 8192           # Token budget for context
retention_days = 90           # Auto-prune commands older than this

[tools]
run_command_allowlist = [     # Commands the AI can run without approval
    "uname", "which", "cat", "head", "tail", "wc",
    "file", "stat", "ls", "echo", "whoami", "hostname",
    "date", "env", "printenv", "id", "df", "free",
    "python3 --version", "node --version",
    "git status", "git branch", "git log", "git diff",
    "pip list", "cargo --version",
]
# Set to ["*"] to allow all commands (use with caution)

[display]
chat_color = "\x1b[3;36m"                       # ANSI escape for responses (default: cyan italic)
thinking_indicator = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"   # Spinner frames
```

### Command Allowlist Matching

The `run_command_allowlist` uses three matching strategies (checked in order):

1. **Exact match** — `"git status"` matches `git status`
2. **Prefix match** — `"git log"` matches `git log --oneline`
3. **First-word match** — `"echo"` matches `echo hello world`

Commands not on the allowlist are denied; the AI is told to use the `command`
tool instead so you can review them at your prompt.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Shell (zsh/bash)                               │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ ? alias  │  │ preexec/ │  │ pending_cmd   │  │
│  │ ?? alias │  │ precmd   │  │ prefill check │  │
│  └────┬─────┘  └────┬─────┘  └───────┬───────┘  │
└───────┼─────────────┼────────────────┼──────────┘
        │             │                │
        ▼             ▼                ▲
  nsh query      nsh record     ~/.nsh/pending_cmd_{id}
        │             │                │
        ▼             ▼                │
  ┌───────────────────────────────┐    │
  │  Query Engine (query.rs)      │    │
  │  ┌─────────────────────────┐  │    │
  │  │ Context Builder         │  │    │
  │  │ (OS, shell, CWD, hist.) │  │    │
  │  └─────────────────────────┘  │    │
  │  ┌─────────────────────────┐  │    │
  │  │ Agentic Tool Loop       │──┼────┘
  │  │ (max 10 iterations)     │  │
  │  └─────────────────────────┘  │
  │            │                  │
  │            ▼                  │
  │  ┌─────────────────────────┐  │
  │  │ LLM Provider            │  │
  │  │ (OpenRouter + streaming)│  │
  │  └─────────────────────────┘  │
  └───────────────────────────────┘
        │
        ▼
  ┌──────────────┐
  │ SQLite DB    │
  │ (WAL mode)   │
  │ ┌──────────┐ │
  │ │ sessions │ │
  │ │ commands │ │
  │ │ FTS5 idx │ │
  │ │ convos   │ │
  │ └──────────┘ │
  └──────────────┘
```

### File-Based IPC

nsh uses the filesystem for inter-process communication between the query
engine and the shell:

| File | Purpose |
|------|---------|
| `~/.nsh/pending_cmd_{session_id}` | Command to prefill at the prompt |
| `~/.nsh/pending_flag_{session_id}` | Signals a multi-step sequence (AI expects to see output) |
| `~/.nsh/scrollback_{session_id}` | PTY scrollback buffer flushed to disk |
| `~/.nsh/nsh.db` | SQLite database (WAL mode) |
| `~/.nsh/config.toml` | User configuration |

### Database Schema

The SQLite database (`~/.nsh/nsh.db`) uses WAL mode with `busy_timeout = 5000`
and foreign keys enabled. It contains four tables:

- **sessions** — one row per shell session (`id`, `tty`, `shell`, `pid`, `started_at`, `ended_at`, `hostname`, `username`)
- **commands** — individual commands with `exit_code`, `cwd`, `started_at`, `duration_ms`, and optional `output`
- **commands_fts** — FTS5 virtual table indexing `command`, `output`, and `cwd` (porter + unicode61 tokenizer)
- **conversations** — LLM query/response pairs per session for multi-turn context (`query`, `response_type`, `response`, `explanation`, `executed`, `pending`)

Triggers keep the FTS5 index in sync automatically on INSERT, UPDATE, and DELETE.

## CLI Reference

| Command | Description |
|---------|-------------|
| `nsh init <shell>` | Print shell integration script (`zsh` or `bash`) |
| `nsh wrap [--shell <path>]` | Start PTY wrapper for scrollback capture (defaults to `$SHELL`) |
| `nsh query <words...>` | Send a natural language query to the LLM |
| `nsh record --session <id> --command <cmd> --cwd <dir> --exit-code <n> --started-at <ts>` | Record a command (called by shell hooks) |
| `nsh session end --session <id>` | End a session |
| `nsh history search <query> [--limit <n>]` | Full-text search across command history (default limit: 20) |
| `nsh reset` | Clear conversation context for current session |
| `nsh config` | Print config file path (default when no subcommand given) |
| `nsh config path` | Print config file path |
| `nsh config show` | Print current config file contents |
| `nsh config edit` | Open config in `$EDITOR` (defaults to `vi`) |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NSH_SESSION_ID` | Unique session UUID, set by `nsh init` |
| `NSH_TTY` | TTY path for the session, set by `nsh init` |
| `SHELL` | Used to detect shell type and as the default for `nsh wrap` |
| `EDITOR` | Used by `nsh config edit` (defaults to `vi`) |
| `RUST_LOG` | Controls tracing output (e.g., `RUST_LOG=debug`) |

## Development

```bash
# Run all tests (unit + integration)
cargo test

# Build debug
cargo build

# Build release (LTO + size-optimized)
cargo build --release

# Run with tracing
RUST_LOG=debug cargo run -- query hello
```

### Project Structure

```
src/
├── main.rs              # Entry point, CLI dispatch via clap
├── cli.rs               # Clap CLI argument definitions
├── config.rs            # TOML config parsing with defaults
├── db.rs                # SQLite schema, CRUD, FTS5 search
├── query.rs             # Agentic LLM tool loop (max 10 iterations)
├── context.rs           # Environment context builder (OS, shell, CWD, cross-TTY)
├── streaming.rs         # SSE stream consumer + spinner display
├── init.rs              # Shell init script generator (zsh/bash)
├── pty.rs               # PTY creation and shell wrapping (fork/exec)
├── pump.rs              # PTY I/O pump + scrollback ring buffer
├── ansi.rs              # ANSI escape sequence stripping
├── shell_hooks.rs       # Pending command file path constants + cleanup
├── util.rs              # String truncation helper
├── provider/
│   ├── mod.rs           # LlmProvider trait, message types, factory
│   ├── openrouter.rs    # OpenRouter provider (fully implemented)
│   ├── anthropic.rs     # Anthropic provider (stub)
│   └── openai.rs        # OpenAI provider (stub)
└── tools/
    ├── mod.rs           # Tool definitions + registry
    ├── command.rs       # Prefill command at prompt
    ├── chat.rs          # Text response display
    ├── scrollback.rs    # Read terminal scrollback
    ├── search_history.rs # FTS5 history search
    ├── grep_file.rs     # Regex search / file read
    ├── list_directory.rs # Directory listing with metadata
    ├── web_search.rs    # Web search via Perplexity/Sonar
    ├── run_command.rs   # Allowlisted command execution
    ├── ask_user.rs      # Interactive user prompting
    └── man_page.rs      # Man page retrieval

shell/
├── nsh.zsh              # Zsh integration hooks
└── nsh.bash             # Bash integration hooks

tests/
└── integration.rs       # Integration tests (CLI, init, config, history)
```

## License

BSD 3-Clause — see [LICENSE](LICENSE) for details.
