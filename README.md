# nsh — Natural Shell

AI-powered shell assistant that lives in your terminal. Ask questions with `?`,
get commands prefilled at your prompt, and let the AI gather context from your
scrollback, history, files, and the web.

## Features

- **Natural language queries** — type `?` or `??` followed by what you want
- **Command prefill** — suggested commands appear at your prompt for review before execution
- **Context-aware** — captures scrollback, command history, and cross-session activity
- **Tool-augmented AI** — the LLM can read files, search history, browse the web, list directories, run safe commands, read man pages, and ask you questions
- **Multi-step workflows** — the AI can chain multiple investigative steps before suggesting a command
- **Full-text search** — SQLite FTS5-backed search across all command history and output
- **Multi-session awareness** — sees what you're doing in other terminal sessions
- **Conversation memory** — maintains context within a session for follow-up queries

## Requirements

- **Rust 1.85+** (2024 edition)
- **macOS or Linux** (uses POSIX PTY APIs)
- **Zsh or Bash**
- An [OpenRouter](https://openrouter.ai/) API key

## Installation

```bash
# Build and install from source
cargo install --path .

# Or build a release binary
cargo build --release
# Binary at target/release/nsh
```

## Setup

### 1. Add shell integration

Add one of these to your shell config file:

```bash
# Zsh (~/.zshrc)
eval "$(nsh init zsh)"

# Bash (~/.bashrc)
eval "$(nsh init bash)"
```

This installs:
- `?` and `??` aliases that route queries to `nsh query`
- `preexec`/`precmd` hooks (zsh) or `DEBUG` trap + `PROMPT_COMMAND` (bash) to record commands
- A pending-command check that prefills suggested commands at your prompt
- Session cleanup on shell exit

### 2. Configure your API key

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

Or retrieve the key from a password manager:

```toml
[provider.openrouter]
api_key_cmd = "op read 'op://Vault/OpenRouter/credential'"
```

### 3. (Optional) Enable scrollback capture

To let the AI read your recent terminal output, start your shell through the PTY wrapper:

```bash
# Add to your shell config, BEFORE the eval line
nsh wrap
```

Without this, the `scrollback` tool will report that PTY wrap mode is not active.

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
nsh config path       # Print config file location
nsh config show       # Print current config
nsh config edit       # Open in $EDITOR
```

## How It Works

1. Shell hooks capture every command and exit code into a local SQLite database
2. `?` / `??` sends your natural language query to the configured LLM with rich context:
   - OS, shell, current directory, username
   - Recent conversation history from this session
   - Commands running in other active terminal sessions
3. The LLM responds exclusively via tool calls in an agentic loop (up to 10 iterations)
4. **Terminal tools** end the loop:
   - `command` — writes the suggested command to a pending file; the shell hook prefills it at your prompt
   - `chat` — displays a text response for knowledge questions
5. **Intermediate tools** gather more context and loop continues:
   - `scrollback` — reads recent terminal output (requires PTY wrap mode)
   - `search_history` — FTS5 search across all command history
   - `grep_file` — regex search or read a local file
   - `list_directory` — list files with metadata
   - `web_search` — search the web via Perplexity/Sonar on OpenRouter
   - `run_command` — execute safe, allowlisted commands silently
   - `ask_user` — prompt for clarification or confirmation
   - `man_page` — retrieve man pages

## Configuration Reference

Configuration lives at `~/.nsh/config.toml`. All fields are optional and have sensible defaults.

```toml
[provider]
default = "openrouter"                        # LLM provider
model = "google/gemini-2.5-flash"             # Primary model
fallback_model = "anthropic/claude-sonnet-4-20250514"  # Fallback if primary fails
web_search_model = "perplexity/sonar"         # Model for web_search tool

[provider.openrouter]
api_key = "sk-or-..."                         # API key (plaintext)
api_key_cmd = "pass show openrouter"          # Or retrieve from command
base_url = "https://openrouter.ai/api/v1"     # Custom base URL

[context]
scrollback_bytes = 1048576    # Scrollback buffer size (1 MB)
scrollback_lines = 1000       # Max scrollback lines to send
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
chat_color = "\x1b[3;36m"                    # ANSI escape for responses (cyan italic)
thinking_indicator = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"    # Spinner frames
```

### Command Allowlist Matching

The `run_command_allowlist` uses three matching strategies:

1. **Exact match** — `"git status"` matches `git status`
2. **Prefix match** — `"git log"` matches `git log --oneline`
3. **First-word match** — `"echo"` matches `echo hello world`

Commands not on the allowlist are denied; the AI is told to use the `command` tool instead so you can review them.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Shell (zsh/bash)                               │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐ │
│  │ ? alias  │  │ preexec/ │  │ pending_cmd   │ │
│  │ ?? alias │  │ precmd   │  │ prefill check │ │
│  └────┬─────┘  └────┬─────┘  └───────┬───────┘ │
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

nsh uses the filesystem for inter-process communication between the query engine and the shell:

| File | Purpose |
|------|---------|
| `~/.nsh/pending_cmd_{session_id}` | Command to prefill at prompt |
| `~/.nsh/pending_flag_{session_id}` | Signals a multi-step sequence (AI expects to see output) |
| `~/.nsh/scrollback_{session_id}` | PTY scrollback buffer flushed to disk |
| `~/.nsh/nsh.db` | SQLite database (WAL mode) |
| `~/.nsh/config.toml` | Configuration |

### Database Schema

The SQLite database (`~/.nsh/nsh.db`) uses WAL mode with four tables:

- **sessions** — one row per shell session (id, tty, shell, pid, timestamps)
- **commands** — individual commands with exit code, CWD, timing, and optional output
- **commands_fts** — FTS5 virtual table indexing command text, output, and CWD (porter + unicode61 tokenizer)
- **conversations** — LLM query/response pairs per session for multi-turn context

Triggers keep the FTS5 index in sync automatically on INSERT, UPDATE, and DELETE.

## CLI Reference

| Command | Description |
|---------|-------------|
| `nsh init <shell>` | Print shell integration script (zsh or bash) |
| `nsh wrap [--shell <path>]` | Start PTY wrapper for scrollback capture |
| `nsh query <words...>` | Send a natural language query to the LLM |
| `nsh record --session <id> --command <cmd> --cwd <dir> --exit-code <n> --started-at <ts>` | Record a command (called by shell hooks) |
| `nsh session end --session <id>` | End a session |
| `nsh history search <query> [--limit <n>]` | Full-text search across command history (default limit: 20) |
| `nsh reset` | Clear conversation context for current session |
| `nsh config [path\|show\|edit]` | Show config path (default), print config, or open in editor |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NSH_SESSION_ID` | Unique session UUID, set by `nsh init` |
| `NSH_TTY` | TTY path for the session |
| `SHELL` | Used to detect shell type and for `nsh wrap` default |
| `EDITOR` | Used by `nsh config edit` (defaults to `vi`) |
| `RUST_LOG` | Controls tracing output (e.g., `RUST_LOG=debug`) |

## Development

```bash
# Run tests (unit + integration)
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
├── main.rs              # Entry point, CLI dispatch
├── cli.rs               # Clap CLI argument definitions
├── config.rs            # TOML config with defaults
├── db.rs                # SQLite schema, CRUD, FTS5
├── query.rs             # Agentic LLM tool loop
├── context.rs           # Environment context builder
├── streaming.rs         # SSE stream consumer + spinner
├── init.rs              # Shell init script generator
├── pty.rs               # PTY creation and shell wrapping
├── pump.rs              # PTY I/O pump + scrollback buffer
├── ansi.rs              # ANSI escape stripping
├── shell_hooks.rs       # Pending command file constants
├── util.rs              # String truncation
├── provider/
│   ├── mod.rs           # LlmProvider trait + factory
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
└── integration.rs       # Integration tests
```

## License

BSD 3-Clause
