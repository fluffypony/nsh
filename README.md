# nsh - Natural Shell

**AI-powered shell assistant for `zsh`, `bash`, and `fish`.**

nsh lives in your terminal. It records command history, understands your project context, reads your scrollback, and turns natural-language requests into shell commands or direct answers - all without leaving your prompt.

```
? why did my last command fail
? set up a python virtualenv for this repo
? fix
```

nsh prefills commands at your prompt for review before execution. It never runs anything blindly.

---

## How It Works

nsh wraps your shell in a PTY, capturing scrollback and command history into a local SQLite database. When you ask a question with `?`, nsh builds a rich context - your OS, shell, working directory, recent terminal output, project structure, git state, and conversation history - then streams a response from your configured LLM provider.

The assistant responds by calling **tools**: `command` to prefill a shell command, `chat` for text answers, or any of 16 other built-in tools for investigation, file editing, web search, and more. It can chain multiple tool calls in a single turn, investigating before acting.

```
you: ? install ripgrep
nsh: [searches history] → [checks brew availability] → [prefills command]
     $ brew install ripgrep
     ↵ Enter to run · Edit first · Ctrl-C to cancel
```

---

## Features

### Natural Language Interface

Three aliases, each a single character:

- **`? ...`** - standard query
- **`?? ...`** - reasoning/thinking mode (extended thinking for complex problems)
- **`?! ...`** - private mode (query and response are not saved to history)

Append `!!` to any query to auto-execute the suggested command without confirmation.

### Command Prefill

nsh writes suggested commands to your shell's editing buffer. You see the command at your prompt, can edit it, then press Enter to run it - or Ctrl-C to cancel. This is the default and safest mode.

Two alternative modes are available via configuration: `confirm` (approve/reject without editing) and `autorun` (execute immediately for safe commands).

### Context Awareness

Every query includes rich context assembled automatically:

- **Terminal scrollback** - recent output from your PTY session, including SSH sessions
- **Command history** - past commands with exit codes, durations, and AI-generated summaries
- **Project detection** - recognizes Rust, Node.js, Python, Go, Ruby, Java, C/C++, Nix, Docker, and Make projects
- **Git state** - current branch, status, and recent commits
- **Cross-TTY context** - optionally includes activity from other open terminal sessions
- **Environment** - OS, architecture, installed package managers, development tools

### Multi-Step Agent Loop

nsh can chain up to 10 tool calls per query. It investigates before acting - searching history, reading files, running safe commands, or querying the web - then responds with a concrete action.

The `pending` flag on command suggestions enables multi-step sequences: nsh prefills a command, waits for you to execute it, reads the output, then continues with the next step.

### 18 Built-In Tools

| Tool | Purpose |
|---|---|
| `command` | Prefill a shell command for review |
| `chat` | Text response for knowledge questions |
| `search_history` | FTS5 + regex search across all command history |
| `grep_file` | Regex search within files with context lines |
| `read_file` | Read file contents with line numbers |
| `list_directory` | List directory contents with metadata |
| `web_search` | Search the web via Perplexity/Sonar |
| `run_command` | Execute safe, allowlisted commands silently |
| `ask_user` | Request clarification or confirmation |
| `write_file` | Create or overwrite files (with diff preview and trash backup) |
| `patch_file` | Surgical find-and-replace in files (with diff preview) |
| `man_page` | Retrieve man pages for commands |
| `manage_config` | Modify nsh settings (with confirmation) |
| `install_skill` | Create reusable custom tool templates |
| `install_mcp_server` | Add MCP tool servers to configuration |
| `remember` | Store persistent facts and preferences |
| `forget_memory` | Delete a stored memory |
| `update_memory` | Modify an existing memory |

### Persistent Memory

nsh maintains a key-value memory store that persists across sessions. Memories are included in every query context, enabling personalized responses:

```
you: ? remember that 192.168.3.55 is my home NAS
nsh: ✓ Memory #1 stored: home NAS IP = 192.168.3.55

you: ? ssh to my NAS
nsh: $ ssh 192.168.3.55
```

nsh also proactively learns - when it discovers how you manage a package or service, it stores the association for future queries.

### Entity-Aware History Search

nsh extracts structured entities (hostnames, IPs) from commands and stores them in a searchable index. This enables queries like:

```
you: ? what servers have I ssh'd into recently
nsh: Recent machine targets for `ssh` (most recent first):
     - [2026-02-11T17:49:15Z] 135.181.128.145 (via ssh)
     - [2026-02-11T17:47:15Z] ssh.phx.nearlyfreespeech.net (via ssh)
```

### Security

- **Secret redaction** - over 60 built-in patterns detect and redact API keys, tokens, private keys, JWTs, database URLs, and more before sending context to the LLM. Custom patterns can be added.
- **Command risk assessment** - every suggested command is classified as `safe`, `elevated`, or `dangerous`. Dangerous commands (recursive deletion of system paths, disk formatting, fork bombs, piping remote scripts to shell) always require explicit `yes` confirmation.
- **Sensitive directory blocking** - reads and writes to `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.docker`, and similar directories are blocked by default.
- **Tool output sandboxing** - tool results are delimited by random boundary tokens and treated as untrusted data. Prompt injection attempts in tool output are filtered.
- **Protected settings** - security-critical configuration keys (API keys, allowlists, redaction settings) cannot be modified by the AI.
- **Audit logging** - all tool calls are logged to `~/.nsh/audit.log` with automatic rotation.

### Custom Skills

Skills are reusable shell command templates with optional parameters, saved as TOML files:

```toml
# ~/.nsh/skills/deploy.toml
name = "deploy"
description = "Deploy to production"
command = "kubectl apply -f deploy/{environment}.yaml"
timeout_seconds = 60

[parameters.environment]
type = "string"
description = "Target environment (staging, production)"
```

Skills appear as tools in the LLM's toolkit and can be invoked naturally:

```
you: ? deploy to staging
nsh: [calls skill_deploy with environment=staging]
```

### MCP Server Support

nsh supports the Model Context Protocol for extending its capabilities with external tool servers. Both stdio (local process) and HTTP (remote endpoint) transports are supported:

```toml
[mcp.servers.filesystem]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"]

[mcp.servers.remote_api]
transport = "http"
url = "https://mcp.example.com"
headers = { Authorization = "Bearer ..." }
```

### Multiple LLM Providers

nsh works with any OpenAI-compatible API. Built-in provider support includes:

- **OpenRouter** (default) - access to hundreds of models
- **Anthropic** - Claude models with prompt caching
- **OpenAI** - GPT models
- **Google Gemini** - Gemini models
- **Ollama** - local models

Model chains with automatic fallback on rate limits or errors are configured via `[models]`:

```toml
[models]
main = ["google/gemini-2.5-flash", "anthropic/claude-sonnet-4.5"]
fast = ["google/gemini-2.5-flash-lite", "anthropic/claude-haiku-4.5"]
```

### Additional Features

- **Interactive chat mode** - `nsh chat` for a REPL-style conversation
- **Shell history import** - automatically imports existing bash, zsh, and fish history on first run
- **Cost tracking** - `nsh cost` shows token usage and estimated costs by model
- **JSON output mode** - `nsh query --json` for structured event stream output
- **Conversation export** - `nsh export` in markdown or JSON format
- **Self-update** - `nsh update` downloads and verifies new releases via DNS TXT records and SHA256
- **Shell completions** - `nsh completions zsh|bash|fish` generates completion scripts
- **Project-local config** - `.nsh.toml` or `.nsh/config.toml` for per-project overrides (restricted to `context` and `display` sections)
- **Custom instructions** - global via config or per-project via `.nsh/instructions.md`
- **Hot-reloading config** - changes to `config.toml` take effect on the next query

---

## Requirements

- **Rust 1.85+** (edition 2024) - for building from source
- **macOS or Linux**
- **zsh, bash, or fish**
- At least one LLM provider API key (OpenRouter is the default)

---

## Installation

### Option 1: Install Script (Recommended)

```bash
curl -fsSL https://nsh.tools/install.sh | bash
```

The installer detects your platform, downloads a pre-built binary with SHA256 and DNS verification, creates a default config, and adds shell integration to your rc file. If no pre-built binary is available, it offers to build from source.

### Option 2: Build from Source

```bash
git clone https://github.com/fluffypony/nsh.git
cd nsh
cargo install --path . --locked
```

### Option 3: Local Release Binary

```bash
cargo build --release
# Binary at target/release/nsh
```

---

## Quick Start

### 1. Configure a Provider

Create `~/.nsh/config.toml`:

```toml
[provider]
default = "openrouter"
model = "google/gemini-2.5-flash"

[provider.openrouter]
api_key = "sk-or-v1-..."
# or: api_key_cmd = "op read 'op://Vault/OpenRouter/credential'"
```

Environment variable fallback is supported: `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`.

### 2. Enable Shell Integration

Add to your shell rc file:

```bash
# ~/.zshrc
command -v nsh >/dev/null && [[ -z "${NSH_PTY_ACTIVE:-}" ]] && nsh wrap
eval "$(nsh init zsh)"

# ~/.bashrc
command -v nsh >/dev/null && [[ -z "${NSH_PTY_ACTIVE:-}" ]] && nsh wrap
eval "$(nsh init bash)"

# fish: ~/.config/fish/conf.d/nsh.fish
command -v nsh >/dev/null; and not set -q NSH_PTY_ACTIVE; and nsh wrap
nsh init fish | source
```

`nsh wrap` runs your shell inside a PTY wrapper for scrollback capture. It's optional but recommended.

### 3. Use It

```bash
? why did my last command fail
?? set up a python virtualenv for this repo
?! what is the safest way to clean docker images
? install ripgrep
? fix         # after a failed command
? ignore      # suppress hint for the last exit code
```

---

## Query Modes

| Alias | Mode | Description |
|---|---|---|
| `? ...` | Normal | Standard query |
| `?? ...` | Reasoning | Extended thinking (`--think`) |
| `?! ...` | Private | No query/response history writes |
| `? ignore [code]` | Suppress | Disable failure hints for an exit code |

---

## CLI Reference

### User Commands

| Command | Purpose |
|---|---|
| `nsh init <shell>` | Print shell integration script |
| `nsh wrap [--shell <path>]` | Run shell inside PTY wrapper |
| `nsh query [--think] [--private] [--json] <words...>` | Ask the assistant |
| `nsh chat` | Interactive REPL chat mode |
| `nsh history search <query> [--limit N]` | Full-text search command history |
| `nsh status` | Show runtime state |
| `nsh doctor [--no-prune] [--no-vacuum] [--prune-days D]` | DB integrity check and cleanup |
| `nsh config [path\|show\|edit]` | View or edit configuration |
| `nsh reset` | Clear session conversation context |
| `nsh cost [today\|week\|month\|all]` | Usage and cost summary |
| `nsh export [--format markdown\|json] [--session ID]` | Export conversation history |
| `nsh provider list-local` | List local Ollama models |
| `nsh update` | Download and verify latest release |
| `nsh redact-next` | Skip capture for the next command |
| `nsh completions <shell>` | Generate shell completion script |

### Internal Commands

| Command | Purpose |
|---|---|
| `nsh record ...` | Command capture hook endpoint |
| `nsh session start\|end\|label ...` | Session lifecycle management |
| `nsh heartbeat --session ID` | Keep session alive |
| `nsh daemon-send ...` | Send request to daemon |
| `nsh daemon-read ...` | Read daemon capture/scrollback |

---

## Configuration

Main config: `~/.nsh/config.toml`

Project-local overrides: `.nsh.toml` or `.nsh/config.toml` (restricted to `context` and `display` sections).

### Full Default Configuration

```toml
[provider]
default = "openrouter"
model = "google/gemini-2.5-flash"
fallback_model = "anthropic/claude-sonnet-4.5"
web_search_model = "perplexity/sonar"
timeout_seconds = 120

[provider.openrouter]
# api_key = "..."
# api_key_cmd = "..."
# base_url = "https://openrouter.ai/api/v1"

[provider.anthropic]
# api_key = "..."

[provider.openai]
# api_key = "..."

[provider.ollama]
# base_url = "http://localhost:11434"

[provider.gemini]
# api_key = "..."

[context]
scrollback_lines = 1000
scrollback_pages = 10
history_summaries = 100
history_limit = 20
other_tty_summaries = 10
max_other_ttys = 20
project_files_limit = 100
git_commits = 10
retention_days = 1095
max_output_storage_bytes = 65536
scrollback_rate_limit_bps = 10485760
scrollback_pause_seconds = 2
include_other_tty = false
restore_last_cwd_per_tty = true
# custom_instructions = "..."

[hints]
suppressed_exit_codes = [130, 137, 141, 143]

[models]
main = [
  "google/gemini-2.5-flash",
  "google/gemini-3-flash-preview",
  "anthropic/claude-sonnet-4.5",
]
fast = [
  "google/gemini-2.5-flash-lite",
  "anthropic/claude-haiku-4.5",
]

[tools]
run_command_allowlist = [
  "uname", "which", "wc", "file", "stat", "ls", "echo",
  "whoami", "hostname", "date", "env", "printenv", "id",
  "df", "free", "python3 --version", "node --version",
  "git status", "git branch", "git log", "git diff",
  "pip list", "cargo --version",
]
sensitive_file_access = "block"  # block | ask | allow

[web_search]
provider = "openrouter"
model = "perplexity/sonar"

[display]
chat_color = "\x1b[3;36m"
thinking_indicator = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

[redaction]
enabled = true
replacement = "[REDACTED]"
disable_builtin = false
patterns = []  # custom regex patterns

[capture]
mode = "vt100"
alt_screen = "drop"  # drop | snapshot

[db]
busy_timeout_ms = 10000

[execution]
mode = "prefill"  # prefill | confirm | autorun
allow_unsafe_autorun = false

[mcp]
# [mcp.servers.example]
# transport = "stdio"
# command = "npx"
# args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
# env = { EXAMPLE = "1" }
# timeout_seconds = 30
```

### Protected Settings

These cannot be modified by the AI via `manage_config`:

- `execution.allow_unsafe_autorun`
- `tools.sensitive_file_access`
- `tools.run_command_allowlist`
- `redaction.enabled` / `redaction.disable_builtin`
- Any `api_key`, `api_key_cmd`, or `base_url` field

---

## Data and Runtime Files

All data is stored in `~/.nsh/`:

| File | Purpose |
|---|---|
| `config.toml` | User configuration |
| `nsh.db` | SQLite database (sessions, commands, conversations, usage, memories) |
| `audit.log` | JSON-line audit log of tool calls |
| `skills/*.toml` | Custom skill definitions |
| `pending_cmd_<session>` | Command prefill buffer |
| `pending_flag_<session>` | Multi-step continuation marker |
| `scrollback_<session>` | Scrollback capture buffer |
| `daemon_<session>.sock` | Daemon Unix socket |
| `update_pending` | Staged self-update metadata |

---

## Development

```bash
cargo fmt -- --check        # format check
cargo clippy --all-targets -- -D warnings  # lint
cargo test                  # full test suite
cargo run -- status         # run local binary
```

`cargo-make` tasks are defined in `Makefile.toml`:

```bash
cargo make test             # lint + test
cargo make quality          # format + lint + test + audit
cargo make quality-full     # + unsafe code audit (geiger)
cargo make release-host     # build release for current platform
cargo make release-matrix   # build for all supported targets
```

### Cross-Compilation

```bash
scripts/release-builds.sh --host-only
scripts/release-builds.sh --targets x86_64-apple-darwin,aarch64-apple-darwin
scripts/release-builds.sh --backend zigbuild
```

Supported targets: macOS (x64/arm64), Linux (x64/arm64/i686/riscv64), FreeBSD (x86/x64).

---

## Troubleshooting

```bash
nsh status                    # inspect session/provider/db state
nsh doctor                    # integrity check + cleanup
nsh config show               # verify config
RUST_LOG=debug nsh query ...  # debug logging
```

API key resolution order: `api_key` in config → `api_key_cmd` → environment variable.

---

## Contributing

Contributions are welcome! Please read the [Contributing Guide](CONTRIBUTING.md) before submitting issues or pull requests. Human-authored PRs are prioritized, but AI-generated contributions that meet the quality bar are also accepted.

---

## License

BSD 3-Clause - see [LICENSE](LICENSE).