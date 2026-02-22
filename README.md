# nsh - Natural Shell

**AI-powered shell assistant for `zsh`, `bash`, `fish`, and PowerShell.**

nsh lives in your terminal. It records command history, understands your project context, reads your scrollback, and turns natural-language requests into shell commands or direct answers - all without leaving your prompt.

```
? why did my last command fail
? set up a python virtualenv for this repo
? fix
```

nsh prefills commands at your prompt for review before execution. It never runs anything blindly (unless you enable the autorun mode!)

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

nsh can chain multiple tool calls per query (30 by default, configurable). It investigates before acting - searching history, reading files, running safe commands, querying the web, and asking clarifying questions when needed - then executes and verifies results.

The `pending` flag on command suggestions enables autonomous multi-step sequences. Safe `pending=true` commands now auto-execute by default and feed their output back into the same tool loop, so nsh can continue investigating, fixing, and verifying without stopping. If you prefer explicit approval for each intermediate step, set `execution.confirm_intermediate_steps = true`.

### 18 Built-In Tools

| Tool | Purpose |
|---|---|
| `command` | Prefill a shell command for review |
| `chat` | Final text response when work is complete or purely informational |
| `search_history` | FTS5 + regex search across all command history |
| `grep_file` | Regex search within files with context lines |
| `read_file` | Read file contents with line numbers |
| `list_directory` | List directory contents with metadata |
| `web_search` | Search the web via Perplexity/Sonar |
| `run_command` | Execute safe, allowlisted commands silently |
| `ask_user` | Clarify ambiguity or gather preferences while keeping the loop active |
| `write_file` | Create or overwrite files (with diff preview and trash backup) |
| `patch_file` | Surgical find-and-replace in files (with diff preview) |
| `man_page` | Retrieve man pages for commands |
| `manage_config` | Modify nsh settings (with confirmation) |
| `install_skill` | Create reusable custom tool templates |
| `install_mcp_server` | Add MCP tool servers to configuration |

 

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
main = ["google/gemini-2.5-flash", "anthropic/claude-sonnet-4.6"]
fast = ["google/gemini-2.5-flash-lite", "anthropic/claude-haiku-4.5"]
```

### Additional Features

- **Interactive chat mode** - `nsh chat` for a REPL-style conversation
- **Shell history import** - automatically imports existing bash, zsh, fish, and PowerShell history on first run
- **Cost tracking** - `nsh cost` shows token usage and estimated costs by model
- **JSON output mode** - `nsh query --json` for structured event stream output
- **Conversation export** - `nsh export` in markdown or JSON format
- **Self-update** - `nsh update` downloads and verifies new releases via DNS TXT records and SHA256
- **Shell completions** - `nsh completions zsh|bash|fish` generates completion scripts
- **Project-local config** - `.nsh.toml` or `.nsh/config.toml` for per-project overrides (restricted to `context` and `display` sections)
- **Custom instructions** - global via config or per-project via `.nsh/instructions.md`
- **Hot-reloading config** - changes to `config.toml` take effect on the next query

### Persistent Memory

Before every query, nsh retrieves relevant long-term memories and injects a structured XML prompt into the system prompt under a "PERSISTENT MEMORY" section. This includes:

- Core memory: user facts, agent persona, environment. Always included.
- Episodic: recent and relevant events (commands, errors, interactions).
- Semantic: facts about projects, tools, preferences.
- Procedural: step-by-step workflows.
- Resource: digests of files/docs.
- Knowledge Vault: captions of sensitive secrets (encrypted values are never shown).

Control memory behavior:

```bash
# Enable incognito mode (skip recording)
nsh config set memory.incognito true

# Re-enable recording
nsh config set memory.incognito false

# Run maintenance (decay + reflection)
nsh memory maintain

# Search memories
nsh memory search --type semantic "cargo build"

# Inspect core memory
nsh memory core
```

The memory prompt is redacted for secrets before inclusion.

---

## Requirements

- **Rust 1.85+** (edition 2024) - for building from source
- **macOS, Linux, FreeBSD, or Windows**
- **zsh, bash, fish, or PowerShell**
- At least one LLM provider API key (OpenRouter is the default)

---

## Installation

### Option 1: Unix / WSL / MSYS Installer

```bash
curl -fsSL https://nsh.tools/install.sh | bash
```

Use this on macOS, Linux, FreeBSD, WSL, and MSYS/Git Bash environments.

### Option 2: Native Windows PowerShell Installer

```powershell
iwr -useb https://nsh.tools/install.ps1 | iex
```

Use this on native Windows PowerShell (not WSL/MSYS).

### Option 3: Build from Source

```bash
git clone https://github.com/fluffypony/nsh.git
cd nsh
# Installs both binaries: nsh (shim) and nsh-core
cargo install --path . --locked
```

### Option 4: Local Release Binary

```bash
cargo build --release
# Binaries at target/release/: nsh (shim), nsh-core (core)
```

### Shim/Core Split

nsh ships as two binaries:

- `nsh` — the stable shim. It handles `nsh wrap` directly so your long-lived terminal session uses frozen, stable PTY code. For all other commands, it resolves and `exec`s the latest `nsh-core` at `~/.nsh/bin/nsh-core`.
- `nsh-core` — the full implementation binary. This is what updates frequently.

Installers place the shim once into your cargo bin if it’s missing, and always update `~/.nsh/bin/nsh-core`. During an update, existing terminals do not need to restart. The next `nsh` invocation transparently runs the new core.

Daemon restarts are graceful: `nsh` signals SIGHUP to the daemon, which drains existing connections with a short timeout and re-execs itself using the latest core.

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

# PowerShell profile ($PROFILE)
Invoke-Expression (nsh init powershell)
```

`nsh wrap` runs your shell inside a PTY wrapper for scrollback capture. It's optional but recommended. The PTY wrapper lives in the stable `nsh` shim, so it never needs to be restarted for updates.

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
| `nsh status` | Show runtime state (includes sidecar status and last update check) |
| `nsh doctor [capture] [--no-prune] [--no-vacuum] [--prune-days D]` | DB integrity check or capture-health diagnostic |
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
fallback_model = "anthropic/claude-sonnet-4.6"
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
  "anthropic/claude-sonnet-4.6",
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
max_tool_iterations = 30
confirm_intermediate_steps = false

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
| `nsh.db` | SQLite database (sessions, commands, conversations, usage) |
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
cargo fmt -- --check                    # format check
cargo clippy --all-targets -- -D warnings  # lint
cargo test                              # full test suite
cargo run --bin nsh -- status           # run shim
cargo run --bin nsh-core -- status      # run core directly
```

`cargo-make` tasks are defined in `Makefile.toml`:

```bash
cargo make test             # lint + test
cargo make quality          # format + lint + test + audit
cargo make quality-full     # + unsafe code audit (geiger)
cargo make release-host     # build release for current platform
cargo make release-matrix   # build for all supported targets
cargo make sync-site-install # copy install scripts -> ../nsh-site/
```

### Cross-Compilation

```bash
scripts/release-builds.sh --host-only
scripts/release-builds.sh --targets x86_64-apple-darwin,aarch64-apple-darwin
scripts/release-builds.sh --backend zigbuild
```

Supported targets: macOS (x64/arm64), Linux (x64/arm64/i686/riscv64), FreeBSD (x86/x64), Windows (x64/aarch64).

### Release Publishing

1. Sync the installer script to the website repo:

```bash
cargo make sync-site-install
# or: cargo make sync-site-install-watch
```

2. Build release artifacts:

```bash
# Builds per-target archives containing both binaries:
#   - nsh         (core binary used by auto-update)
#   - nsh-shim    (shim; installed once if missing)
scripts/release-builds.sh --version 1.0.0
```

3. Create a GitHub release and upload `dist/*` artifacts:

```bash
gh release create v1.0.0 dist/nsh-*.tar.gz dist/nsh-*.tar.gz.sha256 \
  --title "nsh v1.0.0" --notes "nsh v1.0.0"
```

4. Publish updater DNS TXT records for `update.nsh.tools` from `dist/update-records.txt`:

```text
1.0.0:x86_64-unknown-linux-gnu:<sha256-of-core-binary>
1.0.0:aarch64-unknown-linux-gnu:<sha256-of-core-binary>
...
```

Use one TXT record per target line.

---

## Troubleshooting

```bash
nsh status                    # inspect session/provider/db state

When the global daemon is running, `nsh status` also reports the CLIProxyAPI sidecar state and update info:

```
$ nsh status
  Version:    0.9.2
  Session:    7YQ2GNRQ
  Shell:      /bin/zsh
  PTY active: yes
  Global daemon: running
  Sidecar:    running on :8317 (6.6.80)
  Updates:    last_check=2026-02-22T12:00:03Z (2h ago) status=up_to_date
  Provider:   openrouter
  Model:      google/gemini-2.5-flash
  DB path:    /Users/alice/.nsh/nsh.db
  DB size:    8.4 MB
```
nsh doctor                    # integrity check + cleanup
nsh doctor capture            # verify whether per-command output capture is active
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
### Sidecar Management

The local CLIProxyAPI sidecar is managed by the daemon and used to route subscription providers through a local OpenAI-compatible endpoint.

Common operations:

```
nsh cliproxy ensure        # start the sidecar if not running
nsh cliproxy status        # JSON-style status: running, port, version, pid
nsh cliproxy restart       # restart the sidecar
nsh cliproxy check-updates # trigger an immediate update check
```

The daemon also checks for sidecar updates hourly and restarts it if an update is applied.
