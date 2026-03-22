# nsh - The Natural Shell

*Your shell already saw you fail - now it can actually help*

**AI-powered shell assistant for `zsh`, `bash`, `fish`, and PowerShell.**

nsh lives in your terminal. It records command history, understands your project context, reads your scrollback, and turns natural-language requests into shell commands or direct answers - all without leaving your prompt.

```
? why did my last command fail
? set up a python virtualenv for this repo
? fix
```

nsh prefills commands at your prompt for review before execution. It never runs anything blindly (unless you enable autorun mode).

---

## How it works

nsh wraps your shell in a PTY, capturing scrollback and command history into a local SQLite database. When you ask a question with `?`, nsh builds context from your OS, shell, working directory, recent terminal output, project structure, git state, and conversation history, then streams a response from your configured LLM provider.

It responds by calling tools: `command` to prefill a shell command, `chat` for text answers, or any of its other built-in tools for investigation, file editing, web search, memory, and more. It can chain multiple tool calls in a single turn, investigating before acting.

```
you: ? install ripgrep
nsh: [searches history] -> [checks brew availability] -> [prefills command]
     $ brew install ripgrep
     Enter to run . Edit first . Ctrl-C to cancel
```

---

## Features

### Natural language interface

Three aliases, each a single character:

- **`? ...`** - standard query
- **`?? ...`** - reasoning/thinking mode (extended thinking for complex problems)
- **`?! ...`** - private mode (query and response are not saved to history)

Append `!!` to any query to auto-execute the suggested command without confirmation.

### Command prefill

nsh writes suggested commands to your shell's editing buffer. You see the command at your prompt, can edit it, then press Enter to run it - or Ctrl-C to cancel.

Two alternative modes are available via configuration: `confirm` (approve/reject without editing) and `autorun` (execute immediately for safe commands).

### Context awareness

Every query includes context assembled automatically:

- **Terminal scrollback** - recent output from your PTY session, including SSH sessions
- **Command history** - past commands with exit codes, durations, and AI-generated summaries
- **Project detection** - recognizes Rust, Node.js, Python, Go, Ruby, Java, C/C++, Nix, Docker, and Make projects
- **Git state** - current branch, status, and recent commits
- **Cross-TTY context** - optionally includes activity from other open terminal sessions
- **Environment** - OS, architecture, installed package managers, development tools

### Multi-step agent loop

nsh can chain multiple tool calls per query (30 by default, configurable). It investigates before acting - searching history, reading files, running safe commands, querying the web, and asking clarifying questions when needed - then executes and verifies results.

The `pending` flag on command suggestions enables autonomous multi-step sequences. Safe `pending=true` commands auto-execute by default and feed their output back into the same tool loop, so nsh can continue investigating, fixing, and verifying without stopping. If you prefer explicit approval for each intermediate step, set `execution.confirm_intermediate_steps = true`.

### Coding agent

The `code` tool delegates programming tasks to a sandboxed sub-agent that uses a more capable model. The sub-agent can read and write files, search the codebase with grep and glob, and run shell commands (build, test, lint) to verify its work. It operates in its own tool loop with up to 30 iterations.

Use it for writing new code, refactoring, fixing bugs, running tests and fixing failures, debugging, or code reviews. The sub-agent gets the same project context and memory as the main agent.

```
? add pagination to the /users API endpoint
nsh: [launches coding agent] -> [reads existing code] -> [writes changes]
     -> [runs tests] -> [fixes failing test] -> [done]
```

### 26 built-in tools

| Tool | What it does |
|---|---|
| `command` | Prefill a shell command for review |
| `chat` | Text response (status updates, explanations) |
| `done` | End the tool loop with a structured summary |
| `search_history` | FTS5 + regex search across all command history |
| `grep_file` | Regex search within files with context lines |
| `read_file` | Read file contents with line numbers |
| `list_directory` | List directory contents with metadata |
| `glob` | Find files by glob pattern |
| `web_search` | Search the web via Perplexity/Sonar |
| `github` | Fetch READMEs, file trees, or specific files from GitHub repos |
| `run_command` | Execute safe, allowlisted commands silently |
| `ask_user` | Ask a clarifying question while keeping the loop active |
| `code` | Launch a sandboxed coding sub-agent for multi-step file editing |
| `write_file` | Create or overwrite files (with diff preview and trash backup) |
| `patch_file` | Surgical find-and-replace in files (with diff preview) |
| `man_page` | Retrieve man pages for commands |
| `manage_config` | Modify nsh settings (with confirmation) |
| `install_skill` | Create reusable custom tool templates or clone skill repos |
| `uninstall_skill` | Remove installed skills |
| `install_mcp_server` | Add MCP tool servers to configuration |
| `skill_exists` | Check if a skill is already installed |
| `search_memory` | Search across all memory tiers |
| `core_memory_append` | Append to core memory blocks |
| `core_memory_rewrite` | Rewrite core memory blocks |
| `store_memory` | Store entries in semantic, procedural, resource, or knowledge memory |
| `retrieve_secret` | Retrieve encrypted secrets from the knowledge vault |

### Entity-aware history search

nsh extracts structured entities (hostnames, IPs) from commands and stores them in a searchable index:

```
you: ? what servers have I ssh'd into recently
nsh: Recent machine targets for `ssh` (most recent first):
     - [2026-02-11T17:49:15Z] 135.181.128.145 (via ssh)
     - [2026-02-11T17:47:15Z] ssh.phx.nearlyfreespeech.net (via ssh)
```

### Security

- **Secret redaction** - over 100 built-in patterns detect and redact API keys, tokens, private keys, JWTs, database URLs, and more before sending context to the LLM. Custom patterns can be added.
- **Command risk assessment** - every suggested command is classified as `safe`, `elevated`, or `dangerous`. Dangerous commands (recursive deletion of system paths, disk formatting, fork bombs, piping remote scripts to shell) always require explicit `yes` confirmation.
- **Sensitive directory blocking** - reads and writes to `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.docker`, and similar directories are blocked by default.
- **Tool output sandboxing** - tool results are delimited by random boundary tokens and treated as untrusted data. Prompt injection attempts in tool output are filtered.
- **Protected settings** - security-critical configuration keys (API keys, allowlists, redaction settings) cannot be modified by the AI.
- **Audit logging** - all tool calls are logged to `~/.nsh/audit.log` with automatic rotation.

### Persistent memory

nsh has a 6-tier memory system inspired by the MIRIX architecture. Before every query, it retrieves relevant long-term memories and injects them as structured XML into the system prompt.

The six tiers:

- **Core** - three fixed blocks (user facts, agent persona, environment). Always loaded into context.
- **Episodic** - timestamped events: command executions, errors, instructions, file edits. Decays over time.
- **Semantic** - facts extracted from episodes via LLM reflection. Things like "user builds with cargo" or "production database is on port 5433."
- **Procedural** - step-by-step workflows with trigger patterns. Matched when your query resembles the trigger.
- **Resource** - digests of important files and documentation, with content hashing to avoid re-ingestion.
- **Knowledge Vault** - encrypted storage for secrets (AES-256-GCM). The LLM only ever sees captions, never the actual values.

The system runs an automatic lifecycle: ingestion buffers shell events, a classifier filters low-signal commands, a router categorizes what remains, and a consolidator deduplicates with Jaro-Winkler similarity. Periodically, episodic memories are promoted to semantic facts via LLM reflection, and old entries decay.

```bash
nsh memory search "cargo build"             # search all tiers
nsh memory search --type semantic "build"   # search a specific tier
nsh memory stats                            # counts per tier
nsh memory core                             # view core memory blocks
nsh memory maintain                         # run decay + reflection now
nsh memory bootstrap                        # initial scan of existing history
nsh memory clear                            # wipe all memories
nsh memory clear --type episodic            # wipe a specific tier
nsh memory export                           # export all memories as JSON
nsh memory decay                            # run decay only
nsh memory reflect                          # run reflection only
```

Control memory behavior in config:

```bash
# Pause recording (incognito mode)
nsh config edit   # set memory.incognito = true
```

### Remote access and mobile companion

nsh supports P2P remote access using [iroh](https://iroh.computer), allowing you to connect to your shell sessions from a mobile device or another machine.

**Pairing.** Run `nsh remote pair` on your desktop. This generates a keypair (stored in `~/.nsh/remote_key`) and displays a QR code containing your endpoint ID and relay URL. Scan the QR code with the mobile app or enter the endpoint ID manually.

The desktop shows a connection request with a 6-digit SAS verification code (derived from a SHA256 hash of the connecting device's endpoint ID). Confirm the code matches, and the device is added to your allowed keys list.

**Security model.** Connections are end-to-end encrypted over QUIC. Unknown peers are rejected at the QUIC layer before any protocol handling begins. Each connection is also verified against the allowed keys list at the handler level. Device revocation is immediate via `nsh remote revoke`.

**LAN discovery.** `nsh remote discover` advertises your instance via mDNS on the local network, so the mobile app can find it without scanning a QR code. SAS verification still applies.

```bash
nsh remote pair              # show QR code for mobile pairing
nsh remote status            # endpoint ID, relay, connected peers, allowed keys
nsh remote revoke <id>       # remove a paired device (prefix match)
nsh remote discover          # LAN discovery via mDNS
```

### Mobile app

The companion app (in `mobile/`) is built with Tauri 2, TypeScript, and xterm.js. It connects to your desktop's nsh daemon over iroh P2P.

What it does:

- **Session list** - see all active shell sessions with their shell type, TTY, PID, working directory, and git branch
- **Terminal access** - full terminal emulator (xterm.js with WebGL rendering). Keyboard input goes over a QUIC send stream; terminal output comes back on a receive stream. Resize events are forwarded to the shim.
- **Command history** - per-session history viewer showing each command's exit code, working directory, duration, and output preview
- **Notifications** - command completion, error alerts (non-zero exit), and input prompts (password/confirmation requests)

The app has four views: pairing (QR scanner + manual ID entry), sessions (list with inline history), terminal (full screen with back/reconnect), and history (scrollable command log).

### MCP integration

nsh works with MCP (Model Context Protocol) in both directions.

**As a client:** nsh can connect to external MCP servers to gain new tools. Both stdio (local process) and HTTP (remote endpoint) transports are supported. Tool filtering and renaming are available.

```toml
[mcp.servers.filesystem]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"]

[mcp.servers.remote_api]
transport = "http"
url = "https://mcp.example.com"
headers = { Authorization = "Bearer ..." }
```

Advanced HTTP config:

```toml
[mcp.servers.cloudflare]
transport = "http"
url = "https://mcp.cloudflare.com/jsonrpc"
bearer_token = "$CF_API_TOKEN"     # expands from env
timeout_seconds = 30

[mcp.servers.cloudflare.headers]
X-Client = "nsh"

# Tool filtering
disable_tools = ["legacy_", "danger_"]

[mcp.servers.cloudflare.rename_tools]
inject_data = "cf_inject_data"
```

**As a server:** `nsh mcp-serve` runs nsh as a JSON-RPC 2.0 MCP server over stdio, exposing a restricted subset of tools to external clients like Claude Desktop, Cursor, VS Code Copilot, or Windsurf. The exposed tools are: `search_history`, `search_memory`, `read_file`, `grep_file`, `list_directory`, `glob`, `man_page`, `skill_exists`, and `run_command`.

### Custom skills

Skills are reusable tools exposed to the model. nsh supports two flavors:

**Command-template skills** run a shell command with parameter substitution:

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

**Code-based skills** run an inline script with a runtime. Parameters arrive as JSON via stdin and the `NSH_SKILL_PARAMS_JSON` environment variable:

```toml
# ~/.nsh/skills/humanize.toml
name = "humanize"
description = "Format paths or listings more readably"
runtime = "python3"
script = '''
import os, sys, json
params = json.loads(sys.stdin.read() or os.environ.get("NSH_SKILL_PARAMS_JSON","{}"))
text = params.get("text", "")
print(text.replace("/", " -> "))
'''
timeout_seconds = 15

[parameters.text]
type = "string"
description = "Text to humanize"
```

Skills appear as tools in the LLM's toolkit and can be invoked naturally:

```
you: ? deploy to staging
nsh: [calls skill_deploy with environment=staging]
```

Notes:
- Project-local skills live in `./.nsh/skills/` and require a one-time approval per run.
- Either `command` or both `runtime`+`script` must be present.
- Parameters are validated for safe characters in command-template mode.
- Markdown-based skills (`SKILL.md`, `skill.md`, or `README.md` in subdirectories) are also supported.
- Skills from other AI ecosystems (Claude Code, LangChain, OpenAI Agents, Cursor) work too - clone the repo and nsh reads the skill documents directly.

Installing from a git repo:

```bash
nsh tools install_skill --repo https://github.com/owner/skill-repo.git
```

Repos are cloned into `~/.nsh/skills/<repo>/` and auto-discovered if they contain `skill.toml`, `nsh.toml`, `SKILL.md`, or `README.md` at the repo root.

### Multiple LLM providers

nsh works with any OpenAI-compatible API. Built-in provider support:

- **OpenRouter** (default) - access to hundreds of models
- **Anthropic** - Claude models with prompt caching
- **OpenAI** - GPT models
- **Google Gemini** - Gemini models
- **Ollama** - local models

Model chains with automatic fallback on rate limits or errors:

```toml
[models]
main = ["google/gemini-2.5-flash", "anthropic/claude-sonnet-4.6"]
fast = ["google/gemini-2.5-flash-lite", "anthropic/claude-haiku-4.5"]
```

### CLIProxyAPI sidecar

nsh can route queries through subscription-based providers (Copilot, Kiro, Claude, Codex, and others) via a local OpenAI-compatible sidecar proxy. The daemon manages the sidecar lifecycle: downloading the binary, starting it on a random port, running health checks, and auto-updating from GitHub releases.

```bash
nsh cli-proxy ensure        # start the sidecar if not running
nsh cli-proxy status        # running state, port, version, pid
nsh cli-proxy restart       # restart the sidecar
nsh cli-proxy check-updates # trigger an immediate update check
```

The daemon also checks for sidecar updates hourly and restarts it when one is applied.

### Additional features

- **Interactive chat mode** - `nsh chat` for a REPL-style conversation
- **Auto-configure wizard** - `nsh autoconfigure` scans for API keys in your environment and configures nsh automatically. `nsh autoconfigure --interactive` walks you through provider selection, OAuth login for subscription providers, and execution mode choice.
- **Shell history import** - automatically imports existing bash, zsh, fish, and PowerShell history on first run
- **Cost tracking** - `nsh cost` shows token usage and estimated costs by model
- **JSON output mode** - `nsh query --json` for structured event stream output
- **Conversation export** - `nsh export` in markdown or JSON format
- **Self-update** - `nsh update` downloads and verifies new releases via DNS TXT records and SHA256
- **Shell completions** - `nsh completions zsh|bash|fish` generates completion scripts
- **Project-local config** - `.nsh.toml` or `.nsh/config.toml` for per-project overrides (restricted to `context` and `display` sections)
- **Custom instructions** - global via `~/.nsh/instructions.md` or per-project via `.nsh/instructions.md`
- **Hot-reloading config** - changes to `config.toml` take effect on the next query
- **Session labels** - `nsh session label "my project work"` to tag sessions
- **Redact next** - `nsh redact-next` skips capturing the next command's output

---

## Requirements

- **Rust 1.85+** (edition 2024) - for building from source
- **macOS, Linux, FreeBSD, or Windows**
- **zsh, bash, fish, or PowerShell**
- At least one LLM provider API key (OpenRouter is the default)

---

## Installation

### Option 1: Unix / WSL / MSYS installer

```bash
curl -fsSL https://nsh.tools/install.sh | bash
```

Use this on macOS, Linux, FreeBSD, WSL, and MSYS/Git Bash environments.

### Option 2: Native Windows PowerShell installer

```powershell
iwr -useb https://nsh.tools/install.ps1 | iex
```

Use this on native Windows PowerShell (not WSL/MSYS).

### Option 3: Build from source

```bash
git clone https://github.com/fluffypony/nsh.git
cd nsh
# Installs both binaries: nsh (shim) and nsh-core
cargo install --path . --locked
```

### Option 4: Local release binary

```bash
cargo build --release
# Binaries at target/release/: nsh (shim), nsh-core (core)
```

### Shim/core split

nsh ships as two binaries:

- `nsh` -- the stable shim. It handles `nsh wrap` directly so your long-lived terminal session uses frozen, stable PTY code. For all other commands, it resolves and `exec`s the latest `nsh-core` at `~/.nsh/bin/nsh-core`.
- `nsh-core` -- the full implementation. This is what updates frequently.

Installers place the shim once into your cargo bin if it's missing, and always update `~/.nsh/bin/nsh-core`. During an update, existing terminals do not need to restart. The next `nsh` invocation transparently runs the new core.

Daemon restarts are graceful: `nsh` signals SIGHUP to the daemon, which drains existing connections with a short timeout and re-execs itself using the latest core.

---

## Quick start

### 1. Configure a provider

Run the auto-configure wizard:

```bash
nsh autoconfigure --interactive
```

Or create `~/.nsh/config.toml` manually:

```toml
[provider]
default = "openrouter"
model = "google/gemini-2.5-flash"

[provider.openrouter]
api_key = "sk-or-v1-..."
# or: api_key_cmd = "op read 'op://Vault/OpenRouter/credential'"
```

Environment variable fallback is supported: `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`.

### 2. Enable shell integration

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

### 3. Use it

```bash
? why did my last command fail
?? set up a python virtualenv for this repo
?! what is the safest way to clean docker images
? install ripgrep
? fix         # after a failed command
? ignore      # suppress hint for the last exit code
```

---

## Query modes

| Alias | Mode | Description |
|---|---|---|
| `? ...` | Normal | Standard query |
| `?? ...` | Reasoning | Extended thinking (`--think`) |
| `?! ...` | Private | No query/response history writes |
| `? ignore [code]` | Suppress | Disable failure hints for an exit code |

---

## CLI reference

### User commands

| Command | What it does |
|---|---|
| `nsh init <shell>` | Print shell integration script |
| `nsh wrap [--shell <path>]` | Run shell inside PTY wrapper |
| `nsh query [--think] [--private] [--json] <words...>` | Ask the assistant |
| `nsh chat` | Interactive REPL chat mode |
| `nsh history search <query> [--limit N]` | Full-text search command history |
| `nsh status` | Show runtime state, sidecar status, and last update check |
| `nsh doctor [capture] [--no-prune] [--no-vacuum] [--prune-days D]` | DB integrity check or capture-health diagnostic |
| `nsh config [path\|show\|edit]` | View or edit configuration |
| `nsh reset` | Clear session conversation context |
| `nsh cost [today\|week\|month\|all]` | Usage and cost summary |
| `nsh export [--format markdown\|json] [--session ID]` | Export conversation history |
| `nsh provider list-local` | List local Ollama models |
| `nsh autoconfigure [--interactive]` | Auto-detect API keys and configure |
| `nsh update` | Download and verify latest release |
| `nsh redact-next` | Skip capture for the next command |
| `nsh completions <shell>` | Generate shell completion script |
| `nsh restart` | Restart the nsh daemon |

### Memory commands

| Command | What it does |
|---|---|
| `nsh memory search <query> [--type T] [--limit N]` | Search across memory tiers |
| `nsh memory stats` | Show counts per tier |
| `nsh memory core` | View core memory blocks |
| `nsh memory maintain` | Run decay + reflection |
| `nsh memory bootstrap` | Initial scan of existing history |
| `nsh memory decay` | Run decay only |
| `nsh memory reflect` | Run reflection only |
| `nsh memory clear [--type T]` | Clear memories (all or by type) |
| `nsh memory export` | Export all memories as JSON |
| `nsh memory telemetry` | Show maintenance stats |

### Remote commands

| Command | What it does |
|---|---|
| `nsh remote pair` | Show QR code for mobile pairing |
| `nsh remote status` | Endpoint ID, relay, connected peers, allowed keys |
| `nsh remote revoke <id>` | Remove a paired device (prefix match) |
| `nsh remote discover` | LAN discovery via mDNS |

### Sidecar commands

| Command | What it does |
|---|---|
| `nsh cli-proxy ensure` | Start the sidecar if not running |
| `nsh cli-proxy status` | Running state, port, version, pid |
| `nsh cli-proxy restart` | Restart the sidecar |
| `nsh cli-proxy check-updates` | Trigger an immediate update check |

### Internal commands

| Command | What it does |
|---|---|
| `nsh record ...` | Command capture hook endpoint |
| `nsh session start\|end\|label ...` | Session lifecycle management |
| `nsh heartbeat --session ID` | Keep session alive |
| `nsh daemon-send ...` | Send request to daemon |
| `nsh daemon-read ...` | Read daemon capture/scrollback |
| `nsh mcp-serve` | Run as MCP server over stdio |

---

## Configuration

Main config: `~/.nsh/config.toml`

Project-local overrides: `.nsh.toml` or `.nsh/config.toml` (restricted to `context` and `display` sections).

### Full default configuration

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

[memory]
# incognito = true  # pause memory recording

[remote]
# enabled = true
# allowed_keys = []  # paired device EndpointIds

[mcp]
# [mcp.servers.example]
# transport = "stdio"
# command = "npx"
# args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
# env = { EXAMPLE = "1" }
# timeout_seconds = 30
```

### Protected settings

These cannot be modified by the AI via `manage_config`:

- `execution.allow_unsafe_autorun`
- `tools.sensitive_file_access`
- `tools.run_command_allowlist`
- `redaction.enabled` / `redaction.disable_builtin`
- Any `api_key`, `api_key_cmd`, or `base_url` field

---

## Data and runtime files

All data is stored in `~/.nsh/`:

| File | What it is |
|---|---|
| `config.toml` | User configuration |
| `nsh.db` | SQLite database (sessions, commands, conversations, usage, memory) |
| `audit.log` | JSON-line audit log of tool calls |
| `skills/*.toml` | Custom skill definitions |
| `remote_key` | iroh P2P keypair for remote access |
| `vault.key` | AES-256-GCM key for the knowledge vault |
| `pending_<session>.json` | Atomic command prefill payload |
| `scrollback_<session>` | Scrollback capture buffer |
| `daemon_<session>.sock` | Daemon Unix socket |
| `bin/nsh-core` | Latest core binary |
| `bin/cliproxyapi` | CLIProxyAPI sidecar binary |
| `update_pending` | Staged self-update metadata |

---

## Architecture

nsh runs as two processes plus an optional background daemon:

- **`nsh` (shim)** - the stable PTY wrapper binary. It handles `nsh wrap` (which persists for the terminal session lifetime) and forwards all other commands to `nsh-core`. This binary changes rarely so your terminal sessions don't need restarting after updates.

- **`nsh-core`** - the full implementation. Handles queries, tools, memory, configuration, and everything else. Updated frequently.

- **`nshd` (daemon)** - a background process that manages the SQLite database, memory processing, sidecar lifecycle, and the iroh P2P endpoint for remote access. It uses separate reader/writer threads for SQLite, a dedicated thread for LLM-driven memory operations, and Unix socket IPC with UID verification. The daemon starts automatically and shuts down after an idle timeout.

---

## Development

```bash
cargo fmt -- --check                       # format check
cargo clippy --all-targets -- -D warnings  # lint
cargo test                                 # full test suite
cargo run --bin nsh -- status              # run shim
cargo run --bin nsh-core -- status         # run core directly
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

### Mobile app

The mobile app lives in `mobile/` and uses Tauri 2 with a vanilla TypeScript + xterm frontend.

#### Prerequisites

```bash
cargo install tauri-cli
cd mobile && npm install
```

iOS builds require Xcode and the iOS SDK. Android builds require the Android SDK and NDK.

#### Development (desktop window)

```bash
npm run tauri dev
```

#### iOS

```bash
npm run tauri ios init      # one-time setup
npm run tauri ios dev       # run on simulator
npm run tauri ios build     # release build
```

#### Android

```bash
npm run tauri android init  # one-time setup
npm run tauri android dev   # run on emulator
npm run tauri android build # release build
```

### Cross-compilation

```bash
scripts/release-builds.sh --host-only
scripts/release-builds.sh --targets x86_64-apple-darwin,aarch64-apple-darwin
scripts/release-builds.sh --backend zigbuild
```

Supported targets: macOS (x64/arm64), Linux (x64/arm64/i686/riscv64), FreeBSD (x86/x64), Windows (x64/aarch64).

### Release publishing

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
nsh doctor                    # integrity check + cleanup
nsh doctor capture            # verify whether per-command output capture is active
nsh config show               # verify config
RUST_LOG=debug nsh query ...  # debug logging
```

`nsh status` output includes sidecar and remote info when the daemon is running:

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

API key resolution order: `api_key` in config -> `api_key_cmd` -> environment variable.

---

## Contributing

Contributions are welcome. Please read the [Contributing Guide](CONTRIBUTING.md) before submitting issues or pull requests.

---

## License

BSD 3-Clause - see [LICENSE](LICENSE).
