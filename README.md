# nsh - Natural Shell

AI-powered shell assistant for `zsh`, `bash`, and `fish`.

`nsh` sits in your terminal loop: it records command history, understands your active
project context, and turns natural-language requests into either:

- a prefilled shell command for you to review, or
- a direct chat response when no command is needed.

It can investigate with built-in tools (history search, file reads, safe command execution,
web search, config editing, memory, MCP servers, and more) before deciding what to do.

## Highlights

- Natural-language aliases: `?`, `??`, and `?!`
- Command prefill workflow (no blind auto-execution by default)
- Multi-step agent loop with tool calling and follow-up actions
- SQLite-backed command/session/conversation history with FTS5 search
- Cross-session context from other active TTYs (optional)
- PTY capture mode for scrollback-aware assistance
- Secret redaction before model calls
- Multiple providers: `openrouter`, `anthropic`, `openai`, `ollama`, `gemini`
- Built-in self-update flow with SHA256 verification

## Requirements

- Rust 1.85+ (edition 2024)
- macOS or Linux
- `zsh`, `bash`, or `fish`
- At least one model provider configured (OpenRouter is the default path)

## Installation

### Option 1: Install script

```bash
curl -fsSL https://raw.githubusercontent.com/fluffypony/nsh/main/install.sh | bash
```

### Option 2: Build/install from source

```bash
cargo install --path . --locked
```

### Option 3: Build local release binary

```bash
cargo build --release
# target/release/nsh
```

## Quick Start

### 1) Configure a provider

Create `~/.nsh/config.toml`:

```toml
[provider]
default = "openrouter"
model = "google/gemini-2.5-flash"

[provider.openrouter]
api_key = "sk-or-v1-..."
# or: api_key_cmd = "op read 'op://Vault/OpenRouter/credential'"
```

Environment variable fallback is also supported:

- `OPENROUTER_API_KEY`
- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `GEMINI_API_KEY`

### 2) Enable shell integration

Add one line to your shell rc file:

```bash
# zsh
command -v nsh >/dev/null && [[ -z "${NSH_PTY_ACTIVE:-}" ]] && nsh wrap
eval "$(nsh init zsh)"

# bash
command -v nsh >/dev/null && [[ -z "${NSH_PTY_ACTIVE:-}" ]] && nsh wrap
eval "$(nsh init bash)"

# fish
command -v nsh >/dev/null; and not set -q NSH_PTY_ACTIVE; and nsh wrap
nsh init fish | source
```

`nsh wrap` is optional but recommended for scrollback-aware behavior.

### 3) Start using it

```bash
? why did my last command fail
?? set up a python virtualenv for this repo
?! what is the safest way to clean docker images
```

## Query Modes

- `? ...`: normal mode
- `?? ...`: reasoning mode (`--think`)
- `?! ...`: private mode (`--private`, avoids query/response history writes)
- `? ignore [exit_code]`: suppress failure hints for the last failed code (or a specific code)
- `nsh query --json ...`: JSON event stream output

Example JSON mode output includes event lines like:

```json
{"type":"private_mode","enabled":true}
{"type":"tool_start","name":"chat"}
{"type":"tool_end","name":"chat"}
{"type":"done"}
{"type":"chat","response":"..."}
```

## CLI Reference

### User-facing commands

| Command | Purpose |
|---|---|
| `nsh init <shell>` | Print shell integration script (`zsh`, `bash`, `fish`) |
| `nsh wrap [--shell <path>]` | Run your shell inside nsh PTY wrapper |
| `nsh query [--think] [--private] [--json] <words...>` | Ask the assistant |
| `nsh chat` | Interactive REPL chat mode |
| `nsh history search <query> [--limit N]` | Search command history |
| `nsh status` | Show current nsh runtime state |
| `nsh doctor [--no-prune] [--no-vacuum] [--prune-days D]` | DB integrity and cleanup |
| `nsh config [path|show|edit]` | Config path/view/edit |
| `nsh reset` | Clear current session conversation context |
| `nsh cost [today|week|month|all]` | Usage and cost summary |
| `nsh export [--format markdown|json] [--session ID]` | Export conversation history |
| `nsh provider list-local` | List local Ollama models |
| `nsh update` | Download and stage latest verified binary update |
| `nsh redact-next` | Skip capture for the next command |
| `nsh completions <shell>` | Emit shell completion script |

### Hook/daemon/internal commands

| Command | Purpose |
|---|---|
| `nsh record ...` | Command capture hook endpoint |
| `nsh session start|end|label ...` | Session lifecycle |
| `nsh heartbeat --session ID` | Keep session alive |
| `nsh daemon-send ...` | Send request to daemon |
| `nsh daemon-read ...` | Read daemon capture/scrollback |

## Configuration

Main config file: `~/.nsh/config.toml`

Project-local overrides are supported from either:

- `.nsh.toml`
- `.nsh/config.toml`

Project config is intentionally restricted to `context` and `display` sections only.

### Full default config (reference)

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
# api_key_cmd = "..."
# base_url = "..."

[provider.openai]
# api_key = "..."
# api_key_cmd = "..."
# base_url = "..."

[provider.ollama]
# base_url = "http://localhost:11434"

[provider.gemini]
# api_key = "..."
# api_key_cmd = "..."
# base_url = "..."

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
  "uname",
  "which",
  "wc",
  "file",
  "stat",
  "ls",
  "echo",
  "whoami",
  "hostname",
  "date",
  "env",
  "printenv",
  "id",
  "df",
  "free",
  "python3 --version",
  "node --version",
  "git status",
  "git branch",
  "git log",
  "git diff",
  "pip list",
  "cargo --version",
]
sensitive_file_access = "block" # block | ask | allow

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
patterns = [] # add custom regex patterns if needed

[capture]
mode = "vt100"
alt_screen = "drop" # drop | snapshot

[db]
busy_timeout_ms = 10000

[execution]
mode = "prefill" # prefill | confirm | autorun
allow_unsafe_autorun = false

[mcp]
# [mcp.servers.example]
# transport = "stdio" # or "http"
# command = "npx"
# args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
# env = { EXAMPLE = "1" }
# timeout_seconds = 30
# or for http:
# url = "https://mcp.example.com"
# headers = { Authorization = "Bearer ..." }
```

### Protected settings

The assistant cannot change these via `manage_config` tool:

- `execution.allow_unsafe_autorun`
- `tools.sensitive_file_access`
- `tools.run_command_allowlist`
- `redaction.enabled`
- `redaction.disable_builtin`
- any key segment named `api_key`, `api_key_cmd`, or `base_url`

## Built-in Tool Catalog (LLM side)

`nsh` exposes 18 built-in tools to the model:

1. `command`
2. `chat`
3. `search_history`
4. `grep_file`
5. `read_file`
6. `list_directory`
7. `web_search`
8. `run_command`
9. `ask_user`
10. `write_file`
11. `patch_file`
12. `man_page`
13. `manage_config`
14. `install_skill`
15. `install_mcp_server`
16. `remember`
17. `forget_memory`
18. `update_memory`

Custom skills and MCP tools are added on top of these.

## Data and Runtime Files

Default location: `~/.nsh/`

- `config.toml` - user config
- `nsh.db` - SQLite database
- `pending_cmd_<session>` - command prefill file
- `pending_flag_<session>` - pending multi-step continuation marker
- `scrollback_<session>` - scrollback/capture buffers
- `update_pending` / `updates/` - staged self-update files

DB includes tables for `sessions`, `commands`, `commands_fts`, `conversations`,
`usage`, `audit_log`, `memories`, and `meta`.

## Live Smoke Test Checklist

Useful pre-release checks in your real shell environment:

```bash
# status + DB health
target/debug/nsh status
target/debug/nsh doctor --no-prune --no-vacuum

# session flow
SESSION="release-smoke-$$"
target/debug/nsh session start --session "$SESSION" --tty "$(tty)" --shell "$SHELL" --pid $$
target/debug/nsh heartbeat --session "$SESSION"
target/debug/nsh record --session "$SESSION" --command "echo release-smoke" --cwd "$PWD" --exit-code 0 --started-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --tty "$(tty)" --pid $$ --shell "$(basename "$SHELL")"
target/debug/nsh history search "release-smoke" --limit 3
target/debug/nsh session end --session "$SESSION"

# provider reachability (private)
target/debug/nsh query --private "respond with exactly release_smoke_ok"
```

## Release Builds and Cross-Compilation

Use the release build helper:

```bash
# host artifact only
scripts/release-builds.sh --host-only

# default matrix (macOS x64/arm64, FreeBSD x86/x64, Linux x86/x64/arm64/riscv64)
scripts/release-builds.sh

# explicit targets
scripts/release-builds.sh --targets x86_64-apple-darwin,aarch64-apple-darwin

# force backend (auto | cargo | cross | zigbuild)
scripts/release-builds.sh --backend cross
```

The script outputs:

- `dist/nsh-<target>.tar.gz`
- `dist/nsh-<target>.tar.gz.sha256`
- `dist/update-records.txt` (lines: `<version>:<target>:<binary_sha256>`)

`update-records.txt` is intended for `update.nsh.tools` DNS TXT entries used by
`nsh update` verification.

### Cross-build prerequisites on macOS

For non-macOS targets from macOS, install one approach:

1. `cross` backend:
```bash
cargo install cross --locked
```
2. `zigbuild` backend (recommended):
```bash
brew install zig
cargo install cargo-zigbuild --locked
```
3. Native GNU cross toolchains (plain cargo backend, Linux targets only):
```bash
brew tap messense/macos-cross-toolchains
brew install x86_64-unknown-linux-gnu
brew install aarch64-unknown-linux-gnu
# also install matching i686 and riscv64 GNU cross compilers (for example:
# i686-linux-gnu-gcc and riscv64-linux-gnu-gcc) from your preferred toolchain source.
```

## Development

```bash
# format check
cargo fmt -- --check

# lint (warnings are errors)
cargo clippy --all-targets -- -D warnings

# full tests
cargo test

# run local binary
cargo run -- status
```

`cargo-make` tasks are defined in `Makefile.toml`, including:

- `cargo make test`
- `cargo make quality`
- `cargo make release-host`
- `cargo make release-matrix`

## Troubleshooting

- `nsh status` - inspect session/provider/db state
- `nsh doctor` - integrity check + prune/vacuum maintenance
- `nsh config show` - verify effective config file content
- `RUST_LOG=debug nsh query ...` - debug logging

If API calls fail, verify key resolution order for your provider:

1. `api_key` in config
2. `api_key_cmd` in config
3. provider env var fallback

## License

BSD 3-Clause - see [LICENSE](LICENSE).
