# Contributing to nsh

Thank you for your interest in contributing to nsh! This guide covers how to contribute effectively, whether you're fixing a typo, adding a feature, or submitting an AI-generated patch.

## Code of Conduct

Be respectful, constructive, and patient. We're building a tool together.

## Getting Started

1. **Fork the repository** and clone your fork
2. **Set up the development environment:**
   ```bash
   # Rust 1.85+ required
   rustup update
   cargo build
   cargo test
   ```
3. **Run the quality pipeline** before submitting:
   ```bash
   cargo make quality
   ```
   This runs format checking, clippy lints (warnings as errors), all tests, and a dependency audit.

## How to Contribute

### Reporting Issues

- **Search existing issues first** to avoid duplicates
- **Use a clear title** that summarizes the problem
- **Include reproduction steps** - shell type, OS, nsh version (`nsh --version`), relevant config
- **Include logs** - run with `RUST_LOG=debug` and attach relevant output
- **Describe expected vs. actual behavior**

### Proposing Features

- Open a discussion or issue **before** building large features
- Explain the **use case** - what problem does this solve?
- Consider how it fits into nsh's design: local-first, secure by default, non-intrusive

### Submitting Pull Requests

#### Before You Start

- For non-trivial changes, open an issue first to discuss the approach
- Keep PRs focused on a single logical change
- If a PR needs "and" in its title, consider splitting it

#### PR Requirements

1. **All tests pass:** `cargo test`
2. **No lint warnings:** `cargo clippy --all-targets -- -D warnings`
3. **Formatted code:** `cargo fmt -- --check`
4. **Commit messages** are clear, single-line summaries of what changed:
   - ✅ `Add entity-aware history search for hostnames and IPs`
   - ✅ `Fix FTS5 index corruption on concurrent access`
   - ✅ `Update default model chain to include gemini-3-flash`
   - ❌ `Fix stuff`
   - ❌ `WIP changes part 3`
5. **New features include tests** - look at existing tests for patterns
6. **Documentation is updated** if the change affects user-facing behavior

#### PR Process

1. Fork → branch → commit → push → open PR against `main`
2. Fill in the PR template (if one exists) or describe:
   - What the change does
   - Why it's needed
   - How to test it
3. A maintainer will review and may request changes
4. Once approved, the PR will be squash-merged

### AI-Generated Contributions

We welcome AI-generated contributions. Use whatever tools help you be productive - Copilot, Claude, Cursor, Amp, or anything else.

**Important:** AI-generated PRs are held to the same quality bar as any other contribution. They must pass all tests, follow the code style, and solve a real problem. **Human-authored PRs will be prioritized in the review queue** over automated or bulk-generated ones.

If your PR was substantially AI-generated, please mention this in the PR description. This isn't a penalty - it helps reviewers calibrate their review (AI-generated code sometimes has subtle issues that benefit from closer inspection).

Low-effort, bulk-generated PRs (e.g., mass-renaming variables, adding trivial comments, reformatting code that already passes `cargo fmt`) will be closed without review.

## Architecture Overview

Understanding the codebase helps you contribute effectively:

```
src/
├── main.rs          # CLI entry point, command routing
├── cli.rs           # Clap argument definitions
├── config.rs        # Configuration loading, merging, validation
├── context.rs       # Query context building (env, project, git, scrollback)
├── query.rs         # Main query handler, agent loop, tool dispatch
├── db.rs            # SQLite database (schema, queries, FTS5)
├── provider/        # LLM provider implementations
│   ├── mod.rs       # Unified message types, provider factory
│   ├── anthropic.rs # Anthropic API (native)
│   ├── openai_compat.rs # OpenAI-compatible API (shared by OpenRouter, OpenAI, Gemini, Ollama)
│   └── chain.rs     # Model chain with retry and fallback
├── tools/           # Tool implementations
│   ├── mod.rs       # Tool definitions and path validation
│   ├── command.rs   # Command prefill with risk assessment
│   ├── chat.rs      # Text response rendering
│   ├── search_history.rs # FTS5 + entity-aware history search
│   ├── write_file.rs / patch_file.rs # File editing with diff preview
│   └── ...          # Other tools
├── pump.rs          # PTY I/O pump, scrollback capture, daemon socket handler
├── pty.rs           # PTY creation, raw mode, fork/exec
├── daemon.rs        # Daemon protocol, DB command thread
├── redact.rs        # Secret detection and redaction engine
├── security.rs      # Command risk assessment, injection filtering
├── mcp.rs           # MCP client (stdio + HTTP transports)
├── skills.rs        # Custom skill loader and executor
├── streaming.rs     # Stream consumer, spinner, display
├── summary.rs       # Command output summarization
└── shell/           # Shell integration scripts (zsh, bash, fish)
```

### Key Design Decisions

- **PTY wrapper** - `nsh wrap` runs the user's shell inside a PTY so nsh can capture all terminal output without modifying the shell itself
- **Daemon thread** - DB writes and command recording happen on a dedicated thread via `daemon.rs` to avoid blocking the shell
- **Tool-call-only responses** - the LLM must always respond via tool calls, never plain text. This ensures structured, actionable responses
- **Boundary tokens** - tool results are wrapped in random boundary tokens to prevent prompt injection from tool output
- **Schema migrations** - `db.rs` handles schema versioning (currently v5) with backward-compatible migrations

## Code Style

- Follow existing patterns in the codebase
- Use `anyhow` for error handling in application code
- Use `rusqlite::Result` in database code
- Prefer `tracing::debug!` / `tracing::warn!` over `eprintln!` for internal diagnostics
- User-facing output goes to stderr (`eprintln!`), not stdout
- Tests go in `#[cfg(test)] mod tests` at the bottom of each file

## Testing

The test suite is substantial. To run specific subsets:

```bash
cargo test                          # all tests
cargo test --lib                    # unit tests only
cargo test --test integration       # integration tests only
cargo test db::tests                # tests in a specific module
cargo test -- --nocapture           # show test output
```

When adding tests:
- Use `Db::open_in_memory()` for database tests
- Use `tempfile::TempDir` for filesystem tests
- Use `wiremock` for HTTP mocking (provider tests)
- Use `#[serial_test::serial]` for tests that modify environment variables

## Questions?

Open an issue or start a discussion. We're happy to help you find the right place to contribute.