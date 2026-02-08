# nsh — Natural Shell

AI-powered shell assistant that lives in your terminal. Ask questions with `?`,
get commands prefilled at your prompt, and let the AI gather context from your
scrollback, history, files, and the web.

## Quick Start

```bash
# Build from source (requires Rust 1.85+)
cargo install --path .

# Add to your shell config
echo 'eval "$(nsh init zsh)"' >> ~/.zshrc   # or bash

# Configure your API key
mkdir -p ~/.nsh
cat > ~/.nsh/config.toml << 'CONF'
[provider]
default = "openrouter"
model = "google/gemini-2.5-flash"

[provider.openrouter]
api_key = "sk-or-..."
CONF

# Use it
? why is my docker build failing
? install ripgrep
?? set up a python venv for this project
```

## How It Works

1. Shell hooks capture every command + exit code into a local SQLite database
2. `?` / `??` sends your query to the configured LLM with rich context
3. The LLM can call tools (scrollback, history search, file grep, web search, etc.)
4. Suggested commands are prefilled at your prompt for review before execution

## Configuration

See `~/.nsh/config.toml`. Supports OpenRouter, Anthropic, and OpenAI providers.

## License

BSD 3-Clause
