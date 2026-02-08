use crate::{
    config::Config, context, db::Db, provider::*, streaming, tools,
};

pub async fn handle_query(
    query: &str,
    config: &Config,
    db: &Db,
    session_id: &str,
) -> anyhow::Result<()> {
    let provider =
        create_provider(&config.provider.default, config)?;
    let model = &config.provider.model;

    // 1. Assemble context
    let ctx = context::build_context(db, session_id, config)?;

    // 2. Build system prompt + messages
    let system = build_system_prompt(
        &ctx.os_info,
        &ctx.shell,
        &ctx.cwd,
        &ctx.username,
    );
    let mut messages: Vec<Message> = Vec::new();

    // Conversation history from this session
    for exchange in &ctx.conversation_history {
        let tool_id = uuid::Uuid::new_v4().to_string();
        messages.push(exchange.to_user_message());
        messages.push(exchange.to_assistant_message(&tool_id));
        messages.push(exchange.to_tool_result_message(&tool_id));
    }

    // Cross-TTY context
    if !ctx.other_tty_context.is_empty() {
        messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: format!(
                    "[CONTEXT: Recent commands in other sessions]\n{}",
                    ctx.other_tty_context
                ),
            }],
        });
        messages.push(Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Text {
                text: "Noted.".into(),
            }],
        });
    }

    // The user's actual query
    messages.push(Message {
        role: Role::User,
        content: vec![ContentBlock::Text {
            text: query.to_string(),
        }],
    });

    // 3. Agentic tool loop
    let tool_defs = tools::all_tool_definitions();
    let max_iterations = 10;

    for iteration in 0..max_iterations {
        let request = ChatRequest {
            model: model.clone(),
            system: system.clone(),
            messages: messages.clone(),
            tools: tool_defs.clone(),
            tool_choice: if iteration == 0 {
                ToolChoice::Required
            } else {
                ToolChoice::Auto
            },
            max_tokens: 4096,
            stream: true,
        };

        streaming::show_spinner();
        let mut rx = provider.stream(request).await?;
        streaming::hide_spinner();

        let response = streaming::consume_stream(&mut rx).await?;
        messages.push(response.clone());

        // Dispatch tool calls
        let mut has_terminal_tool = false;
        let mut tool_results: Vec<ContentBlock> = Vec::new();

        for block in &response.content {
            if let ContentBlock::ToolUse { id, name, input } = block {
                match name.as_str() {
                    // ── Terminal tools (end the loop) ──────────
                    "command" => {
                        has_terminal_tool = true;
                        tools::command::execute(
                            input, query, db, session_id,
                        )?;
                    }
                    "chat" => {
                        has_terminal_tool = true;
                        tools::chat::execute(
                            input, query, db, session_id,
                        )?;
                    }

                    // ── Intermediate tools (loop continues) ────
                    "scrollback" => {
                        let lines = input["lines"]
                            .as_u64()
                            .unwrap_or(100)
                            as usize;
                        let data =
                            tools::scrollback::execute(lines)?;
                        tool_results.push(
                            ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content: data,
                                is_error: false,
                            },
                        );
                    }
                    "search_history" => {
                        let q = input["query"]
                            .as_str()
                            .unwrap_or("");
                        let limit = input["limit"]
                            .as_u64()
                            .unwrap_or(10)
                            as usize;
                        let data =
                            tools::search_history::execute(
                                db, q, limit,
                            )?;
                        tool_results.push(
                            ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content: data,
                                is_error: false,
                            },
                        );
                    }
                    "grep_file" => {
                        let result =
                            tools::grep_file::execute(input)?;
                        tool_results.push(
                            ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content: result,
                                is_error: false,
                            },
                        );
                    }
                    "list_directory" => {
                        let result =
                            tools::list_directory::execute(input)?;
                        tool_results.push(
                            ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content: result,
                                is_error: false,
                            },
                        );
                    }
                    "web_search" => {
                        let q = input["query"]
                            .as_str()
                            .unwrap_or("");
                        let (content, is_err) =
                            match tools::web_search::execute(
                                q, config,
                            )
                            .await
                            {
                                Ok(result) => (result, false),
                                Err(e) => {
                                    (format!("Error: {e}"), true)
                                }
                            };
                        tool_results.push(
                            ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content,
                                is_error: is_err,
                            },
                        );
                    }
                    "run_command" => {
                        let cmd = input["command"]
                            .as_str()
                            .unwrap_or("");
                        let result =
                            tools::run_command::execute(
                                cmd, config,
                            )?;
                        tool_results.push(
                            ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content: result,
                                is_error: false,
                            },
                        );
                    }
                    "ask_user" => {
                        let question = input["question"]
                            .as_str()
                            .unwrap_or("");
                        let options =
                            input["options"].as_array().map(|a| {
                                a.iter()
                                    .filter_map(|v| {
                                        v.as_str()
                                            .map(String::from)
                                    })
                                    .collect::<Vec<_>>()
                            });
                        let answer = tools::ask_user::execute(
                            question,
                            options.as_deref(),
                        )?;
                        tool_results.push(
                            ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content: answer,
                                is_error: false,
                            },
                        );
                    }
                    "man_page" => {
                        let cmd = input["command"]
                            .as_str()
                            .unwrap_or("");
                        let section =
                            input["section"].as_u64().map(|s| s as u8);
                        let result =
                            tools::man_page::execute(cmd, section)?;
                        tool_results.push(
                            ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content: result,
                                is_error: false,
                            },
                        );
                    }
                    unknown => {
                        tool_results.push(
                            ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content: format!(
                                    "Unknown tool: {unknown}"
                                ),
                                is_error: true,
                            },
                        );
                    }
                }
            }
        }

        if has_terminal_tool {
            break;
        }

        if tool_results.is_empty() {
            eprintln!("nsh: no tool calls in response, aborting");
            break;
        }

        messages.push(Message {
            role: Role::Tool,
            content: tool_results,
        });

        eprintln!("  \x1b[2m↳ gathering more context...\x1b[0m");
    }

    Ok(())
}

pub fn build_system_prompt(
    os_info: &str,
    shell: &str,
    cwd: &str,
    username: &str,
) -> String {
    format!(
        r#"You are nsh (Natural Shell), an AI assistant embedded in the
user's terminal. You help with shell commands, debugging, and system
administration.

## Environment
- OS: {os_info}
- Shell: {shell}
- CWD: {cwd}
- User: {username}

## Response Rules

You MUST respond by calling exactly one tool. Never respond with plain text.

### When to use each tool:

**command** — When the user asks you to DO something (install, remove,
configure, fix, create, delete, move, change, set up, find, search, etc.).
ALWAYS prefer command over chat when action is requested. If unsure what
command to run, use command with pending=true to run an investigative
command first (e.g., `which`, `cat`, `ls`, `grep`), then continue after
seeing the output.

**chat** — ONLY for pure knowledge questions where no action is needed
("what does -r do?", "explain pipes", "how does git rebase work?").

**scrollback** — When you need to see recent terminal output.

**search_history** — When the user references something they did before.

**grep_file** — To search within or read a local file.

**list_directory** — To see what files exist at a path.

**web_search** — For up-to-date information.

**run_command** — To silently run a safe, read-only command and get its
output without bothering the user.

**ask_user** — When you need clarification or a yes/no decision.

**man_page** — When you need to verify exact flags or syntax.

## Style
- Be concise. Explanations should be 1-2 sentences max.
- Prefer simple, portable commands.
- Use long flags (--recursive) over short flags (-r) for generated commands
  unless the short form is universally known.
- For multi-step tasks, use pending=true and guide step by step.

## Multi-step sequences
When you set pending=true on a command, you'll receive a continuation
message after the user executes it. The LAST command in a sequence must NOT
have pending=true."#
    )
}
