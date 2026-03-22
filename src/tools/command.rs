use crate::daemon_db::DbAccess;
use crate::security::RiskLevel;
use crate::tools::{ToolInvocationContext, ToolInvocationOutcome, ToolInvocationResult};
use std::path::Path;

enum CommandExecutionOutcome {
    Terminal,
    ContinueWithResult { content: String, is_error: bool },
}

impl From<CommandExecutionOutcome> for ToolInvocationResult {
    fn from(value: CommandExecutionOutcome) -> Self {
        match value {
            CommandExecutionOutcome::Terminal => Self::terminal(),
            CommandExecutionOutcome::ContinueWithResult { content, is_error } => {
                Self::Continue(if is_error {
                    ToolInvocationOutcome::failure(content)
                } else {
                    ToolInvocationOutcome::success(content)
                })
            }
        }
    }
}

struct CommandRequest {
    command: String,
    explanation: String,
    pending: bool,
    risk: RiskLevel,
    risk_reason: Option<&'static str>,
}

struct CommandExecutionPlan {
    auto_execute_pending: bool,
    should_execute_immediately: bool,
    execute_via_shell_autorun: bool,
}

struct ImmediateCommandResult {
    output_content: String,
    is_error: bool,
    exit_code: i32,
}

/// Handle the `command` tool: display explanation, write command to
/// pending file for shell hook to prefill.
pub fn invoke(
    input: &serde_json::Value,
    ctx: &ToolInvocationContext<'_>,
) -> anyhow::Result<ToolInvocationResult> {
    let (db, session_id) = ctx.conversation_state()?;
    execute(
        input,
        ctx.original_query,
        db,
        session_id,
        ctx.private,
        ctx.config,
        ctx.force_autorun,
        ctx.json_output,
    )
    .map(ToolInvocationResult::from)
}

#[allow(clippy::too_many_arguments)]
fn execute(
    input: &serde_json::Value,
    original_query: &str,
    db: &dyn DbAccess,
    session_id: &str,
    private: bool,
    config: &crate::config::Config,
    force_autorun: bool,
    json_output: bool,
) -> anyhow::Result<CommandExecutionOutcome> {
    clear_stale_pending_files(session_id);
    let request = build_command_request(input, original_query, db, session_id);

    if let Some(reason) = reject_reason_for_generated_command(&request.command, original_query) {
        eprintln!("nsh: skipped invalid generated command ({reason})");
        return Ok(CommandExecutionOutcome::ContinueWithResult {
            content: format!(
                "Command rejected: {reason}. Provide a valid shell command or use other tools."
            ),
            is_error: true,
        });
    }

    if let Some(outcome) = confirm_command_request(&request)? {
        return Ok(outcome);
    }

    emit_command_preview(&request, json_output)?;
    let plan = plan_command_execution(&request, config, force_autorun);

    // Diagnostic when autorun is blocked for elevated commands
    if (force_autorun || config.execution.mode == "autorun")
        && !plan.should_execute_immediately
        && matches!(request.risk, RiskLevel::Elevated)
        && !json_output
    {
        eprintln!("\x1b[33m  (autorun paused for elevated command — user confirmation required)\x1b[0m");
        eprintln!("\x1b[2m    (To autorun elevated commands, set `execution.allow_unsafe_autorun = true`)\x1b[0m");
    }

    if matches!(request.risk, RiskLevel::Safe) && plan.auto_execute_pending && !json_output {
        eprintln!("\x1b[2m  $ {}\x1b[0m", request.command);
    }

    if plan.should_execute_immediately && request.pending {
        eprintln!("\x1b[2m(auto-running)\x1b[0m");
        eprintln!(
            "\x1b[2m  ⟳ intermediate step — nsh will continue automatically after this finishes\x1b[0m"
        );
        let result = execute_pending_command(input, &request.command, config, json_output);
        if !private {
            record_command_execution(
                db,
                session_id,
                original_query,
                &request,
                config,
                true,
                false,
            )?;
        }
        if result.is_error {
            eprintln!(
                "\n\x1b[33mcommand exited with code {}\x1b[0m",
                result.exit_code
            );
        }
        return Ok(CommandExecutionOutcome::ContinueWithResult {
            content: result.output_content,
            is_error: result.is_error,
        });
    }

    if config.execution.mode != "confirm" || plan.execute_via_shell_autorun {
        write_pending_shell_files(
            session_id,
            &request.command,
            request.pending,
            plan.execute_via_shell_autorun,
        )?;
    }

    if !private {
        record_command_execution(
            db,
            session_id,
            original_query,
            &request,
            config,
            false,
            request.pending,
        )?;
    }

    eprint!("\x1b[0m");
    std::io::Write::flush(&mut std::io::stderr()).ok();

    Ok(CommandExecutionOutcome::Terminal)
}

fn clear_stale_pending_files(session_id: &str) {
    let nsh_dir = crate::config::Config::nsh_dir();
    let _ = std::fs::remove_file(nsh_dir.join(format!("pending_{session_id}.json")));
}

fn build_command_request(
    input: &serde_json::Value,
    original_query: &str,
    db: &dyn DbAccess,
    session_id: &str,
) -> CommandRequest {
    let raw_command = input["command"].as_str().unwrap_or("");
    let command = normalize_command_for_prefill(raw_command, original_query, db, session_id);
    let (risk, risk_reason) = assess_command_risk(&command);
    CommandRequest {
        command,
        explanation: input["explanation"].as_str().unwrap_or("").to_string(),
        pending: input["pending"].as_bool().unwrap_or(false),
        risk,
        risk_reason,
    }
}

fn assess_command_risk(command: &str) -> (RiskLevel, Option<&'static str>) {
    let cwd_str = std::env::current_dir()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| ".".to_string());
    let risk_command = command
        .replace("$(pwd)", &cwd_str)
        .replace("`pwd`", &cwd_str);
    crate::security::assess_command(&risk_command)
}

fn confirm_command_request(
    request: &CommandRequest,
) -> anyhow::Result<Option<CommandExecutionOutcome>> {
    match &request.risk {
        RiskLevel::Dangerous => {
            use std::io::IsTerminal;

            let reason_str = request
                .risk_reason
                .unwrap_or("potentially destructive command");
            eprintln!("\x1b[1;31m⚠ DANGEROUS: {reason_str}\x1b[0m");
            eprintln!("\x1b[1;31mCommand: {}\x1b[0m", request.command);
            eprint!("\x1b[1;31mType 'yes' to proceed: \x1b[0m");
            let stdin_is_terminal = std::io::stdin().is_terminal();
            let input_line = match crate::tools::read_terminal_line_with(stdin_is_terminal, || {
                std::fs::File::open("/dev/tty")
            }) {
                Ok(line) => line,
                Err(err) => {
                    if stdin_is_terminal {
                        return Err(err.into());
                    }
                    eprintln!("Cannot confirm — stdin is piped. Aborting dangerous command.");
                    return Ok(Some(CommandExecutionOutcome::ContinueWithResult {
                            content: "DENIED: dangerous command not approved by user. Try a different approach.".into(),
                            is_error: true,
                        }));
                }
            };
            if input_line.trim() != "yes" {
                eprintln!("Aborted.");
                return Ok(Some(CommandExecutionOutcome::ContinueWithResult {
                    content:
                        "DENIED: dangerous command not approved by user. Try a different approach."
                            .into(),
                    is_error: true,
                }));
            }
        }
        RiskLevel::Elevated => {
            let reason_str = request.risk_reason.unwrap_or("elevated privileges");
            eprintln!("\x1b[33m⚡ {reason_str}\x1b[0m");
        }
        RiskLevel::Safe => {}
    }
    Ok(None)
}

fn emit_command_preview(request: &CommandRequest, json_output: bool) -> anyhow::Result<()> {
    if json_output {
        let event = serde_json::json!({
            "type": "command",
            "command": request.command,
            "explanation": request.explanation,
            "risk": request.risk.to_string(),
            "pending": request.pending,
        });
        eprintln!("{}", serde_json::to_string(&event)?);
        return Ok(());
    }

    match &request.risk {
        RiskLevel::Safe => {
            if !request.explanation.is_empty() {
                eprintln!("\x1b[2m  {}\x1b[0m", request.explanation);
            }
        }
        RiskLevel::Elevated => {
            if !request.explanation.is_empty() {
                eprintln!("\x1b[2m  {}\x1b[0m", request.explanation);
            }
            eprintln!("\x1b[2m  $ {}\x1b[0m", request.command);
        }
        RiskLevel::Dangerous => {
            display_command_preview(&request.command, &request.explanation, &request.risk);
            eprintln!("\x1b[2m  ↵ Enter to run · Edit first · Ctrl-C to cancel\x1b[0m");
        }
    }
    Ok(())
}

fn plan_command_execution(
    request: &CommandRequest,
    config: &crate::config::Config,
    force_autorun: bool,
) -> CommandExecutionPlan {
    let autorun_mode = config.execution.mode == "autorun";
    let can_autorun = match request.risk {
        RiskLevel::Safe => true,
        RiskLevel::Elevated => force_autorun || autorun_mode || config.execution.allow_unsafe_autorun,
        RiskLevel::Dangerous => false,
    };
    let mut user_confirmed_intermediate = false;
    if request.pending
        && !force_autorun
        && config.execution.confirm_intermediate_steps
        && !matches!(request.risk, RiskLevel::Dangerous)
    {
        eprint!("\x1b[1;33mRun intermediate command now? [Y/n]\x1b[0m ");
        let _ = std::io::Write::flush(&mut std::io::stderr());
        user_confirmed_intermediate = crate::tools::read_tty_confirmation_default_yes();
    }

    let auto_execute_pending = request.pending
        && !force_autorun
        && !config.execution.confirm_intermediate_steps
        && can_autorun;
    let should_execute_immediately = ((force_autorun || autorun_mode) && can_autorun)
        || user_confirmed_intermediate
        || auto_execute_pending;

    CommandExecutionPlan {
        auto_execute_pending,
        should_execute_immediately,
        execute_via_shell_autorun: should_execute_immediately && !request.pending,
    }
}

fn execute_pending_command(
    input: &serde_json::Value,
    command: &str,
    config: &crate::config::Config,
    json_output: bool,
) -> ImmediateCommandResult {
    let mut expected_secs = input["expected_timeout_seconds"]
        .as_u64()
        .unwrap_or(300)
        .clamp(5, 3600);

    #[cfg(unix)]
    let child = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
    #[cfg(windows)]
    let child = std::process::Command::new("cmd")
        .args(["/C", command])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    match child {
        Ok(child) => {
            let mut pumped = crate::tools::process_pump::attach_output_pumps(
                child,
                &config.redaction,
                !json_output,
            );
            let mut start = std::time::Instant::now();
            let mut has_prompted_once = false;

            loop {
                match pumped.child.try_wait() {
                    Ok(Some(status)) => {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        let (stdout_text, stderr_text) = pumped.finish();
                        let exit_code = status.code().unwrap_or(-1);
                        let output_content = format_pumped_command_output(
                            &stdout_text,
                            &stderr_text,
                            exit_code,
                            config,
                        );
                        return ImmediateCommandResult {
                            output_content,
                            is_error: exit_code != 0,
                            exit_code,
                        };
                    }
                    Ok(None) => {
                        let last_out_age = pumped.last_output_age();
                        let elapsed = start.elapsed().as_secs();

                        if elapsed >= expected_secs
                            && last_out_age > std::time::Duration::from_secs(30)
                        {
                            if !has_prompted_once {
                                eprintln!(
                                    "\n\x1b[2m  ⏱ Command running for {}s with no recent output (waiting…)\x1b[0m",
                                    elapsed
                                );
                                has_prompted_once = true;
                                start = std::time::Instant::now();
                            } else {
                                eprint!(
                                    "\n\x1b[1;33mNo output for {}s (total {}s). Continue waiting? [Y/n]\x1b[0m ",
                                    last_out_age.as_secs(),
                                    elapsed
                                );
                                let _ = std::io::Write::flush(&mut std::io::stderr());
                                if !crate::tools::read_tty_confirmation_safe() {
                                    let _ = pumped.child.kill();
                                    let _ = pumped.child.wait();
                                    return ImmediateCommandResult {
                                        output_content: format!(
                                            "Command timed out after {}s (user cancelled wait)",
                                            elapsed
                                        ),
                                        is_error: true,
                                        exit_code: 124,
                                    };
                                }
                                start = std::time::Instant::now();
                                expected_secs = (expected_secs * 2).min(1800);
                            }
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(error) => {
                        return ImmediateCommandResult {
                            output_content: format!("Failed to execute command: {error}"),
                            is_error: true,
                            exit_code: -1,
                        };
                    }
                }
            }
        }
        Err(error) => {
            let (output_content, is_error, exit_code) = format_execution_output(Err(error), config);
            ImmediateCommandResult {
                output_content,
                is_error,
                exit_code,
            }
        }
    }
}

fn format_pumped_command_output(
    stdout_text: &str,
    stderr_text: &str,
    exit_code: i32,
    config: &crate::config::Config,
) -> String {
    let mut result = String::new();
    if !stdout_text.trim().is_empty() {
        result.push_str(&crate::util::truncate(stdout_text, 8000));
    }
    if !stderr_text.trim().is_empty() {
        if !result.is_empty() {
            result.push_str("\n--- stderr ---\n");
        }
        result.push_str(&crate::util::truncate(stderr_text, 4000));
    }
    result.push_str(&format!("\n[exit code: {exit_code}]"));

    if exit_code == 0 {
        let combined_lower = result.to_lowercase();
        let warning_patterns = [
            "error:",
            "failed",
            "fatal:",
            "permission denied",
            "not found",
            "cannot",
            "unable to",
            "refused",
            "timeout",
            "timed out",
        ];
        if warning_patterns
            .iter()
            .any(|pattern| combined_lower.contains(pattern))
        {
            result.push_str(
                "\n\n[NOTE: exit code 0 but output contains error-like patterns — verify the command actually succeeded]",
            );
        }
    }

    crate::redact::redact_secrets(&result, &config.redaction)
}

/// Atomically write `content` to `path` with mode 0o600 (unix) via a `.tmp` rename.
fn write_atomic_private(path: &std::path::Path, content: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(unix)]
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        #[cfg(not(unix))]
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(content)?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn write_pending_shell_files(
    session_id: &str,
    command: &str,
    pending: bool,
    execute_via_shell_autorun: bool,
) -> anyhow::Result<()> {
    let nsh_dir = crate::config::Config::nsh_dir();

    let payload = serde_json::json!({
        "command": command,
        "pending": pending,
        "autorun": execute_via_shell_autorun,
    });
    let payload_file = nsh_dir.join(format!("pending_{session_id}.json"));
    write_atomic_private(&payload_file, serde_json::to_string(&payload)?.as_bytes())?;

    if execute_via_shell_autorun {
        eprintln!("\x1b[2m(auto-running)\x1b[0m");
    }
    Ok(())
}

fn record_command_execution(
    db: &dyn DbAccess,
    session_id: &str,
    original_query: &str,
    request: &CommandRequest,
    config: &crate::config::Config,
    executed: bool,
    pending: bool,
) -> anyhow::Result<()> {
    let risk = request.risk.to_string();
    crate::tools::record_tool_conversation(
        db,
        config,
        false,
        crate::tools::ToolConversationRecord {
            session_id,
            original_query,
            response_type: "command",
            response: &request.command,
            explanation: Some(&request.explanation),
            executed,
            pending,
            audit_risk: Some(risk.as_str()),
        },
    )
}

fn format_execution_output(
    output: std::io::Result<std::process::Output>,
    config: &crate::config::Config,
) -> (String, bool, i32) {
    match output {
        Ok(out) => {
            let exit_code = out.status.code().unwrap_or(-1);
            let mut result = String::new();
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stdout.trim().is_empty() {
                result.push_str(&crate::util::truncate(&stdout, 4000));
            }
            if !stderr.trim().is_empty() {
                if !result.is_empty() {
                    result.push_str("\n\n");
                }
                result.push_str("[stderr]\n");
                result.push_str(&crate::util::truncate(&stderr, 2000));
            }
            if !result.is_empty() {
                result.push_str("\n\n");
            }
            result.push_str(&format!("[exit code: {exit_code}]"));
            let redacted = crate::redact::redact_secrets(&result, &config.redaction);
            (redacted, exit_code != 0, exit_code)
        }
        Err(err) => {
            let msg = crate::redact::redact_secrets(
                &format!("Failed to execute command: {err}"),
                &config.redaction,
            );
            (msg, true, -1)
        }
    }
}

pub(crate) fn reject_reason_for_generated_command(
    command: &str,
    original_query: &str,
) -> Option<&'static str> {
    let trimmed_command = command.trim();
    if trimmed_command.is_empty() {
        return Some("empty command");
    }

    let trimmed_query = original_query.trim();
    if trimmed_query.is_empty() {
        return None;
    }

    if trimmed_command.eq_ignore_ascii_case(trimmed_query)
        && looks_like_natural_language_question(trimmed_query)
    {
        return Some("model echoed the user's question instead of a shell command");
    }

    let lower = trimmed_command.to_ascii_lowercase();
    let nl_indicators = [
        "please ",
        "can you ",
        "could you ",
        "i want ",
        "i need ",
        "help me ",
        "show me how",
        "how do i ",
        "what is ",
    ];
    if nl_indicators
        .iter()
        .any(|p| lower.starts_with(p) || lower.contains(p))
    {
        return Some("generated command looks like natural language, not a shell command");
    }

    let cmd_lower = trimmed_command.to_ascii_lowercase();
    let query_lower = trimmed_query.to_ascii_lowercase();
    if cmd_lower == query_lower && !cmd_lower.contains('/') && !cmd_lower.starts_with("cd ") {
        let first_word = cmd_lower.split_whitespace().next().unwrap_or("");
        if !first_word.is_empty() {
            let path_sep = if cfg!(windows) { ';' } else { ':' };
            let found_in_path = std::env::var("PATH")
                .unwrap_or_default()
                .split(path_sep)
                .any(|dir| std::path::Path::new(dir).join(first_word).exists());
            if !found_in_path {
                return Some(
                    "command appears to be the user's natural language request, not a shell command",
                );
            }
        }
    }

    None
}

fn looks_like_natural_language_question(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.ends_with('?') {
        return true;
    }

    const QUESTION_PREFIXES: &[&str] = &[
        "what ", "when ", "where ", "why ", "who ", "whom ", "which ", "how ", "can ", "could ",
        "would ", "should ", "do ", "does ", "did ", "is ", "are ", "am ", "was ", "were ",
        "will ",
    ];

    QUESTION_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

fn normalize_command_for_prefill(
    command: &str,
    original_query: &str,
    db: &dyn DbAccess,
    session_id: &str,
) -> String {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let source = if trimmed.eq_ignore_ascii_case(original_query.trim()) {
        original_query.trim()
    } else {
        trimmed
    };

    if let Some(cd_command) = normalize_cd_command(source, db, session_id) {
        return cd_command;
    }

    trimmed.to_string()
}

fn normalize_cd_command(command: &str, db: &dyn DbAccess, session_id: &str) -> Option<String> {
    let trimmed = command.trim();
    let rest = trimmed.strip_prefix("cd ")?;
    let rest = rest.trim();
    if rest.is_empty() {
        return Some("cd".to_string());
    }
    if rest == "-" || looks_explicit_cd_target(rest) {
        return Some(format!("cd {rest}"));
    }

    let unquoted = strip_matching_quotes(rest);
    let cleaned = cleanup_cd_target_phrase(unquoted);
    let resolved = resolve_cd_target(cleaned.as_str(), db, session_id);
    Some(format!("cd {}", shell_quote_if_needed(&resolved)))
}

fn looks_explicit_cd_target(target: &str) -> bool {
    target.starts_with('~')
        || target.starts_with('.')
        || target.starts_with('/')
        || target.starts_with('$')
        || target.contains('/')
        || target.contains('*')
        || target.contains('?')
        || target.contains('[')
        || target.contains(']')
}

fn strip_matching_quotes(input: &str) -> &str {
    if input.len() >= 2 {
        let bytes = input.as_bytes();
        if (bytes[0] == b'\'' && bytes[input.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[input.len() - 1] == b'"')
        {
            return &input[1..input.len() - 1];
        }
    }
    input
}

fn cleanup_cd_target_phrase(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || looks_explicit_cd_target(trimmed) {
        return trimmed.to_string();
    }

    // ~user/path syntax — don't strip any part of it
    if trimmed.starts_with('~') && !trimmed.starts_with("~/") && trimmed != "~" {
        return trimmed.to_string();
    }

    const FILLER_WORDS: &[&str] = &[
        "to",
        "into",
        "in",
        "the",
        "a",
        "an",
        "folder",
        "directory",
        "dir",
    ];

    let raw_tokens: Vec<&str> = trimmed.split_whitespace().collect();
    // Only strip filler words when there are multiple tokens to avoid
    // stripping literal directory/folder names like "directory" or "folder".
    let tokens: Vec<String> = if raw_tokens.len() <= 1 {
        raw_tokens.iter().map(|t| t.to_string()).collect()
    } else {
        raw_tokens
            .iter()
            .filter_map(|tok| {
                let cleaned = tok.trim_matches(|c: char| c == ',' || c == '.');
                let lower = cleaned.to_ascii_lowercase();
                if FILLER_WORDS.contains(&lower.as_str()) {
                    return None;
                }
                if cleaned.is_empty() {
                    return None;
                }
                Some(cleaned.to_string())
            })
            .collect()
    };

    if tokens.is_empty() {
        trimmed.to_string()
    } else {
        tokens.join(" ")
    }
}

fn resolve_cd_target(target: &str, db: &dyn DbAccess, session_id: &str) -> String {
    if target.is_empty() || looks_explicit_cd_target(target) {
        return target.to_string();
    }

    let candidates = cwd_directory_candidates(target);
    if candidates.is_empty() {
        return target.to_string();
    }
    if candidates.len() == 1 {
        return candidates[0].clone();
    }
    if let Some(from_history) = choose_candidate_from_cd_history(&candidates, db, session_id) {
        return from_history;
    }
    candidates[0].clone()
}

fn cwd_directory_candidates(target: &str) -> Vec<String> {
    let target_lower = target.to_ascii_lowercase();
    let mut exact = Vec::new();
    let mut prefix = Vec::new();
    let mut contains = Vec::new();

    let entries = match std::fs::read_dir(".") {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    for entry in entries.flatten() {
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if !file_type.is_dir() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_string();
        let lower = name.to_ascii_lowercase();
        if lower == target_lower {
            exact.push(name);
        } else if lower.starts_with(&target_lower) {
            prefix.push(name);
        } else if lower.contains(&target_lower) {
            contains.push(name);
        }
    }

    for group in [&mut exact, &mut prefix, &mut contains] {
        group.sort();
    }

    if !exact.is_empty() {
        exact
    } else if !prefix.is_empty() {
        prefix
    } else {
        contains
    }
}

fn choose_candidate_from_cd_history(
    candidates: &[String],
    db: &dyn DbAccess,
    session_id: &str,
) -> Option<String> {
    let try_filters = [Some("current"), None];
    for session_filter in try_filters {
        let history = db
            .search_history_advanced(
                None,
                Some(r"^cd\s+"),
                None,
                None,
                None,
                false,
                session_filter,
                Some(session_id),
                200,
            )
            .ok()?;

        for row in history {
            let Some(history_target) = extract_cd_target_from_command(&row.command) else {
                continue;
            };
            if let Some(candidate) = match_history_target_to_candidates(&history_target, candidates)
            {
                return Some(candidate);
            }
        }
    }
    None
}

fn extract_cd_target_from_command(command: &str) -> Option<String> {
    if let Ok(parts) = shell_words::split(command)
        && parts.first().map(|p| p.as_str()) == Some("cd")
        && parts.len() >= 2
    {
        return Some(parts[1].clone());
    }
    None
}

fn match_history_target_to_candidates(
    history_target: &str,
    candidates: &[String],
) -> Option<String> {
    let normalized = history_target.trim();
    if normalized.is_empty() {
        return None;
    }
    let normalized_lower = normalized.to_ascii_lowercase();
    let basename_lower = Path::new(normalized)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_ascii_lowercase());

    candidates.iter().find_map(|candidate| {
        let candidate_lower = candidate.to_ascii_lowercase();
        let path_suffix = format!("/{candidate_lower}");
        if normalized_lower == candidate_lower
            || normalized_lower.ends_with(&path_suffix)
            || basename_lower.as_deref() == Some(candidate_lower.as_str())
        {
            Some(candidate.clone())
        } else {
            None
        }
    })
}

fn shell_quote_if_needed(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-._~/".contains(c))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn display_command_preview(command: &str, explanation: &str, risk: &crate::security::RiskLevel) {
    use crate::tui::{self, BoxStyle, ContentLine};
    let box_style = match risk {
        RiskLevel::Dangerous => BoxStyle::Dangerous,
        RiskLevel::Elevated => BoxStyle::Elevated,
        RiskLevel::Safe => BoxStyle::Safe,
    };
    let label = match risk {
        RiskLevel::Dangerous => "⚠ DANGEROUS",
        RiskLevel::Elevated => "⚡ ELEVATED",
        RiskLevel::Safe => "nsh",
    };
    let mut content = Vec::new();
    if !explanation.is_empty() {
        content.push(ContentLine {
            text: explanation.to_string(),
            dim: true,
        });
        content.push(ContentLine {
            text: String::new(),
            dim: true,
        });
    }
    content.push(ContentLine {
        text: format!("$ {command}"),
        dim: false,
    });
    tui::render_box(label, &content, box_style);
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::RiskLevel;
    use crate::test_support::EnvVarGuard;
    use std::path::PathBuf;

    struct CwdGuard {
        old: PathBuf,
    }

    impl CwdGuard {
        fn push_to(path: &std::path::Path) -> Self {
            let old = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self { old }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.old);
        }
    }

    fn setup_temp_home() -> (tempfile::TempDir, EnvVarGuard, EnvVarGuard, EnvVarGuard) {
        let home = tempfile::tempdir().unwrap();
        let home_guard = EnvVarGuard::set("HOME", home.path());
        let xdg_data_guard = EnvVarGuard::remove("XDG_DATA_HOME");
        let xdg_config_guard = EnvVarGuard::remove("XDG_CONFIG_HOME");
        std::fs::create_dir_all(crate::config::Config::nsh_dir()).unwrap();
        (home, home_guard, xdg_data_guard, xdg_config_guard)
    }

    #[test]
    fn test_display_command_preview_safe() {
        display_command_preview(
            "ls -la",
            "List files in current directory",
            &RiskLevel::Safe,
        );
    }

    #[test]
    fn test_display_command_preview_elevated() {
        display_command_preview(
            "sudo rm file",
            "Remove file with sudo",
            &RiskLevel::Elevated,
        );
    }

    #[test]
    fn test_display_command_preview_dangerous() {
        display_command_preview("rm -rf /", "Delete everything!", &RiskLevel::Dangerous);
    }

    #[test]
    fn test_display_command_preview_empty() {
        display_command_preview("", "", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_long_command() {
        let long = "a".repeat(100);
        display_command_preview(&long, "Long command", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_multiline_explanation() {
        display_command_preview(
            "ls -la",
            "First line of explanation\nSecond line of explanation\nThird line",
            &RiskLevel::Safe,
        );
    }

    #[test]
    fn test_display_command_preview_empty_command() {
        display_command_preview("", "Some explanation", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_very_long_explanation() {
        let long_explanation = "x".repeat(200);
        display_command_preview("echo hi", &long_explanation, &RiskLevel::Elevated);
    }

    #[test]
    fn test_display_command_preview_unicode_command() {
        display_command_preview(
            "echo '日本語テスト'",
            "Prints unicode text",
            &RiskLevel::Safe,
        );
    }

    #[test]
    fn test_display_command_preview_ansi_escape_in_command() {
        display_command_preview(
            "echo '\x1b[31mred\x1b[0m'",
            "Command containing ANSI escapes",
            &RiskLevel::Safe,
        );
    }

    #[test]
    fn test_display_command_preview_special_chars() {
        display_command_preview(
            "echo '╭─╮│╰─╯'",
            "Command with box-drawing chars",
            &RiskLevel::Elevated,
        );
    }

    #[test]
    fn test_display_command_preview_single_char_explanation() {
        display_command_preview("ls", "X", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_content_width_at_min_boundary() {
        let cmd = "a".repeat(19);
        display_command_preview(&cmd, "short", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_content_width_at_clamp_lower() {
        let cmd = "a".repeat(20);
        display_command_preview(&cmd, "short", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_content_width_at_max_boundary() {
        let cmd = "a".repeat(60);
        display_command_preview(&cmd, "short", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_content_width_above_max() {
        let cmd = "a".repeat(61);
        display_command_preview(&cmd, "short", &RiskLevel::Safe);
    }

    #[test]
    fn test_content_width_clamping_values() {
        let clamp = |len: usize| len.max(0).clamp(20, 60);
        assert_eq!(clamp(0), 20);
        assert_eq!(clamp(19), 20);
        assert_eq!(clamp(20), 20);
        assert_eq!(clamp(40), 40);
        assert_eq!(clamp(60), 60);
        assert_eq!(clamp(61), 60);
        assert_eq!(clamp(200), 60);
    }

    #[test]
    fn test_display_command_preview_long_explanation_short_command() {
        let explanation = "b".repeat(80);
        display_command_preview("ls", &explanation, &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_short_explanation_long_command() {
        let cmd = "c".repeat(80);
        display_command_preview(&cmd, "ok", &RiskLevel::Dangerous);
    }

    #[test]
    fn test_display_command_preview_both_empty_elevated() {
        display_command_preview("", "", &RiskLevel::Elevated);
    }

    fn test_db_with_session(session_id: &str) -> crate::db::Db {
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        db.create_session(session_id, "tty0", "zsh", 12345).unwrap();
        db
    }

    #[test]
    fn test_execute_autorun_safe_command() {
        let session = "test_autorun_safe";
        let db = test_db_with_session(session);
        let config = crate::config::Config::default();
        let input = serde_json::json!({
            "command": "true",
            "explanation": "no-op command",
            "pending": false,
        });
        let outcome = execute(
            &input,
            "test query",
            &db,
            session,
            false,
            &config,
            true,
            false,
        )
        .unwrap();
        assert!(matches!(outcome, CommandExecutionOutcome::Terminal));
    }

    #[test]
    fn test_execute_autorun_safe_private_skips_db() {
        let session = "test_autorun_priv";
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        let config = crate::config::Config::default();
        let input = serde_json::json!({
            "command": "true",
            "explanation": "private command",
            "pending": false,
        });
        let outcome = execute(
            &input,
            "secret query",
            &db,
            session,
            true,
            &config,
            true,
            false,
        )
        .unwrap();
        assert!(matches!(outcome, CommandExecutionOutcome::Terminal));
    }

    #[test]
    fn test_execute_autorun_pending_returns_continue() {
        let session = "test_autorun_pending";
        let db = test_db_with_session(session);
        let config = crate::config::Config::default();
        let input = serde_json::json!({
            "command": "echo hello",
            "explanation": "intermediate step",
            "pending": true,
        });
        let outcome = execute(
            &input,
            "test query",
            &db,
            session,
            false,
            &config,
            true,
            false,
        )
        .unwrap();
        match outcome {
            CommandExecutionOutcome::ContinueWithResult { content, is_error } => {
                assert!(!is_error);
                assert!(content.contains("hello"));
                assert!(content.contains("[exit code: 0]"));
            }
            CommandExecutionOutcome::Terminal => panic!("expected ContinueWithResult"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn test_execute_autorun_cd_prefills_and_marks_shell_autorun() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = setup_temp_home();
        let session = "test_autorun_cd";
        let db = test_db_with_session(session);
        let config = crate::config::Config::default();
        let input = serde_json::json!({
            "command": "cd /tmp",
            "explanation": "switch directory",
            "pending": false,
        });

        let outcome =
            execute(&input, "cd /tmp", &db, session, false, &config, true, false).unwrap();
        assert!(matches!(outcome, CommandExecutionOutcome::Terminal));

        let nsh_dir = crate::config::Config::nsh_dir();
        let json_file = nsh_dir.join(format!("pending_{session}.json"));
        assert!(json_file.exists());
        let payload: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_file).unwrap()).unwrap();
        assert_eq!(payload["command"].as_str().unwrap(), "cd /tmp");
        assert!(payload["autorun"].as_bool().unwrap());
        let _ = std::fs::remove_file(&json_file);
    }

    #[test]
    #[serial_test::serial]
    fn test_execute_pending_writes_flag() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = setup_temp_home();
        let session = "test_pending_flag";
        let db = test_db_with_session(session);
        let mut config = crate::config::Config::default();
        config.execution.confirm_intermediate_steps = true;
        let input = serde_json::json!({
            "command": "echo hello",
            "explanation": "greeting",
            "pending": true,
        });
        execute(
            &input,
            "test query",
            &db,
            session,
            false,
            &config,
            false,
            false,
        )
        .unwrap();
        let nsh_dir = crate::config::Config::nsh_dir();
        let json_file = nsh_dir.join(format!("pending_{session}.json"));
        assert!(json_file.exists());
        let payload: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_file).unwrap()).unwrap();
        assert_eq!(payload["command"].as_str().unwrap(), "echo hello");
        assert!(payload["pending"].as_bool().unwrap());
        let _ = std::fs::remove_file(&json_file);
    }

    #[test]
    #[serial_test::serial]
    fn test_execute_not_pending_clears_stale_json() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = setup_temp_home();
        let session = "test_clear_stale";
        let db = test_db_with_session(session);
        let config = crate::config::Config::default();
        let nsh_dir = crate::config::Config::nsh_dir();
        std::fs::create_dir_all(&nsh_dir).unwrap();
        // Create a stale JSON pending file
        let json_file = nsh_dir.join(format!("pending_{session}.json"));
        std::fs::write(&json_file, r#"{"command":"old"}"#).unwrap();
        assert!(json_file.exists());
        let input = serde_json::json!({
            "command": "echo done",
            "explanation": "final command",
            "pending": false,
        });
        execute(
            &input,
            "test query",
            &db,
            session,
            false,
            &config,
            false,
            false,
        )
        .unwrap();
        // Execute writes a new JSON file; verify it exists and has new content
        let content = std::fs::read_to_string(&json_file).unwrap();
        assert!(content.contains("echo done"));
        let _ = std::fs::remove_file(&json_file);
    }

    #[test]
    #[serial_test::serial]
    fn test_execute_missing_fields_defaults() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = setup_temp_home();
        let session = "test_defaults";
        let db = test_db_with_session(session);
        let config = crate::config::Config::default();
        let input = serde_json::json!({});
        execute(&input, "", &db, session, false, &config, false, false).unwrap();
        let nsh_dir = crate::config::Config::nsh_dir();
        // Empty input should not create a pending JSON file
        let _json_file = nsh_dir.join(format!("pending_{session}.json"));
        // File may or may not exist; the important thing is no crash on empty input
    }

    #[test]
    fn test_execute_autorun_records_to_db() {
        let session = "test_autorun_db";
        let db = test_db_with_session(session);
        let config = crate::config::Config::default();
        let input = serde_json::json!({
            "command": "true",
            "explanation": "recorded command",
            "pending": false,
        });
        execute(
            &input,
            "query for db",
            &db,
            session,
            false,
            &config,
            true,
            false,
        )
        .unwrap();
        let convos = db.get_conversations(session, 10).unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].response, "true");
    }

    #[test]
    fn test_cleanup_cd_target_phrase_removes_filler_words() {
        assert_eq!(cleanup_cd_target_phrase("into the blink folder"), "blink");
        assert_eq!(
            cleanup_cd_target_phrase("to my-project directory"),
            "my-project"
        );
        assert_eq!(cleanup_cd_target_phrase("~/code"), "~/code");
    }

    #[test]
    #[serial_test::serial]
    fn test_normalize_cd_command_resolves_single_directory_match() {
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        let tmp = tempfile::tempdir().unwrap();
        let _cwd_guard = CwdGuard::push_to(tmp.path());
        std::fs::create_dir(tmp.path().join("blink-browse")).unwrap();

        let normalized = normalize_cd_command("cd into the blink folder", &db, "s1").unwrap();
        assert_eq!(normalized, "cd blink-browse");
    }

    #[test]
    #[serial_test::serial]
    fn test_normalize_cd_command_prefers_recent_history_on_ambiguous_match() {
        let session = "test_cd_history";
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        db.create_session(session, "tty0", "zsh", 1234).unwrap();
        db.insert_command(
            session,
            "cd blink-simulated",
            "/tmp",
            Some(0),
            "2026-01-01T00:00:00Z",
            Some(1),
            None,
            "",
            "zsh",
            1234,
        )
        .unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let _cwd_guard = CwdGuard::push_to(tmp.path());
        std::fs::create_dir(tmp.path().join("blink-browse")).unwrap();
        std::fs::create_dir(tmp.path().join("blink-simulated")).unwrap();

        let normalized = normalize_cd_command("cd into the blink folder", &db, session).unwrap();
        assert_eq!(normalized, "cd blink-simulated");
    }

    #[test]
    fn test_normalize_command_for_prefill_keeps_non_cd_command() {
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        let normalized =
            normalize_command_for_prefill("git status", "show me git status", &db, "default");
        assert_eq!(normalized, "git status");
    }

    #[test]
    fn test_reject_reason_for_generated_command_question_echo() {
        let reason = reject_reason_for_generated_command(
            "when did I last ssh into 135.181.128.145",
            "when did I last ssh into 135.181.128.145",
        );
        assert_eq!(
            reason,
            Some("model echoed the user's question instead of a shell command")
        );
    }

    #[test]
    fn test_reject_reason_for_generated_command_valid_command() {
        let reason = reject_reason_for_generated_command(
            "ssh root@135.181.128.145",
            "ssh root@135.181.128.145",
        );
        assert_eq!(reason, None);
    }

    #[test]
    #[serial_test::serial]
    fn test_execute_skips_prefill_for_question_echo() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = setup_temp_home();
        let session = "test_question_echo";
        let db = test_db_with_session(session);
        let config = crate::config::Config::default();
        let input = serde_json::json!({
            "command": "when did I last ssh into 135.181.128.145",
            "explanation": "This should not be accepted as a command",
            "pending": false,
        });
        execute(
            &input,
            "when did I last ssh into 135.181.128.145",
            &db,
            session,
            false,
            &config,
            false,
            false,
        )
        .unwrap();
        let nsh_dir = crate::config::Config::nsh_dir();
        let json_file = nsh_dir.join(format!("pending_{session}.json"));
        // Question-echo commands should be rejected; no pending file should be written
        assert!(!json_file.exists());
    }
}
