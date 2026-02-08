use crate::config::Config;
use crate::db::{ConversationExchange, Db};

pub struct QueryContext {
    pub os_info: String,
    pub shell: String,
    pub cwd: String,
    pub username: String,
    pub conversation_history: Vec<ConversationExchange>,
    pub other_tty_context: String,
}

pub fn build_context(
    db: &Db,
    session_id: &str,
    config: &Config,
) -> anyhow::Result<QueryContext> {
    let os_info = detect_os();

    let shell = std::env::var("SHELL")
        .unwrap_or_else(|_| "bash".into())
        .rsplit('/')
        .next()
        .unwrap_or("bash")
        .to_string();

    let cwd =
        std::env::current_dir()?.to_string_lossy().to_string();

    let username =
        std::env::var("USER").unwrap_or_else(|_| "unknown".into());

    let conversation_history =
        db.get_conversations(session_id, config.context.history_limit)
            .unwrap_or_default();

    let other_cmds = db
        .recent_commands_other_sessions(session_id, 20)
        .unwrap_or_default();

    let other_tty_context = if other_cmds.is_empty() {
        String::new()
    } else {
        let mut ctx = String::new();
        let mut current_tty = String::new();
        for cmd in &other_cmds {
            if cmd.tty != current_tty {
                ctx.push_str(&format!("\n[TTY: {}]\n", cmd.tty));
                current_tty.clone_from(&cmd.tty);
            }
            let status = match cmd.exit_code {
                Some(0) | None => "\u{2713}",
                _ => "\u{2717}",
            };
            ctx.push_str(&format!(
                "  {} {} [{}] {}\n",
                status,
                cmd.command,
                cmd.cwd.as_deref().unwrap_or("?"),
                cmd.started_at,
            ));
        }
        ctx
    };

    Ok(QueryContext {
        os_info,
        shell,
        cwd,
        username,
        conversation_history,
        other_tty_context,
    })
}

fn detect_os() -> String {
    #[cfg(target_os = "macos")]
    {
        let version = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            })
            .unwrap_or_default();
        let arch = std::env::consts::ARCH;
        format!("macOS {version} {arch}")
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            let pretty = content
                .lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .and_then(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|v| v.trim_matches('"').to_string())
                .unwrap_or_else(|| "Linux".into());
            let arch = std::env::consts::ARCH;
            format!("{pretty} {arch}")
        } else {
            format!("Linux {}", std::env::consts::ARCH)
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
    }
}
