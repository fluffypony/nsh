use crate::memory::types::{RoutingDecision, CoreUpdateDecision, ShellEvent, ShellEventType};

pub fn route(event: &ShellEvent) -> RoutingDecision {
    let mut decision = RoutingDecision {
        update_episodic: true, // almost always create an episodic record
        ..Default::default()
    };

    match event.event_type {
        ShellEventType::SessionStart | ShellEventType::SessionEnd => {
            decision.reasoning = "Session lifecycle event".into();
            return decision;
        }
        ShellEventType::ProjectSwitch => {
            decision.reasoning = "Project switch event".into();
            return decision;
        }
        ShellEventType::UserInstruction => {
            if let Some(ref text) = event.instruction {
                if is_explicit_memory_directive(text) {
                    decision.update_core = Some(CoreUpdateDecision {
                        label: "human".into(),
                        op: "append".into(),
                    });
                    decision.reasoning = "Explicit memory directive detected".into();
                    return decision;
                }
            }
            decision.update_semantic = true;
            decision.reasoning = "User instruction may contain useful facts".into();
            return decision;
        }
        _ => {}
    }

    let cmd = event.command.as_deref().unwrap_or("");
    let output = event.output.as_deref().unwrap_or("");

    if command_reveals_secrets(cmd) || output_contains_secrets(output) {
        decision.update_knowledge = true;
        decision.reasoning = "Potential secret detected".into();
    }

    if command_reveals_project_info(cmd) {
        decision.update_semantic = true;
        decision.reasoning = "Project information revealed".into();
    }

    if is_environment_changing_command(cmd) {
        decision.update_core = Some(CoreUpdateDecision {
            label: "environment".into(),
            op: "append".into(),
        });
        decision.reasoning = "Environment change detected".into();
    }

    if is_preference_revealing(cmd) {
        decision.update_core = Some(CoreUpdateDecision {
            label: "human".into(),
            op: "append".into(),
        });
        decision.reasoning = "User preference detected".into();
    }

    if let Some(ref path) = event.file_path {
        if is_config_file(path) {
            decision.update_resource = true;
            decision.reasoning = "Config file interaction".into();
        }
    }

    if reads_significant_file(cmd) {
        decision.update_resource = true;
        decision.reasoning = "Significant file read".into();
    }

    if looks_like_config_or_doc(output) && output.len() > 100 {
        decision.update_resource = true;
        decision.reasoning = "Structured config/doc output detected".into();
    }

    if event.exit_code.is_some() && event.exit_code != Some(0) {
        decision.update_procedural = true;
        decision.reasoning = "Error may lead to procedural learning".into();
    }

    if decision.reasoning.is_empty() {
        decision.reasoning = "Standard command execution".into();
    }

    decision
}

fn command_reveals_secrets(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    let patterns = [
        "export api_key", "export api_secret", "export token",
        "export secret", "export password", "export aws_",
        "cat .env", "cat ~/.env", "source .env",
        "ssh-add", "aws configure", "gcloud auth",
        "docker login", "npm login", "heroku auth",
    ];
    patterns.iter().any(|p| lower.contains(p))
}

fn output_contains_secrets(output: &str) -> bool {
    let patterns = [
        "sk-", "ghp_", "gho_", "AKIA", "AIza",
        "-----BEGIN", "xoxb-", "xoxp-",
        "npm_", "pypi-",
    ];
    patterns.iter().any(|p| output.contains(p))
}

fn command_reveals_project_info(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    let triggers = [
        "cargo", "npm", "pip", "pip3", "poetry",
        "git remote", "git clone", "docker", "kubectl",
        "terraform", "ansible", "make", "cmake",
        "go build", "go mod", "gradle", "maven", "mvn",
    ];
    triggers.iter().any(|t| lower.starts_with(t) || lower.contains(&format!(" {t}")))
}

fn is_config_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    let extensions = [
        ".toml", ".yaml", ".yml", ".json", ".env",
        ".ini", ".cfg", ".conf", ".config",
    ];
    let names = [
        "makefile", "dockerfile", "docker-compose",
        "package.json", "cargo.toml", "go.mod",
        "requirements.txt", "pyproject.toml",
        ".gitignore", ".editorconfig",
    ];
    extensions.iter().any(|e| lower.ends_with(e))
        || names.iter().any(|n| lower.ends_with(n))
}

fn is_environment_changing_command(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    let triggers = [
        "export ", "source ", "nvm use", "nvm install",
        "pyenv ", "rbenv ", "rustup default", "rustup toolchain",
        "asdf ", "brew install", "apt install", "dnf install",
        "pacman -S", "pip install", "npm install -g",
        "cargo install",
    ];
    triggers.iter().any(|t| lower.starts_with(t))
}

fn is_preference_revealing(cmd: &str) -> bool {
    let first = cmd.split_whitespace().next().unwrap_or("");
    let base = first.rsplit('/').next().unwrap_or(first);
    let preference_tools = [
        "rg", "bat", "exa", "eza", "fd", "dust", "procs",
        "bottom", "btm", "zoxide", "starship", "delta",
        "lazygit", "gitui", "helix", "hx", "nvim", "micro",
    ];
    preference_tools.contains(&base)
}

fn reads_significant_file(cmd: &str) -> bool {
    let first = cmd.split_whitespace().next().unwrap_or("");
    let base = first.rsplit('/').next().unwrap_or(first);
    let readers = ["cat", "less", "more", "head", "tail", "bat"];
    if !readers.contains(&base) {
        return false;
    }
    let rest = cmd.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
    is_config_file(&rest) || rest.contains("README") || rest.contains("LICENSE")
}

fn is_explicit_memory_directive(text: &str) -> bool {
    let lower = text.to_lowercase();
    let directives = [
        "remember that", "i prefer", "always use", "never use",
        "the password is", "my name is", "i am", "i like",
        "don't forget", "keep in mind", "note that",
        "from now on", "going forward",
    ];
    directives.iter().any(|d| lower.contains(d))
}

fn looks_like_config_or_doc(output: &str) -> bool {
    let line_count = output.lines().count();
    if line_count < 3 {
        return false;
    }
    let structured_indicators = ["=", ":", "->", "│", "├", "└"];
    let indicator_count = structured_indicators
        .iter()
        .filter(|i| output.contains(**i))
        .count();
    indicator_count >= 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::types::GitContext;

    fn make_cmd_event(cmd: &str) -> ShellEvent {
        ShellEvent {
            event_type: ShellEventType::CommandExecution,
            command: Some(cmd.to_string()),
            output: None,
            exit_code: Some(0),
            working_dir: Some("/home/user".into()),
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        }
    }

    #[test]
    fn route_session_events() {
        let event = ShellEvent {
            event_type: ShellEventType::SessionStart,
            command: None,
            output: None,
            exit_code: None,
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        };
        let d = route(&event);
        assert!(d.update_episodic);
        assert!(d.update_core.is_none());
    }

    #[test]
    fn route_memory_directive() {
        let event = ShellEvent {
            event_type: ShellEventType::UserInstruction,
            command: None,
            output: None,
            exit_code: None,
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: Some("Remember that I prefer dark mode".into()),
            file_path: None,
        };
        let d = route(&event);
        assert!(d.update_core.is_some());
    }

    #[test]
    fn route_project_command() {
        let d = route(&make_cmd_event("cargo build --release"));
        assert!(d.update_semantic);
    }

    #[test]
    fn route_env_change() {
        let d = route(&make_cmd_event("export API_KEY=something"));
        assert!(d.update_core.is_some());
        assert!(d.update_knowledge); // also triggers secret detection
    }

    #[test]
    fn route_error_command() {
        let mut event = make_cmd_event("cargo test");
        event.exit_code = Some(1);
        let d = route(&event);
        assert!(d.update_procedural);
    }

    #[test]
    fn explicit_memory_directives() {
        assert!(is_explicit_memory_directive("Remember that I use vim"));
        assert!(is_explicit_memory_directive("I prefer tabs over spaces"));
        assert!(is_explicit_memory_directive("Always use --verbose"));
        assert!(!is_explicit_memory_directive("How do I build this"));
    }
}
