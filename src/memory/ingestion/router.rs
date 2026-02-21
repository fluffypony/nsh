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

    #[test]
    fn route_secret_in_output() {
        let mut event = make_cmd_event("echo hello");
        event.output = Some("Your API key is sk-abc123".into());
        let d = route(&event);
        assert!(d.update_knowledge, "output containing sk- should trigger knowledge update");
    }

    #[test]
    fn route_docker_login_detects_secret() {
        let d = route(&make_cmd_event("docker login -u user"));
        assert!(d.update_knowledge, "docker login should flag secret detection");
    }

    #[test]
    fn route_ssh_add_detects_secret() {
        let d = route(&make_cmd_event("ssh-add ~/.ssh/id_rsa"));
        assert!(d.update_knowledge, "ssh-add should flag secret detection");
    }

    #[test]
    fn route_cat_env_detects_secret() {
        let d = route(&make_cmd_event("cat .env"));
        assert!(d.update_knowledge, "cat .env should flag secret detection");
    }

    #[test]
    fn route_aws_configure_detects_secret() {
        let d = route(&make_cmd_event("aws configure"));
        assert!(d.update_knowledge, "aws configure should flag secret detection");
    }

    #[test]
    fn route_gcloud_auth_detects_secret() {
        let d = route(&make_cmd_event("gcloud auth login"));
        assert!(d.update_knowledge, "gcloud auth should flag secret detection");
    }

    #[test]
    fn route_output_with_ghp_token() {
        let mut event = make_cmd_event("echo token");
        event.output = Some("ghp_abc123def456".into());
        let d = route(&event);
        assert!(d.update_knowledge, "ghp_ token in output should flag secret");
    }

    #[test]
    fn route_output_with_aws_key() {
        let mut event = make_cmd_event("echo key");
        event.output = Some("AKIAIOSFODNN7EXAMPLE".into());
        let d = route(&event);
        assert!(d.update_knowledge, "AKIA prefix in output should flag secret");
    }

    #[test]
    fn route_output_with_private_key() {
        let mut event = make_cmd_event("cat key");
        event.output = Some("-----BEGIN RSA PRIVATE KEY-----\nfoo\n-----END".into());
        let d = route(&event);
        assert!(d.update_knowledge, "-----BEGIN in output should flag secret");
    }

    #[test]
    fn route_npm_project_info() {
        let d = route(&make_cmd_event("npm install express"));
        assert!(d.update_semantic, "npm should reveal project info");
    }

    #[test]
    fn route_pip_project_info() {
        let d = route(&make_cmd_event("pip install requests"));
        assert!(d.update_semantic, "pip should reveal project info");
    }

    #[test]
    fn route_git_clone_project_info() {
        let d = route(&make_cmd_event("git clone https://github.com/user/repo"));
        assert!(d.update_semantic, "git clone should reveal project info");
    }

    #[test]
    fn route_docker_project_info() {
        let d = route(&make_cmd_event("docker build -t myapp ."));
        assert!(d.update_semantic, "docker should reveal project info");
    }

    #[test]
    fn route_kubectl_project_info() {
        let d = route(&make_cmd_event("kubectl get pods"));
        assert!(d.update_semantic, "kubectl should reveal project info");
    }

    #[test]
    fn route_terraform_project_info() {
        let d = route(&make_cmd_event("terraform plan"));
        assert!(d.update_semantic, "terraform should reveal project info");
    }

    #[test]
    fn route_go_build_project_info() {
        let d = route(&make_cmd_event("go build ./..."));
        assert!(d.update_semantic, "go build should reveal project info");
    }

    #[test]
    fn route_gradle_project_info() {
        let d = route(&make_cmd_event("gradle build"));
        assert!(d.update_semantic, "gradle should reveal project info");
    }

    #[test]
    fn route_preference_nvim() {
        let d = route(&make_cmd_event("nvim src/main.rs"));
        assert!(d.update_core.is_some(), "nvim should reveal user preference");
        assert_eq!(d.update_core.as_ref().unwrap().label, "human");
    }

    #[test]
    fn route_preference_rg() {
        let d = route(&make_cmd_event("rg TODO src/"));
        assert!(d.update_core.is_some(), "rg should reveal user preference");
    }

    #[test]
    fn route_preference_bat() {
        let d = route(&make_cmd_event("bat Cargo.toml"));
        assert!(d.update_core.is_some(), "bat should reveal user preference");
    }

    #[test]
    fn route_preference_lazygit() {
        let d = route(&make_cmd_event("lazygit"));
        assert!(d.update_core.is_some(), "lazygit should reveal user preference");
    }

    #[test]
    fn route_env_change_brew_install() {
        let d = route(&make_cmd_event("brew install ripgrep"));
        assert!(d.update_core.is_some(), "brew install should flag environment change");
        assert_eq!(d.update_core.as_ref().unwrap().label, "environment");
    }

    #[test]
    fn route_env_change_nvm_use() {
        let d = route(&make_cmd_event("nvm use 18"));
        assert!(d.update_core.is_some(), "nvm use should flag environment change");
    }

    #[test]
    fn route_env_change_rustup() {
        let d = route(&make_cmd_event("rustup default nightly"));
        assert!(d.update_core.is_some(), "rustup should flag environment change");
    }

    #[test]
    fn route_env_change_pip_install() {
        let d = route(&make_cmd_event("pip install flask"));
        assert!(d.update_core.is_some(), "pip install should flag environment change");
    }

    #[test]
    fn route_env_change_cargo_install() {
        let d = route(&make_cmd_event("cargo install ripgrep"));
        assert!(d.update_core.is_some(), "cargo install should flag environment change");
    }

    #[test]
    fn route_config_file_toml() {
        let mut event = make_cmd_event("vim config.toml");
        event.file_path = Some("config.toml".into());
        let d = route(&event);
        assert!(d.update_resource, ".toml file should trigger resource update");
    }

    #[test]
    fn route_config_file_yaml() {
        let mut event = make_cmd_event("vim deploy.yaml");
        event.file_path = Some("deploy.yaml".into());
        let d = route(&event);
        assert!(d.update_resource, ".yaml file should trigger resource update");
    }

    #[test]
    fn route_config_file_dockerfile() {
        let mut event = make_cmd_event("vim Dockerfile");
        event.file_path = Some("Dockerfile".into());
        let d = route(&event);
        assert!(d.update_resource, "Dockerfile should trigger resource update");
    }

    #[test]
    fn route_config_file_package_json() {
        let mut event = make_cmd_event("code package.json");
        event.file_path = Some("package.json".into());
        let d = route(&event);
        assert!(d.update_resource, "package.json should trigger resource update");
    }

    #[test]
    fn route_reads_significant_file_readme() {
        let d = route(&make_cmd_event("cat README.md"));
        assert!(d.update_resource, "cat README should trigger resource update");
    }

    #[test]
    fn route_reads_significant_file_config() {
        let d = route(&make_cmd_event("cat .editorconfig"));
        assert!(d.update_resource, "cat .editorconfig should trigger resource update");
    }

    #[test]
    fn route_structured_output_as_resource() {
        let mut event = make_cmd_event("cargo tree");
        // Must be > 100 chars and have >= 2 structured indicators
        let structured_output = (0..10).map(|i| format!("├── dep{i} = v{i}.0.0: description")).collect::<Vec<_>>().join("\n");
        event.output = Some(structured_output);
        let d = route(&event);
        assert!(d.update_resource, "structured output should trigger resource update");
    }

    #[test]
    fn route_low_signal_no_extra_flags() {
        let d = route(&make_cmd_event("ls"));
        assert!(d.update_episodic);
        assert!(d.update_core.is_none());
        assert!(!d.update_semantic);
        assert!(!d.update_knowledge);
        assert!(!d.update_resource);
    }

    #[test]
    fn route_project_switch_event() {
        let event = ShellEvent {
            event_type: ShellEventType::ProjectSwitch,
            command: None,
            output: None,
            exit_code: None,
            working_dir: Some("/home/user/new-project".into()),
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        };
        let d = route(&event);
        assert!(d.update_episodic);
        assert!(d.only_episodic(), "ProjectSwitch should only update episodic");
    }

    #[test]
    fn route_user_instruction_without_directive() {
        let event = ShellEvent {
            event_type: ShellEventType::UserInstruction,
            command: None,
            output: None,
            exit_code: None,
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: Some("How do I build this project".into()),
            file_path: None,
        };
        let d = route(&event);
        assert!(d.update_semantic, "non-directive instruction should update semantic");
        assert!(d.update_core.is_none(), "non-directive instruction should not update core");
    }

    #[test]
    fn route_memory_directive_never_use() {
        let event = ShellEvent {
            event_type: ShellEventType::UserInstruction,
            command: None,
            output: None,
            exit_code: None,
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: Some("Never use tabs for indentation".into()),
            file_path: None,
        };
        let d = route(&event);
        assert!(d.update_core.is_some());
        assert_eq!(d.update_core.as_ref().unwrap().label, "human");
    }

    #[test]
    fn route_memory_directive_my_name_is() {
        let event = ShellEvent {
            event_type: ShellEventType::UserInstruction,
            command: None,
            output: None,
            exit_code: None,
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: Some("My name is Alice".into()),
            file_path: None,
        };
        let d = route(&event);
        assert!(d.update_core.is_some());
    }

    #[test]
    fn route_has_any_updates_all_flags() {
        let d = route(&make_cmd_event("export API_KEY=secret"));
        assert!(d.has_any_updates());
    }

    #[test]
    fn route_only_episodic_for_simple() {
        let d = route(&make_cmd_event("echo hello"));
        assert!(d.update_episodic);
        // echo is not low-signal, so it's episodic-only unless other conditions match
    }

    #[test]
    fn explicit_memory_directive_from_now_on() {
        assert!(is_explicit_memory_directive("From now on, use spaces"));
    }

    #[test]
    fn explicit_memory_directive_going_forward() {
        assert!(is_explicit_memory_directive("Going forward, let's use Rust"));
    }

    #[test]
    fn explicit_memory_directive_dont_forget() {
        assert!(is_explicit_memory_directive("Don't forget to run tests"));
    }

    #[test]
    fn route_export_api_secret() {
        let d = route(&make_cmd_event("export API_SECRET=mysecret"));
        assert!(d.update_knowledge, "export API_SECRET should flag secret");
    }

    #[test]
    fn route_source_env_detects_secret() {
        let d = route(&make_cmd_event("source .env"));
        assert!(d.update_knowledge, "source .env should flag secret");
    }

    #[test]
    fn route_npm_login_detects_secret() {
        let d = route(&make_cmd_event("npm login"));
        assert!(d.update_knowledge, "npm login should flag secret");
    }

    #[test]
    fn route_heroku_auth_detects_secret() {
        let d = route(&make_cmd_event("heroku auth:login"));
        assert!(d.update_knowledge, "heroku auth should flag secret");
    }

    #[test]
    fn route_output_with_xoxb_slack_token() {
        let mut event = make_cmd_event("echo test");
        event.output = Some("xoxb-123-456-abc".into());
        let d = route(&event);
        assert!(d.update_knowledge, "xoxb- token in output should flag secret");
    }

    #[test]
    fn route_output_with_npm_token() {
        let mut event = make_cmd_event("echo test");
        event.output = Some("npm_abc123def".into());
        let d = route(&event);
        assert!(d.update_knowledge, "npm_ token in output should flag secret");
    }

    #[test]
    fn route_output_with_pypi_token() {
        let mut event = make_cmd_event("echo test");
        event.output = Some("pypi-abc123".into());
        let d = route(&event);
        assert!(d.update_knowledge, "pypi- token in output should flag secret");
    }

    #[test]
    fn route_make_project_info() {
        let d = route(&make_cmd_event("make build"));
        assert!(d.update_semantic, "make should reveal project info");
    }

    #[test]
    fn route_cmake_project_info() {
        let d = route(&make_cmd_event("cmake .."));
        assert!(d.update_semantic, "cmake should reveal project info");
    }

    #[test]
    fn route_go_mod_project_info() {
        let d = route(&make_cmd_event("go mod tidy"));
        assert!(d.update_semantic, "go mod should reveal project info");
    }

    #[test]
    fn route_maven_project_info() {
        let d = route(&make_cmd_event("mvn package"));
        assert!(d.update_semantic, "mvn should reveal project info");
    }

    #[test]
    fn route_git_remote_project_info() {
        let d = route(&make_cmd_event("git remote -v"));
        assert!(d.update_semantic, "git remote should reveal project info");
    }

    #[test]
    fn route_ansible_project_info() {
        let d = route(&make_cmd_event("ansible-playbook deploy.yml"));
        assert!(d.update_semantic, "ansible should reveal project info");
    }

    #[test]
    fn route_env_change_source() {
        let d = route(&make_cmd_event("source ~/.bashrc"));
        assert!(d.update_core.is_some(), "source should flag environment change");
    }

    #[test]
    fn route_env_change_pyenv() {
        let d = route(&make_cmd_event("pyenv install 3.12"));
        assert!(d.update_core.is_some(), "pyenv should flag environment change");
    }

    #[test]
    fn route_env_change_asdf() {
        let d = route(&make_cmd_event("asdf install nodejs 20"));
        assert!(d.update_core.is_some(), "asdf should flag environment change");
    }

    #[test]
    fn route_env_change_apt_install() {
        let d = route(&make_cmd_event("apt install vim"));
        assert!(d.update_core.is_some(), "apt install should flag environment change");
    }

    #[test]
    fn route_env_change_npm_global() {
        let d = route(&make_cmd_event("npm install -g typescript"));
        assert!(d.update_core.is_some(), "npm install -g should flag environment change");
    }

    #[test]
    fn route_preference_eza() {
        let d = route(&make_cmd_event("eza -la"));
        assert!(d.update_core.is_some(), "eza should reveal user preference");
    }

    #[test]
    fn route_preference_fd() {
        let d = route(&make_cmd_event("fd main.rs"));
        assert!(d.update_core.is_some(), "fd should reveal user preference");
    }

    #[test]
    fn route_preference_helix() {
        let d = route(&make_cmd_event("hx src/main.rs"));
        assert!(d.update_core.is_some(), "hx (helix) should reveal user preference");
    }

    #[test]
    fn route_preference_delta() {
        let d = route(&make_cmd_event("delta file1 file2"));
        assert!(d.update_core.is_some(), "delta should reveal user preference");
    }

    #[test]
    fn route_preference_zoxide() {
        let d = route(&make_cmd_event("zoxide query project"));
        assert!(d.update_core.is_some(), "zoxide should reveal user preference");
    }

    #[test]
    fn route_config_file_env() {
        let mut event = make_cmd_event("vim .env");
        event.file_path = Some(".env".into());
        let d = route(&event);
        assert!(d.update_resource, ".env file should trigger resource update");
    }

    #[test]
    fn route_config_file_gitignore() {
        let mut event = make_cmd_event("vim .gitignore");
        event.file_path = Some(".gitignore".into());
        let d = route(&event);
        assert!(d.update_resource, ".gitignore should trigger resource update");
    }

    #[test]
    fn route_cat_license() {
        let d = route(&make_cmd_event("cat LICENSE"));
        assert!(d.update_resource, "cat LICENSE should trigger resource update");
    }

    #[test]
    fn route_bat_cargo_toml() {
        // bat is both a preference AND reads a significant file
        let d = route(&make_cmd_event("bat Cargo.toml"));
        assert!(d.update_resource, "bat Cargo.toml should trigger resource update");
        assert!(d.update_core.is_some(), "bat usage should reveal user preference");
    }

    #[test]
    fn looks_like_config_or_doc_positive() {
        let output = "key1 = value1\nkey2: value2\n├── dir\n└── file";
        assert!(looks_like_config_or_doc(output));
    }

    #[test]
    fn looks_like_config_or_doc_negative_short() {
        let output = "ok";
        assert!(!looks_like_config_or_doc(output));
    }

    #[test]
    fn looks_like_config_or_doc_negative_no_indicators() {
        let output = "line 1\nline 2\nline 3\nline 4";
        assert!(!looks_like_config_or_doc(output));
    }
}
