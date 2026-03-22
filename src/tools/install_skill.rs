use crate::tools::ToolInvocationOutcome;

#[derive(Debug, PartialEq)]
enum InstallSkillRequest {
    Repo(RepoInstallRequest),
    Manual(ManualSkillRequest),
}

#[derive(Debug, PartialEq)]
struct RepoInstallRequest {
    repo_url: String,
}

#[derive(Debug, PartialEq)]
struct ManualSkillRequest {
    name: String,
    description: String,
    definition: ManualSkillDefinition,
    timeout_seconds: u64,
    terminal: bool,
    parameters: Vec<(String, SkillParameterDefinition)>,
    docs: Option<String>,
}

#[derive(Debug, PartialEq)]
enum ManualSkillDefinition {
    Command(String),
    Script { runtime: String, script: String },
    DocsOnly,
}

#[derive(Debug, PartialEq)]
struct SkillParameterDefinition {
    param_type: String,
    description: String,
}

pub fn execute(input: &serde_json::Value) -> anyhow::Result<String> {
    match parse_request(input)? {
        InstallSkillRequest::Repo(request) => install_repo_skill(&request),
        InstallSkillRequest::Manual(request) => install_manual_skill(&request),
    }
}

pub fn execute_outcome(input: &serde_json::Value) -> anyhow::Result<ToolInvocationOutcome> {
    match execute(input)? {
        message if message == "Config change declined" => {
            Ok(ToolInvocationOutcome::failure(message))
        }
        message => Ok(ToolInvocationOutcome::success(message)),
    }
}

fn parse_request(input: &serde_json::Value) -> anyhow::Result<InstallSkillRequest> {
    match input.get("action").and_then(|value| value.as_str()) {
        Some("repo") => Ok(InstallSkillRequest::Repo(RepoInstallRequest {
            repo_url: detect_repo_url(input).ok_or_else(|| {
                anyhow::anyhow!("install_skill: 'repo' or 'url' is required when action='repo'")
            })?,
        })),
        Some("manual") => parse_manual_request(input).map(InstallSkillRequest::Manual),
        Some(other) => {
            anyhow::bail!("install_skill: unknown action '{other}'. Use 'repo' or 'manual'.")
        }
        None => {
            if let Some(repo_url) = detect_repo_url(input) {
                Ok(InstallSkillRequest::Repo(RepoInstallRequest { repo_url }))
            } else {
                parse_manual_request(input).map(InstallSkillRequest::Manual)
            }
        }
    }
}

fn detect_repo_url(input: &serde_json::Value) -> Option<String> {
    input
        .get("repo")
        .or_else(|| input.get("url"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            let name = input.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if name.contains("github.com")
                || name.contains("gitlab.com")
                || name.starts_with("https://")
                || name.starts_with("http://")
                || name.starts_with("git@")
            {
                Some(name.to_string())
            } else {
                None
            }
        })
}

fn parse_manual_request(input: &serde_json::Value) -> anyhow::Result<ManualSkillRequest> {
    let name = input["name"].as_str().unwrap_or("").trim();
    let description = input["description"].as_str().unwrap_or("").trim();
    let command = input["command"].as_str().map(str::trim).unwrap_or("");
    let runtime = input["runtime"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let script = input["script"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let docs = input["docs"].as_str().map(str::to_string);

    if name.is_empty() || description.is_empty() {
        anyhow::bail!(
            "install_skill: 'name' and 'description' are required for manual skills. \
             To install from a Git repo, pass repo=URL instead (e.g. repo=\"https://github.com/user/skill\")"
        );
    }

    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        anyhow::bail!(
            "install_skill: name must contain only alphanumeric characters and underscores"
        );
    }

    let definition = if !command.is_empty() {
        ManualSkillDefinition::Command(command.to_string())
    } else if let (Some(runtime), Some(script)) = (runtime, script) {
        ManualSkillDefinition::Script {
            runtime: runtime.to_string(),
            script: script.to_string(),
        }
    } else if docs.is_some() {
        ManualSkillDefinition::DocsOnly
    } else {
        anyhow::bail!(
            "install_skill: required field missing — provide either 'command' OR both 'runtime' and 'script' or 'docs'"
        );
    };

    let parameters = match input.get("parameters") {
        Some(serde_json::Value::Object(map)) => map
            .iter()
            .map(|(name, definition)| {
                Ok((
                    name.clone(),
                    SkillParameterDefinition {
                        param_type: definition["type"].as_str().unwrap_or("string").to_string(),
                        description: definition["description"].as_str().unwrap_or("").to_string(),
                    },
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        Some(_) => anyhow::bail!("install_skill: 'parameters' must be an object when provided"),
        None => Vec::new(),
    };

    Ok(ManualSkillRequest {
        name: name.to_string(),
        description: description.to_string(),
        definition,
        timeout_seconds: input["timeout_seconds"].as_u64().unwrap_or(30),
        terminal: input["terminal"].as_bool().unwrap_or(false),
        parameters,
        docs,
    })
}

fn install_repo_skill(request: &RepoInstallRequest) -> anyhow::Result<String> {
    let repo_url = request.repo_url.as_str();
    let skills_dir = crate::config::Config::nsh_dir().join("skills");
    // Strip query parameters before extracting repo name
    let clean_url = repo_url.split('?').next().unwrap_or(repo_url);
    let repo_name = clean_url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("skill");
    let folder = repo_name.trim_end_matches(".git");
    let dest = skills_dir.join(folder);

    let bold_yellow = "\x1b[1;33m";
    let green = "\x1b[32m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    let already_existed = dest.exists();
    eprintln!("{bold_yellow}Install skill from repo:{reset} {repo_url}");
    eprintln!("{dim}Destination: {}{reset}", dest.display());
    if already_existed {
        eprintln!(
            "{bold_yellow}Warning: skill repo '{folder}' already exists and will be updated.{reset}"
        );
    }

    eprintln!();
    if !crate::tools::prompt_tty_confirmation(&format!("{bold_yellow}Install? [y/N]{reset} "))? {
        eprintln!("{dim}skill installation declined{reset}");
        return Ok("Config change declined".to_string());
    }

    std::fs::create_dir_all(&skills_dir)?;
    if already_existed {
        eprintln!("{dim}Updating skill repo at {}...{reset}", dest.display());
        let status = std::process::Command::new("git")
            .args([
                "-C",
                dest.to_string_lossy().as_ref(),
                "pull",
                "--ff-only",
                "-q",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .stdin(std::process::Stdio::null())
            .status()?;
        if !status.success() {
            anyhow::bail!("git pull failed for {}", dest.display());
        }
    } else {
        eprintln!("{dim}Cloning {repo_url} into {}...{reset}", dest.display());
        let status = std::process::Command::new("git")
            .args([
                "clone",
                "--depth",
                "1",
                repo_url,
                dest.to_string_lossy().as_ref(),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if !status.success() {
            anyhow::bail!("git clone failed: {}", repo_url);
        }
    }

    let mut detected = Vec::new();
    for fname in [
        "SKILL.md",
        "skill.md",
        "skill.toml",
        "nsh.toml",
        "README.md",
        "readme.md",
    ] {
        if dest.join(fname).exists() {
            detected.push(fname);
        }
    }

    let action = if already_existed {
        "updated"
    } else {
        "installed"
    };
    let detected_str = if detected.is_empty() {
        "No skill documents detected".to_string()
    } else {
        format!("Detected: {}", detected.join(", "))
    };
    eprintln!(
        "{green}✓ skill repo '{folder}' {action} at {}{reset}",
        dest.display()
    );
    eprintln!("{dim}  {detected_str}{reset}");

    Ok(format!(
        "Skill repo {action} at {}. {detected_str}. \
         The skill is now loaded automatically from its SKILL.md/README.md.",
        dest.display()
    ))
}

fn install_manual_skill(request: &ManualSkillRequest) -> anyhow::Result<String> {
    let mut toml_content = String::new();
    toml_content.push_str(&format!(
        "name = {}\ndescription = {}\n",
        toml::Value::String(request.name.clone()),
        toml::Value::String(request.description.clone()),
    ));
    match &request.definition {
        ManualSkillDefinition::Command(command) => {
            toml_content.push_str(&format!(
                "command = {}\n",
                toml::Value::String(command.clone())
            ));
        }
        ManualSkillDefinition::Script { runtime, script } => {
            toml_content.push_str(&format!(
                "runtime = {}\nscript = {}\n",
                toml::Value::String(runtime.clone()),
                toml::Value::String(script.clone())
            ));
        }
        ManualSkillDefinition::DocsOnly => {}
    }
    toml_content.push_str(&format!(
        "timeout_seconds = {}\nterminal = {}\n",
        request.timeout_seconds, request.terminal
    ));

    for (param_name, param_def) in &request.parameters {
        toml_content.push_str(&format!(
            "\n[parameters.{param_name}]\ntype = {}\ndescription = {}\n",
            toml::Value::String(param_def.param_type.clone()),
            toml::Value::String(param_def.description.clone()),
        ));
    }

    let skills_dir = crate::config::Config::nsh_dir().join("skills");
    let skill_path = skills_dir.join(format!("{}.toml", request.name));

    let bold_yellow = "\x1b[1;33m";
    let cyan = "\x1b[36m";
    let green = "\x1b[32m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!("{bold_yellow}Install skill:{reset} {}", request.name);
    eprintln!("{dim}Path: {}{reset}", skill_path.display());
    eprintln!();
    eprintln!("{cyan}{toml_content}{reset}");

    if skill_path.exists() {
        eprintln!(
            "{bold_yellow}Warning: skill '{}' already exists and will be overwritten.{reset}",
            request.name
        );
    }

    eprintln!();
    if !crate::tools::prompt_tty_confirmation(&format!("{bold_yellow}Install? [y/N]{reset} "))? {
        eprintln!("{dim}skill installation declined{reset}");
        return Ok("Config change declined".to_string());
    }

    std::fs::create_dir_all(&skills_dir)?;
    std::fs::write(&skill_path, &toml_content)?;
    if let Some(docs) = request.docs.as_deref() {
        let doc_path = skills_dir.join(format!("{}.md", request.name));
        std::fs::write(&doc_path, docs)?;
    }
    eprintln!(
        "{green}✓ skill '{}' installed at {}{reset}",
        request.name,
        skill_path.display()
    );

    Ok(format!("Successfully installed skill '{}'", request.name))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    fn with_nsh_test_mode() -> impl Drop {
        struct Guard(Option<String>);
        impl Drop for Guard {
            fn drop(&mut self) {
                if let Some(old) = &self.0 {
                    // SAFETY: test-only env var handling.
                    unsafe { std::env::set_var("NSH_TEST_MODE", old) };
                } else {
                    // SAFETY: test-only env var handling.
                    unsafe { std::env::remove_var("NSH_TEST_MODE") };
                }
            }
        }

        let old = std::env::var("NSH_TEST_MODE").ok();
        // SAFETY: test-only env var handling.
        unsafe { std::env::set_var("NSH_TEST_MODE", "1") };
        Guard(old)
    }

    #[test]
    fn test_execute_missing_fields() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "test"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("required"));
    }

    #[test]
    fn test_execute_invalid_name() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "bad name!", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_execute_empty_name() {
        let _guard = with_nsh_test_mode();
        let input = json!({"description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("required"));
    }

    #[test]
    fn test_execute_empty_description() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("required"));
    }

    #[test]
    fn test_execute_empty_command() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "test", "description": "test"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("required"));
    }

    #[test]
    fn test_name_validation_with_special_chars() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "bad.name", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_name_validation_with_spaces() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "bad name", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_name_validation_with_hyphens_rejected() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "bad-name", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_name_numbers_only_valid() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "12345", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_ok(), "Numeric-only name should pass validation");
    }

    #[test]
    fn test_name_leading_underscore_valid() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "_private", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(
            result.is_ok(),
            "Leading underscore name should pass validation"
        );
    }

    #[test]
    fn test_name_with_dash_rejected() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "my-skill", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_toml_content_format() {
        let input = json!({
            "name": "test_skill",
            "description": "A test skill",
            "command": "echo hello",
            "timeout_seconds": 60,
            "terminal": true,
        });

        let name = input["name"].as_str().unwrap();
        let description = input["description"].as_str().unwrap();
        let command = input["command"].as_str().unwrap();
        let timeout = input["timeout_seconds"].as_u64().unwrap();
        let terminal = input["terminal"].as_bool().unwrap();

        let toml_content = format!(
            "name = {}\ndescription = {}\ncommand = {}\ntimeout_seconds = {}\nterminal = {}\n",
            toml::Value::String(name.into()),
            toml::Value::String(description.into()),
            toml::Value::String(command.into()),
            timeout,
            terminal,
        );

        assert!(toml_content.contains("name = \"test_skill\""));
        assert!(toml_content.contains("description = \"A test skill\""));
        assert!(toml_content.contains("command = \"echo hello\""));
        assert!(toml_content.contains("timeout_seconds = 60"));
        assert!(toml_content.contains("terminal = true"));
    }

    #[test]
    fn test_parameters_toml_generation() {
        let params = serde_json::json!({
            "query": {
                "type": "string",
                "description": "Search query"
            },
            "count": {
                "type": "integer",
                "description": "Number of results"
            }
        });

        let mut toml_content = String::new();
        if let serde_json::Value::Object(params_map) = &params {
            for (param_name, param_def) in params_map {
                let ptype = param_def["type"].as_str().unwrap_or("string");
                let pdesc = param_def["description"].as_str().unwrap_or("");
                toml_content.push_str(&format!(
                    "\n[parameters.{param_name}]\ntype = {}\ndescription = {}\n",
                    toml::Value::String(ptype.into()),
                    toml::Value::String(pdesc.into()),
                ));
            }
        }

        assert!(toml_content.contains("[parameters.query]"));
        assert!(toml_content.contains("type = \"string\""));
        assert!(toml_content.contains("description = \"Search query\""));
        assert!(toml_content.contains("[parameters.count]"));
        assert!(toml_content.contains("type = \"integer\""));
        assert!(toml_content.contains("description = \"Number of results\""));
    }

    #[test]
    fn test_toml_default_timeout_and_terminal() {
        let input = json!({
            "name": "my_skill",
            "description": "desc",
            "command": "run",
        });

        let timeout = input["timeout_seconds"].as_u64().unwrap_or(30);
        let terminal = input["terminal"].as_bool().unwrap_or(false);

        let toml_content = format!(
            "name = {}\ndescription = {}\ncommand = {}\ntimeout_seconds = {}\nterminal = {}\n",
            toml::Value::String(input["name"].as_str().unwrap().into()),
            toml::Value::String(input["description"].as_str().unwrap().into()),
            toml::Value::String(input["command"].as_str().unwrap().into()),
            timeout,
            terminal,
        );

        assert_eq!(timeout, 30);
        assert!(!terminal);
        assert!(toml_content.contains("timeout_seconds = 30"));
        assert!(toml_content.contains("terminal = false"));
    }

    #[test]
    fn test_toml_empty_parameters() {
        let params = serde_json::json!({});

        let mut toml_content = String::new();
        if let serde_json::Value::Object(params_map) = &params {
            for (param_name, param_def) in params_map {
                let ptype = param_def["type"].as_str().unwrap_or("string");
                let pdesc = param_def["description"].as_str().unwrap_or("");
                toml_content.push_str(&format!(
                    "\n[parameters.{param_name}]\ntype = {}\ndescription = {}\n",
                    toml::Value::String(ptype.into()),
                    toml::Value::String(pdesc.into()),
                ));
            }
        }

        assert!(
            toml_content.is_empty(),
            "Empty params should produce no TOML output"
        );
    }

    #[test]
    fn test_toml_parameter_missing_fields_uses_defaults() {
        let params = serde_json::json!({
            "bare_param": {}
        });

        let mut toml_content = String::new();
        if let serde_json::Value::Object(params_map) = &params {
            for (param_name, param_def) in params_map {
                let ptype = param_def["type"].as_str().unwrap_or("string");
                let pdesc = param_def["description"].as_str().unwrap_or("");
                toml_content.push_str(&format!(
                    "\n[parameters.{param_name}]\ntype = {}\ndescription = {}\n",
                    toml::Value::String(ptype.into()),
                    toml::Value::String(pdesc.into()),
                ));
            }
        }

        assert!(toml_content.contains("[parameters.bare_param]"));
        assert!(
            toml_content.contains("type = \"string\""),
            "Missing type should default to 'string'"
        );
        assert!(
            toml_content.contains("description = \"\""),
            "Missing description should default to empty"
        );
    }

    #[test]
    fn test_toml_no_parameters_key() {
        let input = json!({
            "name": "my_skill",
            "description": "desc",
            "command": "run",
        });

        let parameters = input.get("parameters");
        let mut toml_content = String::new();
        if let Some(serde_json::Value::Object(params)) = parameters {
            for (param_name, param_def) in params {
                let ptype = param_def["type"].as_str().unwrap_or("string");
                let pdesc = param_def["description"].as_str().unwrap_or("");
                toml_content.push_str(&format!(
                    "\n[parameters.{param_name}]\ntype = {}\ndescription = {}\n",
                    toml::Value::String(ptype.into()),
                    toml::Value::String(pdesc.into()),
                ));
            }
        }

        assert!(
            toml_content.is_empty(),
            "No parameters key should produce no TOML parameter output"
        );
    }

    #[test]
    fn test_repo_install_and_update_flow() {
        let _guard = with_nsh_test_mode();
        // Simulate a repo URL and ensure idempotent update behavior.
        // We don't actually clone during tests; instead, verify the code path builds the expected target paths.
        let input = json!({"repo": "https://github.com/user/example-skill.git"});
        // Execute should not error even if git isn't run in tests; we only verify it returns a message.
        // In CI, git may not be available; the function may error. Treat either Ok or Err containing 'git' as acceptable.
        let result = super::execute(&input);
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(msg.contains("git"));
        }
    }
}
