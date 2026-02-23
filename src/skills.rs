use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::tools::ToolDefinition;

static APPROVED_SKILLS: Mutex<Option<HashSet<String>>> = Mutex::new(None);

#[derive(Debug, Deserialize)]
struct SkillFile {
    name: String,
    description: String,
    #[serde(default)]
    command: String,
    // Optional code-based skill support
    #[serde(default)]
    runtime: Option<String>, // e.g., "python", "python3", "node"
    #[serde(default)]
    script: Option<String>, // inline script source to execute with runtime
    #[serde(default = "default_skill_timeout")]
    timeout_seconds: u64,
    #[serde(default)]
    terminal: bool,
    #[serde(default)]
    parameters: HashMap<String, SkillParam>,
}

fn default_skill_timeout() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct SkillParam {
    #[serde(rename = "type")]
    pub param_type: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct Skill {
    pub name: String,
    pub description: String,
    pub command: String,
    pub runtime: Option<String>,
    pub script: Option<String>,
    pub timeout_seconds: u64,
    pub terminal: bool,
    pub parameters: HashMap<String, SkillParam>,
    pub is_project: bool,
}

impl From<SkillFile> for Skill {
    fn from(sf: SkillFile) -> Self {
        Skill {
            name: sf.name,
            description: sf.description,
            command: sf.command,
            runtime: sf.runtime,
            script: sf.script,
            timeout_seconds: sf.timeout_seconds,
            terminal: sf.terminal,
            parameters: sf.parameters,
            is_project: false,
        }
    }
}

pub fn load_skills() -> Vec<Skill> {
    let mut skills_by_name: HashMap<String, Skill> = HashMap::new();

    if let Some(home) = dirs::home_dir() {
        let global_dir = home.join(".nsh").join("skills");
        load_skills_from_dir(&global_dir, false, &mut skills_by_name);
        // Also look for repo-style skills: ~/.nsh/skills/<repo>/(skill.toml|nsh.toml)
        if let Ok(entries) = std::fs::read_dir(&global_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    for fname in ["skill.toml", "nsh.toml"] {
                        let candidate = path.join(fname);
                        if candidate.exists() {
                            if let Ok(content) = std::fs::read_to_string(&candidate) {
                                if let Ok(skill_file) = toml::from_str::<SkillFile>(&content) {
                                    let skill: Skill = skill_file.into();
                                    skills_by_name.insert(skill.name.clone(), skill);
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    let project_dir = PathBuf::from(".nsh").join("skills");
    load_skills_from_dir(&project_dir, true, &mut skills_by_name);
    // Project repo-style skills: ./.nsh/skills/<repo>/(skill.toml|nsh.toml)
    if let Ok(entries) = std::fs::read_dir(&project_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                for fname in ["skill.toml", "nsh.toml"] {
                    let candidate = path.join(fname);
                    if candidate.exists() {
                        if let Ok(content) = std::fs::read_to_string(&candidate) {
                            if let Ok(skill_file) = toml::from_str::<SkillFile>(&content) {
                                let mut skill: Skill = skill_file.into();
                                skill.is_project = true;
                                skills_by_name.insert(skill.name.clone(), skill);
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    skills_by_name.into_values().collect()
}

fn load_skills_from_dir(dir: &Path, is_project: bool, skills: &mut HashMap<String, Skill>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to read skill file {}: {e}", path.display());
                continue;
            }
        };

        let skill_file: SkillFile = match toml::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Failed to parse skill file {}: {e}", path.display());
                continue;
            }
        };

        // Require at least a command or a (runtime, script) pair
        let missing_command = skill_file.command.trim().is_empty();
        let has_code = skill_file
            .runtime
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
            && skill_file
                .script
                .as_ref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
        if missing_command && !has_code {
            tracing::warn!(
                "Skill {} missing 'command' and no (runtime+script) provided; skipping",
                skill_file.name
            );
            continue;
        }

        skills.insert(
            skill_file.name.clone(),
            Skill {
                name: skill_file.name,
                description: skill_file.description,
                command: skill_file.command,
                runtime: skill_file.runtime,
                script: skill_file.script,
                timeout_seconds: skill_file.timeout_seconds,
                terminal: skill_file.terminal,
                parameters: skill_file.parameters,
                is_project,
            },
        );
    }
}

pub fn skill_tool_definitions(skills: &[Skill]) -> Vec<ToolDefinition> {
    skills
        .iter()
        .map(|skill| {
            let mut properties = serde_json::Map::new();
            let mut required = Vec::new();

            for (param_name, param) in &skill.parameters {
                properties.insert(
                    param_name.clone(),
                    json!({
                        "type": param.param_type,
                        "description": param.description,
                    }),
                );
                required.push(param_name.clone());
            }

            ToolDefinition {
                name: format!("skill_{}", skill.name),
                description: skill.description.clone(),
                parameters: json!({
                    "type": "object",
                    "properties": properties,
                    "required": required,
                }),
            }
        })
        .collect()
}

fn validate_param_value(value: &str) -> anyhow::Result<()> {
    if !value
        .chars()
        .all(|c| c.is_alphanumeric() || " -_./,:=@+%^#".contains(c))
    {
        anyhow::bail!(
            "Parameter value contains disallowed characters. \
             Only alphanumeric characters and [ -_./,:=@+%^#] are permitted."
        );
    }
    Ok(())
}

fn check_project_skill_approval(skill: &Skill) -> anyhow::Result<()> {
    if !skill.is_project {
        return Ok(());
    }

    let mut guard = APPROVED_SKILLS.lock().unwrap();
    let approved = guard.get_or_insert_with(HashSet::new);

    if approved.contains(&skill.name) {
        return Ok(());
    }

    eprintln!(
        "nsh: project skill '{}' will run: {}",
        skill.name, skill.command
    );
    eprint!("Allow? [y/N] ");

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;

    if answer.trim().eq_ignore_ascii_case("y") {
        approved.insert(skill.name.clone());
        Ok(())
    } else {
        anyhow::bail!("Project skill '{}' was not approved by user", skill.name)
    }
}

pub fn execute_skill(skill: &Skill, input: &serde_json::Value) -> anyhow::Result<String> {
    check_project_skill_approval(skill)?;

    let output = if skill.runtime.is_some() && skill.script.is_some() {
        execute_code_skill(skill, input)?
    } else {
        // Shell-command template mode
        let mut command = skill.command.clone();
        for param_name in skill.parameters.keys() {
            let value = input.get(param_name).and_then(|v| v.as_str()).unwrap_or("");
            validate_param_value(value)?;
            command = command.replace(&format!("{{{param_name}}}"), value);
        }
        #[cfg(unix)]
        { std::process::Command::new("sh").arg("-c").arg(&command).output()? }
        #[cfg(windows)]
        { std::process::Command::new("cmd").args(["/C", &command]).output()? }
    };

    let mut result = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(&stderr);
    }

    if result.len() > 8000 {
        result.truncate(8000);
        result.push_str("\n... (truncated)");
    }

    Ok(result)
}

pub async fn execute_skill_async(skill: Skill, input: serde_json::Value) -> anyhow::Result<String> {
    let timeout_secs = skill.timeout_seconds;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        tokio::task::spawn_blocking(move || execute_skill(&skill, &input)),
    )
    .await;

    match result {
        Ok(Ok(inner)) => inner,
        Ok(Err(e)) => anyhow::bail!("Skill task panicked: {e}"),
        Err(_) => anyhow::bail!("Skill timed out after {timeout_secs}s"),
    }
}

fn resolve_runtime_binary(rt: &str) -> Option<(String, Vec<String>)> {
    let l = rt.trim().to_lowercase();
    match l.as_str() {
        "python" | "python3" => {
            if which::which("python3").is_ok() {
                Some(("python3".into(), vec![]))
            } else if which::which("python").is_ok() {
                Some(("python".into(), vec![]))
            } else {
                None
            }
        }
        "node" | "nodejs" => {
            if which::which("node").is_ok() {
                Some(("node".into(), vec![]))
            } else {
                None
            }
        }
        other => {
            if which::which(other).is_ok() {
                Some((other.into(), vec![]))
            } else {
                None
            }
        }
    }
}

fn execute_code_skill(skill: &Skill, input: &serde_json::Value) -> anyhow::Result<std::process::Output> {
    let rt = skill
        .runtime
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("runtime is required for code-based skill"))?;
    let script = skill
        .script
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("script is required for code-based skill"))?;

    let (bin, mut args) = resolve_runtime_binary(rt)
        .ok_or_else(|| anyhow::anyhow!(format!("runtime not found in PATH: {rt}")))?;

    // Write script to a temp file with appropriate extension for better DX
    let ext = if bin.contains("python") { "py" } else if bin.contains("node") { "js" } else { "txt" };
    let mut file = tempfile::Builder::new().suffix(&format!(".{ext}")).tempfile()?;
    use std::io::Write as _;
    file.write_all(script.as_bytes())?;
    let script_path = file.path().to_path_buf();

    // Build JSON of parameters
    let mut params = serde_json::Map::new();
    for param_name in skill.parameters.keys() {
        if let Some(v) = input.get(param_name) {
            params.insert(param_name.clone(), v.clone());
        }
    }
    let params_json = serde_json::Value::Object(params).to_string();

    // Environment variables for convenience
    let mut cmd = std::process::Command::new(&bin);
    args.push(script_path.to_string_lossy().to_string());
    cmd.args(&args)
        .env("NSH_SKILL_NAME", &skill.name)
        .env("NSH_SKILL_PARAMS_JSON", &params_json)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // Provide params via stdin as JSON as well
    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        let _ = stdin.write_all(params_json.as_bytes());
    }
    let output = child.wait_with_output()?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_param_value_clean() {
        assert!(validate_param_value("hello world").is_ok());
    }

    #[test]
    fn test_validate_param_value_semicolon() {
        assert!(validate_param_value("foo;bar").is_err());
    }

    #[test]
    fn test_validate_param_value_pipe() {
        assert!(validate_param_value("foo|bar").is_err());
    }

    #[test]
    fn test_validate_param_value_backtick() {
        assert!(validate_param_value("foo`bar").is_err());
    }

    #[test]
    fn test_validate_param_value_dollar() {
        assert!(validate_param_value("foo$bar").is_err());
    }

    #[test]
    fn test_validate_param_value_ampersand() {
        assert!(validate_param_value("foo&bar").is_err());
    }

    #[test]
    fn test_skill_tool_definitions_empty() {
        let defs = skill_tool_definitions(&[]);
        assert!(defs.is_empty());
    }

    #[test]
    fn test_skill_tool_definitions_basic() {
        let mut params = HashMap::new();
        params.insert(
            "query".to_string(),
            SkillParam {
                param_type: "string".to_string(),
                description: "search query".to_string(),
            },
        );
        let skill = Skill {
            name: "search".to_string(),
            description: "Search things".to_string(),
            command: "echo {query}".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 30,
            terminal: false,
            parameters: params,
            is_project: false,
        };
        let defs = skill_tool_definitions(&[skill]);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "skill_search");
        assert_eq!(defs[0].description, "Search things");
        let props = defs[0].parameters.get("properties").unwrap();
        assert!(props.get("query").is_some());
        let required = defs[0]
            .parameters
            .get("required")
            .unwrap()
            .as_array()
            .unwrap();
        assert!(required.contains(&serde_json::json!("query")));
    }

    #[test]
    fn test_load_skills_nonexistent_dir() {
        let mut skills = HashMap::new();
        load_skills_from_dir(
            Path::new("/nonexistent/path/that/does/not/exist"),
            false,
            &mut skills,
        );
        assert!(skills.is_empty());
    }

    #[test]
    fn test_execute_skill_echo() {
        let skill = Skill {
            name: "echo_test".to_string(),
            description: "test".to_string(),
            command: "echo hello".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let result = execute_skill(&skill, &serde_json::json!({})).unwrap();
        assert!(result.contains("hello"));
    }

    #[test]
    fn test_execute_skill_with_parameters() {
        let mut params = HashMap::new();
        params.insert(
            "name".to_string(),
            SkillParam {
                param_type: "string".to_string(),
                description: "a name".to_string(),
            },
        );
        let skill = Skill {
            name: "greet".to_string(),
            description: "greet someone".to_string(),
            command: "echo hello {name}".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: params,
            is_project: false,
        };
        let result = execute_skill(&skill, &serde_json::json!({"name": "world"})).unwrap();
        assert!(result.contains("hello world"));
    }

    #[test]
    fn test_execute_skill_param_injection_rejected() {
        let mut params = HashMap::new();
        params.insert(
            "name".to_string(),
            SkillParam {
                param_type: "string".to_string(),
                description: "a name".to_string(),
            },
        );
        let skill = Skill {
            name: "greet".to_string(),
            description: "greet someone".to_string(),
            command: "echo hello {name}".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: params,
            is_project: false,
        };
        let result = execute_skill(&skill, &serde_json::json!({"name": "world; rm -rf /"}));
        assert!(result.is_err());
    }

    #[test]
    fn test_skill_tool_definitions_multiple() {
        let skill_a = Skill {
            name: "alpha".to_string(),
            description: "Alpha skill".to_string(),
            command: "echo a".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 10,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let mut params = HashMap::new();
        params.insert(
            "x".to_string(),
            SkillParam {
                param_type: "string".to_string(),
                description: "param x".to_string(),
            },
        );
        let skill_b = Skill {
            name: "beta".to_string(),
            description: "Beta skill".to_string(),
            command: "echo {x}".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 20,
            terminal: false,
            parameters: params,
            is_project: true,
        };
        let defs = skill_tool_definitions(&[skill_a, skill_b]);
        assert_eq!(defs.len(), 2);
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"skill_alpha"));
        assert!(names.contains(&"skill_beta"));
    }

    #[test]
    fn test_validate_param_value_all_forbidden() {
        let dangerous = [
            ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\\', '\'', '"',
        ];
        for ch in &dangerous {
            let val = format!("foo{ch}bar");
            assert!(
                validate_param_value(&val).is_err(),
                "Expected rejection for char '{ch}'"
            );
        }
    }

    #[test]
    fn test_validate_param_value_allowed_chars() {
        assert!(validate_param_value("hello-world").is_ok());
        assert!(validate_param_value("path/to/file.txt").is_ok());
        assert!(validate_param_value("key=value").is_ok());
        assert!(validate_param_value("user@host").is_ok());
        assert!(validate_param_value("100%").is_ok());
        assert!(validate_param_value("a,b,c").is_ok());
        assert!(validate_param_value("item #1").is_ok());
        assert!(validate_param_value("a+b").is_ok());
        assert!(validate_param_value("foo:bar").is_ok());
        assert!(validate_param_value("a^b").is_ok());
    }

    #[test]
    fn test_default_skill_timeout() {
        assert_eq!(default_skill_timeout(), 30);
    }

    #[tokio::test]
    async fn test_execute_skill_async_simple() {
        let skill = Skill {
            name: "async_echo".to_string(),
            description: "test".to_string(),
            command: "echo hello".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let result = execute_skill_async(skill, serde_json::json!({}))
            .await
            .unwrap();
        assert!(result.contains("hello"));
    }

    #[test]
    fn test_load_skills_from_dir_with_valid_files() {
        let tmp = tempfile::tempdir().unwrap();
        let skill_content = r#"
name = "test_skill"
description = "A test skill"
command = "echo test"
timeout_seconds = 10
"#;
        std::fs::write(tmp.path().join("test_skill.toml"), skill_content).unwrap();
        let mut skills = HashMap::new();
        load_skills_from_dir(tmp.path(), false, &mut skills);
        assert_eq!(skills.len(), 1);
        let skill = skills.get("test_skill").unwrap();
        assert_eq!(skill.name, "test_skill");
        assert_eq!(skill.description, "A test skill");
        assert_eq!(skill.command, "echo test");
        assert_eq!(skill.timeout_seconds, 10);
        assert!(!skill.is_project);
    }

    #[test]
    fn test_load_skills_from_dir_with_parameters() {
        let tmp = tempfile::tempdir().unwrap();
        let skill_content = r#"
name = "param_skill"
description = "Skill with params"
command = "echo {query}"
timeout_seconds = 15

[parameters.query]
type = "string"
description = "search query"
"#;
        std::fs::write(tmp.path().join("param_skill.toml"), skill_content).unwrap();
        let mut skills = HashMap::new();
        load_skills_from_dir(tmp.path(), false, &mut skills);
        assert_eq!(skills.len(), 1);
        let skill = skills.get("param_skill").unwrap();
        assert_eq!(skill.parameters.len(), 1);
        let param = skill.parameters.get("query").unwrap();
        assert_eq!(param.param_type, "string");
        assert_eq!(param.description, "search query");
    }

    #[test]
    fn test_load_skills_from_dir_skips_non_toml() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("readme.txt"), "not a skill").unwrap();
        std::fs::write(tmp.path().join("data.json"), "{}").unwrap();
        let mut skills = HashMap::new();
        load_skills_from_dir(tmp.path(), false, &mut skills);
        assert!(skills.is_empty());
    }

    #[test]
    fn test_load_skills_from_dir_handles_invalid_toml() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bad.toml"), "this is not valid [[[ toml").unwrap();
        let mut skills = HashMap::new();
        load_skills_from_dir(tmp.path(), false, &mut skills);
        assert!(skills.is_empty());
    }

    #[test]
    fn test_load_skills_from_dir_project_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let skill_content = r#"
name = "proj_skill"
description = "A project skill"
command = "echo project"
"#;
        std::fs::write(tmp.path().join("proj.toml"), skill_content).unwrap();
        let mut skills = HashMap::new();
        load_skills_from_dir(tmp.path(), true, &mut skills);
        assert_eq!(skills.len(), 1);
        let skill = skills.get("proj_skill").unwrap();
        assert!(skill.is_project);
        assert_eq!(skill.timeout_seconds, 30);
    }

    #[test]
    fn test_load_skills_from_dir_multiple_files() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..3 {
            let content = format!(
                "name = \"skill_{i}\"\ndescription = \"Skill {i}\"\ncommand = \"echo {i}\"\n"
            );
            std::fs::write(tmp.path().join(format!("skill_{i}.toml")), content).unwrap();
        }
        let mut skills = HashMap::new();
        load_skills_from_dir(tmp.path(), false, &mut skills);
        assert_eq!(skills.len(), 3);
    }

    #[test]
    fn test_execute_skill_truncates_large_output() {
        let skill = Skill {
            name: "big_output".to_string(),
            description: "test".to_string(),
            command: "python3 -c \"print('x' * 10000)\"".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let result = execute_skill(&skill, &serde_json::json!({})).unwrap();
        assert!(result.len() <= 8100);
        assert!(result.contains("truncated"));
    }

    #[tokio::test]
    async fn test_execute_skill_async_timeout() {
        let skill = Skill {
            name: "slow".to_string(),
            description: "test".to_string(),
            command: "sleep 10".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 1,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let result = execute_skill_async(skill, serde_json::json!({})).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[test]
    fn test_check_project_skill_approval_global_skill() {
        let skill = Skill {
            name: "global_test".to_string(),
            description: "test".to_string(),
            command: "echo hi".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        assert!(check_project_skill_approval(&skill).is_ok());
    }

    #[test]
    fn test_load_skills_does_not_panic() {
        let _ = load_skills();
    }

    #[test]
    fn test_load_skills_from_dir_missing_required_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let skill_content = r#"
description = "missing name field"
command = "echo test"
"#;
        std::fs::write(tmp.path().join("incomplete.toml"), skill_content).unwrap();
        let mut skills = HashMap::new();
        load_skills_from_dir(tmp.path(), false, &mut skills);
        assert!(skills.is_empty());
    }

    #[test]
    fn test_load_skills_from_dir_missing_command_field() {
        let tmp = tempfile::tempdir().unwrap();
        let skill_content = r#"
name = "no_cmd"
description = "has no command"
"#;
        std::fs::write(tmp.path().join("no_cmd.toml"), skill_content).unwrap();
        let mut skills = HashMap::new();
        load_skills_from_dir(tmp.path(), false, &mut skills);
        assert!(skills.is_empty());
    }

    #[test]
    fn test_load_skills_from_dir_nonexistent_dir() {
        let mut skills = HashMap::new();
        load_skills_from_dir(
            std::path::Path::new("/nonexistent_dir_xyz_999"),
            false,
            &mut skills,
        );
        assert!(skills.is_empty());
    }

    #[test]
    fn test_execute_skill_stderr_output() {
        let skill = Skill {
            name: "stderr_test".to_string(),
            description: "test".to_string(),
            command: "echo error_msg >&2".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let result = execute_skill(&skill, &serde_json::json!({})).unwrap();
        assert!(result.contains("error_msg"));
    }

    #[test]
    fn test_execute_skill_stdout_and_stderr() {
        let skill = Skill {
            name: "both_test".to_string(),
            description: "test".to_string(),
            command: "echo stdout_line; echo stderr_line >&2".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let result = execute_skill(&skill, &serde_json::json!({})).unwrap();
        assert!(result.contains("stdout_line"));
        assert!(result.contains("stderr_line"));
    }

    #[test]
    fn test_skill_tool_definitions_empty_slice() {
        let defs = skill_tool_definitions(&[]);
        assert!(defs.is_empty());
    }

    #[test]
    fn test_skill_tool_definitions_with_multiple_parameters() {
        let mut params = HashMap::new();
        params.insert(
            "arg1".to_string(),
            SkillParam {
                param_type: "string".to_string(),
                description: "first arg".to_string(),
            },
        );
        params.insert(
            "arg2".to_string(),
            SkillParam {
                param_type: "integer".to_string(),
                description: "second arg".to_string(),
            },
        );
        let skill = Skill {
            name: "multi_param".to_string(),
            description: "skill with many params".to_string(),
            command: "echo {arg1} {arg2}".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 10,
            terminal: false,
            parameters: params,
            is_project: false,
        };
        let defs = skill_tool_definitions(&[skill]);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "skill_multi_param");
        let params_obj = &defs[0].parameters;
        let props = params_obj["properties"].as_object().unwrap();
        assert_eq!(props.len(), 2);
        assert!(props.contains_key("arg1"));
        assert!(props.contains_key("arg2"));
        let required = params_obj["required"].as_array().unwrap();
        assert_eq!(required.len(), 2);
    }

    #[test]
    fn test_skill_file_deserialization() {
        let toml_str = r#"
name = "my_skill"
description = "does things"
command = "echo {query}"
timeout_seconds = 15
terminal = true

[parameters.query]
type = "string"
description = "the query"
"#;
        let sf: SkillFile = toml::from_str(toml_str).unwrap();
        assert_eq!(sf.name, "my_skill");
        assert_eq!(sf.description, "does things");
        assert_eq!(sf.command, "echo {query}");
        assert_eq!(sf.timeout_seconds, 15);
        assert!(sf.terminal);
        assert_eq!(sf.parameters.len(), 1);
        let p = sf.parameters.get("query").unwrap();
        assert_eq!(p.param_type, "string");
        assert_eq!(p.description, "the query");
    }

    #[test]
    fn test_skill_file_deserialization_defaults() {
        let toml_str = r#"
name = "minimal"
description = "minimal skill"
command = "echo hi"
"#;
        let sf: SkillFile = toml::from_str(toml_str).unwrap();
        assert_eq!(sf.timeout_seconds, 30);
        assert!(!sf.terminal);
        assert!(sf.parameters.is_empty());
    }

    #[test]
    fn test_skill_param_clone() {
        let param = SkillParam {
            param_type: "string".to_string(),
            description: "a param".to_string(),
        };
        let cloned = param.clone();
        assert_eq!(cloned.param_type, "string");
        assert_eq!(cloned.description, "a param");
    }

    #[test]
    fn test_skill_debug_trait() {
        let skill = Skill {
            name: "debug_test".to_string(),
            description: "test debug".to_string(),
            command: "echo debug".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let debug_str = format!("{skill:?}");
        assert!(debug_str.contains("debug_test"));
        assert!(debug_str.contains("Skill"));
    }

    #[test]
    fn test_skill_param_debug_trait() {
        let param = SkillParam {
            param_type: "string".to_string(),
            description: "test".to_string(),
        };
        let debug_str = format!("{param:?}");
        assert!(debug_str.contains("SkillParam"));
        assert!(debug_str.contains("string"));
    }

    #[test]
    fn test_skill_clone() {
        let mut params = HashMap::new();
        params.insert(
            "x".to_string(),
            SkillParam {
                param_type: "string".to_string(),
                description: "x".to_string(),
            },
        );
        let skill = Skill {
            name: "clone_test".to_string(),
            description: "test".to_string(),
            command: "echo {x}".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 10,
            terminal: true,
            parameters: params,
            is_project: true,
        };
        let cloned = skill.clone();
        assert_eq!(cloned.name, "clone_test");
        assert_eq!(cloned.timeout_seconds, 10);
        assert!(cloned.terminal);
        assert!(cloned.is_project);
        assert_eq!(cloned.parameters.len(), 1);
    }

    #[test]
    fn test_load_skills_from_dir_overwrite_same_name() {
        let tmp = tempfile::tempdir().unwrap();
        let content1 = r#"
name = "same_name"
description = "first"
command = "echo first"
"#;
        let content2 = r#"
name = "same_name"
description = "second"
command = "echo second"
"#;
        std::fs::write(tmp.path().join("a_skill.toml"), content1).unwrap();
        std::fs::write(tmp.path().join("b_skill.toml"), content2).unwrap();
        let mut skills = HashMap::new();
        load_skills_from_dir(tmp.path(), false, &mut skills);
        assert_eq!(skills.len(), 1);
        let skill = skills.get("same_name").unwrap();
        assert!(skill.description == "first" || skill.description == "second");
    }

    #[test]
    fn test_execute_skill_empty_param_value() {
        let mut params = HashMap::new();
        params.insert(
            "name".to_string(),
            SkillParam {
                param_type: "string".to_string(),
                description: "a name".to_string(),
            },
        );
        let skill = Skill {
            name: "greet".to_string(),
            description: "greet".to_string(),
            command: "echo hello {name}".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: params,
            is_project: false,
        };
        let result = execute_skill(&skill, &serde_json::json!({})).unwrap();
        assert!(result.contains("hello"));
    }

    #[test]
    fn test_execute_skill_no_params() {
        let skill = Skill {
            name: "simple".to_string(),
            description: "test".to_string(),
            command: "echo no_params".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let result = execute_skill(&skill, &serde_json::json!({})).unwrap();
        assert!(result.contains("no_params"));
    }

    #[test]
    fn test_load_skills_from_dir_terminal_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let skill_content = r#"
name = "term_skill"
description = "A terminal skill"
command = "vim"
terminal = true
"#;
        std::fs::write(tmp.path().join("term.toml"), skill_content).unwrap();
        let mut skills = HashMap::new();
        load_skills_from_dir(tmp.path(), false, &mut skills);
        let skill = skills.get("term_skill").unwrap();
        assert!(skill.terminal);
    }

    #[test]
    fn test_skill_file_deserialization_invalid_missing_all() {
        let toml_str = r#"
timeout_seconds = 10
"#;
        let result: Result<SkillFile, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_skill_stderr_only_no_stdout() {
        let skill = Skill {
            name: "stderr_only".to_string(),
            description: "test".to_string(),
            command: "echo only_stderr >&2".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let result = execute_skill(&skill, &serde_json::json!({})).unwrap();
        assert!(result.contains("only_stderr"));
        assert!(!result.starts_with('\n'));
    }

    #[test]
    fn test_execute_skill_nonzero_exit() {
        let skill = Skill {
            name: "fail_cmd".to_string(),
            description: "test".to_string(),
            command: "exit 42".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let result = execute_skill(&skill, &serde_json::json!({}));
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_skills_from_dir_unreadable_file() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secret.toml");
        std::fs::write(
            &path,
            "name = \"x\"\ndescription = \"x\"\ncommand = \"x\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let mut skills = HashMap::new();
        load_skills_from_dir(tmp.path(), false, &mut skills);
        assert!(skills.is_empty());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn test_skill_file_deserialization_terminal_true() {
        let toml_str = r#"
name = "term"
description = "terminal skill"
command = "vim"
terminal = true
"#;
        let sf: SkillFile = toml::from_str(toml_str).unwrap();
        assert!(sf.terminal);
        assert_eq!(sf.timeout_seconds, 30);
    }

    #[test]
    fn test_load_skills_from_dir_nonexistent_directory() {
        let mut skills = HashMap::new();
        load_skills_from_dir(
            std::path::Path::new("/nonexistent/path/xyz"),
            false,
            &mut skills,
        );
        assert!(skills.is_empty());
    }

    #[test]
    fn test_load_skills_from_dir_skips_non_toml_files() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("readme.md"), "# Skills").unwrap();
        std::fs::write(tmp.path().join("data.json"), "{}").unwrap();
        let valid = r#"
name = "real_skill"
description = "a skill"
command = "echo hi"
"#;
        std::fs::write(tmp.path().join("skill.toml"), valid).unwrap();
        let mut skills = HashMap::new();
        load_skills_from_dir(tmp.path(), false, &mut skills);
        assert_eq!(skills.len(), 1);
        assert!(skills.contains_key("real_skill"));
    }

    #[test]
    fn test_load_skills_from_dir_malformed_toml() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bad.toml"), "this is not valid toml {{{{").unwrap();
        let mut skills = HashMap::new();
        load_skills_from_dir(tmp.path(), false, &mut skills);
        assert!(skills.is_empty());
    }

    #[test]
    fn test_skill_tool_definitions_empty_skills() {
        let defs = skill_tool_definitions(&[]);
        assert!(defs.is_empty());
    }

    #[test]
    fn test_skill_tool_definitions_no_params() {
        let skill = Skill {
            name: "simple".to_string(),
            description: "a simple skill".to_string(),
            command: "echo hello".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 10,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let defs = skill_tool_definitions(&[skill]);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "skill_simple");
        let required = defs[0].parameters["required"].as_array().unwrap();
        assert!(required.is_empty());
        let props = defs[0].parameters["properties"].as_object().unwrap();
        assert!(props.is_empty());
    }

    #[test]
    fn test_execute_skill_output_truncation() {
        let skill = Skill {
            name: "big_output".to_string(),
            description: "test".to_string(),
            command: "python3 -c \"print('x' * 10000)\"".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let result = execute_skill(&skill, &serde_json::json!({})).unwrap();
        assert!(result.len() <= 8020);
        if result.len() > 8000 {
            assert!(result.contains("(truncated)"));
        }
    }

    #[test]
    fn test_execute_skill_multiple_params_substitution() {
        let mut params = HashMap::new();
        params.insert(
            "greeting".to_string(),
            SkillParam {
                param_type: "string".to_string(),
                description: "greeting word".to_string(),
            },
        );
        params.insert(
            "target".to_string(),
            SkillParam {
                param_type: "string".to_string(),
                description: "who to greet".to_string(),
            },
        );
        let skill = Skill {
            name: "multi_param".to_string(),
            description: "test".to_string(),
            command: "echo {greeting} {target}".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: params,
            is_project: false,
        };
        let result = execute_skill(
            &skill,
            &serde_json::json!({"greeting": "hello", "target": "world"}),
        )
        .unwrap();
        assert!(
            result.contains("hello world"),
            "expected 'hello world', got: {result}"
        );
    }

    #[test]
    fn test_execute_skill_combined_stdout_and_stderr() {
        let skill = Skill {
            name: "both_streams".to_string(),
            description: "test".to_string(),
            command: "echo stdout_msg; echo stderr_msg >&2".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let result = execute_skill(&skill, &serde_json::json!({})).unwrap();
        assert!(result.contains("stdout_msg"), "missing stdout: {result}");
        assert!(result.contains("stderr_msg"), "missing stderr: {result}");
        assert!(
            result.contains('\n'),
            "stdout and stderr should be separated by newline"
        );
    }

    #[tokio::test]
    async fn test_execute_skill_async_success() {
        let skill = Skill {
            name: "async_test".to_string(),
            description: "test".to_string(),
            command: "echo async_output".to_string(),
            runtime: None,
            script: None,
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        let result = execute_skill_async(skill, serde_json::json!({})).await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("async_output"));
    }
}
