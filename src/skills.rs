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
    command: String,
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
    pub timeout_seconds: u64,
    pub terminal: bool,
    pub parameters: HashMap<String, SkillParam>,
    pub is_project: bool,
}

pub fn load_skills() -> Vec<Skill> {
    let mut skills_by_name: HashMap<String, Skill> = HashMap::new();

    if let Some(home) = dirs::home_dir() {
        let global_dir = home.join(".nsh").join("skills");
        load_skills_from_dir(&global_dir, false, &mut skills_by_name);
    }

    let project_dir = PathBuf::from(".nsh").join("skills");
    load_skills_from_dir(&project_dir, true, &mut skills_by_name);

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

        skills.insert(
            skill_file.name.clone(),
            Skill {
                name: skill_file.name,
                description: skill_file.description,
                command: skill_file.command,
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
    if !value.chars().all(|c| c.is_alphanumeric() || " -_./,:=@+%^#".contains(c)) {
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

    let mut command = skill.command.clone();
    for param_name in skill.parameters.keys() {
        let value = input.get(param_name).and_then(|v| v.as_str()).unwrap_or("");

        validate_param_value(value)?;

        command = command.replace(&format!("{{{param_name}}}"), value);
    }

    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()?;

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
        let required = defs[0].parameters.get("required").unwrap().as_array().unwrap();
        assert!(required.contains(&serde_json::json!("query")));
    }

    #[test]
    fn test_load_skills_nonexistent_dir() {
        let mut skills = HashMap::new();
        load_skills_from_dir(Path::new("/nonexistent/path/that/does/not/exist"), false, &mut skills);
        assert!(skills.is_empty());
    }

    #[test]
    fn test_execute_skill_echo() {
        let skill = Skill {
            name: "echo_test".to_string(),
            description: "test".to_string(),
            command: "echo hello".to_string(),
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
        let dangerous = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\\', '\'', '"'];
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
            timeout_seconds: 5,
            terminal: false,
            parameters: HashMap::new(),
            is_project: false,
        };
        assert!(check_project_skill_approval(&skill).is_ok());
    }
}
