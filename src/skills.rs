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

fn load_skills_from_dir(
    dir: &Path,
    is_project: bool,
    skills: &mut HashMap<String, Skill>,
) {
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

const SHELL_METACHARACTERS: &[char] = &[
    ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\\',
];

fn validate_param_value(value: &str) -> anyhow::Result<()> {
    for ch in SHELL_METACHARACTERS {
        if value.contains(*ch) {
            anyhow::bail!(
                "Parameter value contains forbidden shell metacharacter '{ch}'"
            );
        }
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

pub fn execute_skill(
    skill: &Skill,
    input: &serde_json::Value,
) -> anyhow::Result<String> {
    check_project_skill_approval(skill)?;

    let mut command = skill.command.clone();
    for (param_name, _param) in &skill.parameters {
        let value = input
            .get(param_name)
            .and_then(|v| v.as_str())
            .unwrap_or("");

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

pub async fn execute_skill_async(
    skill: Skill,
    input: serde_json::Value,
) -> anyhow::Result<String> {
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
