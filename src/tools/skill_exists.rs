pub fn execute(input: &serde_json::Value) -> anyhow::Result<String> {
    let name = input["name"].as_str().unwrap_or("");
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        anyhow::bail!("skill_exists: provide a valid skill name (alphanumeric + underscores)");
    }
    let skills = crate::skills::load_skills();
    let found = skills.iter().find(|s| s.name == name);
    if let Some(s) = found {
        let home = dirs::home_dir().unwrap_or_default();
        let base = home.join(".nsh").join("skills");
        let toml = base.join(format!("{name}.toml"));
        let md = base.join(format!("{name}.md"));
        let mut status = format!("Installed: skill_{}\nTOML: {}", s.name, toml.display());
        if md.exists() {
            status.push_str(&format!("\nDocs: {}", md.display()));
        }
        Ok(status)
    } else {
        Ok(format!("Not installed: {name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_invalid_name() {
        assert!(execute(&json!({"name":"bad name"})).is_err());
    }
}
