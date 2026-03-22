pub fn execute(input: &serde_json::Value) -> anyhow::Result<String> {
    let name = input["name"].as_str().unwrap_or("");
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        anyhow::bail!(
            "uninstall_skill: provide a valid skill name (alphanumeric + underscores/hyphens)"
        );
    }
    let remove_dir = input["remove_dir"].as_bool().unwrap_or(true);

    let skills_dir = crate::config::Config::nsh_dir().join("skills");
    let toml_path = skills_dir.join(format!("{name}.toml"));
    let dir_path = skills_dir.join(name);

    if !(toml_path.exists() || (remove_dir && dir_path.exists())) {
        return Ok(format!("No skill files found for '{name}'"));
    }

    if !crate::tools::prompt_tty_confirmation(&format!(
        "\x1b[1;33mUninstall skill '{name}'? [y/N]\x1b[0m "
    ))? {
        return Ok("Uninstall declined".into());
    }

    let mut removed = Vec::new();
    if toml_path.exists() {
        let _ = std::fs::remove_file(&toml_path);
        removed.push("TOML");
    }
    let md_path = skills_dir.join(format!("{name}.md"));
    if md_path.exists() {
        let _ = std::fs::remove_file(&md_path);
        removed.push("docs");
    }
    if remove_dir && dir_path.exists() {
        let _ = std::fs::remove_dir_all(&dir_path);
        removed.push("directory");
    }

    Ok(format!(
        "Skill '{name}' uninstalled ({})",
        removed.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_reject_bad_name() {
        let res = execute(&json!({"name": "bad name"}));
        assert!(res.is_err());
    }
}
