use std::io::{self, Write};

pub fn execute(input: &serde_json::Value) -> anyhow::Result<String> {
    let name = input["name"].as_str().unwrap_or("");
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        anyhow::bail!("uninstall_skill: provide a valid skill name (alphanumeric + underscores)");
    }
    let remove_dir = input["remove_dir"].as_bool().unwrap_or(true);

    let skills_dir = crate::config::Config::nsh_dir().join("skills");
    let toml_path = skills_dir.join(format!("{name}.toml"));
    let dir_path = skills_dir.join(name);

    let bold_yellow = "\x1b[1;33m";
    let dim = "\x1b[2m";
    let green = "\x1b[32m";
    let reset = "\x1b[0m";

    eprintln!("{bold_yellow}Uninstall skill:{reset} {name}");
    if remove_dir {
        let dir_disp = dir_path.display();
        eprintln!("{dim}Paths:{reset} {} and {}", toml_path.display(), dir_disp);
    } else {
        eprintln!("{dim}Path:{reset} {}", toml_path.display());
    }

    if !toml_path.exists() && !(remove_dir && dir_path.exists()) {
        return Ok(format!("No skill files found for '{name}'"));
    }

    eprint!("{bold_yellow}Proceed? [y/N]{reset} ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        return Ok("Uninstall declined".into());
    }

    if toml_path.exists() {
        let _ = std::fs::remove_file(&toml_path);
    }
    if remove_dir && dir_path.exists() {
        let _ = std::fs::remove_dir_all(&dir_path);
    }

    eprintln!("{green}✓ skill '{name}' removed{reset}");
    Ok(format!("Successfully uninstalled skill '{name}'"))
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
