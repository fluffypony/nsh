use std::io::{self, Write};

pub fn execute(input: &serde_json::Value) -> anyhow::Result<()> {
    let name = input["name"].as_str().unwrap_or("");
    let description = input["description"].as_str().unwrap_or("");
    let command = input["command"].as_str().unwrap_or("");
    let timeout = input["timeout_seconds"].as_u64().unwrap_or(30);
    let terminal = input["terminal"].as_bool().unwrap_or(false);
    let parameters = input.get("parameters");

    if name.is_empty() || description.is_empty() || command.is_empty() {
        anyhow::bail!("install_skill: name, description, and command are required");
    }

    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        anyhow::bail!("install_skill: name must contain only alphanumeric characters and underscores");
    }

    // Build TOML content
    let mut toml_content = format!(
        "name = {}\ndescription = {}\ncommand = {}\ntimeout_seconds = {}\nterminal = {}\n",
        toml::Value::String(name.into()),
        toml::Value::String(description.into()),
        toml::Value::String(command.into()),
        timeout,
        terminal,
    );

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

    let skills_dir = crate::config::Config::nsh_dir().join("skills");
    std::fs::create_dir_all(&skills_dir)?;
    let skill_path = skills_dir.join(format!("{name}.toml"));

    let bold_yellow = "\x1b[1;33m";
    let cyan = "\x1b[36m";
    let green = "\x1b[32m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!("{bold_yellow}Install skill:{reset} {name}");
    eprintln!("{dim}Path: {}{reset}", skill_path.display());
    eprintln!();
    eprintln!("{cyan}{toml_content}{reset}");

    if skill_path.exists() {
        eprintln!("{bold_yellow}Warning: skill '{name}' already exists and will be overwritten.{reset}");
    }

    eprintln!();
    eprint!("{bold_yellow}Install? [y/N]{reset} ");
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        eprintln!("{dim}skill installation declined{reset}");
        return Ok(());
    }

    std::fs::write(&skill_path, &toml_content)?;
    eprintln!("{green}✓ skill '{name}' installed at {}{reset}", skill_path.display());

    Ok(())
}