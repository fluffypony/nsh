use std::io::{self, Write};

pub fn execute(input: &serde_json::Value) -> anyhow::Result<()> {
    let action = input["action"].as_str().unwrap_or("set");
    let key = input["key"].as_str().unwrap_or("");
    let value = input.get("value");

    if key.is_empty() {
        anyhow::bail!("manage_config: 'key' is required");
    }

    let config_path = crate::config::Config::path();
    let content = if config_path.exists() {
        std::fs::read_to_string(&config_path)?
    } else {
        String::new()
    };

    let mut doc: toml::Value = if content.is_empty() {
        toml::Value::Table(Default::default())
    } else {
        toml::from_str(&content)?
    };

    let dim = "\x1b[2m";
    let green = "\x1b[32m";
    let red = "\x1b[31m";
    let bold_yellow = "\x1b[1;33m";
    let reset = "\x1b[0m";

    match action {
        "set" => {
            let value = value
                .ok_or_else(|| anyhow::anyhow!("manage_config: 'value' is required for set"))?;
            let toml_value = json_to_toml(value);
            let old_value = get_toml_value(&doc, key);

            set_toml_value(&mut doc, key, toml_value.clone())?;
            let new_content = toml::to_string_pretty(&doc)?;

            eprintln!("{bold_yellow}nsh config change:{reset}");
            eprintln!("  Key: {key}");
            if let Some(old) = &old_value {
                eprintln!("  {red}Old: {old}{reset}");
            } else {
                eprintln!("  {dim}(new key){reset}");
            }
            eprintln!("  {green}New: {toml_value}{reset}");
            eprintln!();
            eprint!("{bold_yellow}Apply? [y/N]{reset} ");
            io::stderr().flush()?;

            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
                eprintln!("{dim}config change declined{reset}");
                return Ok(());
            }

            backup_config(&config_path)?;
            write_config(&config_path, &new_content)?;
            eprintln!("{green}✓ config updated: {key}{reset}");
        }
        "remove" => {
            if !remove_toml_value(&mut doc, key)? {
                eprintln!("Key not found: {key}");
                return Ok(());
            }

            let new_content = toml::to_string_pretty(&doc)?;

            eprintln!("{bold_yellow}nsh config removal:{reset}");
            eprintln!("  {red}Remove key: {key}{reset}");
            eprintln!();
            eprint!("{bold_yellow}Apply? [y/N]{reset} ");
            io::stderr().flush()?;

            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
                eprintln!("{dim}config change declined{reset}");
                return Ok(());
            }

            backup_config(&config_path)?;
            write_config(&config_path, &new_content)?;
            eprintln!("{green}✓ config key removed: {key}{reset}");
        }
        _ => {
            anyhow::bail!("manage_config: unknown action '{action}'. Use 'set' or 'remove'.");
        }
    }

    Ok(())
}

fn backup_config(path: &std::path::Path) -> anyhow::Result<()> {
    if path.exists() {
        let backup = path.with_extension("toml.bak");
        std::fs::copy(path, &backup)?;
    }
    Ok(())
}

fn write_config(path: &std::path::Path, content: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn json_to_toml(v: &serde_json::Value) -> toml::Value {
    match v {
        serde_json::Value::String(s) => toml::Value::String(s.clone()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                toml::Value::Float(f)
            } else {
                toml::Value::String(n.to_string())
            }
        }
        serde_json::Value::Bool(b) => toml::Value::Boolean(*b),
        serde_json::Value::Array(arr) => {
            toml::Value::Array(arr.iter().map(json_to_toml).collect())
        }
        serde_json::Value::Object(map) => {
            let mut table = toml::map::Map::new();
            for (k, v) in map {
                table.insert(k.clone(), json_to_toml(v));
            }
            toml::Value::Table(table)
        }
        serde_json::Value::Null => toml::Value::String(String::new()),
    }
}

fn get_toml_value(root: &toml::Value, key_path: &str) -> Option<String> {
    let parts: Vec<&str> = key_path.split('.').collect();
    let mut current = root;
    for part in &parts {
        match current {
            toml::Value::Table(table) => {
                current = table.get(*part)?;
            }
            _ => return None,
        }
    }
    Some(format!("{current}"))
}

fn set_toml_value(
    root: &mut toml::Value,
    key_path: &str,
    value: toml::Value,
) -> anyhow::Result<()> {
    let parts: Vec<&str> = key_path.split('.').collect();
    if parts.is_empty() {
        anyhow::bail!("empty key path");
    }
    let mut current = root;
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            if let toml::Value::Table(table) = current {
                table.insert(part.to_string(), value);
                return Ok(());
            }
            anyhow::bail!("parent of '{key_path}' is not a table");
        }
        if let toml::Value::Table(table) = current {
            current = table
                .entry(part.to_string())
                .or_insert(toml::Value::Table(Default::default()));
        } else {
            anyhow::bail!("'{part}' is not a table");
        }
    }
    Ok(())
}

fn remove_toml_value(root: &mut toml::Value, key_path: &str) -> anyhow::Result<bool> {
    let parts: Vec<&str> = key_path.split('.').collect();
    if parts.is_empty() {
        return Ok(false);
    }
    let mut current = root;
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            if let toml::Value::Table(table) = current {
                return Ok(table.remove(*part).is_some());
            }
            return Ok(false);
        }
        if let toml::Value::Table(table) = current {
            if let Some(next) = table.get_mut(*part) {
                current = next;
            } else {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }
    }
    Ok(false)
}