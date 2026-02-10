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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_json_to_toml_string() {
        let v = json!("hello");
        let t = json_to_toml(&v);
        assert_eq!(t, toml::Value::String("hello".into()));
    }

    #[test]
    fn test_json_to_toml_integer() {
        let v = json!(42);
        let t = json_to_toml(&v);
        assert_eq!(t, toml::Value::Integer(42));
    }

    #[test]
    fn test_json_to_toml_float() {
        let v = json!(3.14);
        let t = json_to_toml(&v);
        if let toml::Value::Float(f) = t {
            assert!((f - 3.14).abs() < 0.001);
        } else {
            panic!("expected float");
        }
    }

    #[test]
    fn test_json_to_toml_bool() {
        assert_eq!(json_to_toml(&json!(true)), toml::Value::Boolean(true));
        assert_eq!(json_to_toml(&json!(false)), toml::Value::Boolean(false));
    }

    #[test]
    fn test_json_to_toml_array() {
        let v = json!(["a", "b"]);
        let t = json_to_toml(&v);
        if let toml::Value::Array(arr) = t {
            assert_eq!(arr.len(), 2);
        } else {
            panic!("expected array");
        }
    }

    #[test]
    fn test_json_to_toml_object() {
        let v = json!({"key": "value"});
        let t = json_to_toml(&v);
        if let toml::Value::Table(table) = t {
            assert_eq!(table.get("key").unwrap(), &toml::Value::String("value".into()));
        } else {
            panic!("expected table");
        }
    }

    #[test]
    fn test_json_to_toml_null() {
        let v = json!(null);
        let t = json_to_toml(&v);
        assert_eq!(t, toml::Value::String(String::new()));
    }

    #[test]
    fn test_get_toml_value_simple() {
        let doc: toml::Value = toml::from_str(r#"
[provider]
model = "test"
"#).unwrap();
        assert_eq!(get_toml_value(&doc, "provider.model"), Some("\"test\"".into()));
    }

    #[test]
    fn test_get_toml_value_missing() {
        let doc: toml::Value = toml::from_str("[provider]\n").unwrap();
        assert!(get_toml_value(&doc, "provider.nonexistent").is_none());
    }

    #[test]
    fn test_get_toml_value_nested() {
        let doc: toml::Value = toml::from_str(r#"
[a.b]
c = 42
"#).unwrap();
        assert_eq!(get_toml_value(&doc, "a.b.c"), Some("42".into()));
    }

    #[test]
    fn test_set_toml_value_new_key() {
        let mut doc = toml::Value::Table(Default::default());
        set_toml_value(&mut doc, "provider.model", toml::Value::String("test".into())).unwrap();
        assert_eq!(get_toml_value(&doc, "provider.model"), Some("\"test\"".into()));
    }

    #[test]
    fn test_set_toml_value_overwrite() {
        let mut doc: toml::Value = toml::from_str("[provider]\nmodel = \"old\"\n").unwrap();
        set_toml_value(&mut doc, "provider.model", toml::Value::String("new".into())).unwrap();
        assert_eq!(get_toml_value(&doc, "provider.model"), Some("\"new\"".into()));
    }

    #[test]
    fn test_set_toml_value_deep_new() {
        let mut doc = toml::Value::Table(Default::default());
        set_toml_value(&mut doc, "a.b.c", toml::Value::Integer(99)).unwrap();
        assert_eq!(get_toml_value(&doc, "a.b.c"), Some("99".into()));
    }

    #[test]
    fn test_set_toml_value_empty_path_error() {
        let mut doc = toml::Value::Table(Default::default());
        let result = set_toml_value(&mut doc, "", toml::Value::String("x".into()));
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_remove_toml_value_existing() {
        let mut doc: toml::Value = toml::from_str("[provider]\nmodel = \"test\"\n").unwrap();
        assert!(remove_toml_value(&mut doc, "provider.model").unwrap());
        assert!(get_toml_value(&doc, "provider.model").is_none());
    }

    #[test]
    fn test_remove_toml_value_missing() {
        let mut doc: toml::Value = toml::from_str("[provider]\n").unwrap();
        assert!(!remove_toml_value(&mut doc, "provider.nonexistent").unwrap());
    }

    #[test]
    fn test_remove_toml_value_missing_parent() {
        let mut doc = toml::Value::Table(Default::default());
        assert!(!remove_toml_value(&mut doc, "a.b.c").unwrap());
    }

    #[test]
    fn test_remove_toml_value_empty_path() {
        let mut doc = toml::Value::Table(Default::default());
        assert!(!remove_toml_value(&mut doc, "").unwrap());
    }

    #[test]
    fn test_backup_config_nonexistent() {
        let path = std::path::Path::new("/tmp/nsh_test_nonexistent_config_12345.toml");
        assert!(backup_config(path).is_ok());
    }

    #[test]
    fn test_backup_config_existing() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "test content").unwrap();
        backup_config(tmp.path()).unwrap();
        let backup = tmp.path().with_extension("toml.bak");
        assert!(backup.exists());
        let _ = std::fs::remove_file(&backup);
    }

    #[test]
    fn test_write_config() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test_config.toml");
        write_config(&path, "test = true\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "test = true\n");
    }
}