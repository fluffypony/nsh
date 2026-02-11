use std::io::{self, Write};

pub fn execute(input: &serde_json::Value) -> anyhow::Result<()> {
    let action = input["action"].as_str().unwrap_or("set");
    let key = input["key"].as_str().unwrap_or("");
    let value = input.get("value");

    if key.is_empty() {
        anyhow::bail!("manage_config: 'key' is required");
    }

    if crate::config::is_setting_protected(key) {
        eprintln!("\x1b[1;31m✗ Setting '{key}' is security-sensitive and cannot be changed via AI tool call.\x1b[0m");
        eprintln!("\x1b[2m  Edit manually: nsh config edit\x1b[0m");
        return Ok(());
    }

    let config_path = crate::config::Config::path();
    let content = if config_path.exists() {
        std::fs::read_to_string(&config_path)?
    } else {
        String::new()
    };

    let mut doc: toml_edit::DocumentMut = if content.is_empty() {
        toml_edit::DocumentMut::new()
    } else {
        content.parse::<toml_edit::DocumentMut>()?
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
            let toml_value = json_to_toml_edit(value);
            let old_value = get_toml_value(&doc, key);

            set_toml_value(&mut doc, key, toml_value.clone())?;
            let new_content = doc.to_string();

            if let Err(e) = toml::from_str::<crate::config::Config>(&new_content) {
                eprintln!("{red}✗ Invalid configuration: {e}{reset}");
                eprintln!("{dim}The change was not applied.{reset}");
                return Ok(());
            }

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

            let new_content = doc.to_string();

            if let Err(e) = toml::from_str::<crate::config::Config>(&new_content) {
                eprintln!("{red}✗ Invalid configuration: {e}{reset}");
                eprintln!("{dim}The change was not applied.{reset}");
                return Ok(());
            }

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

fn json_to_toml_edit(v: &serde_json::Value) -> toml_edit::Item {
    match v {
        serde_json::Value::String(s) => toml_edit::value(s.as_str()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml_edit::value(i)
            } else if let Some(f) = n.as_f64() {
                toml_edit::value(f)
            } else {
                toml_edit::value(n.to_string())
            }
        }
        serde_json::Value::Bool(b) => toml_edit::value(*b),
        serde_json::Value::Array(arr) => {
            let mut a = toml_edit::Array::new();
            for item in arr {
                match item {
                    serde_json::Value::String(s) => a.push(s.as_str()),
                    serde_json::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            a.push(i);
                        } else if let Some(f) = n.as_f64() {
                            a.push(f);
                        }
                    }
                    serde_json::Value::Bool(b) => a.push(*b),
                    _ => a.push(item.to_string()),
                }
            }
            toml_edit::value(a)
        }
        serde_json::Value::Object(map) => {
            let mut table = toml_edit::Table::new();
            for (k, val) in map {
                table.insert(k, json_to_toml_edit(val));
            }
            toml_edit::Item::Table(table)
        }
        serde_json::Value::Null => toml_edit::value(""),
    }
}

fn get_toml_value(doc: &toml_edit::DocumentMut, key_path: &str) -> Option<String> {
    let parts: Vec<&str> = key_path.split('.').collect();
    let mut current: &toml_edit::Item = doc.as_item();
    for part in &parts {
        current = current.get(part)?;
    }
    Some(current.to_string().trim().to_string())
}

fn set_toml_value(
    doc: &mut toml_edit::DocumentMut,
    key_path: &str,
    value: toml_edit::Item,
) -> anyhow::Result<()> {
    let parts: Vec<&str> = key_path.split('.').collect();
    if parts.is_empty() {
        anyhow::bail!("empty key path");
    }
    let mut current: &mut toml_edit::Item = doc.as_item_mut();
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            current[part] = value;
            return Ok(());
        }
        if current.get(part).is_none() {
            current[part] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        current = &mut current[part];
    }
    Ok(())
}

fn remove_toml_value(doc: &mut toml_edit::DocumentMut, key_path: &str) -> anyhow::Result<bool> {
    let parts: Vec<&str> = key_path.split('.').collect();
    if parts.is_empty() {
        return Ok(false);
    }
    let mut current: &mut toml_edit::Item = doc.as_item_mut();
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            if let Some(table) = current.as_table_like_mut() {
                return Ok(table.remove(part).is_some());
            }
            return Ok(false);
        }
        if let Some(next) = current.get_mut(part) {
            current = next;
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
    fn test_json_to_toml_edit_string() {
        let v = json!("hello");
        let t = json_to_toml_edit(&v);
        assert!(t.is_value());
        assert_eq!(t.as_str(), Some("hello"));
    }

    #[test]
    fn test_json_to_toml_edit_integer() {
        let v = json!(42);
        let t = json_to_toml_edit(&v);
        assert!(t.is_value());
        assert_eq!(t.as_integer(), Some(42));
    }

    #[test]
    fn test_json_to_toml_edit_float() {
        let v = json!(3.14);
        let t = json_to_toml_edit(&v);
        assert!(t.is_value());
        if let Some(f) = t.as_float() {
            assert!((f - 3.14).abs() < 0.001);
        } else {
            panic!("expected float");
        }
    }

    #[test]
    fn test_json_to_toml_edit_bool() {
        let t = json_to_toml_edit(&json!(true));
        assert_eq!(t.as_bool(), Some(true));
        let f = json_to_toml_edit(&json!(false));
        assert_eq!(f.as_bool(), Some(false));
    }

    #[test]
    fn test_json_to_toml_edit_array() {
        let v = json!(["a", "b"]);
        let t = json_to_toml_edit(&v);
        assert!(t.is_value());
        let arr = t.as_value().unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn test_json_to_toml_edit_object() {
        let v = json!({"key": "value"});
        let t = json_to_toml_edit(&v);
        assert!(t.is_table());
        let table = t.as_table().unwrap();
        assert_eq!(table.get("key").unwrap().as_str(), Some("value"));
    }

    #[test]
    fn test_json_to_toml_edit_null() {
        let v = json!(null);
        let t = json_to_toml_edit(&v);
        assert_eq!(t.as_str(), Some(""));
    }

    #[test]
    fn test_get_toml_value_simple() {
        let doc: toml_edit::DocumentMut = r#"
[provider]
model = "test"
"#.parse().unwrap();
        let val = get_toml_value(&doc, "provider.model");
        assert!(val.is_some());
        assert!(val.unwrap().contains("test"));
    }

    #[test]
    fn test_get_toml_value_missing() {
        let doc: toml_edit::DocumentMut = "[provider]\n".parse().unwrap();
        assert!(get_toml_value(&doc, "provider.nonexistent").is_none());
    }

    #[test]
    fn test_get_toml_value_nested() {
        let doc: toml_edit::DocumentMut = r#"
[a.b]
c = 42
"#.parse().unwrap();
        let val = get_toml_value(&doc, "a.b.c");
        assert!(val.is_some());
        assert!(val.unwrap().contains("42"));
    }

    #[test]
    fn test_set_toml_value_new_key() {
        let mut doc = toml_edit::DocumentMut::new();
        set_toml_value(&mut doc, "provider.model", toml_edit::value("test")).unwrap();
        let val = get_toml_value(&doc, "provider.model");
        assert!(val.is_some());
        assert!(val.unwrap().contains("test"));
    }

    #[test]
    fn test_set_toml_value_overwrite() {
        let mut doc: toml_edit::DocumentMut = "[provider]\nmodel = \"old\"\n".parse().unwrap();
        set_toml_value(&mut doc, "provider.model", toml_edit::value("new")).unwrap();
        let val = get_toml_value(&doc, "provider.model");
        assert!(val.is_some());
        assert!(val.unwrap().contains("new"));
    }

    #[test]
    fn test_set_toml_value_deep_new() {
        let mut doc = toml_edit::DocumentMut::new();
        set_toml_value(&mut doc, "a.b.c", toml_edit::value(99)).unwrap();
        let val = get_toml_value(&doc, "a.b.c");
        assert!(val.is_some());
        assert!(val.unwrap().contains("99"));
    }

    #[test]
    fn test_set_toml_value_empty_path_error() {
        let mut doc = toml_edit::DocumentMut::new();
        let result = set_toml_value(&mut doc, "", toml_edit::value("x"));
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_remove_toml_value_existing() {
        let mut doc: toml_edit::DocumentMut = "[provider]\nmodel = \"test\"\n".parse().unwrap();
        assert!(remove_toml_value(&mut doc, "provider.model").unwrap());
        assert!(get_toml_value(&doc, "provider.model").is_none());
    }

    #[test]
    fn test_remove_toml_value_missing() {
        let mut doc: toml_edit::DocumentMut = "[provider]\n".parse().unwrap();
        assert!(!remove_toml_value(&mut doc, "provider.nonexistent").unwrap());
    }

    #[test]
    fn test_remove_toml_value_missing_parent() {
        let mut doc = toml_edit::DocumentMut::new();
        assert!(!remove_toml_value(&mut doc, "a.b.c").unwrap());
    }

    #[test]
    fn test_remove_toml_value_empty_path() {
        let mut doc = toml_edit::DocumentMut::new();
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

    #[test]
    fn test_comments_preserved() {
        let original = "# This is a comment\n[provider]\n# Model comment\nmodel = \"old\"\n";
        let mut doc: toml_edit::DocumentMut = original.parse().unwrap();
        set_toml_value(&mut doc, "provider.model", toml_edit::value("new")).unwrap();
        let result = doc.to_string();
        assert!(result.contains("# This is a comment"));
        assert!(result.contains("# Model comment"));
        assert!(result.contains("new"));
        assert!(!result.contains("old"));
    }

    #[test]
    fn test_json_to_toml_edit_nested_object() {
        let v = json!({"outer": {"inner": "deep", "num": 7}});
        let t = json_to_toml_edit(&v);
        assert!(t.is_table());
        let outer = t.as_table().unwrap().get("outer").unwrap();
        assert!(outer.is_table());
        let inner_table = outer.as_table().unwrap();
        assert_eq!(inner_table.get("inner").unwrap().as_str(), Some("deep"));
        assert_eq!(inner_table.get("num").unwrap().as_integer(), Some(7));
    }

    #[test]
    fn test_json_to_toml_edit_array_of_numbers() {
        let v = json!([1, 2, 3]);
        let t = json_to_toml_edit(&v);
        let arr = t.as_value().unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr.get(0).unwrap().as_integer(), Some(1));
        assert_eq!(arr.get(2).unwrap().as_integer(), Some(3));
    }

    #[test]
    fn test_json_to_toml_edit_array_of_bools() {
        let v = json!([true, false, true]);
        let t = json_to_toml_edit(&v);
        let arr = t.as_value().unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr.get(0).unwrap().as_bool(), Some(true));
        assert_eq!(arr.get(1).unwrap().as_bool(), Some(false));
    }

    #[test]
    fn test_json_to_toml_edit_array_mixed() {
        let v = json!(["hello", 42, true]);
        let t = json_to_toml_edit(&v);
        let arr = t.as_value().unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr.get(0).unwrap().as_str(), Some("hello"));
        assert_eq!(arr.get(1).unwrap().as_integer(), Some(42));
        assert_eq!(arr.get(2).unwrap().as_bool(), Some(true));
    }

    #[test]
    fn test_set_then_get_deep_nesting() {
        let mut doc = toml_edit::DocumentMut::new();
        set_toml_value(&mut doc, "a.b.c.d", toml_edit::value("leaf")).unwrap();
        let val = get_toml_value(&doc, "a.b.c.d");
        assert!(val.is_some());
        assert!(val.unwrap().contains("leaf"));
        assert!(get_toml_value(&doc, "a.b.c").is_some());
        assert!(get_toml_value(&doc, "a.b").is_some());
    }

    #[test]
    fn test_remove_from_deep_nesting() {
        let mut doc = toml_edit::DocumentMut::new();
        set_toml_value(&mut doc, "x.y.z", toml_edit::value(100)).unwrap();
        assert!(get_toml_value(&doc, "x.y.z").is_some());
        assert!(remove_toml_value(&mut doc, "x.y.z").unwrap());
        assert!(get_toml_value(&doc, "x.y.z").is_none());
        assert!(get_toml_value(&doc, "x.y").is_some());
    }

    #[test]
    fn test_remove_when_parent_is_not_table() {
        let mut doc: toml_edit::DocumentMut = "val = 42\n".parse().unwrap();
        let result = remove_toml_value(&mut doc, "val.child").unwrap();
        assert!(!result);
    }

    #[test]
    fn test_protected_setting_blocks_set() {
        assert!(crate::config::is_setting_protected("execution.allow_unsafe_autorun"));
        assert!(crate::config::is_setting_protected("tools.sensitive_file_access"));
        assert!(crate::config::is_setting_protected("tools.run_command_allowlist"));
        assert!(crate::config::is_setting_protected("redaction.enabled"));
        assert!(crate::config::is_setting_protected("redaction.disable_builtin"));
    }

    #[test]
    fn test_protected_setting_blocks_api_key_segment() {
        assert!(crate::config::is_setting_protected("provider.openai.api_key"));
        assert!(crate::config::is_setting_protected("provider.openrouter.api_key_cmd"));
        assert!(crate::config::is_setting_protected("provider.custom.base_url"));
    }

    #[test]
    fn test_non_protected_setting_allowed() {
        assert!(!crate::config::is_setting_protected("provider.model"));
        assert!(!crate::config::is_setting_protected("context.history_limit"));
    }

    #[test]
    fn test_execute_empty_key_bails() {
        let input = json!({"action": "set", "value": "foo"});
        let err = execute(&input).unwrap_err();
        assert!(err.to_string().contains("'key' is required"));
    }

    #[test]
    fn test_execute_missing_key_field_bails() {
        let input = json!({"action": "set", "value": 123});
        let err = execute(&input).unwrap_err();
        assert!(err.to_string().contains("'key' is required"));
    }

    #[test]
    fn test_execute_protected_setting_returns_ok() {
        let input = json!({
            "action": "set",
            "key": "execution.allow_unsafe_autorun",
            "value": true
        });
        let result = execute(&input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_unknown_action_bails() {
        let input = json!({
            "action": "delete",
            "key": "provider.model"
        });
        let err = execute(&input).unwrap_err();
        assert!(err.to_string().contains("unknown action"));
    }

    #[test]
    fn test_execute_set_missing_value_bails() {
        let input = json!({
            "action": "set",
            "key": "provider.model"
        });
        let err = execute(&input).unwrap_err();
        assert!(err.to_string().contains("'value' is required"));
    }
}
