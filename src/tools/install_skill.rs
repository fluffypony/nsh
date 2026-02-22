use std::io::{self, Write};

pub fn execute(input: &serde_json::Value) -> anyhow::Result<()> {
    let name = input["name"].as_str().unwrap_or("");
    let description = input["description"].as_str().unwrap_or("");
    let command = input["command"].as_str().unwrap_or("");
    let runtime = input["runtime"].as_str();
    let script = input["script"].as_str();
    let timeout = input["timeout_seconds"].as_u64().unwrap_or(30);
    let terminal = input["terminal"].as_bool().unwrap_or(false);
    let parameters = input.get("parameters");

    if name.is_empty() || description.is_empty() {
        anyhow::bail!("install_skill: 'name' and 'description' are required");
    }
    let has_command = !command.is_empty();
    let has_code = runtime.map(|s| !s.trim().is_empty()).unwrap_or(false)
        && script.map(|s| !s.trim().is_empty()).unwrap_or(false);
    if !has_command && !has_code {
        anyhow::bail!(
            "install_skill: provide either 'command' OR both 'runtime' and 'script'"
        );
    }

    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        anyhow::bail!(
            "install_skill: name must contain only alphanumeric characters and underscores"
        );
    }

    // Build TOML content
    let mut toml_content = String::new();
    toml_content.push_str(&format!(
        "name = {}\ndescription = {}\n",
        toml::Value::String(name.into()),
        toml::Value::String(description.into()),
    ));
    if has_command {
        toml_content.push_str(&format!(
            "command = {}\n",
            toml::Value::String(command.into())
        ));
    } else if let (Some(rt), Some(sc)) = (runtime, script) {
        toml_content.push_str(&format!(
            "runtime = {}\nscript = {}\n",
            toml::Value::String(rt.into()),
            toml::Value::String(sc.into())
        ));
    }
    toml_content.push_str(&format!(
        "timeout_seconds = {timeout}
terminal = {terminal}
") );

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
        eprintln!(
            "{bold_yellow}Warning: skill '{name}' already exists and will be overwritten.{reset}"
        );
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

    std::fs::create_dir_all(&skills_dir)?;
    std::fs::write(&skill_path, &toml_content)?;
    eprintln!(
        "{green}✓ skill '{name}' installed at {}{reset}",
        skill_path.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    fn with_nsh_test_mode() -> impl Drop {
        struct Guard(Option<String>);
        impl Drop for Guard {
            fn drop(&mut self) {
                if let Some(old) = &self.0 {
                    // SAFETY: test-only env var handling.
                    unsafe { std::env::set_var("NSH_TEST_MODE", old) };
                } else {
                    // SAFETY: test-only env var handling.
                    unsafe { std::env::remove_var("NSH_TEST_MODE") };
                }
            }
        }

        let old = std::env::var("NSH_TEST_MODE").ok();
        // SAFETY: test-only env var handling.
        unsafe { std::env::set_var("NSH_TEST_MODE", "1") };
        Guard(old)
    }

    #[test]
    fn test_execute_missing_fields() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "test"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("required"));
    }

    #[test]
    fn test_execute_invalid_name() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "bad name!", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_execute_empty_name() {
        let _guard = with_nsh_test_mode();
        let input = json!({"description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("required"));
    }

    #[test]
    fn test_execute_empty_description() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("required"));
    }

    #[test]
    fn test_execute_empty_command() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "test", "description": "test"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("required"));
    }

    #[test]
    fn test_name_validation_with_special_chars() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "bad.name", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_name_validation_with_spaces() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "bad name", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_name_validation_with_hyphens_rejected() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "bad-name", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_name_numbers_only_valid() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "12345", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_ok(), "Numeric-only name should pass validation");
    }

    #[test]
    fn test_name_leading_underscore_valid() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "_private", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(
            result.is_ok(),
            "Leading underscore name should pass validation"
        );
    }

    #[test]
    fn test_name_with_dash_rejected() {
        let _guard = with_nsh_test_mode();
        let input = json!({"name": "my-skill", "description": "test", "command": "echo"});
        let result = super::execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_toml_content_format() {
        let input = json!({
            "name": "test_skill",
            "description": "A test skill",
            "command": "echo hello",
            "timeout_seconds": 60,
            "terminal": true,
        });

        let name = input["name"].as_str().unwrap();
        let description = input["description"].as_str().unwrap();
        let command = input["command"].as_str().unwrap();
        let timeout = input["timeout_seconds"].as_u64().unwrap();
        let terminal = input["terminal"].as_bool().unwrap();

        let toml_content = format!(
            "name = {}\ndescription = {}\ncommand = {}\ntimeout_seconds = {}\nterminal = {}\n",
            toml::Value::String(name.into()),
            toml::Value::String(description.into()),
            toml::Value::String(command.into()),
            timeout,
            terminal,
        );

        assert!(toml_content.contains("name = \"test_skill\""));
        assert!(toml_content.contains("description = \"A test skill\""));
        assert!(toml_content.contains("command = \"echo hello\""));
        assert!(toml_content.contains("timeout_seconds = 60"));
        assert!(toml_content.contains("terminal = true"));
    }

    #[test]
    fn test_parameters_toml_generation() {
        let params = serde_json::json!({
            "query": {
                "type": "string",
                "description": "Search query"
            },
            "count": {
                "type": "integer",
                "description": "Number of results"
            }
        });

        let mut toml_content = String::new();
        if let serde_json::Value::Object(params_map) = &params {
            for (param_name, param_def) in params_map {
                let ptype = param_def["type"].as_str().unwrap_or("string");
                let pdesc = param_def["description"].as_str().unwrap_or("");
                toml_content.push_str(&format!(
                    "\n[parameters.{param_name}]\ntype = {}\ndescription = {}\n",
                    toml::Value::String(ptype.into()),
                    toml::Value::String(pdesc.into()),
                ));
            }
        }

        assert!(toml_content.contains("[parameters.query]"));
        assert!(toml_content.contains("type = \"string\""));
        assert!(toml_content.contains("description = \"Search query\""));
        assert!(toml_content.contains("[parameters.count]"));
        assert!(toml_content.contains("type = \"integer\""));
        assert!(toml_content.contains("description = \"Number of results\""));
    }

    #[test]
    fn test_toml_default_timeout_and_terminal() {
        let input = json!({
            "name": "my_skill",
            "description": "desc",
            "command": "run",
        });

        let timeout = input["timeout_seconds"].as_u64().unwrap_or(30);
        let terminal = input["terminal"].as_bool().unwrap_or(false);

        let toml_content = format!(
            "name = {}\ndescription = {}\ncommand = {}\ntimeout_seconds = {}\nterminal = {}\n",
            toml::Value::String(input["name"].as_str().unwrap().into()),
            toml::Value::String(input["description"].as_str().unwrap().into()),
            toml::Value::String(input["command"].as_str().unwrap().into()),
            timeout,
            terminal,
        );

        assert_eq!(timeout, 30);
        assert!(!terminal);
        assert!(toml_content.contains("timeout_seconds = 30"));
        assert!(toml_content.contains("terminal = false"));
    }

    #[test]
    fn test_toml_empty_parameters() {
        let params = serde_json::json!({});

        let mut toml_content = String::new();
        if let serde_json::Value::Object(params_map) = &params {
            for (param_name, param_def) in params_map {
                let ptype = param_def["type"].as_str().unwrap_or("string");
                let pdesc = param_def["description"].as_str().unwrap_or("");
                toml_content.push_str(&format!(
                    "\n[parameters.{param_name}]\ntype = {}\ndescription = {}\n",
                    toml::Value::String(ptype.into()),
                    toml::Value::String(pdesc.into()),
                ));
            }
        }

        assert!(
            toml_content.is_empty(),
            "Empty params should produce no TOML output"
        );
    }

    #[test]
    fn test_toml_parameter_missing_fields_uses_defaults() {
        let params = serde_json::json!({
            "bare_param": {}
        });

        let mut toml_content = String::new();
        if let serde_json::Value::Object(params_map) = &params {
            for (param_name, param_def) in params_map {
                let ptype = param_def["type"].as_str().unwrap_or("string");
                let pdesc = param_def["description"].as_str().unwrap_or("");
                toml_content.push_str(&format!(
                    "\n[parameters.{param_name}]\ntype = {}\ndescription = {}\n",
                    toml::Value::String(ptype.into()),
                    toml::Value::String(pdesc.into()),
                ));
            }
        }

        assert!(toml_content.contains("[parameters.bare_param]"));
        assert!(
            toml_content.contains("type = \"string\""),
            "Missing type should default to 'string'"
        );
        assert!(
            toml_content.contains("description = \"\""),
            "Missing description should default to empty"
        );
    }

    #[test]
    fn test_toml_no_parameters_key() {
        let input = json!({
            "name": "my_skill",
            "description": "desc",
            "command": "run",
        });

        let parameters = input.get("parameters");
        let mut toml_content = String::new();
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

        assert!(
            toml_content.is_empty(),
            "No parameters key should produce no TOML parameter output"
        );
    }
}
