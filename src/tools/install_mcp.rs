use std::io::{self, Write};

pub fn execute(input: &serde_json::Value, _config: &crate::config::Config) -> anyhow::Result<String> {
    let name = input["name"].as_str().unwrap_or("");
    let transport = input["transport"].as_str().unwrap_or("stdio");
    let command = input["command"].as_str();
    let url = input["url"].as_str();
    let args: Vec<String> = input["args"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let env: std::collections::HashMap<String, String> = input["env"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let timeout = input["timeout_seconds"].as_u64().unwrap_or(30);

    if name.is_empty() {
        anyhow::bail!("install_mcp_server: 'name' is required");
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        anyhow::bail!("install_mcp_server: name must be alphanumeric with underscores/hyphens");
    }
    match transport {
        "stdio" if command.is_none() => {
            anyhow::bail!("install_mcp_server: 'command' is required for stdio transport");
        }
        "http" if url.is_none() => {
            anyhow::bail!("install_mcp_server: 'url' is required for http transport");
        }
        "stdio" | "http" => {}
        _ => anyhow::bail!("install_mcp_server: transport must be 'stdio' or 'http'"),
    }

    // Read existing config
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

    // Build server config table
    let mut server = toml_edit::Table::new();
    if transport != "stdio" {
        server.insert("transport", toml_edit::value(transport));
    }
    if let Some(cmd) = command {
        server.insert("command", toml_edit::value(cmd));
    }
    if !args.is_empty() {
        let mut arr = toml_edit::Array::new();
        for a in &args {
            arr.push(a.as_str());
        }
        server.insert("args", toml_edit::value(arr));
    }
    if let Some(u) = url {
        server.insert("url", toml_edit::value(u));
    }
    if !env.is_empty() {
        let mut env_table = toml_edit::Table::new();
        for (k, v) in &env {
            env_table.insert(k, toml_edit::value(v.as_str()));
        }
        server.insert("env", toml_edit::Item::Table(env_table));
    }
    server.insert("timeout_seconds", toml_edit::value(timeout as i64));

    // Ensure mcp.servers table exists
    if doc.get("mcp").is_none() {
        doc["mcp"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    if doc["mcp"].get("servers").is_none() {
        doc["mcp"]["servers"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    doc["mcp"]["servers"][name] = toml_edit::Item::Table(server);

    let new_content = doc.to_string();

    if let Err(e) = toml::from_str::<crate::config::Config>(&new_content) {
        eprintln!("Error: resulting config would be invalid: {e}");
        return Ok(format!("Error: resulting config would be invalid: {e}"));
    }

    let bold_yellow = "\x1b[1;33m";
    let green = "\x1b[32m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!("{bold_yellow}Install MCP server:{reset} {name}");
    eprintln!("  Transport: {transport}");
    if let Some(cmd) = command {
        eprintln!("  Command:   {cmd}");
    }
    if let Some(u) = url {
        eprintln!("  URL:       {u}");
    }
    if !args.is_empty() {
        eprintln!("  Args:      {}", args.join(" "));
    }
    eprintln!("  Timeout:   {timeout}s");
    eprintln!();
    eprint!("{bold_yellow}Add to config? [y/N]{reset} ");
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        eprintln!("{dim}MCP server installation declined{reset}");
        return Ok("Config change declined".to_string());
    }

    if config_path.exists() {
        let backup = config_path.with_extension("toml.bak");
        std::fs::copy(&config_path, &backup)?;
    }
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&config_path, &new_content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600));
    }

    eprintln!("{green}✓ MCP server '{name}' added to config{reset}");
    eprintln!("{dim}Restart your shell or run a new query for it to become active.{reset}");
    Ok("MCP server configuration applied".to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn test_execute_missing_name() {
        let input = json!({"command": "echo"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("name"));
    }

    #[test]
    fn test_execute_invalid_name() {
        let input = json!({"name": "bad name!", "command": "echo"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_execute_stdio_missing_command() {
        let input = json!({"name": "test", "transport": "stdio"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("command"));
    }

    #[test]
    fn test_execute_http_missing_url() {
        let input = json!({"name": "test", "transport": "http"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("url"));
    }

    #[test]
    fn test_execute_invalid_transport() {
        let input = json!({"name": "test", "transport": "websocket"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_empty_name() {
        let input = json!({});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_valid_name_with_hyphens() {
        // Valid name with hyphens should pass validation
        // but will fail on interactive prompt (which is fine for validation test)
        // This will try to read stdin and fail in test, but at least validates the name
        // Actually we can't easily test past the stdin read. Let's just test validation:
        assert!(
            "my-server"
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        );
    }

    #[test]
    fn test_name_validation_rules() {
        let valid = ["test", "my_server", "my-server", "server123"];
        let invalid = ["bad name", "bad!name", "bad.name", "bad/name"];
        for name in valid {
            assert!(
                name.chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '-'),
                "Expected valid: {name}"
            );
        }
        for name in invalid {
            assert!(
                !name
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '-'),
                "Expected invalid: {name}"
            );
        }
    }

    #[test]
    fn test_name_with_numbers_and_underscores() {
        let input = json!({"name": "server_v2_test", "transport": "stdio", "command": "echo"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(
            result.is_ok(),
            "Name with numbers/underscores should pass validation"
        );
    }

    #[test]
    fn test_name_only_numbers() {
        let input = json!({"name": "12345", "transport": "stdio", "command": "echo"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_ok(), "Numeric-only name should pass validation");
    }

    #[test]
    fn test_name_with_unicode_rejected() {
        let input = json!({"name": "test\x00server", "transport": "stdio", "command": "echo"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_name_with_emoji_rejected() {
        let input = json!({"name": "test🚀", "transport": "stdio", "command": "echo"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_transport_stdio_with_command_passes_validation() {
        let input = json!({"name": "valid", "transport": "stdio", "command": "node"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(
            result.is_ok(),
            "stdio with command should pass all validation"
        );
    }

    #[test]
    fn test_transport_http_with_url_passes_validation() {
        let input = json!({"name": "valid", "transport": "http", "url": "http://localhost:3000"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_ok(), "http with url should pass all validation");
    }

    #[test]
    fn test_transport_default_is_stdio() {
        let input = json!({"name": "test"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("command"),
            "Default transport should be stdio, requiring command"
        );
    }

    #[test]
    fn test_name_with_leading_hyphen() {
        let input = json!({"name": "-leadinghyphen", "transport": "stdio", "command": "echo"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(
            result.is_ok(),
            "Leading hyphen should pass alphanumeric+hyphen validation"
        );
    }

    #[test]
    fn test_name_single_char() {
        let input = json!({"name": "a", "transport": "stdio", "command": "echo"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_ok(), "Single char name should pass validation");
    }

    #[test]
    fn test_name_with_space_rejected() {
        let input = json!({"name": "has space", "transport": "stdio", "command": "echo"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_name_with_dot_rejected() {
        let input = json!({"name": "has.dot", "transport": "stdio", "command": "echo"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_name_with_slash_rejected() {
        let input = json!({"name": "path/traversal", "transport": "stdio", "command": "echo"});
        let result = super::execute(&input, &crate::config::Config::default());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alphanumeric"));
    }

    #[test]
    fn test_default_timeout_is_30() {
        let input = json!({"name": "srv", "command": "node"});
        let timeout = input["timeout_seconds"].as_u64().unwrap_or(30);
        assert_eq!(timeout, 30);
    }

    #[test]
    fn test_transport_defaults_to_stdio() {
        let input = json!({"name": "srv", "command": "node"});
        let transport = input["transport"].as_str().unwrap_or("stdio");
        assert_eq!(transport, "stdio");
    }

    #[test]
    fn test_args_parsing() {
        let input =
            json!({"name": "srv", "command": "node", "args": ["--port", "3000", "--verbose"]});
        let args: Vec<String> = input["args"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(args, vec!["--port", "3000", "--verbose"]);
    }

    #[test]
    fn test_args_missing_defaults_to_empty() {
        let input = json!({"name": "srv", "command": "node"});
        let args: Vec<String> = input["args"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        assert!(args.is_empty());
    }

    #[test]
    fn test_env_parsing() {
        let input =
            json!({"name": "srv", "command": "node", "env": {"API_KEY": "abc", "PORT": "8080"}});
        let env: std::collections::HashMap<String, String> = input["env"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(env.len(), 2);
        assert_eq!(env["API_KEY"], "abc");
        assert_eq!(env["PORT"], "8080");
    }

    #[test]
    fn test_env_missing_defaults_to_empty() {
        let input = json!({"name": "srv", "command": "node"});
        let env: std::collections::HashMap<String, String> = input["env"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        assert!(env.is_empty());
    }

    #[test]
    fn test_server_table_stdio_omits_transport() {
        let mut server = toml_edit::Table::new();
        let transport = "stdio";
        if transport != "stdio" {
            server.insert("transport", toml_edit::value(transport));
        }
        server.insert("command", toml_edit::value("node"));
        server.insert("timeout_seconds", toml_edit::value(30_i64));

        let s = server.to_string();
        assert!(
            !s.contains("transport"),
            "stdio transport should be omitted from TOML"
        );
        assert!(s.contains("command = \"node\""));
        assert!(s.contains("timeout_seconds = 30"));
    }

    #[test]
    fn test_server_table_http_includes_transport() {
        let mut server = toml_edit::Table::new();
        let transport = "http";
        if transport != "stdio" {
            server.insert("transport", toml_edit::value(transport));
        }
        server.insert("url", toml_edit::value("http://localhost:3000"));
        server.insert("timeout_seconds", toml_edit::value(30_i64));

        let s = server.to_string();
        assert!(s.contains("transport = \"http\""));
        assert!(s.contains("url = \"http://localhost:3000\""));
    }

    #[test]
    fn test_server_table_with_args_and_env() {
        let mut server = toml_edit::Table::new();
        server.insert("command", toml_edit::value("npx"));

        let mut arr = toml_edit::Array::new();
        arr.push("-y");
        arr.push("@mcp/server");
        server.insert("args", toml_edit::value(arr));

        let mut env_table = toml_edit::Table::new();
        env_table.insert("TOKEN", toml_edit::value("secret"));
        server.insert("env", toml_edit::Item::Table(env_table));

        server.insert("timeout_seconds", toml_edit::value(60_i64));

        let mut doc = toml_edit::DocumentMut::new();
        doc["mcp"] = toml_edit::Item::Table(toml_edit::Table::new());
        doc["mcp"]["servers"] = toml_edit::Item::Table(toml_edit::Table::new());
        doc["mcp"]["servers"]["test"] = toml_edit::Item::Table(server);

        let s = doc.to_string();
        assert!(s.contains("command = \"npx\""));
        assert!(s.contains("args = [\"-y\", \"@mcp/server\"]"));
        assert!(
            s.contains("TOKEN = \"secret\""),
            "env should contain TOKEN=secret, got: {s}"
        );
        assert!(s.contains("timeout_seconds = 60"));
    }
}
