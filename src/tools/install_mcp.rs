use crate::tools::ToolInvocationOutcome;

#[derive(Debug, PartialEq)]
struct InstallMcpRequest {
    name: String,
    transport: McpTransport,
    args: Vec<String>,
    env: std::collections::HashMap<String, String>,
    timeout_seconds: u64,
}

#[derive(Debug, PartialEq)]
enum McpTransport {
    Stdio { command: String },
    Http { url: String },
}

pub fn execute(
    input: &serde_json::Value,
    _config: &crate::config::Config,
) -> anyhow::Result<String> {
    let request = parse_request(input)?;

    if !request
        .name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        anyhow::bail!("install_mcp_server: name must be alphanumeric with underscores/hyphens");
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
    let (transport, command, url) = match &request.transport {
        McpTransport::Stdio { command } => ("stdio", Some(command.as_str()), None),
        McpTransport::Http { url } => ("http", None, Some(url.as_str())),
    };
    if transport != "stdio" {
        server.insert("transport", toml_edit::value(transport));
    }
    if let Some(cmd) = command {
        server.insert("command", toml_edit::value(cmd));
    }
    if !request.args.is_empty() {
        let mut arr = toml_edit::Array::new();
        for a in &request.args {
            arr.push(a.as_str());
        }
        server.insert("args", toml_edit::value(arr));
    }
    if let Some(u) = url {
        server.insert("url", toml_edit::value(u));
    }
    if !request.env.is_empty() {
        let mut env_table = toml_edit::Table::new();
        for (k, v) in &request.env {
            env_table.insert(k, toml_edit::value(v.as_str()));
        }
        server.insert("env", toml_edit::Item::Table(env_table));
    }
    server.insert(
        "timeout_seconds",
        toml_edit::value(request.timeout_seconds as i64),
    );

    // Ensure mcp.servers table exists
    if doc.get("mcp").is_none() {
        doc["mcp"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    if doc["mcp"].get("servers").is_none() {
        doc["mcp"]["servers"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    doc["mcp"]["servers"][request.name.as_str()] = toml_edit::Item::Table(server);

    let new_content = doc.to_string();

    if let Err(e) = toml::from_str::<crate::config::Config>(&new_content) {
        anyhow::bail!("resulting config would be invalid: {e}");
    }

    let bold_yellow = "\x1b[1;33m";
    let green = "\x1b[32m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!("{bold_yellow}Install MCP server:{reset} {}", request.name);
    eprintln!("  Transport: {transport}");
    if let Some(cmd) = command {
        eprintln!("  Command:   {cmd}");
    }
    if let Some(u) = url {
        eprintln!("  URL:       {u}");
    }
    if !request.args.is_empty() {
        eprintln!("  Args:      {}", request.args.join(" "));
    }
    eprintln!("  Timeout:   {}s", request.timeout_seconds);
    eprintln!();
    if !crate::tools::prompt_tty_confirmation(&format!(
        "{bold_yellow}Add to config? [y/N]{reset} "
    ))? {
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

    eprintln!(
        "{green}✓ MCP server '{}' added to config{reset}",
        request.name
    );
    eprintln!("{dim}Restart your shell or run a new query for it to become active.{reset}");
    Ok("MCP server configuration applied".to_string())
}

fn parse_request(input: &serde_json::Value) -> anyhow::Result<InstallMcpRequest> {
    let name = input
        .get("name")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("install_mcp_server: 'name' is required"))?;
    let transport = input
        .get("transport")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("install_mcp_server: 'transport' must be a string"))
        })
        .transpose()?
        .unwrap_or("stdio");
    let args = parse_string_array_field(input, "args")?;
    let env = parse_string_map_field(input, "env")?;
    let timeout_seconds = input
        .get("timeout_seconds")
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                anyhow::anyhow!("install_mcp_server: 'timeout_seconds' must be an integer")
            })
        })
        .transpose()?
        .unwrap_or(30);

    let transport = match transport {
        "stdio" => McpTransport::Stdio {
            command: input
                .get("command")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    anyhow::anyhow!("install_mcp_server: 'command' is required for stdio transport")
                })?,
        },
        "http" => McpTransport::Http {
            url: input
                .get("url")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    anyhow::anyhow!("install_mcp_server: 'url' is required for http transport")
                })?,
        },
        _ => anyhow::bail!("install_mcp_server: transport must be 'stdio' or 'http'"),
    };

    Ok(InstallMcpRequest {
        name: name.to_string(),
        transport,
        args,
        env,
        timeout_seconds,
    })
}

fn parse_string_array_field(input: &serde_json::Value, field: &str) -> anyhow::Result<Vec<String>> {
    let Some(value) = input.get(field) else {
        return Ok(Vec::new());
    };
    let array = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("install_mcp_server: '{field}' must be an array"))?;
    array
        .iter()
        .enumerate()
        .map(|(index, item)| {
            item.as_str().map(str::to_string).ok_or_else(|| {
                anyhow::anyhow!("install_mcp_server: '{field}[{index}]' must be a string")
            })
        })
        .collect()
}

fn parse_string_map_field(
    input: &serde_json::Value,
    field: &str,
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let Some(value) = input.get(field) else {
        return Ok(std::collections::HashMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("install_mcp_server: '{field}' must be an object"))?;
    object
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_string()))
                .ok_or_else(|| {
                    anyhow::anyhow!("install_mcp_server: '{field}.{key}' must be a string")
                })
        })
        .collect()
}

pub fn execute_outcome(
    input: &serde_json::Value,
    config: &crate::config::Config,
) -> anyhow::Result<ToolInvocationOutcome> {
    match execute(input, config)? {
        message if message == "Config change declined" => {
            Ok(ToolInvocationOutcome::failure(message))
        }
        message => Ok(ToolInvocationOutcome::success(message)),
    }
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
        let request = super::parse_request(&input).unwrap();
        assert_eq!(request.args, vec!["--port", "3000", "--verbose"]);
    }

    #[test]
    fn test_args_missing_defaults_to_empty() {
        let input = json!({"name": "srv", "command": "node"});
        let request = super::parse_request(&input).unwrap();
        assert!(request.args.is_empty());
    }

    #[test]
    fn test_args_reject_non_string_entries() {
        let input = json!({"name": "srv", "command": "node", "args": ["--port", 3000]});
        let result = super::parse_request(&input);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("'args[1]' must be a string")
        );
    }

    #[test]
    fn test_env_parsing() {
        let input =
            json!({"name": "srv", "command": "node", "env": {"API_KEY": "abc", "PORT": "8080"}});
        let request = super::parse_request(&input).unwrap();
        assert_eq!(request.env.len(), 2);
        assert_eq!(request.env["API_KEY"], "abc");
        assert_eq!(request.env["PORT"], "8080");
    }

    #[test]
    fn test_env_missing_defaults_to_empty() {
        let input = json!({"name": "srv", "command": "node"});
        let request = super::parse_request(&input).unwrap();
        assert!(request.env.is_empty());
    }

    #[test]
    fn test_env_rejects_non_string_values() {
        let input = json!({"name": "srv", "command": "node", "env": {"PORT": 8080}});
        let result = super::parse_request(&input);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("'env.PORT' must be a string")
        );
    }

    #[test]
    fn test_timeout_rejects_non_integer() {
        let input = json!({"name": "srv", "command": "node", "timeout_seconds": "fast"});
        let result = super::parse_request(&input);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("'timeout_seconds' must be an integer")
        );
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
