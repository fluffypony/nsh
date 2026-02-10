use std::io::{self, Write};

pub fn execute(
    input: &serde_json::Value,
    _config: &crate::config::Config,
) -> anyhow::Result<()> {
    let name = input["name"].as_str().unwrap_or("");
    let transport = input["transport"].as_str().unwrap_or("stdio");
    let command = input["command"].as_str();
    let url = input["url"].as_str();
    let args: Vec<String> = input["args"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
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
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
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

    let mut doc: toml::Value = if content.is_empty() {
        toml::Value::Table(Default::default())
    } else {
        toml::from_str(&content)?
    };

    // Build server config table
    let mut server = toml::map::Map::new();
    if transport != "stdio" {
        server.insert("transport".into(), toml::Value::String(transport.into()));
    }
    if let Some(cmd) = command {
        server.insert("command".into(), toml::Value::String(cmd.into()));
    }
    if !args.is_empty() {
        server.insert(
            "args".into(),
            toml::Value::Array(args.iter().map(|a| toml::Value::String(a.clone())).collect()),
        );
    }
    if let Some(u) = url {
        server.insert("url".into(), toml::Value::String(u.into()));
    }
    if !env.is_empty() {
        let mut env_table = toml::map::Map::new();
        for (k, v) in &env {
            env_table.insert(k.clone(), toml::Value::String(v.clone()));
        }
        server.insert("env".into(), toml::Value::Table(env_table));
    }
    server.insert("timeout_seconds".into(), toml::Value::Integer(timeout as i64));

    // Insert into config TOML tree
    if let toml::Value::Table(root) = &mut doc {
        let mcp = root
            .entry("mcp")
            .or_insert(toml::Value::Table(Default::default()));
        if let toml::Value::Table(mcp_table) = mcp {
            let servers = mcp_table
                .entry("servers")
                .or_insert(toml::Value::Table(Default::default()));
            if let toml::Value::Table(servers_table) = servers {
                servers_table.insert(name.into(), toml::Value::Table(server));
            }
        }
    }

    let new_content = toml::to_string_pretty(&doc)?;

    if let Err(e) = toml::from_str::<crate::config::Config>(&new_content) {
        eprintln!("Error: resulting config would be invalid: {e}");
        return Ok(());
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
        return Ok(());
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
    Ok(())
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
}