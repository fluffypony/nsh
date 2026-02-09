use crate::config::{McpConfig, McpServerConfig};
use crate::tools::ToolDefinition;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct JsonRpcNotification {
    jsonrpc: &'static str,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    id: Option<u64>,
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

struct McpToolInfo {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

struct McpServer {
    child: Child,
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
    tools: Vec<McpToolInfo>,
    next_id: u64,
    timeout: Duration,
}

impl McpServer {
    async fn send_request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        let id = self.next_id;
        self.next_id += 1;

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params,
        };

        let mut line = serde_json::to_string(&request)?;
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.flush().await?;

        let response = tokio::time::timeout(self.timeout, self.read_response())
            .await
            .map_err(|_| anyhow::anyhow!("MCP request '{method}' timed out"))??;

        if let Some(err) = response.error {
            anyhow::bail!("MCP error {}: {}", err.code, err.message);
        }

        Ok(response.result.unwrap_or(serde_json::Value::Null))
    }

    async fn send_notification(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        let notification = JsonRpcNotification {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
        };
        let mut line = serde_json::to_string(&notification)?;
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn read_response(&mut self) -> anyhow::Result<JsonRpcResponse> {
        loop {
            let mut line = String::new();
            let n = self.stdout.read_line(&mut line).await?;
            if n == 0 {
                anyhow::bail!("MCP server closed stdout");
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(trimmed) {
                if resp.id.is_some() {
                    return Ok(resp);
                }
            }
        }
    }
}

pub struct McpClient {
    servers: HashMap<String, McpServer>,
}

impl McpClient {
    pub fn new() -> Self {
        Self {
            servers: HashMap::new(),
        }
    }

    pub async fn start_servers(&mut self, config: &McpConfig) {
        for (name, server_config) in &config.servers {
            match Self::start_server(name, server_config).await {
                Ok(server) => {
                    tracing::debug!("MCP server '{name}' started with {} tools", server.tools.len());
                    self.servers.insert(name.clone(), server);
                }
                Err(e) => {
                    tracing::warn!("Failed to start MCP server '{name}': {e}");
                }
            }
        }
    }

    async fn start_server(
        name: &str,
        config: &McpServerConfig,
    ) -> anyhow::Result<McpServer> {
        let mut cmd = Command::new(&config.command);
        cmd.args(&config.args)
            .envs(&config.env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());

        let mut child = cmd.spawn().map_err(|e| {
            anyhow::anyhow!("Failed to spawn MCP server '{name}' ({}): {e}", config.command)
        })?;

        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let timeout = Duration::from_secs(config.timeout_seconds);

        let mut server = McpServer {
            child,
            stdin,
            stdout,
            tools: Vec::new(),
            next_id: 1,
            timeout,
        };

        server
            .send_request(
                "initialize",
                Some(json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "nsh",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })),
            )
            .await?;

        server
            .send_notification("notifications/initialized", None)
            .await
            .ok();

        let tools_result = server.send_request("tools/list", None).await?;

        if let Some(tools) = tools_result.get("tools").and_then(|t| t.as_array()) {
            for tool in tools {
                let tool_name = tool
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let description = tool
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                let input_schema = tool
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or(json!({"type": "object", "properties": {}}));

                if !tool_name.is_empty() {
                    server.tools.push(McpToolInfo {
                        name: tool_name,
                        description,
                        input_schema,
                    });
                }
            }
        }

        Ok(server)
    }

    pub fn tool_definitions(&self) -> Vec<ToolDefinition> {
        let mut defs = Vec::new();
        for (server_name, server) in &self.servers {
            for tool in &server.tools {
                defs.push(ToolDefinition {
                    name: format!("mcp_{server_name}_{}", tool.name),
                    description: tool.description.clone(),
                    parameters: tool.input_schema.clone(),
                });
            }
        }
        defs
    }

    pub fn has_tool(&self, prefixed_name: &str) -> bool {
        self.parse_tool_name(prefixed_name).is_some()
    }

    fn parse_tool_name<'a>(&'a self, prefixed_name: &'a str) -> Option<(&'a str, &'a str)> {
        let rest = prefixed_name.strip_prefix("mcp_")?;
        for server_name in self.servers.keys() {
            if let Some(tool_name) = rest.strip_prefix(server_name).and_then(|s| s.strip_prefix('_'))
            {
                return Some((server_name.as_str(), tool_name));
            }
        }
        None
    }

    pub async fn call_tool(
        &mut self,
        prefixed_name: &str,
        input: serde_json::Value,
    ) -> anyhow::Result<String> {
        let (server_name, tool_name) = self
            .parse_tool_name(prefixed_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown MCP tool: {prefixed_name}"))?;

        let server_name = server_name.to_string();
        let tool_name = tool_name.to_string();

        let server = self
            .servers
            .get_mut(&server_name)
            .ok_or_else(|| anyhow::anyhow!("MCP server '{server_name}' not found"))?;

        let result = server
            .send_request(
                "tools/call",
                Some(json!({
                    "name": tool_name,
                    "arguments": input
                })),
            )
            .await?;

        if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
            let texts: Vec<&str> = content
                .iter()
                .filter_map(|item| item.get("text").and_then(|t| t.as_str()))
                .collect();
            if !texts.is_empty() {
                return Ok(texts.join("\n"));
            }
        }

        Ok(serde_json::to_string_pretty(&result)?)
    }

    pub async fn shutdown(&mut self) {
        for (name, server) in &mut self.servers {
            if let Err(e) = server.send_request("shutdown", None).await {
                tracing::debug!("MCP server '{name}' shutdown error: {e}");
            }
            let _ = server.child.kill().await;
        }
        self.servers.clear();
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        for (_, server) in &mut self.servers {
            let _ = server.child.start_kill();
        }
    }
}
