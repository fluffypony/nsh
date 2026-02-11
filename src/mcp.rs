use crate::config::{McpConfig, McpServerConfig};
use crate::tools::ToolDefinition;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

const MCP_PROTOCOL_VERSION: &str = "2025-03-26";

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

enum McpTransport {
    Stdio {
        child: Child,
        stdin: tokio::process::ChildStdin,
        stdout: BufReader<tokio::process::ChildStdout>,
    },
    Http {
        client: reqwest::Client,
        url: String,
        session_id: Option<String>,
        headers: Vec<(String, String)>,
    },
}

struct McpServer {
    transport: McpTransport,
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

        match &mut self.transport {
            McpTransport::Stdio { stdin, stdout, .. } => {
                let request = JsonRpcRequest {
                    jsonrpc: "2.0",
                    id,
                    method: method.to_string(),
                    params,
                };
                let mut line = serde_json::to_string(&request)?;
                line.push('\n');
                stdin.write_all(line.as_bytes()).await?;
                stdin.flush().await?;

                let response =
                    tokio::time::timeout(self.timeout, read_stdio_response(stdout, id))
                        .await
                        .map_err(|_| anyhow::anyhow!("MCP stdio request '{method}' timed out"))??;

                if let Some(err) = response.error {
                    anyhow::bail!("MCP error {}: {}", err.code, err.message);
                }
                Ok(response.result.unwrap_or(serde_json::Value::Null))
            }
            McpTransport::Http {
                client,
                url,
                session_id,
                headers,
            } => {
                let request = JsonRpcRequest {
                    jsonrpc: "2.0",
                    id,
                    method: method.to_string(),
                    params,
                };

                let mut req = client
                    .post(url.as_str())
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream")
                    .json(&request);

                if let Some(sid) = session_id {
                    req = req.header("Mcp-Session-Id", sid.as_str());
                }
                for (k, v) in headers.iter() {
                    req = req.header(k.as_str(), v.as_str());
                }

                let resp = tokio::time::timeout(self.timeout, req.send())
                    .await
                    .map_err(|_| anyhow::anyhow!("MCP HTTP request '{method}' timed out"))??
                    .error_for_status()?;

                // Capture session ID
                if let Some(sid) = resp.headers().get("mcp-session-id") {
                    if let Ok(s) = sid.to_str() {
                        *session_id = Some(s.to_string());
                    }
                }

                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                if content_type.contains("text/event-stream") {
                    use futures::StreamExt;
                    let sse_fut = async {
                        let mut body_stream = resp.bytes_stream();
                        let mut raw_buffer: Vec<u8> = Vec::new();
                        while let Some(chunk) = body_stream.next().await {
                            let chunk = chunk?;
                            raw_buffer.extend_from_slice(&chunk);

                            while let Some(pos) = raw_buffer.windows(2).position(|w| w == b"\n\n") {
                                let event_bytes = raw_buffer[..pos].to_vec();
                                raw_buffer = raw_buffer[pos + 2..].to_vec();

                                let event_block = String::from_utf8_lossy(&event_bytes);
                                for line in event_block.lines() {
                                    if let Some(data) = line.strip_prefix("data: ") {
                                        let data = data.trim();
                                        if data.is_empty() {
                                            continue;
                                        }
                                        if let Ok(resp) =
                                            serde_json::from_str::<JsonRpcResponse>(data)
                                        {
                                            if resp.id.is_some() {
                                                if let Some(err) = resp.error {
                                                    anyhow::bail!(
                                                        "MCP error {}: {}",
                                                        err.code,
                                                        err.message
                                                    );
                                                }
                                                return Ok(resp
                                                    .result
                                                    .unwrap_or(serde_json::Value::Null));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        anyhow::bail!("No JSON-RPC response found in SSE stream")
                    };
                    tokio::time::timeout(self.timeout, sse_fut)
                        .await
                        .map_err(|_| {
                            anyhow::anyhow!("MCP SSE response for '{method}' timed out")
                        })?
                } else {
                    let rpc_resp: JsonRpcResponse = resp.json().await?;
                    if let Some(err) = rpc_resp.error {
                        anyhow::bail!("MCP error {}: {}", err.code, err.message);
                    }
                    Ok(rpc_resp.result.unwrap_or(serde_json::Value::Null))
                }
            }
        }
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

        match &mut self.transport {
            McpTransport::Stdio { stdin, .. } => {
                let mut line = serde_json::to_string(&notification)?;
                line.push('\n');
                stdin.write_all(line.as_bytes()).await?;
                stdin.flush().await?;
            }
            McpTransport::Http {
                client,
                url,
                session_id,
                headers,
            } => {
                let mut req = client
                    .post(url.as_str())
                    .header("Content-Type", "application/json")
                    .json(&notification);
                if let Some(sid) = session_id {
                    req = req.header("Mcp-Session-Id", sid.as_str());
                }
                for (k, v) in headers.iter() {
                    req = req.header(k.as_str(), v.as_str());
                }
                let _ = req.send().await;
            }
        }
        Ok(())
    }
}

async fn read_stdio_response(
    stdout: &mut BufReader<tokio::process::ChildStdout>,
    expected_id: u64,
) -> anyhow::Result<JsonRpcResponse> {
    loop {
        let mut line = String::new();
        let n = stdout.read_line(&mut line).await?;
        if n == 0 {
            anyhow::bail!("MCP server closed stdout");
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(trimmed) {
            if resp.id == Some(expected_id) {
                return Ok(resp);
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
                    tracing::debug!(
                        "MCP server '{name}' started with {} tools",
                        server.tools.len()
                    );
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
        let timeout = Duration::from_secs(config.timeout_seconds);
        let transport_type = config.effective_transport();

        let transport = match transport_type.as_str() {
            "http" => {
                let url = config
                    .url
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("MCP server '{name}': url required for http transport"))?
                    .clone();
                let client = reqwest::Client::builder()
                    .timeout(timeout)
                    .build()?;
                let headers: Vec<(String, String)> = config
                    .headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                McpTransport::Http {
                    client,
                    url,
                    session_id: None,
                    headers,
                }
            }
            _ => {
                let cmd_str = config.command.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("MCP server '{name}': command required for stdio transport")
                })?;

                let mut cmd = Command::new(cmd_str);
                cmd.args(&config.args)
                    .envs(&config.env)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null());

                let mut child = cmd.spawn().map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to spawn MCP server '{name}' ({cmd_str}): {e}"
                    )
                })?;

                let stdin = child.stdin.take().unwrap();
                let stdout = BufReader::new(child.stdout.take().unwrap());

                McpTransport::Stdio {
                    child,
                    stdin,
                    stdout,
                }
            }
        };

        let mut server = McpServer {
            transport,
            tools: Vec::new(),
            next_id: 1,
            timeout,
        };

        // Initialize
        server
            .send_request(
                "initialize",
                Some(json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
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

        // List tools
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
        let mut keys: Vec<&str> = self.servers.keys().map(|s| s.as_str()).collect();
        keys.sort_by(|a, b| b.len().cmp(&a.len()));
        for server_name in keys {
            if let Some(tool_name) =
                rest.strip_prefix(server_name).and_then(|s| s.strip_prefix('_'))
            {
                return Some((server_name, tool_name));
            }
        }
        None
    }

    pub fn server_info(&self) -> Vec<(String, usize)> {
        self.servers
            .iter()
            .map(|(name, server)| (name.clone(), server.tools.len()))
            .collect()
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
            if let McpTransport::Stdio { ref mut child, .. } = server.transport {
                let _ = child.kill().await;
            }
        }
        self.servers.clear();
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        for (_, server) in &mut self.servers {
            if let McpTransport::Stdio { ref mut child, .. } = server.transport {
                let _ = child.start_kill();
            }
        }
    }
}
